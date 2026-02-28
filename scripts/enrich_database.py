#!/usr/bin/env python3
"""
Nexus Automation Framework - Knowledge Enrichment Script

Populates the advanced tables in knowledge.db:
1. exploit_patterns (via Exploit-DB)
2. evasion_patterns (via Atomic Red Team)
3. service_vulnerabilities (Aggregation from CISA KEV and CVEs)
"""

import asyncio
import json
import logging
import sqlite3
import requests
import csv
from io import StringIO
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from nexus_framework.strategic.knowledge import (
    KnowledgeDatabase, ExploitPattern, EvasionPattern, ServiceVulnerability
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class KnowledgeEnricher:
    """Enriches the secondary tables of knowledge.db."""
    
    def __init__(self, db_path: str = "knowledge.db"):
        self.db_path = db_path
        self.knowledge_db = KnowledgeDatabase(db_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Nexus-Automation-Framework/1.0 (Enricher)'
        })
        
    def import_exploit_db(self) -> int:
        """Import exploit patterns from Exploit-DB CSV."""
        logger.info("🔄 Downloading Exploit-DB manifest...")
        url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            reader = list(csv.DictReader(StringIO(resp.text)))
        except Exception as e:
            logger.error(f"❌ Failed to download Exploit-DB data: {e}")
            return 0
            
        imported = 0
        for row in reader:
            # We don't want to import all 45k, just map a solid chunk for patterns
            if imported >= 5000:
                break
                
            edb_id = row.get("id")
            description = row.get("description", "")
            type_str = row.get("type", "Unknown")
            platform = row.get("platform", "Unknown")
            
            pattern = ExploitPattern(
                pattern_id=f"EDB-{edb_id}",
                name=f"[{platform}] {description[:100]}",
                vulnerability_type=type_str,
                exploitation_method="Public PoC Exploit",
                required_conditions=[f"Platform: {platform}"],
                success_indicators=["Code execution", "Privilege escalation", "Data exfiltration"],
                failure_indicators=["Access denied", "Not vulnerable"],
                side_effects=["Possible service crash"],
                detection_signatures=[f"Exploit-DB ID: {edb_id}"],
                mitigation_techniques=["Apply vendor patch"]
            )
            
            if self.knowledge_db.add_exploit_pattern(pattern):
                imported += 1
                
        logger.info(f"🎯 Exploit-DB import completed: {imported} exploit patterns added.")
        return imported

    def import_unprotect_evasion(self) -> int:
        """Import evasion patterns from Unprotect Project API."""
        logger.info("🔄 Downloading Unprotect evasion techniques...")
        url = "https://unprotect.it/api/techniques/"
        
        imported = 0
        while url:
            try:
                resp = self.session.get(url, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.error(f"❌ Failed to download Unprotect data: {e}")
                break
                
            for technique in data.get("results", []):
                pattern_id = f"UPR-{technique.get('id', 'UNK')}"
                name = technique.get("name", "Unknown Evasion")
                desc = technique.get("description", "Evasion technique.")
                platforms = [p.get("name") for p in technique.get("platforms", [])] if isinstance(technique.get("platforms"), list) else []
                category = technique.get("category", {}).get("name") if isinstance(technique.get("category"), dict) else "General"
                
                evasion_tech = EvasionPattern(
                    pattern_id=pattern_id,
                    name=f"[{category}] {name}",
                    evasion_technique=desc[:200] + "..." if len(desc) > 200 else desc,
                    target_defenses=["Heuristics", "Sandbox", "AV/EDR"],
                    implementation_methods=platforms,
                    detection_bypasses=[desc[:50] + "..." if len(desc) > 50 else desc],
                    effectiveness_score=0.9,
                    countermeasures=["Advanced dynamic analysis", "Behavioral monitoring"]
                )
                
                if self.knowledge_db.add_evasion_pattern(evasion_tech):
                    imported += 1
            
            url = data.get("next")
            
        logger.info(f"🎯 Unprotect API import completed: {imported} evasion patterns added.")
        return imported

    def generate_service_vulnerabilities(self) -> int:
        """Generate Service to CVE mapping by parsing CISA KEV entries."""
        logger.info("🔄 Generating Service Vulnerabilities from database KEV/CVEs...")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Fetch CVEs with high/critical severity and affected products
                cursor.execute("SELECT cve_id, affected_products FROM cve_entries WHERE exploit_available = 1 AND severity >= 0.7")
                rows = cursor.fetchall()
        except Exception as e:
            logger.error(f"❌ Failed to query database: {e}")
            return 0
            
        service_map = {}
        for cve_id, products_str in rows:
            try:
                products = json.loads(products_str)
                if len(products) >= 2:
                    vendor = products[0].lower()
                    product = products[1].lower()
                    
                    if vendor and product:
                        key = f"{vendor}_{product}"
                        if key not in service_map:
                            service_map[key] = {
                                "service_name": f"{vendor.capitalize()} {product.capitalize()}",
                                "cve_ids": []
                            }
                        service_map[key]["cve_ids"].append(cve_id)
            except:
                pass
                
        imported = 0
        for key, data in service_map.items():
            # Skip noise
            if len(key) < 4: continue
            
            cve_list = data["cve_ids"][:50] # Limit to top 50 CVEs per service
            
            # Predict default port/protocol roughly based on name
            port = 0
            protocol = "tcp"
            if "apache" in key or "http" in key or "nginx" in key:
                port = 80
            elif "ssh" in key:
                port = 22
            elif "mysql" in key:
                port = 3306
            elif "dns" in key:
                port = 53
                protocol = "udp"
            elif "smb" in key or "microsoft" in key:
                port = 445
                
            service_vuln = ServiceVulnerability(
                service_name=data["service_name"],
                service_version="Various",
                port=port if port > 0 else None,
                protocol=protocol,
                cve_ids=cve_list,
                default_credentials=[],
                common_misconfigurations=["Outdated version", "Default configuration"],
                exploitation_methods=["Public exploit available"],
                detection_signatures=[data["service_name"]]
            )
            
            if self.knowledge_db.add_service_vulnerability(service_vuln):
                imported += 1
                
        logger.info(f"🎯 Service Vulnerabilities generation completed: {imported} services mapped.")
        return imported
        
async def main():
    enricher = KnowledgeEnricher()
    total = 0
    total += enricher.import_exploit_db()
    total += enricher.import_unprotect_evasion()
    total += enricher.generate_service_vulnerabilities()
    logger.info(f"🚀 Enrichment fully completed. {total} new records in advanced tables.")

if __name__ == "__main__":
    asyncio.run(main())
