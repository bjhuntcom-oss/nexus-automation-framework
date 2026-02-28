#!/usr/bin/env python3
"""
Nexus Automation Framework - CVE Database Import Script

This script imports the complete CVE database from multiple sources:
1. NVD JSON 2.0 Feeds (Official US Government source)
2. CVEProject/cvelistV5 (Official CVE records)
3. fkie-cad/nvd-json-data-feeds (Community reconstruction)
4. olbat/nvdcve (Daily updated JSON files)

Usage:
    python scripts/import_cve_database.py --source nvd
    python scripts/import_cve_database.py --source all
    python scripts/import_cve_database.py --source github --limit 1000
"""

import argparse
import asyncio
import json
import logging
import sqlite3
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import sys
import os

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from nexus_framework.strategic.knowledge import (
    KnowledgeDatabase, CVEEntry, VulnerabilitySeverity
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CVEImporter:
    """Complete CVE database importer from multiple sources."""
    
    def __init__(self, db_path: str = "knowledge.db"):
        self.db_path = db_path
        self.knowledge_db = KnowledgeDatabase(db_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Nexus-Automation-Framework/1.0 (CVE-Importer)'
        })
        
    async def import_from_nvd_api(self, limit: Optional[int] = None) -> int:
        """Import CVEs from NVD JSON 2.0 API."""
        logger.info("🔄 Starting NVD API import...")
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params: Dict[str, str] = {}
        
        total_imported = 0
        page = 0
        results_per_page = 2000
        
        while True:
            if limit and total_imported >= limit:
                break
                
            params['startIndex'] = str(page * results_per_page)
            params['resultsPerPage'] = str(results_per_page)
            
            try:
                response = self.session.get(base_url, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                if 'vulnerabilities' not in data or not data['vulnerabilities']:
                    logger.info("✅ No more CVEs to import from NVD")
                    break
                
                cves = data['vulnerabilities']
                logger.info(f"📥 Processing page {page + 1} with {len(cves)} CVEs...")
                
                imported_count = await self._process_nvd_cves(cves[:limit - total_imported] if limit else cves)
                total_imported += imported_count
                
                logger.info(f"✅ Page {page + 1} imported {imported_count} CVEs (total: {total_imported})")
                
                page += 1
                
                # Rate limiting - NVD allows 5 requests per 30 seconds window
                if page % 5 == 0:
                    logger.info("⏱️ Rate limiting - waiting 30 seconds...")
                    await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"❌ Error importing from NVD API: {e}")
                break
        
        logger.info(f"🎯 NVD import completed: {total_imported} CVEs imported")
        return total_imported
    
    async def _process_nvd_cves(self, cves: List[Dict[str, Any]]) -> int:
        """Process CVEs from NVD API format."""
        imported = 0
        
        for cve_data in cves:
            try:
                cve_entry = self._convert_nvd_to_cve_entry(cve_data)
                if cve_entry and self.knowledge_db.add_cve_entry(cve_entry):
                    imported += 1
            except Exception as e:
                logger.warning(f"⚠️ Failed to process CVE {cve_data.get('cve', {}).get('id', 'Unknown')}: {e}")
        
        return imported
    
    def _convert_nvd_to_cve_entry(self, cve_data: Dict[str, Any]) -> Optional[CVEEntry]:
        """Convert NVD API format to CVEEntry."""
        try:
            cve = cve_data.get('cve', {})
            metrics = cve_data.get('metrics', {})
            
            # Get CVSS score (try v4 first, then v3, then v2)
            cvss_score = 0.0
            cvss_vector = ""
            severity = VulnerabilitySeverity.LOW
            
            # CVSS v4
            if 'cvssMetricV40' in metrics:
                cvss_data = metrics['cvssMetricV40'][0]['cvssV4']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = self._cvss_to_severity(cvss_score)
            
            # CVSS v3.1
            elif 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssV3_1']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = self._cvss_to_severity(cvss_score)
            
            # CVSS v3.0
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssV3']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = self._cvss_to_severity(cvss_score)
            
            # CVSS v2
            elif 'cvssMetricV20' in metrics:
                cvss_data = metrics['cvssMetricV20'][0]['cvssV2']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = self._cvss_to_severity(cvss_score)
            
            # Extract dates
            published_date = datetime.fromisoformat(cve.get('published', '2020-01-01T00:00:00.000'))
            modified_date = datetime.fromisoformat(cve.get('lastModified', published_date.isoformat()))
            
            # Extract affected products
            affected_products = []
            if 'configurations' in cve_data:
                for config in cve_data['configurations']:
                    for node in config.get('nodes', []):
                        if 'cpeMatch' in node:
                            for match in node['cpeMatch']:
                                if 'criteria' in match:
                                    affected_products.append(match['criteria'])
            
            # Check if exploit is available
            exploit_available = any(
                'exploit' in desc.lower() or 'poc' in desc.lower()
                for desc in [cve.get('descriptions', [{}])[0].get('value', '')]
            )
            
            return CVEEntry(
                cve_id=cve['id'],
                description=cve.get('descriptions', [{}])[0].get('value', ''),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published_date,
                modified_date=modified_date,
                affected_products=affected_products[:10],  # Limit to 10 products
                references=[],
                exploit_available=exploit_available,
                exploit_complexity="Unknown",
                required_privileges="Unknown",
                user_interaction=False,
                scope_changed=False,
                confidentiality_impact="Unknown",
                integrity_impact="Unknown",
                availability_impact="Unknown"
            )
            
        except Exception as e:
            logger.error(f"Error converting CVE {cve_data.get('cve', {}).get('id', 'Unknown')}: {e}")
            return None
    
    def _cvss_to_severity(self, score: float) -> VulnerabilitySeverity:
        """Convert CVSS score to severity enum."""
        if score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        else:
            return VulnerabilitySeverity.LOW

    async def import_attack_techniques_from_mitre(self, limit: Optional[int] = None) -> int:
        """Import MITRE ATT&CK techniques from the official STIX bundle."""
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        logger.info("🔄 Downloading MITRE ATT&CK bundle...")
        try:
            resp = self.session.get(url, timeout=120)
            resp.raise_for_status()
            bundle = resp.json()
        except Exception as e:
            logger.error(f"❌ Failed to download MITRE ATT&CK data: {e}")
            return 0

        imported = 0
        objects = bundle.get("objects", [])
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if limit and imported >= limit:
                break

            technique_id = next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None)
            if not technique_id:
                continue

            name = obj.get("name", "")
            description = obj.get("description", "")
            phase_names = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
            platforms = obj.get("x_mitre_platforms", [])
            permissions = obj.get("x_mitre_permissions_required", [])
            data_sources = obj.get("x_mitre_data_sources", [])
            detection = obj.get("x_mitre_detection", "")

            # Map phase to enum (fallback to DISCOVERY)
            from nexus_framework.strategic.knowledge import AttackPhase, AttackTechnique
            phase_map = {
                "reconnaissance": AttackPhase.RECONNAISSANCE,
                "initial-access": AttackPhase.INITIAL_ACCESS,
                "execution": AttackPhase.EXECUTION,
                "persistence": AttackPhase.PERSISTENCE,
                "privilege-escalation": AttackPhase.PRIVILEGE_ESCALATION,
                "defense-evasion": AttackPhase.DEFENSE_EVASION,
                "credential-access": AttackPhase.CREDENTIAL_ACCESS,
                "discovery": AttackPhase.DISCOVERY,
                "lateral-movement": AttackPhase.LATERAL_MOVEMENT,
                "collection": AttackPhase.COLLECTION,
                "command-and-control": AttackPhase.COMMAND_AND_CONTROL,
                "exfiltration": AttackPhase.EXFILTRATION,
                "impact": AttackPhase.IMPACT,
            }
            phase_value = phase_map.get(phase_names[0], AttackPhase.DISCOVERY) if phase_names else AttackPhase.DISCOVERY

            technique = AttackTechnique(
                technique_id=technique_id,
                name=name,
                description=description,
                phase=phase_value,
                platforms=platforms,
                required_permissions=permissions,
                data_sources=data_sources,
                detection_methods=[detection] if detection else [],
                mitigation=obj.get("x_mitre_mitigations", ""),
                effectiveness_score=0.7,
                detection_difficulty="Unknown",
                tool_requirements=obj.get("x_mitre_tools", []),
                sub_techniques=obj.get("x_mitre_is_subtechnique", []),
            )

            if self.knowledge_db.add_attack_technique(technique):
                imported += 1

        logger.info(f"🎯 MITRE ATT&CK import completed: {imported} techniques")
        return imported

    async def import_from_cisa_kev(self) -> int:
        """Import CISA Known Exploited Vulnerabilities (KEV) catalog."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        logger.info("🔄 Downloading CISA KEV catalog...")
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(f"❌ Failed to download CISA KEV: {e}")
            return 0

        vulnerabilities = data.get("vulnerabilities", [])
        logger.info(f"📥 Processing {len(vulnerabilities)} KEV entries...")
        
        imported = 0
        for kev in vulnerabilities:
            cve_id = kev.get("cveID")
            if not cve_id:
                continue
                
            # Update existing CVE or create new skeleton
            # Since KEV only has some info, we'll try to fetch full info if not present
            # For now, just mark exploit_available = True
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    # Check if CVE exists
                    cursor.execute("SELECT cve_id FROM cve_entries WHERE cve_id = ?", (cve_id,))
                    exists = cursor.fetchone()
                    
                    if exists:
                        cursor.execute("""
                            UPDATE cve_entries 
                            SET exploit_available = 1, 
                                exploit_complexity = 'Known Exploited'
                            WHERE cve_id = ?
                        """, (cve_id,))
                    else:
                        # Create minimal entry
                        published = datetime.now() # Fallback
                        cve_entry = CVEEntry(
                            cve_id=cve_id,
                            description=kev.get("shortDescription", "CISA Known Exploited Vulnerability"),
                            severity=VulnerabilitySeverity.HIGH,
                            cvss_score=8.0,
                            cvss_vector="Unknown",
                            published_date=published,
                            modified_date=published,
                            affected_products=[kev.get("vendorProject", ""), kev.get("product", "")],
                            references=[kev.get("requiredAction", "")],
                            exploit_available=True,
                            exploit_complexity="Known Exploited",
                            required_privileges="Unknown",
                            user_interaction=False,
                            scope_changed=False,
                            confidentiality_impact="Unknown",
                            integrity_impact="Unknown",
                            availability_impact="Unknown"
                        )
                        self.knowledge_db.add_cve_entry(cve_entry)
                    conn.commit()
                    imported += 1
            except Exception as e:
                logger.warning(f"⚠️ Failed to process KEV {cve_id}: {e}")
                
        logger.info(f"🎯 CISA KEV import completed: {imported} vulnerabilities flagged as known exploited")
        return imported

    async def import_from_olbat_nvdcve(self, years: Optional[List[int]] = None, limit: Optional[int] = None) -> int:
        """Import CVEs from olbat/nvdcve JSON feeds (yearly files, .json.gz when available)."""
        if years is None:
            years = list(range(2023, 2001, -1))  # 2023 back to 2002

        base = "https://raw.githubusercontent.com/olbat/nvdcve/master/"
        total = 0
        for year in years:
            if limit and total >= limit:
                break
            url_gz = f"{base}nvdcve-1.1-{year}.json.gz"
            url_json = f"{base}nvdcve-1.1-{year}.json"
            url = url_gz
            logger.info(f"🔄 Downloading olbat nvdcve feed for {year}...")
            try:
                resp = self.session.get(url, timeout=180)
                if resp.status_code == 404:
                    url = url_json
                    resp = self.session.get(url, timeout=180)
                resp.raise_for_status()
                content = resp.content
                if url.endswith('.gz'):
                    import gzip
                    data = json.loads(gzip.decompress(content).decode('utf-8'))
                else:
                    data = resp.json()
            except Exception as e:
                logger.error(f"❌ Failed to download {url}: {e}")
                continue

            cve_items = data.get("CVE_Items", []) if isinstance(data, dict) else data
            logger.info(f"📥 Processing {len(cve_items)} CVEs from {year}...")
            imported = await self._process_github_cves(cve_items[: limit - total] if limit else cve_items)
            total += imported
            logger.info(f"✅ {year}: {imported} CVEs imported (total {total})")

        logger.info(f"🎯 olbat/nvdcve import completed: {total} CVEs")
        return total
    
    async def import_from_github_releases(self, repo: str, limit: Optional[int] = None) -> int:
        """Import CVEs from GitHub releases (fkie-cad/nvd-json-data-feeds)."""
        logger.info(f"🔄 Starting GitHub import from {repo}...")
        
        try:
            # Get latest release
            api_url = f"https://api.github.com/repos/{repo}/releases/latest"
            response = self.session.get(api_url, timeout=30)
            response.raise_for_status()
            
            release_data = response.json()
            assets = release_data.get('assets', [])
            
            # Find CVE JSON files
            cve_files = [
                asset for asset in assets 
                if asset['name'].startswith('CVE-') and asset['name'].endswith('.json')
            ]
            
            if not cve_files:
                logger.warning("⚠️ No CVE JSON files found in release")
                return 0
            
            total_imported = 0
            
            for asset in cve_files[:5]:  # Limit to 5 most recent years
                if limit and total_imported >= limit:
                    break
                
                logger.info(f"📥 Downloading {asset['name']} ({asset['size']/1024/1024:.1f}MB)...")
                
                # Download file
                download_url = asset['browser_download_url']
                response = self.session.get(download_url, timeout=300)
                response.raise_for_status()
                
                # Process CVEs
                cve_data = response.json()
                if isinstance(cve_data, dict) and 'CVE_Items' in cve_data:
                    # Old NVD format
                    cve_items = cve_data['CVE_Items']
                elif isinstance(cve_data, list):
                    # New format
                    cve_items = cve_data
                else:
                    logger.warning(f"⚠️ Unknown format in {asset['name']}")
                    continue
                
                imported = await self._process_github_cves(cve_items[:limit - total_imported] if limit else cve_items)
                total_imported += imported
                
                logger.info(f"✅ {asset['name']}: {imported} CVEs imported")
            
            logger.info(f"🎯 GitHub import completed: {total_imported} CVEs imported")
            return total_imported
            
        except Exception as e:
            logger.error(f"❌ Error importing from GitHub: {e}")
            return 0
    
    async def _process_github_cves(self, cve_items: List[Dict[str, Any]]) -> int:
        """Process CVEs from GitHub format."""
        imported = 0
        
        for item in cve_items:
            try:
                cve_entry = self._convert_github_to_cve_entry(item)
                if cve_entry and self.knowledge_db.add_cve_entry(cve_entry):
                    imported += 1
            except Exception as e:
                logger.warning(f"⚠️ Failed to process GitHub CVE: {e}")
        
        return imported
    
    def _convert_github_to_cve_entry(self, item: Dict[str, Any]) -> Optional[CVEEntry]:
        """Convert GitHub format to CVEEntry."""
        try:
            cve = item.get('cve', {})
            impact = item.get('impact', {})
            
            # Extract basic info
            cve_id = cve.get('CVE_data_meta', {}).get('ID', '')
            description = cve.get('description', {}).get('description_data', [{}])[0].get('value', '')
            
            # Extract CVSS
            cvss_score = 0.0
            cvss_vector = ""
            severity = VulnerabilitySeverity.LOW
            
            if 'baseMetricV3' in impact:
                cvss_data = impact['baseMetricV3']['cvssV3']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = self._cvss_to_severity(cvss_score)
            elif 'baseMetricV2' in impact:
                cvss_data = impact['baseMetricV2']['cvssV2']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = self._cvss_to_severity(cvss_score)
            
            # Extract dates
            published_date = datetime.fromisoformat(cve.get('publishedDate', '2020-01-01T00:00:00.000'))
            modified_date = datetime.fromisoformat(cve.get('lastModifiedDate', published_date.isoformat()))
            
            # Check exploit availability
            exploit_available = any(
                'exploit' in desc.lower() or 'poc' in desc.lower()
                for desc in [description]
            )
            
            return CVEEntry(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published_date,
                modified_date=modified_date,
                affected_products=[],
                references=[],
                exploit_available=exploit_available,
                exploit_complexity="Unknown",
                required_privileges="Unknown",
                user_interaction=False,
                scope_changed=False,
                confidentiality_impact="Unknown",
                integrity_impact="Unknown",
                availability_impact="Unknown"
            )
            
        except Exception as e:
            logger.error(f"Error converting GitHub CVE: {e}")
            return None
    
    async def import_critical_cves_only(self) -> int:
        """Import only critical and high severity CVEs from all sources."""
        logger.info("🔥 Starting critical CVEs import...")
        
        total_imported = 0
        
        # Import from NVD API (critical only)
        nvd_count = await self.import_from_nvd_api(limit=1000)
        total_imported += nvd_count
        
        # Import from GitHub (recent years)
        github_count = await self.import_from_github_releases(
            "fkie-cad/nvd-json-data-feeds", 
            limit=2000
        )
        total_imported += github_count
        
        logger.info(f"🎯 Critical CVEs import completed: {total_imported} CVEs imported")
        return total_imported
    
    def get_import_statistics(self) -> Dict[str, Any]:
        """Get statistics about imported CVEs."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total CVEs
                cursor.execute("SELECT COUNT(*) FROM cve_entries")
                total_cves = cursor.fetchone()[0]
                
                # By severity
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN severity >= 0.9 THEN 'CRITICAL'
                            WHEN severity >= 0.7 THEN 'HIGH' 
                            WHEN severity >= 0.5 THEN 'MEDIUM'
                            ELSE 'LOW'
                        END as severity_level,
                        COUNT(*) as count
                    FROM cve_entries 
                    GROUP BY severity_level
                """)
                severity_stats = dict(cursor.fetchall())
                
                # By CVSS score ranges
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN cvss_score >= 9.0 THEN '9.0-10.0'
                            WHEN cvss_score >= 7.0 THEN '7.0-8.9'
                            WHEN cvss_score >= 4.0 THEN '4.0-6.9'
                            ELSE '0.0-3.9'
                        END as score_range,
                        COUNT(*) as count
                    FROM cve_entries 
                    GROUP BY score_range
                """)
                score_stats = dict(cursor.fetchall())
                
                # Exploit availability
                cursor.execute("""
                    SELECT 
                        exploit_available,
                        COUNT(*) as count
                    FROM cve_entries 
                    GROUP BY exploit_available
                """)
                exploit_stats = dict(cursor.fetchall())
                
                # Recent CVEs (last 30 days)
                thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
                cursor.execute("""
                    SELECT COUNT(*) FROM cve_entries 
                    WHERE published_date >= ?
                """, (thirty_days_ago,))
                recent_cves = cursor.fetchone()[0]
                
                return {
                    'total_cves': total_cves,
                    'severity_distribution': severity_stats,
                    'cvss_score_distribution': score_stats,
                    'exploit_availability': exploit_stats,
                    'recent_cves_30_days': recent_cves,
                    'last_updated': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


async def main():
    """Main import function."""
    parser = argparse.ArgumentParser(description="Import CVE database into Nexus Framework")
    parser.add_argument(
        '--source', 
        choices=['nvd', 'github', 'critical', 'kev', 'all'],
        default='critical',
        help='Source to import from'
    )
    parser.add_argument(
        '--limit', 
        type=int,
        help='Limit number of CVEs to import'
    )
    parser.add_argument(
        '--db-path',
        default='knowledge.db',
        help='Database path'
    )
    
    args = parser.parse_args()
    
    # Create importer
    importer = CVEImporter(args.db_path)
    
    count = 0
    # Import based on source
    if args.source == 'nvd':
        count = await importer.import_from_nvd_api(limit=args.limit)
    elif args.source == 'github':
        count = await importer.import_from_github_releases(
            "fkie-cad/nvd-json-data-feeds", 
            limit=args.limit
        )
    elif args.source == 'critical':
        # NVD + GitHub + MITRE techniques + CISA KEV (critical focus)
        count += await importer.import_from_nvd_api(limit=args.limit or 2000)
        count += await importer.import_from_github_releases(
            "fkie-cad/nvd-json-data-feeds", 
            limit=args.limit or 2000
        )
        count += await importer.import_from_olbat_nvdcve(limit=args.limit or 2000)
        count += await importer.import_attack_techniques_from_mitre(limit=500)
        count += await importer.import_from_cisa_kev()
    elif args.source == 'kev':
        count = await importer.import_from_cisa_kev()
    elif args.source == 'all':
        logger.info("🔄 Starting comprehensive import...")
        count += await importer.import_from_nvd_api(limit=args.limit or 10000)
        count += await importer.import_from_github_releases(
            "fkie-cad/nvd-json-data-feeds", 
            limit=args.limit or 10000
        )
        count += await importer.import_from_olbat_nvdcve(limit=args.limit or 15000)
        count += await importer.import_attack_techniques_from_mitre()
        count += await importer.import_from_cisa_kev()
    
    # Show statistics
    stats = importer.get_import_statistics()
    print(f"\n📊 Import Statistics:")
    print(f"   Total CVEs: {stats.get('total_cves', 0)}")
    print(f"   Critical: {stats.get('severity_distribution', {}).get('CRITICAL', 0)}")
    print(f"   High: {stats.get('severity_distribution', {}).get('HIGH', 0)}")
    print(f"   Exploits available: {stats.get('exploit_availability', {}).get(True, 0)}")
    print(f"   Recent (30 days): {stats.get('recent_cves_30_days', 0)}")
    
    logger.info(f"✅ Import completed: {count} CVEs imported")


if __name__ == "__main__":
    asyncio.run(main())
