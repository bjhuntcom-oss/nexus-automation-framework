#!/usr/bin/env python3
"""
Nexus Automation Framework - Recent CVEs Import Script (v2)

Populates knowledge.db with the latest 2023, 2024, 2025 and Modified CVEs.
Uses NVD 2.0 format parsing and optimized SQLite transactions.
"""

import asyncio
import json
import logging
import sqlite3
import requests
import lzma
from datetime import datetime
from pathlib import Path
import sys

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


def cvss_to_severity(score: float) -> VulnerabilitySeverity:
    if score >= 9.0: return VulnerabilitySeverity.CRITICAL
    elif score >= 7.0: return VulnerabilitySeverity.HIGH
    elif score >= 4.0: return VulnerabilitySeverity.MEDIUM
    else: return VulnerabilitySeverity.LOW


def parse_cve_item(item: dict) -> CVEEntry:
    # Handle NVD 2.0 format (unwrapped)
    if 'id' in item and 'descriptions' in item:
        cve_id = item['id']
        descriptions = item.get('descriptions', [])
        description = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), '')
        if not description and descriptions:
            description = descriptions[0].get('value', '')
            
        metrics = item.get('metrics', {})
        cvss_score = 0.0
        cvss_vector = "Unknown"
        severity = VulnerabilitySeverity.LOW
        
        cvss_data = None
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            
        if cvss_data:
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_vector = cvss_data.get('vectorString', 'Unknown')
            severity = cvss_to_severity(cvss_score)
            
        pub_str = item.get('published', '2020-01-01T00:00:00.000').replace('Z', '')
        mod_str = item.get('lastModified', pub_str).replace('Z', '')
        published_date = datetime.fromisoformat(pub_str)
        modified_date = datetime.fromisoformat(mod_str)
    else:
        # Fallback to old NVD format
        cve = item.get('cve', {})
        impact = item.get('impact', {})
        cve_id = cve.get('CVE_data_meta', {}).get('ID', '')
        description = "".join([d.get('value', '') for d in cve.get('description', {}).get('description_data', [])]).strip()
        
        cvss_score = 0.0
        cvss_vector = "Unknown"
        severity = VulnerabilitySeverity.LOW
        if 'baseMetricV3' in impact:
            cvss_data = impact['baseMetricV3']['cvssV3']
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_vector = cvss_data.get('vectorString', 'Unknown')
            severity = cvss_to_severity(cvss_score)
        elif 'baseMetricV2' in impact:
            cvss_data = impact['baseMetricV2']['cvssV2']
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_vector = cvss_data.get('vectorString', 'Unknown')
            severity = cvss_to_severity(cvss_score)
            
        pub_str = item.get('publishedDate', '2020-01-01T00:00:00.000').replace('Z', '')
        mod_str = item.get('lastModifiedDate', pub_str).replace('Z', '')
        published_date = datetime.fromisoformat(pub_str)
        modified_date = datetime.fromisoformat(mod_str)

    exploit_available = any(x in description.lower() for x in ['exploit', 'poc', 'proof of concept'])
    
    return CVEEntry(
        cve_id=cve_id, description=description, severity=severity,
        cvss_score=cvss_score, cvss_vector=cvss_vector,
        published_date=published_date, modified_date=modified_date,
        affected_products=[], references=[], exploit_available=exploit_available,
        exploit_complexity="Unknown", required_privileges="Unknown",
        user_interaction=False, scope_changed=False, confidentiality_impact="Unknown",
        integrity_impact="Unknown", availability_impact="Unknown"
    )


async def main():
    db_path = "knowledge.db"
    session = requests.Session()
    session.headers.update({'User-Agent': 'Nexus-Framework-Enricher/2.0'})
    
    logger.info("🔄 Checking for latest CVE data feeds...")
    api_url = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"
    release_data = session.get(api_url).json()
    
    target_files = ['CVE-2023.json.xz', 'CVE-2024.json.xz', 'CVE-2025.json.xz', 'CVE-modified.json.xz', 'CVE-recent.json.xz']
    assets = [a for a in release_data.get('assets', []) if a['name'] in target_files]
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    total_new = 0
    for asset in assets:
        logger.info(f"📥 Downloading and processing {asset['name']}...")
        content = session.get(asset['browser_download_url']).content
        data = json.loads(lzma.decompress(content).decode('utf-8'))
        cve_items = data if isinstance(data, list) else data.get('cve_items', data.get('CVE_Items', []))
        
        logger.info(f"⚙️  Importing {len(cve_items)} entries into database...")
        stmt = """
            INSERT OR REPLACE INTO cve_entries 
            (cve_id, description, severity, cvss_score, cvss_vector,
             published_date, modified_date, affected_products, cve_references,
             exploit_available, exploit_complexity, required_privileges,
             user_interaction, scope_changed, confidentiality_impact,
             integrity_impact, availability_impact)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        count = 0
        for item in cve_items:
            try:
                cve = parse_cve_item(item)
                cursor.execute(stmt, (
                    cve.cve_id, cve.description, cve.severity.value, cve.cvss_score,
                    cve.cvss_vector, cve.published_date.isoformat(), cve.modified_date.isoformat(),
                    json.dumps(cve.affected_products), json.dumps(cve.references),
                    cve.exploit_available, cve.exploit_complexity, cve.required_privileges,
                    cve.user_interaction, cve.scope_changed, cve.confidentiality_impact,
                    cve.integrity_impact, cve.availability_impact
                ))
                count += 1
            except Exception:
                continue
        
        conn.commit()
        total_new += count
        logger.info(f"✅ Finished {asset['name']}: {count} records updated.")

    cursor.execute("SELECT COUNT(*) FROM cve_entries")
    total_db = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE published_date > '2024-01-01'")
    recent_db = cursor.fetchone()[0]
    conn.close()
    
    logger.info(f"📊 FINAL STATISTICS: Total CVEs: {total_db} | Post-2024: {recent_db}")

if __name__ == "__main__":
    asyncio.run(main())
