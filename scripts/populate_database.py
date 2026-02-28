#!/usr/bin/env python3
"""
Nexus Automation Framework - Complete Database Population Script

Imports ALL CVEs from cve-cvelistV5 (CVE JSON 5.0 format),
MITRE ATT&CK techniques from STIX, and populates service_vulnerabilities,
exploit_patterns, and evasion_patterns tables.

Usage:
    python scripts/populate_database.py --phase all
    python scripts/populate_database.py --phase cve
    python scripts/populate_database.py --phase mitre
    python scripts/populate_database.py --phase services
    python scripts/populate_database.py --phase patterns
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
import time
import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("populate_db")

DB_PATH = "knowledge.db"
CVELIST_DIR = "cve-cvelistV5/cves"
BATCH_SIZE = 5000

# ═══════════════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═══════════════════════════════════════════════════════════════════════

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def wipe_database():
    """Wipe all data from the database while keeping schema."""
    logger.info("🗑️  Wiping database...")
    conn = get_connection()
    tables = ["cve_entries", "attack_techniques", "service_vulnerabilities",
              "exploit_patterns", "evasion_patterns", "knowledge_versions"]
    for t in tables:
        conn.execute(f"DELETE FROM {t}")
    conn.execute("DELETE FROM sqlite_sequence")
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    logger.info("✅ Database wiped")


def ensure_schema():
    """Ensure the database schema exists."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS cve_entries (
        cve_id TEXT PRIMARY KEY, description TEXT, severity REAL,
        cvss_score REAL, cvss_vector TEXT, published_date TEXT,
        modified_date TEXT, affected_products TEXT, cve_references TEXT,
        exploit_available BOOLEAN, exploit_complexity TEXT,
        required_privileges TEXT, user_interaction BOOLEAN,
        scope_changed BOOLEAN, confidentiality_impact TEXT,
        integrity_impact TEXT, availability_impact TEXT,
        knowledge_version INTEGER DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS attack_techniques (
        technique_id TEXT PRIMARY KEY, name TEXT, description TEXT,
        phase TEXT, platforms TEXT, required_permissions TEXT,
        data_sources TEXT, detection_methods TEXT, mitigation TEXT,
        effectiveness_score REAL, detection_difficulty TEXT,
        tool_requirements TEXT, sub_techniques TEXT,
        knowledge_version INTEGER DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS service_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT,
        service_version TEXT, port INTEGER, protocol TEXT,
        cve_ids TEXT, default_credentials TEXT,
        common_misconfigurations TEXT, exploitation_methods TEXT,
        detection_signatures TEXT, knowledge_version INTEGER DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS exploit_patterns (
        pattern_id TEXT PRIMARY KEY, name TEXT, vulnerability_type TEXT,
        exploitation_method TEXT, required_conditions TEXT,
        success_indicators TEXT, failure_indicators TEXT,
        side_effects TEXT, detection_signatures TEXT,
        mitigation_techniques TEXT, knowledge_version INTEGER DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evasion_patterns (
        pattern_id TEXT PRIMARY KEY, name TEXT, evasion_technique TEXT,
        target_defenses TEXT, implementation_methods TEXT,
        detection_bypasses TEXT, effectiveness_score REAL,
        countermeasures TEXT, knowledge_version INTEGER DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS knowledge_versions (
        version INTEGER PRIMARY KEY, created_at TEXT,
        description TEXT, changes_summary TEXT)""")
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════
# PHASE 1: CVE IMPORT FROM cve-cvelistV5
# ═══════════════════════════════════════════════════════════════════════

def strip_html(text: str) -> str:
    """Strip HTML tags and decode entities."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


def parse_cvss_from_cna(metrics: list) -> Tuple[float, str, str]:
    """Extract best CVSS score, vector, and severity from CNA metrics."""
    best_score = 0.0
    best_vector = ""
    best_severity = ""

    for m in metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss = m.get(key)
            if cvss and isinstance(cvss, dict):
                score = cvss.get("baseScore", 0)
                if score and float(score) >= best_score:
                    best_score = float(score)
                    best_vector = cvss.get("vectorString", "")
                    best_severity = cvss.get("baseSeverity", "")
    return best_score, best_vector, best_severity


def severity_float(severity_str: str, cvss_score: float) -> float:
    """Convert severity string or CVSS score to float 0-1."""
    mapping = {
        "CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3, "NONE": 0.0
    }
    if severity_str and severity_str.upper() in mapping:
        return mapping[severity_str.upper()]
    if cvss_score >= 9.0:
        return 0.9
    if cvss_score >= 7.0:
        return 0.7
    if cvss_score >= 4.0:
        return 0.5
    if cvss_score > 0:
        return 0.3
    return 0.0


def extract_affected_products(affected: list) -> List[str]:
    """Extract product names from CVE JSON 5.0 affected array."""
    products = []
    for a in affected:
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        if vendor and product:
            products.append(f"{vendor} {product}")
        elif product:
            products.append(product)
    return products


def extract_references(refs: list) -> List[str]:
    """Extract URLs from references."""
    urls = []
    for r in refs:
        url = r.get("url", "")
        if url:
            urls.append(url)
    return urls


def has_exploit_tag(refs: list) -> bool:
    """Check if any reference has exploit tag."""
    for r in refs:
        tags = r.get("tags", [])
        if isinstance(tags, list):
            for t in tags:
                if "exploit" in str(t).lower():
                    return True
        elif isinstance(tags, str) and "exploit" in tags.lower():
            return True
    return False


def parse_cve_json5(filepath: str) -> Optional[Tuple]:
    """Parse a CVE JSON 5.0 file and return a tuple ready for INSERT."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if data.get("dataType") != "CVE_RECORD":
        return None

    meta = data.get("cveMetadata", {})
    state = meta.get("state", "")
    if state == "REJECTED":
        return None

    cve_id = meta.get("cveId", "")
    if not cve_id:
        return None

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # Description
    descriptions = cna.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang", "en").startswith("en"):
            description = strip_html(d.get("value", ""))
            break
    if not description and descriptions:
        description = strip_html(descriptions[0].get("value", ""))

    # Metrics
    metrics = cna.get("metrics", [])
    cvss_score, cvss_vector, severity_str = parse_cvss_from_cna(metrics)

    # Also check ADP metrics if CNA has none
    if cvss_score == 0:
        for adp in containers.get("adp", []):
            adp_metrics = adp.get("metrics", [])
            if adp_metrics:
                s, v, sv = parse_cvss_from_cna(adp_metrics)
                if s > cvss_score:
                    cvss_score, cvss_vector, severity_str = s, v, sv

    severity = severity_float(severity_str, cvss_score)

    # Dates
    published = meta.get("datePublished", meta.get("dateReserved", ""))
    modified = meta.get("dateUpdated", published)
    if not published:
        published = "2000-01-01T00:00:00.000Z"
    if not modified:
        modified = published

    # Affected products
    affected = cna.get("affected", [])
    products = extract_affected_products(affected)

    # References
    refs = cna.get("references", [])
    ref_urls = extract_references(refs)

    # Exploit available
    exploit_available = has_exploit_tag(refs)

    # CVSS details
    best_cvss = {}
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            if key in m and isinstance(m[key], dict):
                best_cvss = m[key]
                break
        if best_cvss:
            break

    exploit_complexity = best_cvss.get("attackComplexity", "")
    required_privileges = best_cvss.get("privilegesRequired", "")
    user_interaction = best_cvss.get("userInteraction", "NONE") != "NONE"
    scope_changed = best_cvss.get("scope", "UNCHANGED") == "CHANGED"
    confidentiality_impact = best_cvss.get("confidentialityImpact", "")
    integrity_impact = best_cvss.get("integrityImpact", "")
    availability_impact = best_cvss.get("availabilityImpact", "")

    return (
        cve_id, description, severity, cvss_score, cvss_vector,
        published, modified,
        json.dumps(products), json.dumps(ref_urls),
        exploit_available, exploit_complexity, required_privileges,
        user_interaction, scope_changed,
        confidentiality_impact, integrity_impact, availability_impact
    )


def import_cves():
    """Import all CVEs from cve-cvelistV5 directory."""
    if not os.path.isdir(CVELIST_DIR):
        logger.error(f"❌ Directory {CVELIST_DIR} not found")
        return 0

    conn = get_connection()
    cursor = conn.cursor()

    total = 0
    skipped = 0
    errors = 0
    batch = []

    # Collect all year directories
    year_dirs = sorted(
        [d for d in os.listdir(CVELIST_DIR) if os.path.isdir(os.path.join(CVELIST_DIR, d))],
        reverse=True
    )

    logger.info(f"📂 Found {len(year_dirs)} year directories")

    for year_dir in year_dirs:
        year_path = os.path.join(CVELIST_DIR, year_dir)
        year_count = 0

        # Iterate sub-directories (e.g., 0xxx, 1xxx, ...)
        sub_dirs = sorted(os.listdir(year_path))
        for sub_dir in sub_dirs:
            sub_path = os.path.join(year_path, sub_dir)
            if not os.path.isdir(sub_path):
                continue

            for filename in os.listdir(sub_path):
                if not filename.endswith(".json"):
                    continue

                filepath = os.path.join(sub_path, filename)
                result = parse_cve_json5(filepath)

                if result is None:
                    skipped += 1
                    continue

                batch.append(result)
                year_count += 1

                if len(batch) >= BATCH_SIZE:
                    try:
                        cursor.executemany("""
                            INSERT OR REPLACE INTO cve_entries
                            (cve_id, description, severity, cvss_score, cvss_vector,
                             published_date, modified_date, affected_products, cve_references,
                             exploit_available, exploit_complexity, required_privileges,
                             user_interaction, scope_changed, confidentiality_impact,
                             integrity_impact, availability_impact)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """, batch)
                        conn.commit()
                        total += len(batch)
                        batch = []
                    except Exception as e:
                        errors += len(batch)
                        logger.error(f"Batch insert error: {e}")
                        batch = []

        # Flush remaining batch for this year
        if batch:
            try:
                cursor.executemany("""
                    INSERT OR REPLACE INTO cve_entries
                    (cve_id, description, severity, cvss_score, cvss_vector,
                     published_date, modified_date, affected_products, cve_references,
                     exploit_available, exploit_complexity, required_privileges,
                     user_interaction, scope_changed, confidentiality_impact,
                     integrity_impact, availability_impact)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, batch)
                conn.commit()
                total += len(batch)
                batch = []
            except Exception as e:
                errors += len(batch)
                logger.error(f"Batch insert error: {e}")
                batch = []

        logger.info(f"  📅 {year_dir}: {year_count:,} CVEs imported (running total: {total:,})")

    conn.close()
    logger.info(f"✅ CVE import complete: {total:,} imported, {skipped:,} skipped, {errors:,} errors")
    return total


# ═══════════════════════════════════════════════════════════════════════
# PHASE 2: MITRE ATT&CK TECHNIQUES
# ═══════════════════════════════════════════════════════════════════════

def import_mitre_attack():
    """Import MITRE ATT&CK techniques from STIX bundle."""
    import urllib.request

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    logger.info("🔄 Downloading MITRE ATT&CK Enterprise STIX bundle...")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NexusFramework/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.error(f"❌ Failed to download MITRE ATT&CK: {e}")
        return 0

    objects = bundle.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern" and not o.get("revoked", False)]
    logger.info(f"📥 Processing {len(techniques)} techniques...")

    # Build phase mapping
    phase_map = {}
    for o in objects:
        if o.get("type") == "x-mitre-tactic":
            short = o.get("x_mitre_shortname", "")
            if short:
                phase_map[short] = short

    conn = get_connection()
    cursor = conn.cursor()
    count = 0

    for t in techniques:
        tid = ""
        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                break
        if not tid:
            continue

        name = t.get("name", "")
        description = t.get("description", "")[:2000]

        # Phase from kill chain
        phase = "unknown"
        for kc in t.get("kill_chain_phases", []):
            if kc.get("kill_chain_name") == "mitre-attack":
                phase = kc.get("phase_name", "unknown")
                break

        platforms = json.dumps(t.get("x_mitre_platforms", []))
        permissions = json.dumps(t.get("x_mitre_permissions_required", []))
        data_sources = json.dumps(t.get("x_mitre_data_sources", []))
        detection = t.get("x_mitre_detection", "")
        detection_methods = json.dumps([detection] if detection else [])

        # Mitigation from relationships (simplified)
        mitigation = ""
        for ref in t.get("external_references", []):
            if "mitigation" in ref.get("description", "").lower():
                mitigation = ref.get("description", "")[:500]
                break

        effectiveness = 0.7 if t.get("x_mitre_is_subtechnique", False) else 0.8
        detection_difficulty = "Medium"
        if phase in ("defense-evasion", "persistence"):
            detection_difficulty = "Hard"
        elif phase in ("reconnaissance", "discovery"):
            detection_difficulty = "Easy"

        tool_requirements = json.dumps([])
        sub_techniques = json.dumps([])

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO attack_techniques
                (technique_id, name, description, phase, platforms,
                 required_permissions, data_sources, detection_methods,
                 mitigation, effectiveness_score, detection_difficulty,
                 tool_requirements, sub_techniques)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (tid, name, description, phase, platforms,
                  permissions, data_sources, detection_methods,
                  mitigation, effectiveness, detection_difficulty,
                  tool_requirements, sub_techniques))
            count += 1
        except Exception as e:
            logger.error(f"Error inserting {tid}: {e}")

    conn.commit()
    conn.close()
    logger.info(f"✅ MITRE ATT&CK import complete: {count} techniques")
    return count


# ═══════════════════════════════════════════════════════════════════════
# PHASE 3: SERVICE VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════

SERVICE_VULNERABILITIES_DATA = [
    # (service_name, version, port, protocol, cve_ids, default_creds, misconfigs, exploit_methods, signatures)
    ("Apache HTTP Server", "2.4.49", 80, "tcp", ["CVE-2021-41773", "CVE-2021-42013"], [], ["Directory listing enabled", "Server version disclosure", "mod_status public"], ["Path traversal", "RCE via CGI"], ["Server: Apache/2.4.49"]),
    ("Apache HTTP Server", "2.4.50", 80, "tcp", ["CVE-2021-42013"], [], ["Directory listing enabled", "AllowOverride None"], ["Path traversal RCE"], ["Server: Apache/2.4.50"]),
    ("Apache HTTP Server", "2.4.48", 80, "tcp", ["CVE-2021-33193", "CVE-2021-34798", "CVE-2021-36160", "CVE-2021-39275"], [], ["Server version disclosure", "Default error pages"], ["HTTP request smuggling", "NULL pointer dereference"], ["Server: Apache/2.4.48"]),
    ("Nginx", "1.18.0", 80, "tcp", ["CVE-2021-23017"], [], ["Autoindex enabled", "Server tokens on", "Missing security headers"], ["DNS resolver vulnerability"], ["Server: nginx/1.18.0"]),
    ("Nginx", "1.20.0", 80, "tcp", ["CVE-2021-23017"], [], ["Autoindex enabled", "Proxy buffering misconfiguration"], ["DNS resolver 0.5 byte off-by-one"], ["Server: nginx/1.20.0"]),
    ("OpenSSH", "7.4", 22, "tcp", ["CVE-2018-15473", "CVE-2017-15906"], [], ["Root login permitted", "Weak key exchange algorithms", "Password authentication enabled"], ["Username enumeration", "Brute force"], ["SSH-2.0-OpenSSH_7.4"]),
    ("OpenSSH", "8.2", 22, "tcp", ["CVE-2020-15778"], [], ["Agent forwarding enabled", "Weak MACs"], ["Command injection via scp"], ["SSH-2.0-OpenSSH_8.2"]),
    ("OpenSSH", "8.9", 22, "tcp", ["CVE-2023-38408"], [], ["Unused subsystems enabled"], ["PKCS#11 provider RCE"], ["SSH-2.0-OpenSSH_8.9"]),
    ("OpenSSH", "9.1", 22, "tcp", ["CVE-2023-25136"], [], ["Weak MACs configured"], ["Double-free pre-auth"], ["SSH-2.0-OpenSSH_9.1"]),
    ("MySQL", "5.7.30", 3306, "tcp", ["CVE-2020-14812", "CVE-2020-14769"], ["root:", "root:root", "root:password", "root:mysql"], ["Anonymous user access", "Weak passwords", "Remote root login"], ["SQL injection", "Auth bypass", "Privilege escalation"], ["MySQL native protocol"]),
    ("MySQL", "8.0.28", 3306, "tcp", ["CVE-2022-21367", "CVE-2022-21270"], ["root:"], ["Remote root login", "No audit logging"], ["Optimizer privilege escalation"], ["mysql_native_password"]),
    ("PostgreSQL", "13.4", 5432, "tcp", ["CVE-2021-23214", "CVE-2021-23222"], ["postgres:postgres"], ["Trust authentication on pg_hba.conf", "No SSL enforcement"], ["Man-in-the-middle", "SQL injection via libpq"], ["PostgreSQL protocol v3"]),
    ("PostgreSQL", "14.0", 5432, "tcp", ["CVE-2022-1552", "CVE-2022-2625"], ["postgres:postgres"], ["Default listen_addresses='*'", "Missing pg_hba restrictions"], ["Autovacuum privilege escalation", "Extension script RCE"], ["PostgreSQL protocol v3"]),
    ("Microsoft SQL Server", "2019", 1433, "tcp", ["CVE-2022-29143"], ["sa:sa", "sa:password"], ["Mixed auth mode", "xp_cmdshell enabled", "CLR enabled"], ["xp_cmdshell RCE", "SQL injection", "Linked server abuse"], ["TDS protocol"]),
    ("Redis", "6.2.6", 6379, "tcp", ["CVE-2022-0543"], [], ["No authentication", "Bind 0.0.0.0", "No rename-command"], ["Unauthenticated access", "Lua sandbox escape", "Module loading RCE"], ["REDIS protocol"]),
    ("Redis", "7.0.0", 6379, "tcp", ["CVE-2022-35951", "CVE-2022-36021"], [], ["No authentication required", "Dangerous commands exposed"], ["Integer overflow", "String pattern DoS"], ["REDIS protocol"]),
    ("MongoDB", "4.4.0", 27017, "tcp", ["CVE-2021-32040"], [], ["No authentication", "Bind all interfaces", "No TLS"], ["Unauthenticated access", "Query injection"], ["MongoDB Wire Protocol"]),
    ("Elasticsearch", "7.16.0", 9200, "tcp", ["CVE-2021-44228", "CVE-2021-45046"], [], ["No authentication", "Network host 0.0.0.0", "Script execution enabled"], ["Log4Shell via user-agent", "JNDI injection"], ["Elasticsearch REST API"]),
    ("Apache Tomcat", "9.0.50", 8080, "tcp", ["CVE-2021-42340", "CVE-2021-41079"], ["tomcat:tomcat", "admin:admin", "tomcat:s3cret"], ["Manager app exposed", "Default credentials", "AJP enabled"], ["DoS via file upload", "AJP ghostcat", "War file deployment"], ["Server: Apache-Coyote/1.1"]),
    ("Apache Tomcat", "10.0.0", 8080, "tcp", ["CVE-2022-23181", "CVE-2022-29885"], ["tomcat:tomcat"], ["Manager app public", "AJP connector on 8009"], ["TOCTOU race condition", "Cluster channel info leak"], ["Server: Apache Tomcat"]),
    ("vsftpd", "3.0.3", 21, "tcp", ["CVE-2021-3618"], [], ["Anonymous login enabled", "Write access to root", "No TLS"], ["ALPACA attack", "Anonymous upload", "Brute force"], ["220 (vsFTPd 3.0.3)"]),
    ("ProFTPD", "1.3.7", 21, "tcp", ["CVE-2021-46854"], [], ["Anonymous login", "Default shell"], ["Unauthenticated memory read"], ["220 ProFTPD 1.3.7"]),
    ("Samba", "4.13.0", 445, "tcp", ["CVE-2021-44142", "CVE-2022-32742"], [], ["Guest access enabled", "Wide links enabled", "Null sessions allowed"], ["Heap overflow via VFS", "SMB info leak", "Relay attacks"], ["SMB2/3 protocol"]),
    ("Microsoft IIS", "10.0", 80, "tcp", ["CVE-2021-31166", "CVE-2022-21907"], [], ["WebDAV enabled", "Directory browsing", "Stack traces exposed"], ["HTTP.sys RCE", "HTTP protocol stack RCE"], ["Server: Microsoft-IIS/10.0"]),
    ("WordPress", "5.8", 80, "tcp", ["CVE-2022-21661", "CVE-2022-21662", "CVE-2022-21663", "CVE-2022-21664"], ["admin:admin", "admin:password"], ["xmlrpc.php exposed", "wp-cron public", "Debug mode", "File editing enabled"], ["SQL injection via WP_Query", "XSS stored", "Plugin exploitation"], ["X-Powered-By: WordPress"]),
    ("Drupal", "9.3.0", 80, "tcp", ["CVE-2022-25277", "CVE-2022-25275"], ["admin:admin"], ["User registration open", "PHP input filter", "Views UI public"], ["File upload RCE via .htaccess", "Info disclosure"], ["X-Generator: Drupal"]),
    ("Joomla", "4.0.0", 80, "tcp", ["CVE-2023-23752"], ["admin:admin"], ["Debug mode enabled", "Error reporting verbose"], ["Unauthenticated info disclosure", "SQL injection"], ["X-Powered-By: Joomla"]),
    ("GitLab", "14.6.0", 443, "tcp", ["CVE-2022-0735", "CVE-2021-22205"], [], ["Public registration enabled", "Exiftool enabled"], ["Runner token disclosure", "RCE via image upload"], ["X-GitLab-Meta"]),
    ("Jenkins", "2.319", 8080, "tcp", ["CVE-2022-27925", "CVE-2024-23897"], ["admin:admin"], ["Script console public", "No auth configured", "CSRF disabled"], ["Arbitrary file read", "Groovy script RCE"], ["X-Jenkins"]),
    ("Docker API", "20.10", 2375, "tcp", ["CVE-2022-24769", "CVE-2021-21285"], [], ["API exposed without TLS", "No auth on socket"], ["Container escape", "Unauthenticated API access", "Privileged container abuse"], ["Docker-Engine"]),
    ("Kubernetes API", "1.23", 6443, "tcp", ["CVE-2022-0185", "CVE-2021-25741"], [], ["Anonymous auth enabled", "RBAC misconfiguration", "etcd exposed"], ["Container escape via kernel", "Symlink exchange attack"], ["kube-apiserver"]),
    ("Grafana", "8.3.0", 3000, "tcp", ["CVE-2021-43798", "CVE-2021-43813"], ["admin:admin"], ["Default credentials", "Anonymous access enabled"], ["Path traversal to /etc/passwd", "Arbitrary file read"], ["Grafana login page"]),
    ("Prometheus", "2.33.0", 9090, "tcp", [], [], ["No authentication", "Public metrics endpoint", "Remote write enabled"], ["Information disclosure", "SSRF via targets"], ["Prometheus HTTP API"]),
    ("RabbitMQ", "3.9.0", 5672, "tcp", ["CVE-2021-32718", "CVE-2021-32719"], ["guest:guest"], ["Default credentials", "Management UI public"], ["XSS via shovel", "Federation plugin abuse"], ["AMQP 0-9-1"]),
    ("Memcached", "1.6.12", 11211, "tcp", ["CVE-2022-43571"], [], ["No authentication", "Bind 0.0.0.0", "UDP enabled"], ["Unauthenticated access", "DDoS amplification"], ["Memcached protocol"]),
    ("CouchDB", "3.2.0", 5984, "tcp", ["CVE-2022-24706"], ["admin:admin"], ["Admin party mode", "No authentication"], ["RCE via erlang", "Unauthenticated admin access"], ["CouchDB REST API"]),
    ("Consul", "1.11.0", 8500, "tcp", ["CVE-2022-29153", "CVE-2021-38698"], [], ["ACL disabled", "No encryption"], ["SSRF via DNS", "Unauthenticated RCE"], ["Consul HTTP API"]),
    ("HAProxy", "2.4.0", 80, "tcp", ["CVE-2021-40346", "CVE-2023-25725"], [], ["Stats page public", "No auth on stats"], ["HTTP request smuggling", "Header parsing bypass"], ["HAProxy stats"]),
    ("Postfix", "3.5.0", 25, "tcp", ["CVE-2023-51764"], [], ["Open relay", "No TLS enforcement", "Weak auth"], ["SMTP smuggling", "Open relay abuse"], ["220 ESMTP Postfix"]),
    ("Dovecot", "2.3.16", 143, "tcp", ["CVE-2022-30550"], [], ["Plaintext auth allowed", "No TLS"], ["Privilege escalation via auth"], ["* OK Dovecot IMAP"]),
    ("BIND", "9.16.0", 53, "udp", ["CVE-2021-25216", "CVE-2021-25215"], [], ["Recursive queries allowed", "Zone transfer open", "Version disclosure"], ["Buffer overflow via GSS-TSIG", "DNAME assertion failure"], ["BIND DNS"]),
    ("Squid", "5.2", 3128, "tcp", ["CVE-2022-41318", "CVE-2021-46784"], [], ["Open proxy", "No authentication", "Cache poisoning possible"], ["Buffer overflow via SSPI/SMB", "HTTP response splitting"], ["Squid proxy"]),
    ("Exim", "4.95", 25, "tcp", ["CVE-2023-42115", "CVE-2023-42116", "CVE-2023-42117"], [], ["No TLS enforcement", "Weak auth"], ["Out-of-bounds write RCE", "Stack buffer overflow", "Auth bypass"], ["220 ESMTP Exim"]),
    ("OpenVPN", "2.5.0", 1194, "udp", ["CVE-2022-0547"], [], ["Weak cipher suites", "No MFA", "Default key"], ["Auth bypass via plugins"], ["OpenVPN protocol"]),
    ("WireGuard", "1.0.0", 51820, "udp", [], [], ["Key rotation missing", "No pre-shared key"], ["Key compromise exposure"], ["WireGuard handshake"]),
    ("Asterisk", "18.0.0", 5060, "udp", ["CVE-2022-26498", "CVE-2022-26499"], ["admin:admin"], ["SIP no auth", "Default passwords"], ["Stack buffer overflow", "STUN DoS"], ["SIP/2.0"]),
    ("Webmin", "1.984", 10000, "tcp", ["CVE-2022-0824", "CVE-2021-31760"], ["admin:admin", "root:root"], ["Remote access enabled", "Default port exposed"], ["RCE via file manager", "CSRF to RCE"], ["MiniServ/1.984"]),
    ("phpMyAdmin", "5.1.0", 80, "tcp", ["CVE-2022-23807", "CVE-2022-23808"], ["root:", "root:root"], ["Default credentials", "No blowfish secret", "Setup page accessible"], ["Brute force", "XSS via setup", "SQL injection"], ["phpMyAdmin login"]),
    ("Spring Boot", "2.6.0", 8080, "tcp", ["CVE-2022-22965", "CVE-2022-22963"], [], ["Actuator endpoints public", "H2 console enabled", "Debug mode"], ["Spring4Shell RCE", "SpEL injection"], ["Whitelabel Error Page"]),
    ("Log4j", "2.14.1", 0, "tcp", ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"], [], ["JNDI lookup enabled", "Pattern layout with user input"], ["JNDI injection RCE", "Recursive lookup DoS"], ["Log4j in classpath"]),
    ("Confluence", "7.13.0", 8090, "tcp", ["CVE-2022-26134", "CVE-2021-26084"], [], ["Public registration", "Default credentials"], ["OGNL injection RCE", "Webwork OGNL injection"], ["X-Confluence-Request-Time"]),
    ("Exchange Server", "2019", 443, "tcp", ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-27065", "CVE-2021-34473"], [], ["Autodiscover exposed", "ECP accessible"], ["ProxyLogon SSRF", "ProxyShell RCE"], ["X-OWA-Version"]),
    ("VMware vCenter", "7.0", 443, "tcp", ["CVE-2021-21985", "CVE-2021-22005"], [], ["Default admin credentials", "CEIP enabled"], ["RCE via VSAN plugin", "Arbitrary file upload"], ["VMware vCenter"]),
    ("Citrix ADC", "13.0", 443, "tcp", ["CVE-2023-3519", "CVE-2019-19781"], [], ["Management interface public", "NSIP exposed"], ["Unauthenticated RCE", "Path traversal RCE"], ["Citrix NetScaler"]),
    ("F5 BIG-IP", "16.1.0", 443, "tcp", ["CVE-2022-1388", "CVE-2021-22986"], [], ["iControl REST public", "Self IPs accessible"], ["Auth bypass RCE via iControl", "SSRF RCE"], ["F5 BIG-IP"]),
    ("SonarQube", "9.0", 9000, "tcp", ["CVE-2021-42392"], ["admin:admin"], ["Public access enabled", "Default credentials"], ["H2 JNDI injection", "API token leakage"], ["SonarQube dashboard"]),
    ("MinIO", "2022-01-01", 9000, "tcp", ["CVE-2023-28432"], ["minioadmin:minioadmin"], ["Default credentials", "Public buckets"], ["Env variable disclosure", "SSRF"], ["MinIO Console"]),
    ("Keycloak", "18.0.0", 8080, "tcp", ["CVE-2022-2256", "CVE-2022-1245"], [], ["Admin console public", "Self-registration enabled"], ["XSS via client redirect", "Privilege escalation via CSRF"], ["Keycloak login"]),
]


def import_service_vulnerabilities():
    """Import service vulnerabilities data."""
    conn = get_connection()
    cursor = conn.cursor()
    count = 0

    for svc in SERVICE_VULNERABILITIES_DATA:
        name, version, port, proto, cves, creds, misconf, exploits, sigs = svc
        try:
            cursor.execute("""
                INSERT INTO service_vulnerabilities
                (service_name, service_version, port, protocol, cve_ids,
                 default_credentials, common_misconfigurations,
                 exploitation_methods, detection_signatures)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (name, version, port, proto,
                  json.dumps(cves), json.dumps(creds), json.dumps(misconf),
                  json.dumps(exploits), json.dumps(sigs)))
            count += 1
        except Exception as e:
            logger.error(f"Error inserting service {name} {version}: {e}")

    conn.commit()
    conn.close()
    logger.info(f"✅ Service vulnerabilities import: {count} entries")
    return count


# ═══════════════════════════════════════════════════════════════════════
# PHASE 4: EXPLOIT PATTERNS + EVASION PATTERNS
# ═══════════════════════════════════════════════════════════════════════

EXPLOIT_PATTERNS_DATA = [
    ("EP001", "Buffer Overflow - Stack", "Memory corruption", "Stack buffer overflow", ["Fixed buffer size", "No stack canary", "No ASLR"], ["EIP/RIP control", "Shellcode execution", "Segfault with controlled crash"], ["Stack cookie detected", "Access violation at random addr"], ["Service crash", "Memory corruption"], ["Unusual stack pointer", "NOP sled patterns"], ["Stack canaries", "ASLR", "DEP/NX", "CFI"]),
    ("EP002", "Buffer Overflow - Heap", "Memory corruption", "Heap exploitation", ["Heap allocator predictability", "No heap guard"], ["Arbitrary write primitive", "Code execution"], ["Heap corruption detected", "Double free error"], ["Heap metadata corruption"], ["Heap spray patterns", "Unusual allocation sizes"], ["Heap guards", "ASLR", "Safe unlinking"]),
    ("EP003", "SQL Injection - Union", "Input validation", "UNION-based SQL injection", ["User input in SQL query", "No parameterized queries"], ["Data exfiltration", "Database access", "Schema enumeration"], ["SQL syntax error", "Query timeout"], ["Data corruption risk", "Log entries"], ["UNION SELECT in params", "OR 1=1 patterns", "Encoded SQL keywords"], ["Parameterized queries", "Input validation", "WAF", "Least privilege DB"]),
    ("EP004", "SQL Injection - Blind Boolean", "Input validation", "Boolean-based blind SQL injection", ["User input in SQL WHERE clause", "Different response for true/false"], ["Bit-by-bit data extraction", "Schema discovery"], ["Consistent response regardless of payload"], ["Increased query load", "Slow extraction"], ["Multiple similar requests with varying conditions"], ["Parameterized queries", "WAF", "Query timeout"]),
    ("EP005", "SQL Injection - Time-based", "Input validation", "Time-based blind SQL injection", ["User input in SQL query", "SLEEP/WAITFOR available"], ["Measurable response time difference", "Data extraction via timing"], ["No timing difference observed"], ["Database performance impact", "Connection pool exhaustion"], ["Abnormal response times", "SLEEP/BENCHMARK in params"], ["Parameterized queries", "Query timeout limits"]),
    ("EP006", "XSS - Reflected", "Input validation", "Reflected cross-site scripting", ["User input reflected in response", "No output encoding", "No CSP"], ["Script execution in victim browser", "Cookie theft"], ["Input sanitized", "CSP blocks execution"], ["Session hijacking", "Keylogging"], ["Script tags in parameters", "Event handlers in input"], ["Output encoding", "CSP headers", "HttpOnly cookies"]),
    ("EP007", "XSS - Stored", "Input validation", "Stored/persistent cross-site scripting", ["User input stored and displayed", "No sanitization on output"], ["Persistent script execution", "Multiple victim impact"], ["Input stripped on storage"], ["Mass session hijacking", "Worm propagation"], ["Script in stored content", "Event handlers in DB data"], ["Input sanitization", "Output encoding", "CSP"]),
    ("EP008", "XSS - DOM-based", "Input validation", "DOM-based cross-site scripting", ["Client-side JS uses URL fragments", "innerHTML without sanitization"], ["Script execution via DOM manipulation"], ["Framework auto-escapes"], ["Client-side data theft"], ["document.write with user input", "innerHTML assignments"], ["DOMPurify", "Avoid innerHTML", "CSP"]),
    ("EP009", "Command Injection", "Code injection", "OS command injection", ["User input in system command", "No input sanitization"], ["Command output returned", "Shell access obtained"], ["Command not found", "Permission denied"], ["System compromise", "Data exfiltration"], ["Shell metacharacters in input", "Pipe/semicolon patterns"], ["Input validation", "Avoid system() calls", "Sandboxing"]),
    ("EP010", "SSTI", "Code injection", "Server-side template injection", ["User input in template rendering", "No sandbox"], ["Template engine code execution", "File read/write"], ["Template syntax error", "Sandbox restriction"], ["Full server compromise", "Data theft"], ["Template syntax probes ({{7*7}})", "Engine-specific payloads"], ["Sandbox templates", "No user input in templates", "WAF"]),
    ("EP011", "Path Traversal", "Access control", "Directory traversal / LFI", ["User input in file path", "No path canonicalization"], ["Arbitrary file read", "/etc/passwd access"], ["File not found", "Permission denied"], ["Information disclosure", "Config file exposure"], ["../ sequences", "Encoded path characters", "Null byte injection"], ["Path canonicalization", "Chroot/jail", "Input validation"]),
    ("EP012", "SSRF", "Access control", "Server-side request forgery", ["Server makes requests based on user input", "No URL validation"], ["Internal network access", "Cloud metadata access"], ["URL blocked", "Timeout on internal"], ["Internal service discovery", "Credential theft from metadata"], ["Requests to 169.254.169.254", "Internal IP access patterns"], ["URL allowlisting", "Network segmentation", "Disable redirects"]),
    ("EP013", "Deserialization", "Code injection", "Insecure deserialization", ["User-controlled serialized data", "No type checking"], ["Remote code execution", "Object injection"], ["Class not found", "Invalid stream header"], ["Full compromise", "Data tampering"], ["Java serialized object headers", "Python pickle patterns"], ["Type-safe deserialization", "Input validation", "Integrity checks"]),
    ("EP014", "XXE", "Input validation", "XML external entity injection", ["XML parser with external entities enabled", "User-controlled XML input"], ["File read via entity expansion", "SSRF via external DTD"], ["XML parsing error", "DTD not allowed"], ["File disclosure", "SSRF", "DoS via billion laughs"], ["DOCTYPE declarations", "ENTITY definitions", "SYSTEM references"], ["Disable external entities", "Use JSON", "Input validation"]),
    ("EP015", "LDAP Injection", "Input validation", "LDAP query injection", ["User input in LDAP query", "No input sanitization"], ["Authentication bypass", "Data exfiltration"], ["LDAP syntax error"], ["Unauthorized access", "Directory enumeration"], ["LDAP special characters in input", "Wildcard injection"], ["Input escaping", "Parameterized LDAP queries"]),
    ("EP016", "Authentication Bypass", "Authentication", "Authentication mechanism bypass", ["Weak auth implementation", "Default credentials", "Logic flaw"], ["Unauthorized access", "Admin panel access"], ["Account locked", "MFA challenge"], ["Full account takeover"], ["Direct object reference", "JWT manipulation", "Session fixation"], ["MFA", "Rate limiting", "Account lockout"]),
    ("EP017", "Privilege Escalation - Linux", "Privilege escalation", "Linux privilege escalation", ["SUID binaries", "Writable cron jobs", "Kernel vulnerability"], ["Root shell obtained", "UID 0 achieved"], ["Permission denied", "Operation not permitted"], ["Full system compromise"], ["SUID file access", "Cron job modification", "Kernel exploit execution"], ["Remove unnecessary SUID", "Kernel updates", "SELinux/AppArmor"]),
    ("EP018", "Privilege Escalation - Windows", "Privilege escalation", "Windows privilege escalation", ["Unquoted service paths", "Weak service permissions", "Token impersonation"], ["SYSTEM shell", "Admin access"], ["Access denied", "Privilege not held"], ["Domain compromise potential"], ["Service manipulation", "Token stealing", "Potato attacks"], ["Least privilege", "Service hardening", "Credential Guard"]),
    ("EP019", "Pass the Hash", "Credential access", "NTLM hash relay/pass-the-hash", ["Valid NTLM hash", "SMB signing disabled", "Network access"], ["Authenticated session", "Remote command execution"], ["Hash invalid", "SMB signing required"], ["Lateral movement", "Domain escalation"], ["NTLM auth without cleartext password", "Relay to different host"], ["SMB signing", "Kerberos-only auth", "Network segmentation"]),
    ("EP020", "Kerberoasting", "Credential access", "Kerberos TGS ticket cracking", ["Domain user account", "SPN-enabled service accounts"], ["Service account password cracked"], ["Strong passwords resist cracking"], ["Lateral movement with service accounts"], ["TGS-REP requests for SPNs"], ["Strong service account passwords", "Managed service accounts", "AES encryption"]),
    ("EP021", "DNS Rebinding", "Network attack", "DNS rebinding attack", ["Victim visits attacker page", "Internal service without auth"], ["Internal service access from browser"], ["DNS pinning", "CORS restrictions"], ["Internal network access", "Router config changes"], ["Rapid DNS TTL changes", "Multiple A records"], ["DNS pinning", "Host header validation", "Network segmentation"]),
    ("EP022", "HTTP Request Smuggling", "Protocol manipulation", "HTTP desync / request smuggling", ["Frontend-backend with different HTTP parsing", "Transfer-Encoding/Content-Length ambiguity"], ["Request routing bypass", "Cache poisoning", "WAF bypass"], ["Consistent parsing between servers"], ["Cache poisoning", "Session hijacking"], ["CL.TE or TE.CL discrepancies", "Unusual Transfer-Encoding headers"], ["Normalize HTTP parsing", "HTTP/2 end-to-end", "WAF tuning"]),
    ("EP023", "WebSocket Hijacking", "Protocol manipulation", "Cross-site WebSocket hijacking", ["WebSocket without origin check", "Session cookies sent automatically"], ["Real-time data theft", "Action on behalf of victim"], ["Origin validation blocks"], ["Data exfiltration in real-time"], ["Cross-origin WebSocket connections"], ["Origin header validation", "CSRF tokens in WebSocket handshake"]),
    ("EP024", "JWT Attack", "Authentication", "JSON Web Token exploitation", ["JWT without signature verification", "Weak secret", "Algorithm confusion"], ["Token forgery", "Privilege escalation"], ["Signature validation fails"], ["Unauthorized access", "Role escalation"], ["alg:none attacks", "Key confusion RS256/HS256"], ["Strong secrets", "Algorithm allowlisting", "Short expiry"]),
    ("EP025", "Race Condition", "Logic flaw", "Time-of-check to time-of-use", ["Non-atomic operations", "Shared resource access"], ["Double spending", "Privilege escalation"], ["Mutex/locking prevents race"], ["Data inconsistency"], ["Rapid parallel requests", "Timing attacks"], ["Atomic operations", "Proper locking", "Idempotency"]),
]

EVASION_PATTERNS_DATA = [
    ("EV001", "Process Hollowing", "Process manipulation", ["Process monitoring", "Antivirus", "EDR"], ["CreateProcess(SUSPENDED)", "NtUnmapViewOfSection", "WriteProcessMemory", "ResumeThread"], ["Process name spoofing", "Parent process hiding", "Memory section replacement"], 0.85, ["ETW monitoring", "Process creation auditing", "Memory integrity checks", "Sysmon"]),
    ("EV002", "Living off the Land (LOLBins)", "Legitimate tool abuse", ["Allowlisting", "Tool-based detection", "Signature AV"], ["PowerShell", "WMI", "Certutil", "Bitsadmin", "Mshta", "Regsvr32", "Rundll32"], ["Signed binary execution", "Legitimate process trees", "No malware on disk"], 0.80, ["Command-line logging", "PowerShell ScriptBlock logging", "AMSI", "Behavioral analysis"]),
    ("EV003", "Rootkit - Kernel", "System modification", ["File integrity monitoring", "Kernel protection", "Secure Boot"], ["Kernel module loading", "DKOM", "System call hooking", "IDT/SSDT manipulation"], ["Hidden processes", "File system hiding", "Network traffic hiding"], 0.92, ["Kernel integrity checking", "Secure Boot", "Hypervisor-based protection"]),
    ("EV004", "DLL Side-Loading", "Code execution via trusted app", ["Application whitelisting", "DLL signing enforcement"], ["Place malicious DLL in trusted app directory", "Exploit DLL search order"], ["Legitimate parent process", "Signed application loading"], 0.78, ["DLL signing verification", "Known DLL protection", "Sysmon DLL monitoring"]),
    ("EV005", "Timestomping", "Artifact manipulation", ["File timeline analysis", "NTFS forensics"], ["SetFileTime API", "PowerShell Set-ItemProperty", "Touch command"], ["Modified timestamps match expected patterns"], 0.65, ["$MFT analysis", "USN Journal monitoring", "EDR file tracking"]),
    ("EV006", "Traffic Encryption/Tunneling", "Network evasion", ["Network monitoring", "IDS/IPS", "DPI"], ["DNS tunneling", "HTTPS C2", "Domain fronting", "ICMP tunneling", "SSH tunneling"], ["Encrypted traffic appears normal", "DNS queries look benign", "CDN-fronted traffic"], 0.82, ["DNS analytics", "JA3/JA3S fingerprinting", "Traffic volume anomaly", "Beacon detection"]),
    ("EV007", "Obfuscation - PowerShell", "Script obfuscation", ["AMSI", "ScriptBlock logging", "Signature detection"], ["String concatenation", "Encoding (Base64, XOR)", "Invoke-Expression", "Variable substitution", "Tick marks"], ["Bypasses static signatures", "Evades simple pattern matching"], 0.70, ["AMSI integration", "Deep ScriptBlock logging", "Behavioral detection", "ML-based analysis"]),
    ("EV008", "AMSI Bypass", "Security control bypass", ["AMSI scanning", "PowerShell protection"], ["amsiInitFailed patching", "AmsiScanBuffer hooking", "CLR reflection", "AMSI provider unloading"], ["In-memory AV scanning disabled", "Malicious scripts execute undetected"], 0.75, ["AMSI integrity monitoring", "ETW provider monitoring", "Memory protection"]),
    ("EV009", "UAC Bypass", "Privilege escalation evasion", ["User Account Control", "Integrity level enforcement"], ["Fodhelper.exe registry hijack", "Eventvwr.exe hijack", "DiskCleanup scheduled task", "CMSTP.exe exploit"], ["Auto-elevated process runs payload", "No UAC prompt shown"], 0.72, ["UAC set to Always Notify", "Monitor auto-elevate binaries", "Registry auditing"]),
    ("EV010", "ETW Patching", "Telemetry evasion", ["ETW-based monitoring", "EDR telemetry", ".NET logging"], ["NtTraceEvent hooking", "EtwEventWrite patching", "Provider disabling"], ["Security product telemetry blinded", "Log gaps"], 0.80, ["ETW integrity monitoring", "Kernel-level ETW protection", "Out-of-process logging"]),
    ("EV011", "Anti-Forensics - Log Clearing", "Evidence destruction", ["SIEM log collection", "Windows Event Log", "Syslog"], ["wevtutil cl", "Clear-EventLog", "Log file deletion", "/var/log manipulation"], ["Forensic timeline gaps", "Missing evidence"], 0.60, ["Remote log forwarding", "Immutable logging", "Log integrity monitoring"]),
    ("EV012", "Fileless Malware", "Memory-only execution", ["File-based AV", "On-disk scanning"], ["PowerShell in-memory execution", "Reflective DLL injection", ".NET assembly loading", "WMI event subscriptions"], ["No malicious files on disk", "In-memory only payload"], 0.83, ["Memory scanning", "AMSI", "ETW monitoring", "Behavioral analysis"]),
    ("EV013", "Domain Fronting", "Network evasion", ["Domain blocking", "SNI inspection", "Network monitoring"], ["CDN-based fronting", "Different SNI vs Host header", "Cloud service abuse"], ["Traffic appears to go to legitimate CDN", "Encrypted payload hidden"], 0.78, ["TLS inspection", "JA3 fingerprinting", "CDN log analysis"]),
    ("EV014", "Sandbox Evasion", "Analysis evasion", ["Automated sandboxes", "Dynamic analysis"], ["Sleep timers", "Environment checks", "User interaction requirements", "Hardware fingerprinting"], ["Malware only executes in real environments"], 0.75, ["Extended sandbox timeout", "Human interaction simulation", "Bare-metal analysis"]),
    ("EV015", "AV/EDR Unhooking", "Security control bypass", ["EDR user-mode hooks", "Inline function hooking"], ["Ntdll fresh copy from disk", "Direct syscalls", "Manual DLL mapping", "Hardware breakpoint hooks"], ["EDR monitoring bypassed", "Direct kernel calls"], 0.85, ["Kernel-level monitoring", "ETW-based detection", "Hypervisor-enforced hooks"]),
    ("EV016", "Token Manipulation", "Privilege evasion", ["Integrity level checks", "Token-based access control"], ["Token impersonation", "Token duplication", "SID manipulation", "Potato exploits"], ["Elevated access without password", "Different security context"], 0.77, ["Token creation auditing", "Credential Guard", "Protected Process Light"]),
    ("EV017", "Masquerading", "Identity evasion", ["Process name monitoring", "Binary verification"], ["Renamed binaries", "Matching legitimate file metadata", "Right-to-left override char"], ["Malicious process appears legitimate"], 0.68, ["Hash verification", "Digital signature checking", "Sysmon file hash logging"]),
    ("EV018", "Proxy/Redirector Chains", "Attribution evasion", ["IP-based tracking", "Network forensics"], ["Multi-hop SSH", "Tor routing", "VPN chains", "Compromised host pivoting"], ["Source IP obscured", "Attribution extremely difficult"], 0.85, ["Traffic pattern analysis", "Behavioral correlation", "Multi-source intelligence"]),
]


def import_exploit_patterns():
    """Import exploit patterns."""
    conn = get_connection()
    cursor = conn.cursor()
    count = 0

    for p in EXPLOIT_PATTERNS_DATA:
        pid, name, vtype, method, conditions, success, failure, side_fx, sigs, mitigations = p
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO exploit_patterns
                (pattern_id, name, vulnerability_type, exploitation_method,
                 required_conditions, success_indicators, failure_indicators,
                 side_effects, detection_signatures, mitigation_techniques)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (pid, name, vtype, method,
                  json.dumps(conditions), json.dumps(success), json.dumps(failure),
                  json.dumps(side_fx), json.dumps(sigs), json.dumps(mitigations)))
            count += 1
        except Exception as e:
            logger.error(f"Error inserting exploit pattern {pid}: {e}")

    conn.commit()
    conn.close()
    logger.info(f"✅ Exploit patterns import: {count} entries")
    return count


def import_evasion_patterns():
    """Import evasion patterns."""
    conn = get_connection()
    cursor = conn.cursor()
    count = 0

    for p in EVASION_PATTERNS_DATA:
        pid, name, technique, defenses, methods, bypasses, effectiveness, counters = p
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO evasion_patterns
                (pattern_id, name, evasion_technique, target_defenses,
                 implementation_methods, detection_bypasses,
                 effectiveness_score, countermeasures)
                VALUES (?,?,?,?,?,?,?,?)
            """, (pid, name, technique,
                  json.dumps(defenses), json.dumps(methods), json.dumps(bypasses),
                  effectiveness, json.dumps(counters)))
            count += 1
        except Exception as e:
            logger.error(f"Error inserting evasion pattern {pid}: {e}")

    conn.commit()
    conn.close()
    logger.info(f"✅ Evasion patterns import: {count} entries")
    return count


# ═══════════════════════════════════════════════════════════════════════
# KNOWLEDGE VERSION
# ═══════════════════════════════════════════════════════════════════════

def create_knowledge_version(description: str, changes: str):
    conn = get_connection()
    cursor = conn.cursor()

    # Get stats
    cursor.execute("SELECT COUNT(*) FROM cve_entries")
    cve_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM attack_techniques")
    tech_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM service_vulnerabilities")
    svc_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM exploit_patterns")
    ep_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM evasion_patterns")
    ev_count = cursor.fetchone()[0]

    summary = (f"{changes} | Stats: {cve_count} CVEs, {tech_count} techniques, "
               f"{svc_count} services, {ep_count} exploit patterns, {ev_count} evasion patterns")

    cursor.execute("""
        INSERT OR REPLACE INTO knowledge_versions (version, created_at, description, changes_summary)
        VALUES (?, ?, ?, ?)
    """, (2, datetime.now().isoformat(), description, summary))
    conn.commit()
    conn.close()
    logger.info(f"📚 Knowledge version created: {summary}")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Nexus Automation Framework - Database Population")
    parser.add_argument("--phase", choices=["all", "cve", "mitre", "services", "patterns", "wipe"],
                        default="all", help="Which phase to run")
    parser.add_argument("--no-wipe", action="store_true", help="Skip database wipe")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("🚀 Nexus Automation Framework - Database Population")
    logger.info("=" * 60)

    ensure_schema()

    if args.phase == "wipe":
        wipe_database()
        return

    if not args.no_wipe and args.phase == "all":
        wipe_database()

    start = time.time()
    totals = {}

    if args.phase in ("all", "cve"):
        logger.info("\n📦 PHASE 1: CVE Import from cve-cvelistV5")
        totals["cve"] = import_cves()

    if args.phase in ("all", "mitre"):
        logger.info("\n⚔️  PHASE 2: MITRE ATT&CK Techniques")
        totals["mitre"] = import_mitre_attack()

    if args.phase in ("all", "services"):
        logger.info("\n🖥️  PHASE 3: Service Vulnerabilities")
        totals["services"] = import_service_vulnerabilities()

    if args.phase in ("all", "patterns"):
        logger.info("\n🔧 PHASE 4: Exploit & Evasion Patterns")
        totals["exploit_patterns"] = import_exploit_patterns()
        totals["evasion_patterns"] = import_evasion_patterns()

    if args.phase == "all":
        create_knowledge_version(
            "Complete database population v2",
            f"Full import from cve-cvelistV5 + MITRE ATT&CK + services + patterns"
        )

    elapsed = time.time() - start
    logger.info("\n" + "=" * 60)
    logger.info("📊 IMPORT SUMMARY")
    logger.info("=" * 60)
    for key, val in totals.items():
        logger.info(f"  {key}: {val:,}")
    logger.info(f"  Total time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    logger.info("=" * 60)
    logger.info("✅ Database population complete!")


if __name__ == "__main__":
    main()
