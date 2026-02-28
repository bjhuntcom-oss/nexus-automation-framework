"""
Knowledge Engine - CVE & MITRE ATT&CK Database

Embedded knowledge base containing:
- Structured CVE database
- Service-to-vulnerability mappings
- MITRE ATT&CK techniques
- Exploit patterns (structure only)
- Evasion patterns (defensive abstraction)
- Risk taxonomy
- Versionable knowledge updates

Features:
- Local knowledge storage
- Version control
- Fast lookups
- Pattern matching
- Risk scoring
- Technique mapping
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import re
import hashlib
from collections import defaultdict, Counter
import sqlite3
import threading


class VulnerabilitySeverity(Enum):
    """CVSS severity levels."""
    NONE = 0.0
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    CRITICAL = 0.9


class AttackPhase(Enum):
    """MITRE ATT&CK attack phases."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class CVEEntry:
    """CVE vulnerability entry."""
    cve_id: str
    description: str
    severity: VulnerabilitySeverity
    cvss_score: float
    cvss_vector: str
    published_date: datetime
    modified_date: datetime
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_complexity: str = ""
    required_privileges: str = ""
    user_interaction: bool = False
    scope_changed: bool = False
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'published_date': self.published_date.isoformat(),
            'modified_date': self.modified_date.isoformat(),
            'affected_products': self.affected_products,
            'references': self.references,
            'exploit_available': self.exploit_available,
            'exploit_complexity': self.exploit_complexity,
            'required_privileges': self.required_privileges,
            'user_interaction': self.user_interaction,
            'scope_changed': self.scope_changed,
            'confidentiality_impact': self.confidentiality_impact,
            'integrity_impact': self.integrity_impact,
            'availability_impact': self.availability_impact
        }


@dataclass
class AttackTechnique:
    """MITRE ATT&CK technique."""
    technique_id: str
    name: str
    description: str
    phase: AttackPhase
    platforms: List[str] = field(default_factory=list)
    required_permissions: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    mitigation: str = ""
    effectiveness_score: float = 0.5
    detection_difficulty: str = ""
    tool_requirements: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'technique_id': self.technique_id,
            'name': self.name,
            'description': self.description,
            'phase': self.phase.value,
            'platforms': self.platforms,
            'required_permissions': self.required_permissions,
            'data_sources': self.data_sources,
            'detection_methods': self.detection_methods,
            'mitigation': self.mitigation,
            'effectiveness_score': self.effectiveness_score,
            'detection_difficulty': self.detection_difficulty,
            'tool_requirements': self.tool_requirements,
            'sub_techniques': self.sub_techniques
        }


@dataclass
class ServiceVulnerability:
    """Service-to-vulnerability mapping."""
    service_name: str
    service_version: str
    port: Optional[int]
    protocol: str
    cve_ids: List[str] = field(default_factory=list)
    default_credentials: List[str] = field(default_factory=list)
    common_misconfigurations: List[str] = field(default_factory=list)
    exploitation_methods: List[str] = field(default_factory=list)
    detection_signatures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'service_name': self.service_name,
            'service_version': self.service_version,
            'port': self.port,
            'protocol': self.protocol,
            'cve_ids': self.cve_ids,
            'default_credentials': self.default_credentials,
            'common_misconfigurations': self.common_misconfigurations,
            'exploitation_methods': self.exploitation_methods,
            'detection_signatures': self.detection_signatures
        }


@dataclass
class ExploitPattern:
    """Exploit pattern structure."""
    pattern_id: str
    name: str
    vulnerability_type: str
    exploitation_method: str
    required_conditions: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    detection_signatures: List[str] = field(default_factory=list)
    mitigation_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern_id': self.pattern_id,
            'name': self.name,
            'vulnerability_type': self.vulnerability_type,
            'exploitation_method': self.exploitation_method,
            'required_conditions': self.required_conditions,
            'success_indicators': self.success_indicators,
            'failure_indicators': self.failure_indicators,
            'side_effects': self.side_effects,
            'detection_signatures': self.detection_signatures,
            'mitigation_techniques': self.mitigation_techniques
        }


@dataclass
class EvasionPattern:
    """Evasion pattern for defensive analysis."""
    pattern_id: str
    name: str
    evasion_technique: str
    target_defenses: List[str] = field(default_factory=list)
    implementation_methods: List[str] = field(default_factory=list)
    detection_bypasses: List[str] = field(default_factory=list)
    effectiveness_score: float = 0.5
    countermeasures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern_id': self.pattern_id,
            'name': self.name,
            'evasion_technique': self.evasion_technique,
            'target_defenses': self.target_defenses,
            'implementation_methods': self.implementation_methods,
            'detection_bypasses': self.detection_bypasses,
            'effectiveness_score': self.effectiveness_score,
            'countermeasures': self.countermeasures
        }


class KnowledgeDatabase:
    """Main knowledge database with SQLite backend.
    
    IMPORTANT: This class must match the ACTUAL enriched DB schema.
    The enriched DB has these tables with these columns:
    
    - cve_entries: cve_id, description, severity, cvss_score, cvss_vector,
      published_date, modified_date, affected_products, cve_references,
      exploit_available, exploit_complexity, required_privileges,
      user_interaction, scope_changed, confidentiality_impact,
      integrity_impact, availability_impact, knowledge_version, 
      created_at, updated_at
      
    - attack_techniques: technique_id, name, description, tactic, platforms,
      data_sources, detection, mitigation, ref_links, knowledge_version,
      created_at, updated_at
      
    - service_vulnerabilities: vuln_id, service_name, version_pattern,
      vulnerability_type, description, severity, cve_refs, exploit_refs,
      detection_methods, mitigation, created_at, updated_at
      
    - exploit_patterns: pattern_id, name, description, category,
      technique_refs, service_refs, payload_examples, detection_indicators,
      success_indicators, complexity, reliability, side_effects,
      created_at, updated_at
      
    - evasion_patterns: pattern_id, name, description, category,
      target_systems, technique_refs, implementation, detection_bypass,
      effectiveness, created_at, updated_at
      
    - workflow_rules: rule_id, name, phase, category, description,
      conditions, actions, priority, enabled, created_at, updated_at
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db")
        self.logger = logging.getLogger("knowledge_database")
        self._lock = threading.Lock()
        
        # Only initialize schema if DB doesn't exist yet
        self._ensure_schema()
    
    def _ensure_schema(self):
        """Ensure DB tables exist. Uses the ACTUAL enriched schema.
        Creates only missing tables — never overwrites existing ones.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if DB is already populated
            try:
                count = cursor.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
                if count > 0:
                    self.logger.info(f"Knowledge DB already populated: {count} CVEs")
                    return  # DB exists and has data, don't touch schema
            except Exception:
                pass  # Table doesn't exist, create it
            
            # CVE table (actual enriched schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_entries (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    severity REAL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    affected_products TEXT,
                    cve_references TEXT,
                    exploit_available BOOLEAN,
                    exploit_complexity TEXT,
                    required_privileges TEXT,
                    user_interaction BOOLEAN,
                    scope_changed BOOLEAN,
                    confidentiality_impact TEXT,
                    integrity_impact TEXT,
                    availability_impact TEXT,
                    knowledge_version INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Attack techniques (actual enriched schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_techniques (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    tactic TEXT,
                    platforms TEXT,
                    data_sources TEXT,
                    detection TEXT,
                    mitigation TEXT,
                    ref_links TEXT,
                    knowledge_version INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Service vulnerabilities (actual enriched schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS service_vulnerabilities (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT,
                    version_pattern TEXT,
                    vulnerability_type TEXT,
                    description TEXT,
                    severity TEXT,
                    cve_refs TEXT,
                    exploit_refs TEXT,
                    detection_methods TEXT,
                    mitigation TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Exploit patterns (actual enriched schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploit_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    category TEXT,
                    technique_refs TEXT,
                    service_refs TEXT,
                    payload_examples TEXT,
                    detection_indicators TEXT,
                    success_indicators TEXT,
                    complexity TEXT,
                    reliability TEXT,
                    side_effects TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Evasion patterns (actual enriched schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evasion_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    category TEXT,
                    target_systems TEXT,
                    technique_refs TEXT,
                    implementation TEXT,
                    detection_bypass TEXT,
                    effectiveness TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Workflow rules (actual enriched schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS workflow_rules (
                    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    phase TEXT,
                    category TEXT,
                    description TEXT,
                    conditions TEXT,
                    actions TEXT,
                    priority INTEGER DEFAULT 5,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Knowledge versions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_versions (
                    version INTEGER PRIMARY KEY,
                    created_at TEXT,
                    description TEXT,
                    changes_summary TEXT
                )
            """)

            # Tool profiles (queried by specialists agents on startup)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_profiles (
                    tool_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    category TEXT,
                    command_template TEXT,
                    parameters TEXT,
                    output_formats TEXT,
                    capabilities TEXT,
                    dependencies TEXT,
                    install_commands TEXT,
                    version TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            conn.commit()
    
    def _load_initial_knowledge(self):
        """Load initial knowledge base."""
        # Check if database is empty
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_entries")
            cve_count = cursor.fetchone()[0]
            
            if cve_count == 0:
                # Load sample knowledge
                self._load_sample_cve_data()
                self._load_sample_attack_techniques()
                self._load_sample_service_vulnerabilities()
                self._load_sample_exploit_patterns()
                self._load_sample_evasion_patterns()
                
                # Create initial version
                self._create_knowledge_version(1, "Initial knowledge base", "Loaded initial CVE, ATT&CK, and pattern data")
    
    def _load_sample_cve_data(self):
        """Load sample CVE data."""
        sample_cves = [
            CVEEntry(
                cve_id="CVE-2021-44228",
                description="Apache Log4j2 remote code execution vulnerability",
                severity=VulnerabilitySeverity.CRITICAL,
                cvss_score=10.0,
                cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
                published_date=datetime(2021, 12, 10),
                modified_date=datetime(2021, 12, 15),
                affected_products=["Apache Log4j2", "Various applications using Log4j2"],
                exploit_available=True,
                exploit_complexity="Low",
                user_interaction=False,
                scope_changed=False,
                confidentiality_impact="High",
                integrity_impact="High",
                availability_impact="High"
            ),
            CVEEntry(
                cve_id="CVE-2021-34527",
                description="Windows Print Spooler remote code execution (PrintNightmare)",
                severity=VulnerabilitySeverity.CRITICAL,
                cvss_score=8.8,
                cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
                published_date=datetime(2021, 7, 1),
                modified_date=datetime(2021, 7, 7),
                affected_products=["Windows 10", "Windows Server 2019", "Windows Server 2016"],
                exploit_available=True,
                exploit_complexity="Low",
                required_privileges="None",
                user_interaction=False,
                scope_changed=False,
                confidentiality_impact="High",
                integrity_impact="High",
                availability_impact="High"
            ),
            CVEEntry(
                cve_id="CVE-2019-0708",
                description="BlueKeep - Remote Desktop Protocol remote code execution",
                severity=VulnerabilitySeverity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
                published_date=datetime(2019, 5, 14),
                modified_date=datetime(2019, 9, 6),
                affected_products=["Windows 7", "Windows Server 2008", "Windows Server 2008 R2"],
                exploit_available=True,
                exploit_complexity="Low",
                required_privileges="None",
                user_interaction=False,
                scope_changed=False,
                confidentiality_impact="High",
                integrity_impact="High",
                availability_impact="High"
            )
        ]
        
        for cve in sample_cves:
            self.add_cve_entry(cve)
    
    def _load_sample_attack_techniques(self):
        """Load sample MITRE ATT&CK techniques."""
        sample_techniques = [
            AttackTechnique(
                technique_id="T1018",
                name="Remote System Discovery",
                description="Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.",
                phase=AttackPhase.DISCOVERY,
                platforms=["Windows", "Linux", "macOS"],
                required_permissions=["User"],
                data_sources=["Process monitoring", "Network connection creation", "Network traffic content"],
                detection_methods=["Monitor for network connections to unknown hosts", "Analyze process execution"],
                mitigation="Limit system and domain information available to non-administrators",
                effectiveness_score=0.8,
                detection_difficulty="Medium",
                tool_requirements=["nmap", "netexec", "ping", "arp"]
            ),
            AttackTechnique(
                technique_id="T1075",
                name="Pass the Hash",
                description="An adversary with a valid NTLM hash or clear-text password can authenticate to a remote system using pass-the-hash authentication.",
                phase=AttackPhase.CREDENTIAL_ACCESS,
                platforms=["Windows"],
                required_permissions=["User"],
                data_sources=["Process monitoring", "Network connection creation", "Account logon events"],
                detection_methods=["Monitor for unusual authentication patterns", "Analyze logon types"],
                mitigation="Implement multi-factor authentication", 
                effectiveness_score=0.9,
                detection_difficulty="Hard",
                tool_requirements=["impacket", "crackmapexec", "mimikatz"]
            ),
            AttackTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                phase=AttackPhase.EXECUTION,
                platforms=["Windows", "Linux", "macOS"],
                required_permissions=["User"],
                data_sources=["Process monitoring", "Command-line logging"],
                detection_methods=["Monitor process execution", "Analyze command-line arguments"],
                mitigation="Restrict command-line access", 
                effectiveness_score=0.7,
                detection_difficulty="Medium",
                tool_requirements=["cmd.exe", "powershell", "bash", "sh"]
            )
        ]
        
        for technique in sample_techniques:
            self.add_attack_technique(technique)
    
    def _load_sample_service_vulnerabilities(self):
        """Load sample service vulnerability mappings."""
        sample_services = [
            ServiceVulnerability(
                service_name="Apache HTTP Server",
                service_version="2.4.48",
                port=80,
                protocol="tcp",
                cve_ids=["CVE-2021-33193", "CVE-2021-34798"],
                common_misconfigurations=["Directory listing enabled", "Server version disclosure"],
                exploitation_methods=["HTTP request smuggling", "Path traversal"],
                detection_signatures=["Server: Apache/2.4.48", "OPTIONS method enabled"]
            ),
            ServiceVulnerability(
                service_name="OpenSSH",
                service_version="7.4",
                port=22,
                protocol="tcp",
                cve_ids=["CVE-2018-15473"],
                common_misconfigurations=["Weak cryptography", "Root login permitted"],
                exploitation_methods=["Username enumeration", "Brute force"],
                detection_signatures=["SSH-2.0-OpenSSH_7.4"]
            ),
            ServiceVulnerability(
                service_name="MySQL",
                service_version="5.7.30",
                port=3306,
                protocol="tcp",
                default_credentials=["root:root", "root:password"],
                common_misconfigurations=["Anonymous user access", "Weak passwords"],
                exploitation_methods=["SQL injection", "Authentication bypass"],
                detection_signatures=["MySQL native protocol"]
            )
        ]
        
        for service in sample_services:
            self.add_service_vulnerability(service)
    
    def _load_sample_exploit_patterns(self):
        """Load sample exploit patterns."""
        sample_patterns = [
            ExploitPattern(
                pattern_id="EP001",
                name="Buffer Overflow",
                vulnerability_type="Memory corruption",
                exploitation_method="Stack smashing",
                required_conditions=["Fixed buffer size", "No input validation"],
                success_indicators=["Segmentation fault", "EIP control"],
                failure_indicators=["Access violation", "Exception"],
                side_effects=["Service crash", "Memory corruption"],
                detection_signatures=["Unusual memory access patterns"],
                mitigation_techniques=["Stack canaries", "ASLR", "DEP"]
            ),
            ExploitPattern(
                pattern_id="EP002",
                name="SQL Injection",
                vulnerability_type="Input validation",
                exploitation_method="Malicious SQL queries",
                required_conditions=["User input in SQL query", "No input sanitization"],
                success_indicators=["Database access", "Data exfiltration"],
                failure_indicators=["SQL syntax error", "Query failure"],
                side_effects=["Data corruption", "Information disclosure"],
                detection_signatures=["SQL syntax in parameters", "UNION SELECT"],
                mitigation_techniques=["Parameterized queries", "Input validation", "WAF"]
            ),
            ExploitPattern(
                pattern_id="EP003",
                name="Remote Code Execution",
                vulnerability_type="Code injection",
                exploitation_method="Command injection",
                required_conditions=["Command execution", "User input"],
                success_indicators=["Command output", "Shell access"],
                failure_indicators=["Command not found", "Permission denied"],
                side_effects=["System compromise", "Privilege escalation"],
                detection_signatures=["Shell commands in input", "System calls"],
                mitigation_techniques=["Input sanitization", "Command filtering", "Sandboxing"]
            )
        ]
        
        for pattern in sample_patterns:
            self.add_exploit_pattern(pattern)
    
    def _load_sample_evasion_patterns(self):
        """Load sample evasion patterns."""
        sample_patterns = [
            EvasionPattern(
                pattern_id="EV001",
                name="Process Hollowing",
                evasion_technique="Process manipulation",
                target_defenses=["Process monitoring", "Antivirus"],
                implementation_methods=["CreateProcess", "WriteProcessMemory", "ResumeThread"],
                detection_bypasses=["Process name spoofing", "Parent process hiding"],
                effectiveness_score=0.8,
                countermeasures=["Process creation monitoring", "Memory integrity checks"]
            ),
            EvasionPattern(
                pattern_id="EV002",
                name="Living off the Land",
                evasion_technique="Legitimate tool abuse",
                target_defenses=["Tool-based detection", "Whitelisting"],
                implementation_methods=["PowerShell", "WMI", "Certutil", "Bitsadmin"],
                detection_bypasses=["Legitimate process usage", "Signed binaries"],
                effectiveness_score=0.7,
                countermeasures=["Command-line logging", "Behavioral analysis"]
            ),
            EvasionPattern(
                pattern_id="EV003",
                name="Rootkit Techniques",
                evasion_technique="System modification",
                target_defenses=["File system monitoring", "Integrity checking"],
                implementation_methods=["Kernel module loading", "System call hooking", "DKOM"],
                detection_bypasses=["Hidden processes", "File system hiding"],
                effectiveness_score=0.9,
                countermeasures=["Kernel integrity checking", "Trusted boot"]
            )
        ]
        
        for pattern in sample_patterns:
            self.add_evasion_pattern(pattern)
    
    def _create_knowledge_version(self, version: int, description: str, changes: str):
        """Create a knowledge version entry."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO knowledge_versions (version, created_at, description, changes_summary)
                VALUES (?, ?, ?, ?)
            """, (version, datetime.now().isoformat(), description, changes))
            conn.commit()
    
    def add_cve_entry(self, cve: CVEEntry) -> bool:
        """Add CVE entry to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO cve_entries 
                    (cve_id, description, severity, cvss_score, cvss_vector,
                     published_date, modified_date, affected_products, cve_references,
                     exploit_available, exploit_complexity, required_privileges,
                     user_interaction, scope_changed, confidentiality_impact,
                     integrity_impact, availability_impact)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve.cve_id, cve.description, cve.severity.value, cve.cvss_score,
                    cve.cvss_vector, cve.published_date.isoformat(), cve.modified_date.isoformat(),
                    json.dumps(cve.affected_products), json.dumps(cve.references),
                    cve.exploit_available, cve.exploit_complexity, cve.required_privileges,
                    cve.user_interaction, cve.scope_changed, cve.confidentiality_impact,
                    cve.integrity_impact, cve.availability_impact
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to add CVE entry {cve.cve_id}: {e}")
            return False
    
    def add_attack_technique(self, technique: AttackTechnique) -> bool:
        """Add attack technique to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO attack_techniques 
                    (technique_id, name, description, tactic, platforms,
                     data_sources, detection, mitigation, ref_links)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    technique.technique_id, technique.name, technique.description,
                    technique.phase.value, json.dumps(technique.platforms),
                    json.dumps(technique.data_sources), json.dumps(technique.detection_methods),
                    technique.mitigation, json.dumps([])
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to add attack technique {technique.technique_id}: {e}")
            return False
    
    def add_service_vulnerability(self, service: ServiceVulnerability) -> bool:
        """Add service vulnerability to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO service_vulnerabilities
                    (service_name, version_pattern, vulnerability_type, description,
                     severity, cve_refs, exploit_refs, detection_methods, mitigation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    service.service_name, service.service_version, "Unknown", "",
                    "Medium", json.dumps(service.cve_ids), json.dumps(service.exploitation_methods),
                    json.dumps(service.detection_signatures), ""
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to add service vulnerability {service.service_name}: {e}")
            return False
    
    def add_exploit_pattern(self, pattern: ExploitPattern) -> bool:
        """Add exploit pattern to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO exploit_patterns 
                    (pattern_id, name, description, category, technique_refs,
                     service_refs, payload_examples, detection_indicators,
                     success_indicators, complexity, reliability, side_effects)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern.pattern_id, pattern.name, "", pattern.vulnerability_type, json.dumps([]),
                    json.dumps([]), json.dumps([]), json.dumps(pattern.detection_signatures),
                    json.dumps(pattern.success_indicators), "Medium", "High", json.dumps(pattern.side_effects)
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to add exploit pattern {pattern.pattern_id}: {e}")
            return False
    
    def add_evasion_pattern(self, pattern: EvasionPattern) -> bool:
        """Add evasion pattern to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO evasion_patterns 
                    (pattern_id, name, description, category, target_systems,
                     technique_refs, implementation, detection_bypass, effectiveness)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern.pattern_id, pattern.name, "", pattern.evasion_technique, json.dumps(pattern.target_defenses),
                    json.dumps([]), json.dumps(pattern.implementation_methods), json.dumps(pattern.detection_bypasses),
                    pattern.effectiveness_score
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to add evasion pattern {pattern.pattern_id}: {e}")
            return False
    
    def search_cve(self, query: str, limit: int = 50) -> List[CVEEntry]:
        """Search CVE entries."""
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Search by CVE ID, description, or affected products
                search_pattern = f"%{query}%"
                cursor.execute("""
                    SELECT * FROM cve_entries 
                    WHERE cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?
                    ORDER BY cvss_score DESC
                    LIMIT ?
                """, (search_pattern, search_pattern, search_pattern, limit))
                
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                for row in rows:
                    data = dict(zip(columns, row))
                    cve = CVEEntry(
                        cve_id=data['cve_id'],
                        description=data['description'],
                        severity=VulnerabilitySeverity(data['severity']),
                        cvss_score=data['cvss_score'],
                        cvss_vector=data['cvss_vector'],
                        published_date=datetime.fromisoformat(data['published_date']),
                        modified_date=datetime.fromisoformat(data['modified_date']),
                        affected_products=json.loads(data['affected_products']),
                        references=json.loads(data['cve_references']),
                        exploit_available=data['exploit_available'],
                        exploit_complexity=data['exploit_complexity'],
                        required_privileges=data['required_privileges'],
                        user_interaction=data['user_interaction'],
                        scope_changed=data['scope_changed'],
                        confidentiality_impact=data['confidentiality_impact'],
                        integrity_impact=data['integrity_impact'],
                        availability_impact=data['availability_impact']
                    )
                    results.append(cve)
        
        except Exception as e:
            self.logger.error(f"CVE search failed for query '{query}': {e}")
        
        return results
    
    def get_attack_techniques_by_phase(self, phase: AttackPhase) -> List[Dict]:
        """Get attack techniques by tactic phase.
        
        NOTE: Actual DB column is 'tactic' not 'phase'.
        Returns dicts instead of dataclass because schema doesn't match dataclass.
        """
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT technique_id, name, description, tactic, platforms,
                           detection, mitigation
                    FROM attack_techniques WHERE tactic = ?
                    ORDER BY name
                """, (phase.value,))
                
                for row in cursor.fetchall():
                    results.append({
                        'technique_id': row[0],
                        'name': row[1],
                        'description': row[2],
                        'tactic': row[3],
                        'platforms': json.loads(row[4]) if row[4] else [],
                        'detection': row[5],
                        'mitigation': row[6],
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to get techniques for tactic {phase.value}: {e}")
        
        return results
    
    def get_service_vulnerabilities(self, service_name: str, version: str = "") -> List[Dict]:
        """Get vulnerabilities for a specific service.
        
        NOTE: Actual DB uses version_pattern, cve_refs, exploit_refs, etc.
        """
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if version:
                    cursor.execute("""
                        SELECT vuln_id, service_name, version_pattern, vulnerability_type,
                               description, severity, cve_refs, exploit_refs,
                               detection_methods, mitigation
                        FROM service_vulnerabilities 
                        WHERE service_name LIKE ? AND version_pattern LIKE ?
                    """, (f"%{service_name}%", f"%{version}%"))
                else:
                    cursor.execute("""
                        SELECT vuln_id, service_name, version_pattern, vulnerability_type,
                               description, severity, cve_refs, exploit_refs,
                               detection_methods, mitigation
                        FROM service_vulnerabilities 
                        WHERE service_name LIKE ?
                    """, (f"%{service_name}%",))
                
                for row in cursor.fetchall():
                    results.append({
                        'vuln_id': row[0],
                        'service_name': row[1],
                        'version_pattern': row[2],
                        'vulnerability_type': row[3],
                        'description': row[4],
                        'severity': row[5],
                        'cve_refs': json.loads(row[6]) if row[6] else [],
                        'exploit_refs': json.loads(row[7]) if row[7] else [],
                        'detection_methods': json.loads(row[8]) if row[8] else [],
                        'mitigation': row[9],
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to get service vulnerabilities for {service_name}: {e}")
        
        return results
    
    def get_exploit_patterns_by_type(self, vulnerability_type: str) -> List[Dict]:
        """Get exploit patterns by category/vulnerability type.
        
        NOTE: Actual DB uses 'category' column, not 'vulnerability_type'.
        """
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT pattern_id, name, description, category,
                           technique_refs, service_refs, payload_examples,
                           success_indicators, complexity, reliability
                    FROM exploit_patterns 
                    WHERE category LIKE ? OR description LIKE ?
                """, (f"%{vulnerability_type}%", f"%{vulnerability_type}%"))
                
                for row in cursor.fetchall():
                    results.append({
                        'pattern_id': row[0],
                        'name': row[1],
                        'description': row[2],
                        'category': row[3],
                        'technique_refs': json.loads(row[4]) if row[4] else [],
                        'service_refs': json.loads(row[5]) if row[5] else [],
                        'payload_examples': json.loads(row[6]) if row[6] else [],
                        'success_indicators': json.loads(row[7]) if row[7] else [],
                        'complexity': row[8],
                        'reliability': row[9],
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to get exploit patterns for type {vulnerability_type}: {e}")
        
        return results
    
    def get_knowledge_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        stats = {}
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # CVE statistics
                cursor.execute("SELECT COUNT(*) FROM cve_entries")
                stats['cve_count'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity")
                stats['cve_by_severity'] = dict(cursor.fetchall())
                
                # Attack techniques statistics
                cursor.execute("SELECT COUNT(*) FROM attack_techniques")
                stats['technique_count'] = cursor.fetchone()[0]
                
                # Use 'tactic' column (actual DB schema)
                cursor.execute("SELECT tactic, COUNT(*) FROM attack_techniques GROUP BY tactic")
                stats['techniques_by_tactic'] = dict(cursor.fetchall())
                
                # Service vulnerabilities statistics
                cursor.execute("SELECT COUNT(*) FROM service_vulnerabilities")
                stats['service_vuln_count'] = cursor.fetchone()[0]
                
                # Exploit patterns statistics
                cursor.execute("SELECT COUNT(*) FROM exploit_patterns")
                stats['exploit_pattern_count'] = cursor.fetchone()[0]
                
                # Evasion patterns statistics
                cursor.execute("SELECT COUNT(*) FROM evasion_patterns")
                stats['evasion_pattern_count'] = cursor.fetchone()[0]
                
                # Workflow rules
                cursor.execute("SELECT COUNT(*) FROM workflow_rules")
                stats['workflow_rule_count'] = cursor.fetchone()[0]
                
                # CVE depth
                cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE exploit_available = 1")
                stats['exploitable_cves'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE cvss_score >= 9.0")
                stats['critical_cves'] = cursor.fetchone()[0]
                
                # Knowledge version
                cursor.execute("SELECT MAX(version) FROM knowledge_versions")
                stats['knowledge_version'] = cursor.fetchone()[0] or 0
        
        except Exception as e:
            self.logger.error(f"Failed to get knowledge statistics: {e}")
        
        return stats
    
    def export_knowledge(self, format: str = "json") -> Dict[str, Any]:
        """Export knowledge base."""
        export_data = {
            'metadata': {
                'exported_at': datetime.now().isoformat(),
                'knowledge_version': self.get_knowledge_statistics().get('knowledge_version', 0)
            },
            'cve_entries': [],
            'attack_techniques': [],
            'service_vulnerabilities': [],
            'exploit_patterns': [],
            'evasion_patterns': []
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Export CVEs
                cursor.execute("SELECT * FROM cve_entries")
                for row in cursor.fetchall():
                    data = dict(zip([desc[0] for desc in cursor.description], row))
                    export_data['cve_entries'].append(data)
                
                # Export attack techniques
                cursor.execute("SELECT * FROM attack_techniques")
                for row in cursor.fetchall():
                    data = dict(zip([desc[0] for desc in cursor.description], row))
                    export_data['attack_techniques'].append(data)
                
                # Export service vulnerabilities
                cursor.execute("SELECT * FROM service_vulnerabilities")
                for row in cursor.fetchall():
                    data = dict(zip([desc[0] for desc in cursor.description], row))
                    export_data['service_vulnerabilities'].append(data)
                
                # Export exploit patterns
                cursor.execute("SELECT * FROM exploit_patterns")
                for row in cursor.fetchall():
                    data = dict(zip([desc[0] for desc in cursor.description], row))
                    export_data['exploit_patterns'].append(data)
                
                # Export evasion patterns
                cursor.execute("SELECT * FROM evasion_patterns")
                for row in cursor.fetchall():
                    data = dict(zip([desc[0] for desc in cursor.description], row))
                    export_data['evasion_patterns'].append(data)
        
        except Exception as e:
            self.logger.error(f"Failed to export knowledge: {e}")
        
        return export_data
