"""
Specialized Pentest Agents - Core Intelligence Layer

Implements the highest-priority agents from the architecture doc:
    - ReconAgent: Passive/active reconnaissance
    - VulnHunterAgent: Critical vulnerability hunter (CVSS 10/10 focus)
    - AttackChainAgent: MITRE ATT&CK path analysis & escalation
    - ExploitAgent: Exploitation orchestration  
    - CorrelationBrainAgent: Cross-tool correlation & prioritization
    - EvasionAgent: OPSEC, stealth, and anti-detection

Each agent wraps existing framework modules and exposes 
capabilities via the BaseAgent interface.
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
# RECON AGENT
# ══════════════════════════════════════════════════════════════════════════════

class ReconAgent(BaseAgent):
    """Reconnaissance agent covering passive + active recon.
    
    Wraps existing framework tools:
        - nmap/masscan for port scanning
        - subfinder/amass for subdomain enum
        - DNS enumeration
        - Service fingerprinting
    
    Corresponds to doc agents: Reconnaissance Passive, Network Mapper,
    Service Enumeration, Infrastructure Detector
    """

    def __init__(self):
        super().__init__(
            agent_id="recon_agent",
            name="Reconnaissance Agent",
            category=AgentCategory.RECONNAISSANCE,
            description=(
                "Multi-phase reconnaissance: passive OSINT, "
                "subdomain enumeration, port scanning, service detection, "
                "OS fingerprinting, infrastructure profiling"
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="passive_recon",
                description="Passive OSINT: subdomain enum, DNS records, cert transparency, Shodan/Censys",
                requires_tools=["subfinder", "amass", "dig", "curl"],
                risk_level=1,
                estimated_duration=60.0,
            ),
            AgentCapability(
                name="port_scan",
                description="Port scanning with service detection and OS fingerprinting",
                requires_tools=["nmap", "masscan"],
                risk_level=2,
                estimated_duration=120.0,
            ),
            AgentCapability(
                name="service_enum",
                description="Deep service enumeration: SMB, LDAP, NFS, databases, web servers",
                requires_tools=["nmap", "enum4linux", "ldapsearch"],
                risk_level=3,
                estimated_duration=90.0,
            ),
            AgentCapability(
                name="infrastructure_detect",
                description="Cloud/container/CI-CD infrastructure detection",
                requires_tools=["curl", "nmap"],
                risk_level=1,
                estimated_duration=45.0,
            ),
        ]

    async def _initialize(self):
        """Load tool profiles from knowledge DB."""
        self._tool_commands = {}
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            for row in cur.execute(
                "SELECT tool_id, command_template, parameters FROM tool_profiles"
            ).fetchall():
                self._tool_commands[row[0]] = {
                    "template": row[1],
                    "defaults": json.loads(row[2]) if row[2] else {},
                }
            conn.close()
            self.logger.info(f"Loaded {len(self._tool_commands)} tool profiles")
        except Exception as e:
            self.logger.warning(f"Could not load tool profiles: {e}")

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target is required")

        if task_type == "passive_recon":
            return await self._passive_recon(target, params)
        elif task_type == "port_scan":
            return await self._port_scan(target, params)
        elif task_type == "service_enum":
            return await self._service_enum(target, params)
        elif task_type == "infrastructure_detect":
            return await self._infra_detect(target, params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _passive_recon(self, target: str, params: Dict) -> Dict:
        """Passive reconnaissance pipeline."""
        results = {"target": target, "type": "passive_recon", "findings": []}

        # Build command plan
        commands = [
            f"subfinder -d {target} -silent",
            f"dig ANY {target} +noall +answer",
            f"dig {target} MX +short",
            f"dig {target} TXT +short",
            f"dig {target} NS +short",
        ]

        results["commands"] = commands
        results["recommended_next"] = "port_scan"
        return results

    async def _port_scan(self, target: str, params: Dict) -> Dict:
        """Port scanning pipeline."""
        scan_type = params.get("scan_type", "quick")
        
        if scan_type == "quick":
            cmd = f"nmap -sV -sC --top-ports 1000 -T4 {target}"
        elif scan_type == "comprehensive":
            cmd = f"nmap -sV -sC -O -p- -T3 {target}"
        elif scan_type == "stealth":
            cmd = f"nmap -sS -sV -T2 --randomize-hosts -D RND:5 {target}"
        else:
            cmd = f"nmap -sV {target}"

        return {
            "target": target,
            "type": "port_scan",
            "scan_type": scan_type,
            "command": cmd,
            "recommended_next": "service_enum",
        }

    async def _service_enum(self, target: str, params: Dict) -> Dict:
        """Service enumeration based on discovered ports."""
        services = params.get("services", [])
        commands = []

        for svc in services:
            port = svc.get("port", 0)
            name = svc.get("name", "").lower()
            
            if "smb" in name or port in (139, 445):
                commands.append(f"enum4linux -a {target}")
                commands.append(f"netexec smb {target} --shares")
            elif "ldap" in name or port in (389, 636):
                commands.append(f"ldapsearch -x -H ldap://{target} -b '' -s base")
            elif "http" in name or port in (80, 443, 8080, 8443):
                commands.append(f"whatweb {target}:{port}")
                commands.append(f"nikto -h {target}:{port}")
            elif "ssh" in name or port == 22:
                commands.append(f"nmap --script ssh-auth-methods -p {port} {target}")
            elif "ftp" in name or port == 21:
                commands.append(f"nmap --script ftp-anon -p {port} {target}")
            elif "mysql" in name or port == 3306:
                commands.append(f"nmap --script mysql-info -p {port} {target}")
            elif "redis" in name or port == 6379:
                commands.append(f"redis-cli -h {target} INFO")
            elif "mongo" in name or port == 27017:
                commands.append(f"nmap --script mongodb-info -p {port} {target}")

        return {
            "target": target,
            "type": "service_enum",
            "commands": commands,
            "service_count": len(services),
            "recommended_next": "vulnerability_assessment",
        }

    async def _infra_detect(self, target: str, params: Dict) -> Dict:
        """Infrastructure detection."""
        commands = [
            f"curl -sI https://{target} | head -20",
            f"nmap --script http-headers -p 80,443 {target}",
        ]
        return {
            "target": target,
            "type": "infrastructure_detect",
            "commands": commands,
            "checks": ["cloud_provider", "cdn", "waf", "containers", "ci_cd"],
        }


# ══════════════════════════════════════════════════════════════════════════════
# VULN HUNTER AGENT
# ══════════════════════════════════════════════════════════════════════════════

class VulnHunterAgent(BaseAgent):
    """Critical Vulnerability Hunter - CVSS 10/10 focus.
    
    Specializes in finding the highest-severity vulnerabilities
    and RCE opportunities. Cross-references the knowledge DB
    to identify known vulns in discovered services.
    
    Corresponds to doc agents: Critical Vulnerability Hunter,
    Auto Vulnerability Scanner
    """

    def __init__(self):
        super().__init__(
            agent_id="vuln_hunter",
            name="Critical Vulnerability Hunter",
            category=AgentCategory.VULNERABILITY,
            description=(
                "Specialized in finding CVSS 9.0+ vulnerabilities with RCE potential. "
                "Cross-references discovered services with 317K+ CVE database, "
                "identifies exploit chains, and prioritizes attack paths."
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="vuln_assess",
                description="Cross-reference discovered services with CVE database for critical vulns",
                risk_level=2,
                estimated_duration=30.0,
            ),
            AgentCapability(
                name="rce_hunt",
                description="Hunt for RCE vulnerabilities: deserialization, command injection, SSTI, file upload",
                risk_level=4,
                estimated_duration=120.0,
            ),
            AgentCapability(
                name="auto_scan",
                description="Run automated scanners (nuclei, nmap scripts) against target",
                requires_tools=["nuclei", "nmap"],
                risk_level=3,
                estimated_duration=180.0,
            ),
            AgentCapability(
                name="cve_lookup",
                description="Deep CVE lookup for specific service/version",
                risk_level=1,
                estimated_duration=5.0,
            ),
        ]

    async def _initialize(self):
        """Pre-load critical CVE patterns."""
        self._critical_patterns = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            # Load RCE-capable CVEs
            rows = cur.execute("""
                SELECT cve_id, description, cvss_score, affected_products, 
                       exploit_available, exploit_complexity
                FROM cve_entries 
                WHERE cvss_score >= 9.0 AND exploit_available = 1
                ORDER BY cvss_score DESC
                LIMIT 500
            """).fetchall()
            for row in rows:
                self._critical_patterns.append({
                    "cve_id": row[0],
                    "description": row[1],
                    "cvss": row[2],
                    "products": row[3],
                    "exploit_complexity": row[5],
                })
            conn.close()
            self.logger.info(f"Loaded {len(self._critical_patterns)} critical CVE patterns")
        except Exception as e:
            self.logger.warning(f"Could not pre-load CVEs: {e}")

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "vuln_assess":
            return await self._vuln_assess(params)
        elif task_type == "rce_hunt":
            return await self._rce_hunt(params)
        elif task_type == "auto_scan":
            return await self._auto_scan(params)
        elif task_type == "cve_lookup":
            return await self._cve_lookup(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _vuln_assess(self, params: Dict) -> Dict:
        """Cross-reference services with CVE database."""
        services = params.get("services", [])
        target = params.get("target", "")
        findings = []

        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()

            for svc in services:
                name = svc.get("name", "").lower()
                version = svc.get("version", "")
                port = svc.get("port", 0)
                search = f"%{name}%"

                # Find service vulns
                svc_vulns = cur.execute("""
                    SELECT service_name, version_pattern, vulnerability_type,
                           severity, cve_refs, description
                    FROM service_vulnerabilities
                    WHERE service_name LIKE ?
                    LIMIT 10
                """, (search,)).fetchall()

                # Find CVEs
                cve_search = f"%{name}%"
                if version:
                    cve_search = f"%{name}%{version}%"

                cves = cur.execute("""
                    SELECT cve_id, cvss_score, description, exploit_available,
                           exploit_complexity
                    FROM cve_entries
                    WHERE (description LIKE ? OR affected_products LIKE ?)
                          AND cvss_score >= 7.0
                    ORDER BY cvss_score DESC
                    LIMIT 15
                """, (cve_search, cve_search)).fetchall()

                if svc_vulns or cves:
                    finding = {
                        "service": name,
                        "version": version,
                        "port": port,
                        "service_vulns": len(svc_vulns),
                        "critical_cves": len([c for c in cves if c[1] and c[1] >= 9.0]),
                        "exploitable_cves": len([c for c in cves if c[3]]),
                        "top_cves": [
                            {"cve": c[0], "cvss": c[1], "exploit": bool(c[3]),
                             "complexity": c[4]}
                            for c in cves[:5]
                        ],
                        "rce_potential": any(
                            "remote code" in (c[2] or "").lower() or
                            "command injection" in (c[2] or "").lower() or
                            "arbitrary code" in (c[2] or "").lower()
                            for c in cves
                        ),
                    }
                    findings.append(finding)
        finally:
            conn.close()

        # Sort by criticality
        findings.sort(key=lambda f: (f.get("rce_potential", False), 
                                     f.get("critical_cves", 0)), reverse=True)

        return {
            "target": target,
            "type": "vuln_assess",
            "total_services_checked": len(services),
            "vulnerable_services": len(findings),
            "rce_candidates": sum(1 for f in findings if f.get("rce_potential")),
            "findings": findings,
            "recommended_next": "rce_hunt" if any(f.get("rce_potential") for f in findings) else "auto_scan",
        }

    async def _rce_hunt(self, params: Dict) -> Dict:
        """Hunt for RCE vectors."""
        target = params.get("target", "")
        services = params.get("services", [])
        
        rce_checks = []
        for svc in services:
            name = svc.get("name", "").lower()
            port = svc.get("port", 0)
            
            checks = {"service": name, "port": port, "tests": []}
            
            # RCE test patterns by service
            if "http" in name or port in (80, 443, 8080):
                checks["tests"].extend([
                    {"type": "ssti", "cmd": f"nuclei -u http://{target}:{port} -tags ssti -severity critical,high"},
                    {"type": "rce", "cmd": f"nuclei -u http://{target}:{port} -tags rce -severity critical"},
                    {"type": "upload", "cmd": f"nuclei -u http://{target}:{port} -tags fileupload"},
                    {"type": "deserialization", "cmd": f"nuclei -u http://{target}:{port} -tags deserialization"},
                ])
            if "java" in name or "tomcat" in name or port in (8080, 8443):
                checks["tests"].append(
                    {"type": "java_deser", "cmd": f"nuclei -u http://{target}:{port} -tags java,deserialization -severity critical"}
                )
            if "smb" in name or port == 445:
                checks["tests"].append(
                    {"type": "eternal_blue", "cmd": f"nmap --script smb-vuln-ms17-010 -p 445 {target}"}
                )
            if "redis" in name or port == 6379:
                checks["tests"].append(
                    {"type": "redis_rce", "cmd": f"redis-cli -h {target} CONFIG GET dir"}
                )
            
            if checks["tests"]:
                rce_checks.append(checks)

        return {
            "target": target,
            "type": "rce_hunt",
            "rce_checks": rce_checks,
            "total_tests": sum(len(c["tests"]) for c in rce_checks),
            "recommended_next": "exploit",
        }

    async def _auto_scan(self, params: Dict) -> Dict:
        """Automated vulnerability scanning."""
        target = params.get("target", "")
        scan_type = params.get("scan_type", "critical")
        
        commands = []
        if scan_type in ("critical", "comprehensive"):
            commands.append(f"nuclei -u {target} -severity critical,high -stats")
        if scan_type == "comprehensive":
            commands.append(f"nuclei -u {target} -severity medium -stats")
            commands.append(f"nikto -h {target} -C all")
        
        commands.append(f"nmap --script vuln -p- {target}")
        
        return {
            "target": target,
            "type": "auto_scan",
            "scan_type": scan_type,
            "commands": commands,
        }

    async def _cve_lookup(self, params: Dict) -> Dict:
        """Deep CVE lookup."""
        query = params.get("query", "")
        conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
        cur = conn.cursor()
        
        rows = cur.execute("""
            SELECT cve_id, description, cvss_score, severity,
                   exploit_available, exploit_complexity, affected_products,
                   confidentiality_impact, integrity_impact, availability_impact
            FROM cve_entries
            WHERE cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?
            ORDER BY cvss_score DESC
            LIMIT 20
        """, (f"%{query}%", f"%{query}%", f"%{query}%")).fetchall()
        conn.close()

        return {
            "query": query,
            "type": "cve_lookup",
            "count": len(rows),
            "results": [
                {
                    "cve_id": r[0], "description": (r[1] or "")[:300],
                    "cvss": r[2], "severity": r[3],
                    "exploit_available": bool(r[4]),
                    "complexity": r[5],
                    "products": r[6][:200] if r[6] else "",
                    "cia": f"C:{r[7]} I:{r[8]} A:{r[9]}",
                }
                for r in rows
            ],
        }


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CHAIN AGENT
# ══════════════════════════════════════════════════════════════════════════════

class AttackChainAgent(BaseAgent):
    """Attack Chain Analyzer - MITRE ATT&CK path optimization.
    
    Analyzes discovered vulnerabilities and maps them to MITRE ATT&CK
    techniques to find optimal attack paths from initial access to RCE.
    Specializes in escalating minor vulns to critical chains.
    
    Corresponds to doc agents: Correlation Brain (attack paths),
    Critical Vulnerability Hunter (chain analysis)
    """

    def __init__(self):
        super().__init__(
            agent_id="attack_chain",
            name="Attack Chain Analyzer",
            category=AgentCategory.INTELLIGENCE,
            description=(
                "MITRE ATT&CK path optimizer. Maps vulns to techniques, "
                "builds attack graphs, finds shortest path to RCE, "
                "and escalates minor vulns through chained exploitation."
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="build_attack_graph",
                description="Build attack graph from discovered vulns + MITRE ATT&CK techniques",
                risk_level=1,
                estimated_duration=15.0,
            ),
            AgentCapability(
                name="find_attack_path",
                description="Find optimal attack paths from initial access to target (RCE/data/persistence)",
                risk_level=1,
                estimated_duration=10.0,
            ),
            AgentCapability(
                name="escalation_chains",
                description="Find chains that escalate minor vulns to critical impact via chaining",
                risk_level=2,
                estimated_duration=20.0,
            ),
        ]

    async def _initialize(self):
        """Load MITRE ATT&CK techniques and tactic kill chain."""
        self._techniques = {}
        self._tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            rows = cur.execute("""
                SELECT technique_id, name, tactic, description, platforms, detection
                FROM attack_techniques
            """).fetchall()
            for row in rows:
                self._techniques[row[0]] = {
                    "name": row[1], "tactic": row[2],
                    "description": (row[3] or "")[:200],
                    "platforms": row[4], "detection": row[5],
                }
            conn.close()
            self.logger.info(f"Loaded {len(self._techniques)} ATT&CK techniques")
        except Exception as e:
            self.logger.warning(f"Could not load techniques: {e}")

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "build_attack_graph":
            return await self._build_graph(params)
        elif task_type == "find_attack_path":
            return await self._find_path(params)
        elif task_type == "escalation_chains":
            return await self._escalation_chains(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _build_graph(self, params: Dict) -> Dict:
        """Build attack graph from vulnerability findings."""
        findings = params.get("findings", [])
        target = params.get("target", "")

        nodes = []
        edges = []

        # Add target as root node
        nodes.append({"id": "target", "type": "target", "label": target})

        # Map findings to tactics
        for i, finding in enumerate(findings):
            node_id = f"vuln_{i}"
            service = finding.get("service", "unknown")
            port = finding.get("port", 0)
            
            nodes.append({
                "id": node_id,
                "type": "vulnerability",
                "label": f"{service}:{port}",
                "severity": finding.get("severity", "unknown"),
                "rce_potential": finding.get("rce_potential", False),
            })
            
            # Connect to target
            edges.append({"from": "target", "to": node_id, "type": "exposes"})

            # Map to ATT&CK techniques
            cves = finding.get("top_cves", [])
            for cve in cves:
                cve_node = f"cve_{cve.get('cve', '')}"
                nodes.append({
                    "id": cve_node,
                    "type": "cve",
                    "label": cve.get("cve", ""),
                    "cvss": cve.get("cvss", 0),
                    "exploit": cve.get("exploit", False),
                })
                edges.append({"from": node_id, "to": cve_node, "type": "has_cve"})

        # Find relevant ATT&CK techniques
        relevant_techniques = []
        for tid, tech in self._techniques.items():
            tactic = tech.get("tactic", "")
            if tactic in ("initial-access", "execution", "privilege-escalation"):
                relevant_techniques.append({
                    "id": tid,
                    "name": tech["name"],
                    "tactic": tactic,
                })

        return {
            "target": target,
            "type": "attack_graph",
            "nodes": len(nodes),
            "edges": len(edges),
            "graph": {"nodes": nodes[:50], "edges": edges[:100]},
            "relevant_techniques": relevant_techniques[:20],
            "attack_surface_score": len(findings) * 10,
        }

    async def _find_path(self, params: Dict) -> Dict:
        """Find optimal attack path to objective."""
        findings = params.get("findings", [])
        objective = params.get("objective", "rce")
        
        paths = []
        
        # Score each finding as a potential path
        for finding in findings:
            score = 0
            steps = []
            
            if finding.get("rce_potential"):
                score += 50
                steps.append({"phase": "initial_access", "via": finding.get("service", "")})
                steps.append({"phase": "execution", "via": "RCE exploit"})
                if objective == "persistence":
                    steps.append({"phase": "persistence", "via": "backdoor installation"})
                    score += 10
            
            if finding.get("critical_cves", 0) > 0:
                score += finding["critical_cves"] * 15
            
            if finding.get("exploitable_cves", 0) > 0:
                score += finding["exploitable_cves"] * 20
            
            if score > 0:
                paths.append({
                    "service": finding.get("service", ""),
                    "port": finding.get("port", 0),
                    "score": score,
                    "steps": steps,
                    "rce_direct": finding.get("rce_potential", False),
                    "top_cve": finding.get("top_cves", [{}])[0] if finding.get("top_cves") else {},
                })

        # Sort by score
        paths.sort(key=lambda p: p["score"], reverse=True)

        return {
            "type": "attack_path",
            "objective": objective,
            "total_paths": len(paths),
            "best_path": paths[0] if paths else None,
            "all_paths": paths[:10],
            "recommended_next": "exploit" if paths else "deeper_recon",
        }

    async def _escalation_chains(self, params: Dict) -> Dict:
        """Find escalation chains from minor to critical."""
        findings = params.get("findings", [])
        
        chains = []
        
        # Look for chaining opportunities
        info_vulns = [f for f in findings if f.get("severity") in ("low", "medium", "info")]
        high_vulns = [f for f in findings if f.get("severity") in ("high", "critical")]
        
        # Example chains: info disclosure -> credential -> lateral -> RCE
        for info_v in info_vulns:
            for high_v in high_vulns:
                chain = {
                    "start": info_v.get("service", ""),
                    "end": high_v.get("service", ""),
                    "chain": [
                        {"step": 1, "action": f"Exploit {info_v.get('service', '')} info disclosure", "severity": "low"},
                        {"step": 2, "action": "Extract credentials/tokens", "severity": "medium"},
                        {"step": 3, "action": f"Use credentials on {high_v.get('service', '')}", "severity": "high"},
                        {"step": 4, "action": "Achieve RCE via authenticated exploit", "severity": "critical"},
                    ],
                    "feasibility": 0.5,
                    "techniques": ["T1078", "T1021", "T1059"],
                }
                chains.append(chain)
        
        return {
            "type": "escalation_chains",
            "total_chains": len(chains),
            "chains": chains[:10],
            "recommended_next": "exploit",
        }


# ══════════════════════════════════════════════════════════════════════════════
# EXPLOIT AGENT
# ══════════════════════════════════════════════════════════════════════════════

class ExploitAgent(BaseAgent):
    """Exploitation orchestration agent.
    
    Wraps existing auto_exploit.py and payload_manager.py
    to execute exploits against targets.
    
    Corresponds to doc agents: Exploit Agent, RCE Specialist,
    Payload Orchestrator
    """

    def __init__(self):
        super().__init__(
            agent_id="exploit_agent",
            name="Exploit Orchestrator",
            category=AgentCategory.EXPLOITATION,
            description=(
                "Orchestrates exploitation using Metasploit, custom exploits, "
                "and payload management. Handles exploit selection, "
                "payload encoding, session management, and post-exploit actions."
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="exploit_plan",
                description="Generate exploitation plan for identified vulnerabilities",
                risk_level=4,
                estimated_duration=15.0,
            ),
            AgentCapability(
                name="payload_select",
                description="Select and encode optimal payload for target + exploit combination",
                risk_level=3,
                estimated_duration=10.0,
            ),
            AgentCapability(
                name="exploit_execute",
                description="Execute exploit against target",
                risk_level=5,
                estimated_duration=60.0,
            ),
        ]

    async def _initialize(self):
        """Load exploit patterns from knowledge DB."""
        self._exploit_patterns = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            rows = cur.execute("""
                SELECT pattern_id, name, category, complexity, reliability,
                       payload_examples, success_indicators
                FROM exploit_patterns
                ORDER BY reliability DESC
            """).fetchall()
            for row in rows:
                self._exploit_patterns.append({
                    "id": row[0], "name": row[1], "category": row[2],
                    "complexity": row[3], "reliability": row[4],
                    "payloads": json.loads(row[5]) if row[5] else [],
                    "indicators": json.loads(row[6]) if row[6] else [],
                })
            conn.close()
            self.logger.info(f"Loaded {len(self._exploit_patterns)} exploit patterns")
        except Exception as e:
            self.logger.warning(f"Could not load exploit patterns: {e}")

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "exploit_plan":
            return await self._exploit_plan(params)
        elif task_type == "payload_select":
            return await self._payload_select(params)
        elif task_type == "exploit_execute":
            return await self._exploit_execute(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _exploit_plan(self, params: Dict) -> Dict:
        """Generate exploitation plan."""
        target = params.get("target", "")
        vulns = params.get("vulnerabilities", [])
        
        plan = []
        for vuln in vulns:
            cve = vuln.get("cve_id", "")
            service = vuln.get("service", "")
            
            # Match with exploit patterns
            matching_patterns = [
                p for p in self._exploit_patterns
                if service.lower() in p.get("name", "").lower() or
                   service.lower() in p.get("category", "").lower()
            ]
            
            plan.append({
                "target": target,
                "vulnerability": cve or service,
                "exploit_options": [
                    {"name": p["name"], "reliability": p["reliability"], "complexity": p["complexity"]}
                    for p in matching_patterns[:3]
                ],
                "metasploit_search": f"search cve:{cve}" if cve else f"search {service}",
                "priority": "high" if vuln.get("rce_potential") else "medium",
            })
        
        return {
            "type": "exploit_plan",
            "target": target,
            "total_vulns": len(vulns),
            "exploitable": len(plan),
            "plan": plan,
        }

    async def _payload_select(self, params: Dict) -> Dict:
        """Select optimal payload."""
        target_service = params.get("target_service", "")
        exploit_type = params.get("exploit_type", "reverse_shell")
        
        payloads = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            
            rows = cur.execute("""
                SELECT payload_id, name, category, severity, content
                FROM payloads
                WHERE category LIKE ? OR name LIKE ? OR content LIKE ?
                ORDER BY CASE severity 
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 ELSE 4 END
                LIMIT 10
            """, (f"%{exploit_type}%", f"%{target_service}%", f"%{target_service}%")).fetchall()
            
            for row in rows:
                payloads.append({
                    "id": row[0], "name": row[1], "category": row[2],
                    "severity": row[3],
                })
            conn.close()
        except Exception:
            pass
        
        return {
            "type": "payload_select",
            "target_service": target_service,
            "exploit_type": exploit_type,
            "payloads": payloads,
        }

    async def _exploit_execute(self, params: Dict) -> Dict:
        """Generate exploit execution commands."""
        target = params.get("target", "")
        exploit = params.get("exploit", "")
        payload = params.get("payload", "")
        
        return {
            "type": "exploit_execute",
            "target": target,
            "status": "pending_approval",
            "commands": [
                f"# Exploit: {exploit}",
                f"# Payload: {payload}",
                f"# Target: {target}",
                "# Commands will be generated based on exploit selection",
            ],
            "warning": "Exploitation requires explicit approval",
        }


# ══════════════════════════════════════════════════════════════════════════════
# CORRELATION BRAIN AGENT
# ══════════════════════════════════════════════════════════════════════════════

class CorrelationBrainAgent(BaseAgent):
    """Correlation Brain - Cross-tool result correlation & prioritization.
    
    Wraps the existing correlation.py engine.
    Provides intelligent cross-referencing between tools.
    
    Corresponds to doc agents: Correlation Brain
    """

    def __init__(self):
        super().__init__(
            agent_id="correlation_brain",
            name="Correlation Brain",
            category=AgentCategory.INTELLIGENCE,
            description=(
                "Cross-tool correlation engine. Deduplicates findings, "
                "validates results across tools, identifies contradictions, "
                "scores confidence, and prioritizes attack paths."
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="correlate_findings",
                description="Correlate and deduplicate findings from multiple tools",
                risk_level=1,
                estimated_duration=10.0,
            ),
            AgentCapability(
                name="prioritize_targets",
                description="Score and prioritize targets based on attack surface",
                risk_level=1,
                estimated_duration=5.0,
            ),
            AgentCapability(
                name="intelligence_brief",
                description="Generate comprehensive intelligence brief for a target",
                risk_level=1,
                estimated_duration=15.0,
            ),
        ]

    async def _initialize(self):
        """Initialize correlation engine."""
        try:
            from ..strategic.correlation import CorrelationEngine
            self._engine = CorrelationEngine()
        except ImportError:
            self._engine = None
            self.logger.warning("Correlation engine not available")

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "correlate_findings":
            return await self._correlate(params)
        elif task_type == "prioritize_targets":
            return await self._prioritize(params)
        elif task_type == "intelligence_brief":
            return await self._intel_brief(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _correlate(self, params: Dict) -> Dict:
        """Correlate findings from multiple sources."""
        findings = params.get("findings", [])
        
        # Group by target
        by_target = {}
        for f in findings:
            target = f.get("target", "unknown")
            if target not in by_target:
                by_target[target] = []
            by_target[target].append(f)
        
        correlations = []
        for target, target_findings in by_target.items():
            # Find duplicates  
            seen = {}
            for f in target_findings:
                key = f"{f.get('service', '')}:{f.get('port', '')}:{f.get('type', '')}"
                if key in seen:
                    correlations.append({
                        "type": "duplicate",
                        "target": target,
                        "tools": [seen[key].get("tool", ""), f.get("tool", "")],
                        "finding": key,
                    })
                else:
                    seen[key] = f
        
        return {
            "type": "correlation",
            "total_findings": len(findings),
            "unique_targets": len(by_target),
            "correlations": correlations,
            "deduplicated_count": len(findings) - len(correlations),
        }

    async def _prioritize(self, params: Dict) -> Dict:
        """Prioritize targets."""
        targets = params.get("targets", [])
        
        scored = []
        for t in targets:
            score = 0
            score += t.get("critical_cves", 0) * 20
            score += t.get("exploitable_cves", 0) * 15
            score += 50 if t.get("rce_potential") else 0
            score += t.get("open_ports", 0) * 2
            
            scored.append({**t, "priority_score": score})
        
        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return {
            "type": "prioritization",
            "total_targets": len(targets),
            "ranked_targets": scored,
        }

    async def _intel_brief(self, params: Dict) -> Dict:
        """Generate intelligence brief using auto_analyze."""
        target = params.get("target", "")
        
        try:
            from ..strategic.brain import StrategicBrainEngine
            engine = StrategicBrainEngine()
            results = engine.query_knowledge("auto_analyze", target)
            return {
                "type": "intelligence_brief",
                "target": target,
                "brief": results[0] if results else {},
            }
        except Exception as e:
            return {
                "type": "intelligence_brief",
                "target": target,
                "error": str(e),
            }


# ══════════════════════════════════════════════════════════════════════════════
# EVASION AGENT
# ══════════════════════════════════════════════════════════════════════════════

class EvasionAgent(BaseAgent):
    """Evasion & OPSEC Agent.
    
    Wraps existing opsec.py for stealth operations.
    
    Corresponds to doc agents: Blue Guardian, WAF/IPS Detector,
    Anti-Forensics Agent
    """

    def __init__(self):
        super().__init__(
            agent_id="evasion_agent",
            name="Evasion & OPSEC Agent",
            category=AgentCategory.ACQUISITION,
            description=(
                "OPSEC manager: noise reduction, WAF/IPS detection and bypass, "
                "scan timing optimization, scope enforcement, "
                "honeypot detection, and anti-forensics coordination."
            ),
        )

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="stealth_check",
                description="Analyze operation for stealth compliance",
                risk_level=1,
                estimated_duration=5.0,
            ),
            AgentCapability(
                name="waf_detect",
                description="Detect and fingerprint WAF/IPS in front of target",
                requires_tools=["wafw00f", "nmap"],
                risk_level=2,
                estimated_duration=30.0,
            ),
            AgentCapability(
                name="evasion_suggest",
                description="Suggest evasion techniques for detected defenses",
                risk_level=1,
                estimated_duration=10.0,
            ),
        ]

    async def _initialize(self):
        """Load evasion patterns."""
        self._evasion_patterns = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cur = conn.cursor()
            rows = cur.execute("""
                SELECT pattern_id, name, category, target_systems, 
                       implementation, detection_bypass, effectiveness
                FROM evasion_patterns
            """).fetchall()
            for row in rows:
                self._evasion_patterns.append({
                    "id": row[0], "name": row[1], "category": row[2],
                    "targets": row[3], "implementation": row[4],
                    "bypass": row[5], "effectiveness": row[6],
                })
            conn.close()
            self.logger.info(f"Loaded {len(self._evasion_patterns)} evasion patterns")
        except Exception as e:
            self.logger.warning(f"Could not load evasion patterns: {e}")

    async def _execute_task(self, task_type: str, params: Dict) -> Dict:
        if task_type == "stealth_check":
            return await self._stealth_check(params)
        elif task_type == "waf_detect":
            return await self._waf_detect(params)
        elif task_type == "evasion_suggest":
            return await self._evasion_suggest(params)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _stealth_check(self, params: Dict) -> Dict:
        """Check operation stealth compliance."""
        operation = params.get("operation", {})
        
        warnings = []
        score = 100
        
        # Check scan intensity
        if operation.get("scan_type") == "comprehensive":
            warnings.append("Comprehensive scan generates high noise")
            score -= 30
        
        # Check timing
        if not operation.get("jitter"):
            warnings.append("No jitter configured - predictable timing")
            score -= 15
        
        # Check concurrent connections
        if operation.get("concurrent", 0) > 10:
            warnings.append(f"High concurrency ({operation.get('concurrent')}) may trigger IDS")
            score -= 20
        
        return {
            "type": "stealth_check",
            "stealth_score": max(score, 0),
            "warnings": warnings,
            "recommendations": [
                "Add 1-3s jitter between requests",
                "Limit concurrent connections to 5",
                "Use stealth scan mode (-sS -T2)",
                "Rotate user agents",
            ] if score < 70 else [],
        }

    async def _waf_detect(self, params: Dict) -> Dict:
        """WAF detection."""
        target = params.get("target", "")
        return {
            "type": "waf_detect",
            "target": target,
            "commands": [
                f"wafw00f {target}",
                f"nmap --script http-waf-detect -p 80,443 {target}",
                f"nmap --script http-waf-fingerprint -p 80,443 {target}",
            ],
        }

    async def _evasion_suggest(self, params: Dict) -> Dict:
        """Suggest evasion techniques."""
        waf_type = params.get("waf_type", "unknown")
        defenses = params.get("defenses", [])
        
        suggestions = []
        for pattern in self._evasion_patterns:
            category = pattern.get("category", "").lower()
            if waf_type.lower() in str(pattern.get("targets", "")).lower() or \
               any(d.lower() in category for d in defenses):
                suggestions.append({
                    "name": pattern["name"],
                    "category": pattern["category"],
                    "effectiveness": pattern["effectiveness"],
                })
        
        return {
            "type": "evasion_suggest",
            "waf_type": waf_type,
            "suggestions": suggestions[:10],
            "generic_bypasses": [
                "URL encoding double-encode",
                "Case variation",
                "Null byte injection",
                "Unicode normalization",
                "HTTP parameter pollution",
                "Chunked transfer encoding",
                "Multipart boundary manipulation",
            ],
        }
