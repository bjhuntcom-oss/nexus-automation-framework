#!/usr/bin/env python3
"""
Nexus Automation Framework - Patterns & Services Enrichment

Adds many more exploit_patterns, evasion_patterns, and service_vulnerabilities
to the knowledge database. Appends without duplicating (INSERT OR IGNORE).
"""

import json
import logging
import sqlite3
import sys
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("enrich")

DB_PATH = "knowledge.db"

def get_conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    return c

# ═══════════════════════════════════════════════════════════════════════
# ADDITIONAL EXPLOIT PATTERNS (EP026-EP070)
# ═══════════════════════════════════════════════════════════════════════
EXTRA_EXPLOIT_PATTERNS = [
    ("EP026", "Prototype Pollution", "Logic flaw", "JavaScript prototype chain manipulation", ["Object.assign or merge with user input", "No frozen prototypes"], ["Modified Object.prototype", "Property injection"], ["TypeError on frozen object"], ["Global object contamination"], ["__proto__ in JSON payloads", "constructor.prototype access"], ["Object.freeze", "Map instead of plain objects", "Input validation"]),
    ("EP027", "NoSQL Injection", "Input validation", "MongoDB/NoSQL query injection", ["User input in NoSQL query", "No input sanitization"], ["Data exfiltration", "Auth bypass via $gt/$ne operators"], ["Query syntax error"], ["Database manipulation"], ["$gt, $ne, $regex in parameters", "JSON body with operators"], ["Input validation", "Parameterized queries", "Disable $where"]),
    ("EP028", "GraphQL Injection", "Input validation", "GraphQL query abuse", ["Introspection enabled", "No query depth/complexity limits"], ["Schema disclosure", "Batch query abuse", "Nested query DoS"], ["Query too complex error"], ["Resource exhaustion", "Data exposure"], ["Introspection queries", "Deeply nested queries", "Alias-based batching"], ["Disable introspection in prod", "Query depth limiting", "Rate limiting"]),
    ("EP029", "WebSocket Injection", "Input validation", "WebSocket message injection", ["No message validation", "Shared WebSocket channels"], ["Message injection", "Cross-user data access"], ["Connection closed by server"], ["Data manipulation"], ["Malformed WebSocket frames", "Cross-origin connections"], ["Message validation", "Origin checking", "Authentication per message"]),
    ("EP030", "CRLF Injection", "Input validation", "HTTP header injection via CRLF", ["User input reflected in HTTP headers", "No CRLF filtering"], ["Header injection", "Response splitting", "XSS via injected headers"], ["Input sanitized"], ["Cache poisoning", "Session fixation"], ["\\r\\n in URL parameters", "Encoded CRLF sequences"], ["Strip CRLF from input", "Output encoding", "WAF rules"]),
    ("EP031", "CSV Injection", "Input validation", "Spreadsheet formula injection", ["User input exported to CSV/Excel", "No cell sanitization"], ["Formula execution in Excel", "Data exfiltration via hyperlinks"], ["Formulas blocked"], ["Local file access via DDE", "Data theft"], ["Cells starting with =, +, -, @"], ["Prefix cells with tab/quote", "Sanitize on export"]),
    ("EP032", "Open Redirect", "Input validation", "Unvalidated redirect", ["User-controlled redirect URL", "No whitelist validation"], ["Redirect to phishing page", "Token leakage via Referer"], ["Redirect blocked"], ["Phishing", "OAuth token theft"], ["URL parameter pointing to external domain"], ["URL whitelist", "Relative redirects only", "User confirmation"]),
    ("EP033", "Mass Assignment", "Access control", "Object property injection", ["Framework auto-binds request params to model", "No field allowlist"], ["Admin role assignment", "Password override"], ["Field rejected by validation"], ["Privilege escalation"], ["Extra fields in POST/PUT body (isAdmin, role, etc.)"], ["Field allowlisting", "DTOs", "ReadOnly properties"]),
    ("EP034", "IDOR - Insecure Direct Object Reference", "Access control", "Direct object reference without authorization", ["Sequential/predictable IDs", "No access control check"], ["Access other users' data", "Modify other users' resources"], ["403 Forbidden", "Authorization error"], ["Data breach", "Account takeover"], ["Incrementing IDs in URLs", "UUID guessing"], ["Authorization checks", "UUIDs", "Object-level access control"]),
    ("EP035", "Business Logic Flaw - Price Manipulation", "Logic flaw", "Client-side price/quantity manipulation", ["Price sent from client", "No server-side validation"], ["Purchase at arbitrary price", "Negative quantity refund"], ["Server recalculates price"], ["Financial loss"], ["Modified price/discount in request body"], ["Server-side price calculation", "Integrity checks"]),
    ("EP036", "Business Logic Flaw - 2FA Bypass", "Authentication", "Two-factor authentication bypass", ["2FA check in separate request", "No session binding"], ["Authentication without 2FA", "Direct access to post-2FA endpoints"], ["2FA enforced correctly"], ["Account compromise"], ["Skip 2FA step by direct navigation", "Response manipulation"], ["Server-side 2FA enforcement", "Session binding"]),
    ("EP037", "HTTP Parameter Pollution", "Input validation", "Duplicate parameter confusion", ["Backend processes duplicate parameters differently than frontend/WAF"], ["WAF bypass", "Logic manipulation"], ["Consistent parameter handling"], ["Payload injection past WAF"], ["Duplicate parameters with different values"], ["Consistent parameter parsing", "WAF tuning"]),
    ("EP038", "Type Juggling", "Logic flaw", "PHP/JavaScript loose comparison abuse", ["Loose comparison (== instead of ===)", "Type coercion"], ["Authentication bypass", "Authorization bypass"], ["Strict comparison used"], ["Access control bypass"], ["String vs int comparison: '0' == false", "Magic hashes"], ["Strict comparison (===)", "Type checking"]),
    ("EP039", "Insecure Randomness", "Cryptographic", "Predictable random values", ["Math.random() or rand() for security tokens", "Known seed"], ["Token prediction", "Session ID guessing"], ["CSPRNG used"], ["Session hijacking", "Password reset abuse"], ["Sequential tokens", "Timestamp-based tokens"], ["Use CSPRNG", "Sufficient entropy", "Token rotation"]),
    ("EP040", "Clickjacking", "UI redress", "UI overlay attack", ["No X-Frame-Options header", "No CSP frame-ancestors"], ["User performs unintended actions", "OAuth consent phishing"], ["Frame blocked by headers"], ["Unauthorized actions", "Data theft"], ["Iframe embedding test", "UI overlays"], ["X-Frame-Options: DENY", "CSP frame-ancestors: 'self'"]),
    ("EP041", "Cache Poisoning", "Protocol manipulation", "Web cache deception/poisoning", ["Shared caching proxy", "Unkeyed headers in cache key"], ["Cached malicious response served to other users"], ["Cache key includes all relevant headers"], ["XSS via cache", "Credential theft"], ["X-Forwarded-Host manipulation", "Unkeyed header injection"], ["Cache key normalization", "Cache validation", "Vary headers"]),
    ("EP042", "Subdomain Takeover", "DNS/Infrastructure", "Dangling DNS record exploitation", ["CNAME pointing to unclaimed resource", "Service deprovisioned"], ["Full control of subdomain", "Cookie theft for parent domain"], ["Resource already claimed"], ["Phishing", "Session hijacking"], ["DNS CNAME to unregistered services"], ["Regular DNS auditing", "Remove stale records"]),
    ("EP043", "Container Escape", "Infrastructure", "Docker/container breakout", ["Privileged container", "Mounted host filesystem", "Kernel vulnerability"], ["Host OS access", "Other container access"], ["Seccomp/AppArmor blocks"], ["Full host compromise"], ["Exploiting /proc/self/exe", "cgroup escape", "Mounted Docker socket"], ["No privileged containers", "Seccomp profiles", "Kernel hardening"]),
    ("EP044", "Kubernetes RBAC Abuse", "Infrastructure", "Kubernetes permission escalation", ["Overly permissive RBAC", "Default service account tokens"], ["Cluster admin access", "Secret theft"], ["Restrictive RBAC"], ["Cluster compromise"], ["Service account token abuse", "Create privileged pods"], ["Least privilege RBAC", "Pod security policies", "Network policies"]),
    ("EP045", "SAML Assertion Manipulation", "Authentication", "SAML XML manipulation", ["No XML signature validation", "Comment injection"], ["Authentication as any user"], ["Signature validation blocks"], ["SSO bypass", "Account takeover"], ["XML comment between username characters", "Signature wrapping"], ["Strict XML signature validation", "Assertion recipient check"]),
    ("EP046", "OAuth Token Theft", "Authentication", "OAuth flow exploitation", ["Open redirect in callback", "Lax redirect_uri validation"], ["Access token theft", "Account linking abuse"], ["Strict redirect_uri match"], ["Account takeover"], ["Modified redirect_uri", "State parameter missing"], ["Strict redirect_uri matching", "PKCE", "State parameter"]),
    ("EP047", "PDF Generation SSRF", "Code injection", "Server-side PDF rendering SSRF", ["HTML-to-PDF with user input", "Headless browser renders user content"], ["Internal file read via file://", "SSRF via http:// in HTML"], ["Protocol restrictions"], ["Internal network access", "File theft"], ["<iframe src='file:///etc/passwd'>", "CSS @import for SSRF"], ["Sandboxed PDF rendering", "Protocol whitelist"]),
    ("EP048", "Email Header Injection", "Input validation", "SMTP header injection", ["User input in email headers", "No CRLF filtering"], ["BCC injection", "From spoofing", "Spam relay"], ["Input sanitized"], ["Phishing from trusted domain"], ["\\r\\n in email fields"], ["Sanitize email inputs", "Use library APIs not raw SMTP"]),
    ("EP049", "Regex DoS (ReDoS)", "Denial of service", "Catastrophic backtracking in regex", ["User input matched against complex regex", "Exponential backtracking pattern"], ["CPU exhaustion", "Service unresponsive"], ["Timeout kills regex"], ["Service denial"], ["Specially crafted long strings matching nested quantifiers"], ["Use RE2/non-backtracking engine", "Regex timeout", "Input length limits"]),
    ("EP050", "Dependency Confusion", "Supply chain", "Package namespace confusion", ["Internal package names not reserved on public registry"], ["Malicious package installed from public registry"], ["Private registry priority configured"], ["Code execution in CI/CD", "Supply chain compromise"], ["Public package with same name as internal"], ["Reserve namespaces", "Registry scoping", "Lockfile verification"]),
]

# ═══════════════════════════════════════════════════════════════════════
# ADDITIONAL EVASION PATTERNS (EV019-EV040)
# ═══════════════════════════════════════════════════════════════════════
EXTRA_EVASION_PATTERNS = [
    ("EV019", "Reflective DLL Injection", "Code execution in-memory", ["Disk-based scanning", "DLL monitoring"], ["Manual DLL mapping in memory", "PEB manipulation", "No LoadLibrary call"], ["DLL loaded without touching disk", "No entry in PEB module list"], 0.87, ["Memory scanning", "ETW DLL load events", "Syscall monitoring"]),
    ("EV020", "Process Ghosting", "Process evasion", ["Process integrity checks", "File scanning on creation"], ["Create file -> map section -> delete file -> create process from section"], ["Process runs from deleted file, AV cannot scan"], 0.90, ["Section object monitoring", "ETW process creation", "Kernel callbacks"]),
    ("EV021", "Syscall Stomping", "Hook evasion", ["Inline hooks on ntdll", "User-mode API monitoring"], ["Read ntdll from disk", "Replace hooked functions with clean ones"], ["Clean ntdll functions bypass hooks"], 0.86, ["Kernel-level hooking", "ETW syscall tracing", "Hypervisor-based monitoring"]),
    ("EV022", "Heaven's Gate", "Architecture evasion", ["32-bit process monitoring", "WoW64 layer hooks"], ["Switch from 32-bit to 64-bit mode via far jump", "Execute 64-bit syscalls from 32-bit process"], ["Bypasses WoW64 hooks and 32-bit instrumentation"], 0.80, ["64-bit hook coverage", "WoW64 transition monitoring"]),
    ("EV023", "Thread Pool Injection", "Execution evasion", ["Thread creation monitoring", "CreateRemoteThread detection"], ["Queue APC to thread pool", "Use TP_CALLBACK_ENVIRON", "NtSetTimer2 abuse"], ["Code executes in existing thread pool, no new thread"], 0.78, ["Thread pool callback monitoring", "Stack trace analysis"]),
    ("EV024", "VEH Hooking", "Hook evasion", ["API hooking", "Breakpoint detection"], ["Register Vectored Exception Handler", "Set hardware breakpoints on APIs", "Handle exception to redirect flow"], ["Transparent API hooking without modifying code"], 0.75, ["VEH registration monitoring", "Debug register auditing"]),
    ("EV025", "Callback-based Execution", "Execution evasion", ["Thread creation monitoring", "Process injection detection"], ["EnumWindows callback", "EnumFonts callback", "CertEnumSystemStore callback", "SetTimer callback"], ["Code executes via legitimate API callbacks"], 0.73, ["Callback registration monitoring", "Stack trace validation"]),
    ("EV026", "DNS over HTTPS (DoH) C2", "Network evasion", ["DNS monitoring", "DNS firewall"], ["Use DoH providers (Cloudflare, Google)", "Encrypt DNS queries", "Tunnel data in DNS responses"], ["C2 traffic hidden in HTTPS to legitimate DNS providers"], 0.84, ["DoH provider blocking", "Certificate inspection", "TLS decryption"]),
    ("EV027", "Steganography C2", "Data hiding", ["DPI", "Content inspection", "Network monitoring"], ["Hide data in image pixels", "Embed commands in audio/video", "Use EXIF metadata"], ["C2 data invisible in normal traffic analysis"], 0.80, ["Statistical analysis of media files", "Baseline comparison", "EXIF stripping"]),
    ("EV028", "Application Shimming", "Persistence evasion", ["Startup monitoring", "Registry auditing"], ["Custom application compatibility shim", "SDB file registration", "InjectDll shim"], ["Persistence via Windows compatibility mechanism"], 0.72, ["Shim database auditing", "sdbinst.exe monitoring", "Registry shim keys"]),
    ("EV029", "COM Object Hijacking", "Persistence evasion", ["COM registration monitoring", "Registry auditing"], ["Register malicious COM server", "Hijack InprocServer32 registry key", "CLSID hijacking"], ["Code loads when legitimate app requests COM object"], 0.76, ["COM registration auditing", "InprocServer32 monitoring", "Baseline CLSID hashes"]),
    ("EV030", "WMI Event Subscription", "Persistence evasion", ["WMI activity monitoring", "Event subscription auditing"], ["__EventFilter + CommandLineEventConsumer", "Permanent WMI subscription", "Trigger on system events"], ["Persistent execution without files or registry"], 0.79, ["WMI subscription enumeration", "WMI activity logging", "MOF compilation monitoring"]),
    ("EV031", "Print Spooler Abuse", "Execution evasion", ["Print service monitoring"], ["Add printer with malicious driver", "Abuse SpoolSV for DLL loading"], ["DLL loaded by trusted spooler process"], 0.71, ["Print driver verification", "Spooler service hardening"]),
    ("EV032", "PPID Spoofing", "Parent process evasion", ["Parent-child process relationship analysis"], ["CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", "Set arbitrary parent PID"], ["Malicious process appears spawned by legitimate parent"], 0.77, ["ETW process creation with real parent", "Kernel callbacks"]),
    ("EV033", "Module Stomping", "Memory evasion", ["Module integrity checks", "Memory scanning"], ["Load legitimate DLL", "Overwrite its .text section with payload", "Execute from legitimate module space"], ["Payload runs from legitimate module memory region"], 0.83, ["Module integrity verification", "Periodic memory hashing", "Code signing verification"]),
    ("EV034", "NTFS Alternate Data Streams", "File hiding", ["File listing", "Antivirus scanning"], ["Attach payload to ADS: file.txt:hidden.exe", "Execute from ADS"], ["Payload invisible to normal file listing"], 0.65, ["ADS-aware file scanning", "Stream enumeration", "NTFS stream auditing"]),
    ("EV035", "Phantom DLL Loading", "DLL evasion", ["DLL load monitoring", "Known DLL protection"], ["Create DLL in location searched before system32", "Exploit DLL search order for missing DLLs"], ["Malicious DLL loaded by legitimate process searching for non-existent DLL"], 0.74, ["Monitor known missing DLL loads", "Restrict DLL search paths"]),
    ("EV036", "Indirect Syscalls", "Hook evasion", ["Inline hooks", "Direct syscall detection"], ["Jump to middle of ntdll syscall stub", "Avoid syscall instruction at suspicious RIP"], ["Syscall originates from ntdll address space, appears legitimate"], 0.88, ["Return address validation", "Syscall origin verification", "Hardware performance counters"]),
    ("EV037", "MSBuild Inline Task Execution", "LOLBin execution", ["Application whitelisting", "Script blocking"], ["Embed C# in .csproj XML", "Execute via MSBuild.exe (signed Microsoft binary)"], ["Code execution via trusted developer tool"], 0.73, ["MSBuild execution monitoring", "XML task auditing", "Command line logging"]),
    ("EV038", "Time-based Evasion", "Sandbox evasion", ["Sandbox analysis", "Automated detonation"], ["Sleep for extended period", "Check system uptime", "Wait for user interaction count"], ["Payload only executes after sandbox timeout"], 0.70, ["Accelerated sandbox clocks", "Extended analysis duration", "API call patching"]),
    ("EV039", "Anti-VM Detection", "Analysis evasion", ["Virtual machine analysis", "Cloud sandboxes"], ["Check for VM artifacts (VMware tools, Hyper-V)", "CPUID checks", "Timing-based detection", "Registry VM indicators"], ["Payload refuses to run in analysis environment"], 0.72, ["Remove VM artifacts", "Bare-metal analysis", "Nested virtualization hiding"]),
    ("EV040", "Traffic Mirroring via DNS", "Data exfiltration evasion", ["DLP", "Outbound content inspection", "Firewall"], ["Encode data in DNS subdomain labels", "Use TXT record responses", "Slow drip exfiltration"], ["Data leaves via DNS, bypassing HTTP/HTTPS inspection"], 0.81, ["DNS query analytics", "Subdomain length analysis", "DNS tunneling detection tools"]),
]

# ═══════════════════════════════════════════════════════════════════════
# ADDITIONAL SERVICE VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════
EXTRA_SERVICES = [
    ("Apache Struts", "2.5.30", 8080, "tcp", ["CVE-2023-50164", "CVE-2021-31805"], [], ["OGNL evaluation enabled", "Dev mode active"], ["File upload path traversal RCE", "OGNL injection"], ["Struts framework detection"]),
    ("Apache Solr", "8.11.0", 8983, "tcp", ["CVE-2021-44228", "CVE-2021-27905", "CVE-2019-17558"], [], ["Admin UI public", "Remote streaming enabled"], ["SSRF", "Log4Shell", "Velocity template RCE"], ["Solr Admin UI"]),
    ("Apache Kafka", "3.0.0", 9092, "tcp", ["CVE-2023-25194"], [], ["No authentication", "No ACLs", "JMX exposed"], ["JNDI injection via connector", "Unauthenticated access"], ["Kafka protocol"]),
    ("Apache Cassandra", "4.0.0", 9042, "tcp", ["CVE-2021-44521"], [], ["No authentication", "RPC enabled", "JMX public"], ["UDF sandbox escape RCE"], ["Cassandra native protocol"]),
    ("Apache ZooKeeper", "3.7.0", 2181, "tcp", ["CVE-2023-44981"], [], ["No authentication", "Four letter commands enabled"], ["Authorization bypass via SASL", "Info disclosure"], ["ZooKeeper protocol"]),
    ("RabbitMQ", "3.10.0", 5672, "tcp", ["CVE-2022-31008"], ["guest:guest"], ["Management plugin public", "Default credentials"], ["Credential theft via federation", "Queue poisoning"], ["AMQP protocol"]),
    ("Vault (HashiCorp)", "1.12.0", 8200, "tcp", ["CVE-2023-24999", "CVE-2023-0620"], [], ["Dev mode", "Root token in env"], ["SQL injection in PMK", "Permissive CORS"], ["Vault HTTP API"]),
    ("Terraform Enterprise", "1.0", 443, "tcp", ["CVE-2023-1299"], [], ["API token exposure", "No MFA"], ["Sentinel policy bypass"], ["Terraform API"]),
    ("GitLab", "15.0.0", 443, "tcp", ["CVE-2023-2825", "CVE-2022-2884", "CVE-2021-22205"], [], ["Public registration", "Import feature enabled"], ["Path traversal file read", "RCE via import"], ["X-GitLab-Meta"]),
    ("Nexus Repository", "3.40.0", 8081, "tcp", ["CVE-2024-4956"], ["admin:admin123"], ["Default credentials", "Anonymous access"], ["Path traversal", "Unauthenticated access"], ["Nexus Repository Manager"]),
    ("JBoss/WildFly", "7.0", 8080, "tcp", ["CVE-2017-12149", "CVE-2015-7501"], ["admin:admin"], ["JMX console exposed", "Management interface public"], ["Deserialization RCE", "JMXInvokerServlet"], ["JBoss/WildFly"]),
    ("GlassFish", "5.1.0", 4848, "tcp", ["CVE-2017-1000028"], ["admin:admin", "admin:adminadmin"], ["Admin console public", "Default credentials"], ["Path traversal", "Admin panel access"], ["GlassFish Server"]),
    ("Splunk", "9.0.0", 8089, "tcp", ["CVE-2023-22935", "CVE-2023-22941"], ["admin:changeme"], ["Default credentials", "REST API public"], ["SSRF via search", "RCE via custom apps"], ["Splunk REST API"]),
    ("Nagios", "4.4.0", 80, "tcp", ["CVE-2021-33042", "CVE-2021-37382"], ["nagiosadmin:nagios"], ["Default credentials", "CGI exposed"], ["Command injection", "Auth bypass"], ["Nagios XI"]),
    ("Zabbix", "6.0.0", 80, "tcp", ["CVE-2022-23131", "CVE-2022-23132"], ["Admin:zabbix", "guest:"], ["SAML misconfigured", "Guest access enabled"], ["Auth bypass via SAML", "API token abuse"], ["Zabbix dashboard"]),
    ("InfluxDB", "2.0.0", 8086, "tcp", ["CVE-2019-20933"], [], ["No authentication", "API token exposed"], ["Auth bypass", "Unauthenticated query"], ["InfluxDB HTTP API"]),
    ("Elasticsearch", "8.0.0", 9200, "tcp", ["CVE-2022-23708", "CVE-2023-31419"], [], ["No security plugin", "Anonymous access"], ["Stack overflow DoS", "Search query injection"], ["Elasticsearch API"]),
    ("Kibana", "8.0.0", 5601, "tcp", ["CVE-2023-31415", "CVE-2022-38778"], [], ["No authentication", "Reporting plugin enabled"], ["Prototype pollution RCE", "Path traversal"], ["Kibana dashboard"]),
    ("Logstash", "8.0.0", 5044, "tcp", ["CVE-2023-46672"], [], ["No TLS on Beats input", "Pipeline accessible"], ["Env var leak in pipeline", "Input manipulation"], ["Beats protocol"]),
    ("Mosquitto MQTT", "2.0.0", 1883, "tcp", ["CVE-2023-28366"], [], ["No authentication", "No TLS", "Anonymous access"], ["Memory leak DoS", "Message interception", "Topic injection"], ["MQTT protocol"]),
    ("ETCD", "3.5.0", 2379, "tcp", ["CVE-2022-41723", "CVE-2023-32082"], [], ["No authentication", "Exposed to network"], ["Unauthenticated data read", "Kubernetes secret theft"], ["ETCD client protocol"]),
    ("CockroachDB", "22.0", 26257, "tcp", ["CVE-2023-43797"], ["root:"], ["No authentication", "Web UI public"], ["SQL injection", "Unauthenticated access"], ["CockroachDB protocol"]),
    ("Neo4j", "4.4.0", 7474, "tcp", ["CVE-2023-23926"], ["neo4j:neo4j"], ["Default credentials", "Browser public"], ["Cypher injection", "APOC RCE"], ["Neo4j Browser"]),
    ("Jupyter Notebook", "6.4.0", 8888, "tcp", ["CVE-2022-29238", "CVE-2022-39286"], [], ["No password/token", "Open to network"], ["Unauthenticated code execution", "CSRF"], ["Jupyter Notebook"]),
    ("Portainer", "2.15.0", 9443, "tcp", ["CVE-2022-26134"], ["admin:admin"], ["Default credentials", "API exposed"], ["Container management abuse", "Host escape"], ["Portainer UI"]),
    ("MinIO", "2023-01-01", 9000, "tcp", ["CVE-2023-28432", "CVE-2023-28434"], ["minioadmin:minioadmin"], ["Default credentials", "Public buckets"], ["Env var disclosure", "Privilege escalation"], ["MinIO Console"]),
    ("Traefik", "2.9.0", 8080, "tcp", ["CVE-2023-29013"], [], ["Dashboard public", "API exposed without auth"], ["DoS via HTTP/2 WINDOW_UPDATE", "Route manipulation"], ["Traefik Dashboard"]),
    ("Caddy", "2.6.0", 80, "tcp", ["CVE-2022-29718"], [], ["Admin API exposed", "No auth on admin endpoint"], ["Admin API SSRF", "Config manipulation"], ["Caddy Server"]),
    ("phpMyAdmin", "5.2.0", 80, "tcp", ["CVE-2023-25727"], ["root:", "root:root"], ["Default credentials", "Setup accessible"], ["XSS in drag-and-drop upload", "SQL injection"], ["phpMyAdmin login"]),
    ("Adminer", "4.8.1", 80, "tcp", ["CVE-2021-21311", "CVE-2021-43008"], [], ["Public access", "No IP restriction"], ["SSRF", "Arbitrary file read"], ["Adminer login page"]),
    ("Telerik UI", "2019.3.1023", 80, "tcp", ["CVE-2019-18935", "CVE-2017-9248"], [], ["Telerik handler public", "Weak encryption key"], ["Deserialization RCE", "Encryption key brute force"], ["Telerik.Web.UI.WebResource.axd"]),
    ("Atlassian Bitbucket", "8.0.0", 7990, "tcp", ["CVE-2022-36804"], [], ["Public repositories", "Archive endpoint accessible"], ["Command injection via archive endpoint"], ["Bitbucket dashboard"]),
    ("Ivanti Connect Secure", "22.0", 443, "tcp", ["CVE-2024-21887", "CVE-2023-46805"], [], ["Management interface public"], ["Auth bypass + RCE chain"], ["Pulse Secure VPN"]),
    ("Fortinet FortiOS", "7.0", 443, "tcp", ["CVE-2024-21762", "CVE-2022-42475"], [], ["SSL VPN enabled", "Management on WAN"], ["Out-of-bounds write RCE", "Heap overflow RCE"], ["FortiGate login"]),
    ("SonicWall SMA", "10.2.0", 443, "tcp", ["CVE-2023-34362", "CVE-2021-20016"], [], ["Management interface public"], ["SQL injection", "Credential theft"], ["SonicWall SMA login"]),
    ("Palo Alto GlobalProtect", "10.0", 443, "tcp", ["CVE-2024-3400"], [], ["GlobalProtect portal public"], ["OS command injection zero-day"], ["GlobalProtect portal"]),
]


def insert_exploit_patterns():
    conn = get_conn()
    c = conn.cursor()
    count = 0
    for p in EXTRA_EXPLOIT_PATTERNS:
        pid, name, vtype, method, conds, succ, fail, side, sigs, mit = p
        try:
            c.execute("""INSERT OR IGNORE INTO exploit_patterns
                (pattern_id, name, vulnerability_type, exploitation_method,
                 required_conditions, success_indicators, failure_indicators,
                 side_effects, detection_signatures, mitigation_techniques)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (pid, name, vtype, method, json.dumps(conds), json.dumps(succ),
                 json.dumps(fail), json.dumps(side), json.dumps(sigs), json.dumps(mit)))
            count += 1
        except Exception as e:
            logger.error(f"EP {pid}: {e}")
    conn.commit(); conn.close()
    logger.info(f"✅ Exploit patterns: +{count}")
    return count

def insert_evasion_patterns():
    conn = get_conn()
    c = conn.cursor()
    count = 0
    for p in EXTRA_EVASION_PATTERNS:
        pid, name, tech, defs, meths, byps, eff, counters = p
        try:
            c.execute("""INSERT OR IGNORE INTO evasion_patterns
                (pattern_id, name, evasion_technique, target_defenses,
                 implementation_methods, detection_bypasses,
                 effectiveness_score, countermeasures)
                VALUES (?,?,?,?,?,?,?,?)""",
                (pid, name, tech, json.dumps(defs), json.dumps(meths),
                 json.dumps(byps), eff, json.dumps(counters)))
            count += 1
        except Exception as e:
            logger.error(f"EV {pid}: {e}")
    conn.commit(); conn.close()
    logger.info(f"✅ Evasion patterns: +{count}")
    return count

def insert_services():
    conn = get_conn()
    c = conn.cursor()
    count = 0
    for s in EXTRA_SERVICES:
        name, ver, port, proto, cves, creds, misconf, exploits, sigs = s
        try:
            c.execute("""INSERT INTO service_vulnerabilities
                (service_name, service_version, port, protocol, cve_ids,
                 default_credentials, common_misconfigurations,
                 exploitation_methods, detection_signatures)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (name, ver, port, proto, json.dumps(cves), json.dumps(creds),
                 json.dumps(misconf), json.dumps(exploits), json.dumps(sigs)))
            count += 1
        except Exception as e:
            logger.error(f"SVC {name}: {e}")
    conn.commit(); conn.close()
    logger.info(f"✅ Services: +{count}")
    return count


if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("🚀 Nexus - Database Enrichment")
    logger.info("=" * 60)
    t1 = insert_exploit_patterns()
    t2 = insert_evasion_patterns()
    t3 = insert_services()
    logger.info(f"📊 Total: +{t1} exploit, +{t2} evasion, +{t3} services")

    # Update knowledge version
    conn = get_conn()
    c = conn.cursor()
    stats = {}
    for tbl in ["cve_entries", "attack_techniques", "service_vulnerabilities", "exploit_patterns", "evasion_patterns", "workflow_rules"]:
        c.execute(f"SELECT COUNT(*) FROM {tbl}")
        stats[tbl] = c.fetchone()[0]
    c.execute("""INSERT OR REPLACE INTO knowledge_versions (version, created_at, description, changes_summary)
        VALUES (?, ?, ?, ?)""",
        (4, datetime.now().isoformat(), "Database enrichment v2",
         json.dumps(stats)))
    conn.commit(); conn.close()
    logger.info(f"📚 Final stats: {stats}")
    logger.info("✅ Done!")
