"""
Nexus Automation Framework - Centralized Configuration

Single source of truth for all framework settings.
Environment-variable driven with secure defaults.
"""

import os
import secrets
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict, Any
from pathlib import Path
from enum import Enum


# ══════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT
# ══════════════════════════════════════════════════════════════════════════════

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, str(default)).lower()
    return val in ("true", "1", "yes", "on")


def _env_int(key: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _env_float(key: str, default: float = 0.0) -> float:
    try:
        return float(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _env_list(key: str, default: str = "", sep: str = ",") -> List[str]:
    raw = os.environ.get(key, default)
    return [item.strip() for item in raw.split(sep) if item.strip()] if raw else []


# ══════════════════════════════════════════════════════════════════════════════
# BASE PATHS
# ══════════════════════════════════════════════════════════════════════════════

APP_DIR = Path(_env("NEXUS_APP_DIR", "/app"))
DATA_DIR = APP_DIR / "data"
LOGS_DIR = APP_DIR / "logs"
SESSIONS_DIR = APP_DIR / "sessions"
REPORTS_DIR = APP_DIR / "reports"
LOOT_DIR = APP_DIR / "loot"
DOWNLOADS_DIR = APP_DIR / "downloads"
METRICS_DIR = APP_DIR / "metrics"
PLUGINS_DIR = APP_DIR / "plugins"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"

# Ensure directories exist
for d in [DATA_DIR, LOGS_DIR, SESSIONS_DIR, REPORTS_DIR, LOOT_DIR,
          DOWNLOADS_DIR, METRICS_DIR, PLUGINS_DIR, KNOWLEDGE_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# SERVER CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ServerConfig:
    """MCP Server configuration."""
    host: str = _env("NEXUS_HOST", "0.0.0.0")
    port: int = _env_int("NEXUS_PORT", 8000)
    transport: str = _env("NEXUS_TRANSPORT", "sse")
    debug: bool = _env_bool("NEXUS_DEBUG", False)
    log_level: str = _env("NEXUS_LOG_LEVEL", "INFO")
    max_request_size: int = _env_int("NEXUS_MAX_REQUEST_SIZE", 10 * 1024 * 1024)
    request_timeout: int = _env_int("NEXUS_REQUEST_TIMEOUT", 600)
    cors_origins: List[str] = field(default_factory=lambda: _env_list("NEXUS_CORS_ORIGINS", "*"))
    environment: str = _env("NEXUS_ENVIRONMENT", "production")


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityConfig:
    """Security and kill switch configuration."""
    # Kill switch
    kill_switch_enabled: bool = _env_bool("NEXUS_KILL_SWITCH_ENABLED", True)
    kill_switch_secret: str = _env("NEXUS_KILL_SWITCH_SECRET", "")
    vpn_kill_switch_only: bool = _env_bool("NEXUS_VPN_KILL_SWITCH_ONLY", True)
    host_only_mode: bool = _env_bool("NEXUS_HOST_ONLY_MODE", True)

    # IDS (Intrusion Detection System)
    ids_enabled: bool = _env_bool("NEXUS_IDS_ENABLED", True)
    ids_sensitivity: str = _env("NEXUS_IDS_SENSITIVITY", "high")

    # Connection policies
    max_concurrent_connections: int = _env_int("NEXUS_MAX_CONNECTIONS", 10)
    max_failed_auth_attempts: int = _env_int("NEXUS_MAX_FAILED_AUTH", 3)
    lockdown_on_escape_attempt: bool = _env_bool("NEXUS_LOCKDOWN_ON_ESCAPE", True)

    # Trusted networks
    trusted_external_ips: Set[str] = field(default_factory=lambda: set(_env_list("NEXUS_TRUSTED_IPS")))
    vpn_ip_ranges: List[str] = field(default_factory=lambda: _env_list("NEXUS_VPN_RANGES"))
    host_subnets: List[str] = field(default_factory=lambda: _env_list(
        "NEXUS_HOST_SUBNETS", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"
    ))

    # Audit
    audit_log_path: str = str(LOGS_DIR / "security_audit.jsonl")
    audit_chain_enabled: bool = _env_bool("NEXUS_AUDIT_CHAIN", True)

    # Rate limiting
    global_rate_limit: int = _env_int("NEXUS_GLOBAL_RATE_LIMIT", 100)
    per_tool_rate_limit: int = _env_int("NEXUS_PER_TOOL_RATE_LIMIT", 30)
    rate_limit_window: int = _env_int("NEXUS_RATE_LIMIT_WINDOW", 60)

    # Filesystem integrity
    filesystem_monitoring: bool = _env_bool("NEXUS_FS_MONITORING", True)
    critical_paths: List[str] = field(default_factory=lambda: [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/proc/1/root", "/var/run/docker.sock"
    ])

    def __post_init__(self):
        if not self.kill_switch_secret:
            self.kill_switch_secret = secrets.token_urlsafe(64)


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class DatabaseConfig:
    """Database configuration."""
    db_path: str = _env("NEXUS_DB_PATH", str(APP_DIR / "knowledge.db"))
    pool_size: int = _env_int("NEXUS_DB_POOL_SIZE", 5)
    max_overflow: int = _env_int("NEXUS_DB_MAX_OVERFLOW", 10)
    timeout: int = _env_int("NEXUS_DB_TIMEOUT", 30)
    journal_mode: str = _env("NEXUS_DB_JOURNAL_MODE", "WAL")
    cache_size: int = _env_int("NEXUS_DB_CACHE_SIZE", -64000)  # 64MB
    synchronous: str = _env("NEXUS_DB_SYNCHRONOUS", "NORMAL")
    mmap_size: int = _env_int("NEXUS_DB_MMAP_SIZE", 268435456)  # 256MB
    auto_vacuum: bool = _env_bool("NEXUS_DB_AUTO_VACUUM", True)
    wal_checkpoint_interval: int = _env_int("NEXUS_DB_WAL_CHECKPOINT", 1000)


# ══════════════════════════════════════════════════════════════════════════════
# EXECUTION CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ExecutionConfig:
    """Command execution configuration."""
    default_timeout: int = _env_int("NEXUS_CMD_TIMEOUT", 300)
    max_timeout: int = _env_int("NEXUS_CMD_MAX_TIMEOUT", 3600)
    max_output_size: int = _env_int("NEXUS_CMD_MAX_OUTPUT", 10 * 1024 * 1024)
    max_concurrent_commands: int = _env_int("NEXUS_MAX_CONCURRENT_CMDS", 20)
    max_background_jobs: int = _env_int("NEXUS_MAX_BACKGROUND_JOBS", 50)
    retry_max_attempts: int = _env_int("NEXUS_RETRY_MAX", 3)
    retry_base_delay: float = _env_float("NEXUS_RETRY_DELAY", 1.0)
    retry_max_delay: float = _env_float("NEXUS_RETRY_MAX_DELAY", 60.0)


# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIC ENGINE CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class StrategicConfig:
    """Strategic engine configuration."""
    enabled: bool = _env_bool("NEXUS_STRATEGIC_ENGINE_ENABLED", True)
    observability_enabled: bool = _env_bool("NEXUS_OBSERVABILITY_ENABLED", True)
    governance_key: str = _env(
        "NEXUS_GOVERNANCE_KEY",
        "nexus-automation-framework-production-key-change-in-production"
    )
    max_operations: int = _env_int("NEXUS_MAX_OPERATIONS", 10)
    max_tasks_per_operation: int = _env_int("NEXUS_MAX_TASKS_PER_OP", 100)
    default_stealth: float = _env_float("NEXUS_DEFAULT_STEALTH", 0.5)
    default_risk_tolerance: float = _env_float("NEXUS_DEFAULT_RISK", 0.5)
    knowledge_refresh_interval: int = _env_int("NEXUS_KNOWLEDGE_REFRESH", 3600)
    auto_escalation: bool = _env_bool("NEXUS_AUTO_ESCALATION", False)


# ══════════════════════════════════════════════════════════════════════════════
# REPORTING CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ReportingConfig:
    """Report generation configuration."""
    default_format: str = _env("NEXUS_REPORT_FORMAT", "markdown")
    include_evidence: bool = _env_bool("NEXUS_REPORT_EVIDENCE", True)
    include_raw_output: bool = _env_bool("NEXUS_REPORT_RAW", False)
    max_findings_per_report: int = _env_int("NEXUS_REPORT_MAX_FINDINGS", 500)
    company_name: str = _env("NEXUS_COMPANY_NAME", "Nexus Red Team")
    classification: str = _env("NEXUS_CLASSIFICATION", "CONFIDENTIAL")
    output_dir: str = str(REPORTS_DIR)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL CATEGORIES
# ══════════════════════════════════════════════════════════════════════════════

TOOL_CATEGORIES: Dict[str, List[str]] = {
    "reconnaissance": [
        "nmap", "masscan", "netdiscover", "arp-scan", "fping", "hping3",
        "whois", "dig", "nslookup", "traceroute", "theharvester",
        "amass", "subfinder", "dnsenum", "dnsrecon",
    ],
    "web_scanning": [
        "nikto", "gobuster", "dirb", "ffuf", "whatweb", "wpscan",
        "sqlmap", "nuclei", "katana", "gospider", "hakrawler",
    ],
    "exploitation": [
        "msfconsole", "msfvenom", "searchsploit",
        "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
        "impacket-secretsdump", "impacket-GetNPUsers", "impacket-GetUserSPNs",
    ],
    "credential_attacks": [
        "hydra", "medusa", "john", "hashcat", "hashid",
        "crunch", "cewl", "responder",
    ],
    "post_exploitation": [
        "crackmapexec", "netexec", "enum4linux", "smbclient", "smbmap",
        "ldapsearch", "bloodhound-python",
    ],
    "network_attacks": [
        "responder", "ettercap", "mitmproxy", "macchanger",
        "arpspoof", "bettercap",
    ],
    "tunneling": [
        "chisel", "socat", "ncat", "netcat", "proxychains4", "sshuttle",
    ],
    "wireless": [
        "aircrack-ng", "airodump-ng", "aireplay-ng", "reaver",
    ],
    "forensics": [
        "binwalk", "foremost", "exiftool", "steghide",
        "strings", "file", "xxd", "hexdump",
    ],
    "osint": [
        "theharvester", "amass", "subfinder", "waybackurls",
        "httpx", "dnsgen",
    ],
    "crypto": [
        "sslscan", "sslyze", "testssl.sh",
    ],
    "utilities": [
        "curl", "wget", "httpie", "jq", "tree",
        "tmux", "screen", "vim", "nano",
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# CONTAINER ESCAPE SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════

CONTAINER_ESCAPE_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"docker\.sock", "vector": "docker_socket_access", "severity": "critical"},
    {"pattern": r"/proc/\d+/root", "vector": "proc_mount_abuse", "severity": "critical"},
    {"pattern": r"nsenter\s+", "vector": "nsenter_abuse", "severity": "critical"},
    {"pattern": r"mount.*-t\s+cgroup", "vector": "cgroup_escape", "severity": "critical"},
    {"pattern": r"mount.*-t\s+sysfs", "vector": "sysfs_mount_abuse", "severity": "high"},
    {"pattern": r"capsh\s+--print", "vector": "capability_probe", "severity": "medium"},
    {"pattern": r"--privileged", "vector": "privileged_exec", "severity": "critical"},
    {"pattern": r"chroot\s+/host", "vector": "chroot_escape", "severity": "critical"},
    {"pattern": r"/proc/sysrq-trigger", "vector": "sysrq_abuse", "severity": "critical"},
    {"pattern": r"modprobe\s+", "vector": "kernel_module_load", "severity": "critical"},
    {"pattern": r"insmod\s+", "vector": "kernel_module_insert", "severity": "critical"},
    {"pattern": r"debugfs\s+", "vector": "debugfs_abuse", "severity": "critical"},
    {"pattern": r"/proc/\d+/ns/", "vector": "namespace_escape", "severity": "critical"},
    {"pattern": r"unshare\s+", "vector": "namespace_manipulation", "severity": "high"},
    {"pattern": r"runc\s+", "vector": "runc_escape", "severity": "critical"},
    {"pattern": r"overlay.*upperdir=/", "vector": "overlay_escape", "severity": "critical"},
    {"pattern": r"/dev/sd[a-z]", "vector": "host_disk_access", "severity": "critical"},
    {"pattern": r"ip\s+netns", "vector": "network_namespace_escape", "severity": "high"},
    {"pattern": r"pivot_root", "vector": "pivot_root_escape", "severity": "critical"},
]


# ══════════════════════════════════════════════════════════════════════════════
# DATA EXFILTRATION SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════

EXFILTRATION_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"curl\s+.*-d\s+@", "technique": "http_post_exfil", "severity": "high"},
    {"pattern": r"wget\s+--post-file", "technique": "http_post_exfil", "severity": "high"},
    {"pattern": r"nc\s+-[^l].*\d+\s*<", "technique": "netcat_exfil", "severity": "high"},
    {"pattern": r"scp\s+.*@.*:", "technique": "scp_exfil", "severity": "medium"},
    {"pattern": r"rsync\s+.*@.*:", "technique": "rsync_exfil", "severity": "medium"},
    {"pattern": r"base64\s+-w0\s+.*\|\s*curl", "technique": "encoded_exfil", "severity": "critical"},
    {"pattern": r"xxd\s+-p\s+.*\|\s*nc", "technique": "hex_exfil", "severity": "critical"},
    {"pattern": r"dig\s+.*TXT\s+.*@", "technique": "dns_exfil", "severity": "critical"},
    {"pattern": r"nslookup\s+.*\..*\..*\.", "technique": "dns_exfil", "severity": "high"},
]


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL CONFIG INSTANCE
# ══════════════════════════════════════════════════════════════════════════════

server_config = ServerConfig()
security_config = SecurityConfig()
database_config = DatabaseConfig()
execution_config = ExecutionConfig()
strategic_config = StrategicConfig()
reporting_config = ReportingConfig()


def get_all_configs() -> Dict[str, Any]:
    """Return all configuration as a serializable dictionary."""
    from dataclasses import asdict
    return {
        "server": asdict(server_config),
        "security": {k: v for k, v in asdict(security_config).items()
                     if k not in ("kill_switch_secret",)},
        "database": asdict(database_config),
        "execution": asdict(execution_config),
        "strategic": {k: v for k, v in asdict(strategic_config).items()
                      if k not in ("governance_key",)},
        "reporting": asdict(reporting_config),
    }
