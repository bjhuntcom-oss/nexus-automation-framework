# 🔥 Nexus Automation Framework

**Enterprise-grade automation framework** — A comprehensive system orchestration platform providing intelligent automation capabilities for modern infrastructure management and security operations.

[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Automation](https://img.shields.io/badge/Automation-FF6B6B?style=for-the-badge&logo=robot&logoColor=white)](https://github.com/bjhuntcom-oss/nexus-automation-framework)

---

## 📋 Overview

Nexus Automation Framework provides a comprehensive orchestration platform for intelligent system automation. The framework enables seamless integration with modern infrastructure through advanced protocol support and extensible tool ecosystem.

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| 🔍 **System Monitoring** | Process management, resource tracking, health diagnostics |
| 🕸️ **Network Operations** | Service discovery, traffic analysis, protocol inspection |
| 🧪 **Automation Tools** | Task scheduling, workflow orchestration, event handling |
| 🔑 **Security Operations** | Vulnerability assessment, compliance checking, audit trails |
| 🏢 **Infrastructure Management** | Container orchestration, service deployment, configuration management |
| 📡 **Communication** | Message queuing, API integration, data streaming |
| 📶 **Wireless Operations** | Network scanning, signal analysis, device management |
| 🔐 **Encryption & Security** | Certificate management, secure communications, access control |
| 🔎 **Intelligence** | Data collection, analysis pipelines, reporting systems |
| 🧰 **File Management** | Backup automation, synchronization, archival systems |
| 🔒 **Compliance** | Audit logging, policy enforcement, security monitoring |

---

## 🚀 Quick Start

### 1. Build & Run with Docker

```powershell
# Using the helper script (Windows)
.\run_docker.ps1

# Or manually:
docker build -t nexus-framework .
docker run -p 8000:8000 nexus-framework
```

### 2. Connect to Claude Desktop

Edit your Claude Desktop config:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nexus-framework": {
      "transport": "sse",
      "url": "http://localhost:8000/sse",
      "command": "docker run -p 8000:8000 nexus-framework"
    }
  }
}
```

---

## 🛠️ Available MCP Tools

### Core Tools

| Tool | Description |
|------|-------------|
| `run` | Execute **any** shell command (unrestricted) |
| `sudo` | Execute command with sudo privileges |
| `fetch` | Fetch and return web content |
| `resources` | List system resources and command examples |
| `health_check`| Run full system diagnostics and health report |

### Scanning & Enumeration

| Tool | Description |
|------|-------------|
| `vulnerability_scan` | Automated vuln assessment (quick/comprehensive/web/network) |
| `web_enumeration` | Web app discovery (basic/full/aggressive) |
| `network_discovery` | Network recon (quick/comprehensive/stealth) |
| `exploit_search` | Search exploits via searchsploit |

### Web Application Testing

| Tool | Description |
|------|-------------|
| `spider_website` | Web crawling with gospider |
| `form_analysis` | Analyze web forms for vulnerabilities |
| `header_analysis` | HTTP security header analysis |
| `ssl_analysis` | SSL/TLS assessment with testssl.sh |
| `subdomain_enum` | Subdomain enumeration (subfinder, amass) |
| `web_audit` | Comprehensive web security audit |

### Offensive Tools

| Tool | Description |
|------|-------------|
| `msfvenom_payload` | Generate Metasploit payloads |
| `metasploit_handler` | Start multi/handler listener |
| `impacket_attack` | AD/Windows attacks (psexec, wmiexec, secretsdump) |
| `netexec_attack` | Network pentesting (SMB, LDAP, WinRM, SSH) |
| `responder_start` | LLMNR/NBT-NS/MDNS poisoning |
| `bloodhound_collect` | Active Directory data collection |
| `reverse_shell_listener` | Start listener with payload hints |
| `chisel_tunnel` | Tunneling for pivoting |
| `wifi_scan` | WiFi network scanning (aircrack-ng) |
| `hash_crack` | Hash cracking (hashcat/john) |

### File & Session Management

| Tool | Description |
|------|-------------|
| `save_output` | Save content to timestamped file |
| `create_report` | Generate structured reports (md/txt/json) |
| `file_analysis` | Analyze files (type, strings, hash) |
| `download_file` | Download files with hash verification |
| `session_create` | Create pentest session |
| `session_list` | List all sessions |
| `session_switch` | Switch active session |
| `session_status` | Show session summary |
| `session_delete` | Delete session and evidence |
| `session_history` | Show session history |

### Process & Proxy Management

| Tool | Description |
|------|-------------|
| `start_mitmdump` | HTTP(S) interception proxy |
| `start_proxify` | ProjectDiscovery proxify proxy |
| `list_processes` | List running processes |
| `stop_process` | Stop processes by pattern |

---

## 🏥 Health & Diagnostics

Nexus Automation Framework includes a comprehensive health monitoring system that validates all system components, service availability, and operational readiness.

### Integrated MCP Tool
Call the `health_check` tool from your AI assistant to get a live status report:
- `health_check(quick=True)` — (Default) Fast check of core components
- `health_check(quick=False)` — Deep check including network and all 39 tool routes

### CLI Usage
Run diagnostics directly from the terminal:
```powershell
python -m nexus_framework.healthcheck          # Human-readable report
python -m nexus_framework.healthcheck --json   # JSON machine-readable output
```

---

## 📁 Project Structure

```
nexus-framework/
├── nexus_framework/         # Main Python package
│   ├── __init__.py           # Package metadata (v1.0.0)
│   ├── __main__.py           # Entry point (python -m nexus_framework)
│   ├── server.py             # Framework server & service registry
│   ├── tools.py              # Core automation implementations
│   └── healthcheck.py        # Integrated diagnostic system
├── tests/                    # Comprehensive test suite
│   └── test_nexus.py         # Framework validation tests
├── Dockerfile                # Enterprise container configuration
├── pyproject.toml            # Python project configuration
├── run_docker.ps1            # Windows deployment script
└── README.md                 # Documentation
```

---

## 🔒 Security Features

- **Credential sanitization** — Passwords and hashes are automatically masked in all outputs
- **Audit trail** — All actions logged to `bjhunt_audit.jsonl` in structured JSON
- **Health Check monitoring** — Proactive detection of environment issues
- **Session management** — Isolated environments for different assessments
- **File rotation** — Automatic cleanup keeps the workspace tidy

---

## 👨‍💻 Development & Testing

```powershell
# Install for development
pip install -e "."
pip install pytest pytest-asyncio

# Run the comprehensive test suite
pytest tests/test_nexus.py -v

# Run individual health checks
python -m nexus_framework.healthcheck
```

---

## ⚠️ Security Notice

This framework provides powerful automation capabilities for enterprise environments. Please:

- ✅ Use **only** in authorized production environments
- ✅ Follow proper change management procedures
- ✅ Monitor system logs and performance metrics
- ✅ Maintain security best practices
- ❌ Do not expose management interfaces publicly
- ❌ Do not share credentials or configuration data

---

## 📋 Requirements

- Docker Desktop
- Claude Desktop or other SSE-enabled MCP client
- Port 8000 available on your host

---

<p align="center">
  <sub>Nexus Automation Framework v1.0.0 — Enterprise-grade orchestration platform</sub>
</p>
