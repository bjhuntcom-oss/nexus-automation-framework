FROM kalilinux/kali-rolling

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# ══════════════════════════════════════════════════════════════════════════════
# NEXUS AUTOMATION FRAMEWORK - Kali Linux Pentest Arsenal
# Optimized: single apt-get update, deduplicated packages, multi-layer cache
# ══════════════════════════════════════════════════════════════════════════════

# ── Layer 1: Base system + ALL tools in a single apt transaction ──
# This reduces image layers and avoids repeated apt-get update calls
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    --no-install-recommends -o Acquire::Retries=5 --fix-missing \
    # ── Base system ──
    python3 python3-pip python3-venv python3-dev \
    git build-essential procps psmisc ca-certificates \
    net-tools iproute2 iputils-ping openssh-client \
    vim nano tmux jq tree unzip curl wget \
    # ── Network scanning ──
    nmap masscan netdiscover arp-scan fping hping3 \
    traceroute tcpdump dnsutils whois \
    # ── Web application testing ──
    nikto gobuster dirb ffuf whatweb sqlmap httpie \
    # ── Exploitation + AD ──
    metasploit-framework exploitdb impacket-scripts python3-impacket \
    crackmapexec enum4linux smbclient smbmap ldap-utils \
    # ── Credential attacks ──
    hydra medusa john hashcat hashid crunch cewl wordlists seclists \
    # ── Network attacks ──
    responder ettercap-text-only mitmproxy macchanger \
    # ── Wireless ──
    aircrack-ng reaver \
    # ── Modern security tools ──
    amass testssl.sh sslscan sslyze wpscan \
    # ── Tunneling & pivoting (deduplicated) ──
    netcat-openbsd ncat socat proxychains4 chisel sshuttle \
    # ── OSINT ──
    theharvester \
    # ── Forensics ──
    binwalk foremost exiftool steghide \
    # ── BloodHound ──
    bloodhound.py \
    # ── Programming ──
    golang nodejs npm \
    # ── pwntools system dependencies ──
    libffi-dev libssl-dev libcapstone-dev binutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ── Layer 2: Go tools (optional, non-fatal) ──
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true && \
    go install github.com/hakluke/hakrawler@latest 2>/dev/null || true && \
    go install github.com/jaeles-project/gospider@latest 2>/dev/null || true && \
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || true && \
    cp /root/go/bin/* /usr/local/bin/ 2>/dev/null || true && \
    rm -rf /root/go/pkg /tmp/*

# ── Layer 3: Application setup ──
WORKDIR /app

# Copy requirements first for Docker cache optimization
COPY requirements.txt pyproject.toml /app/

# Create virtual environment and install dependencies
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:/root/go/bin:/usr/local/bin:$PATH"

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pwntools droopescan dnsgen

# ── Layer 4: Copy application code ──
COPY nexus_framework/ /app/nexus_framework/
COPY scripts/ /app/scripts/
COPY tests/ /app/tests/

# Create working directories
RUN mkdir -p /app/loot /app/sessions /app/reports /app/downloads \
    /app/data/knowledge /app/logs /app/metrics /app/plugins \
    /opt/custom_wordlists

# Configure passwordless sudo
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    chmod 440 /etc/sudoers

# Ensure output file exists
RUN touch /app/command_output.txt && chmod 666 /app/command_output.txt

# Decompress rockyou wordlist
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# ── Environment variables ──
ENV NEXUS_ENVIRONMENT=production
ENV NEXUS_APP_DIR=/app
ENV NEXUS_LOG_LEVEL=INFO
ENV NEXUS_TRANSPORT=sse
ENV NEXUS_PORT=8000
ENV NEXUS_KILL_SWITCH_ENABLED=true
ENV NEXUS_IDS_ENABLED=true
ENV NEXUS_HOST_ONLY_MODE=true
ENV NEXUS_VPN_KILL_SWITCH_ONLY=true
ENV NEXUS_DB_JOURNAL_MODE=WAL
ENV NEXUS_DB_PATH=/app/knowledge.db

# Health check — HTTP endpoint (faster than Python module invocation)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

EXPOSE 8000

# Entrypoint: ensures knowledge.db is a proper file (not a directory from Docker mount)
COPY scripts/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["python", "-m", "nexus_framework.server", "--transport", "sse", "--port", "8000"]