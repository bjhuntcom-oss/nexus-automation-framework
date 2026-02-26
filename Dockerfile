FROM kalilinux/kali-rolling

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# ══════════════════════════════════════════════════════════════════════════════
# BJHUNT ALPHA - Kali Linux Pentest Arsenal
# Full offensive security toolkit - validated packages
# ══════════════════════════════════════════════════════════════════════════════

# Base system
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    git build-essential procps psmisc ca-certificates \
    net-tools iproute2 iputils-ping openssh-client \
    vim nano tmux jq tree unzip curl wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Network scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    nmap masscan netdiscover arp-scan fping hping3 \
    traceroute tcpdump dnsutils whois \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Web application testing tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    nikto gobuster dirb ffuf whatweb sqlmap httpie \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Exploitation and AD tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    metasploit-framework exploitdb impacket-scripts python3-impacket \
    crackmapexec enum4linux smbclient smbmap ldap-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Credential attack tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    hydra medusa john hashcat hashid crunch cewl wordlists seclists \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Network attack tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    responder ettercap-text-only mitmproxy macchanger \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Wireless tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    aircrack-ng reaver \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Reverse shell and tunneling tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    netcat-openbsd ncat socat proxychains4 sshuttle \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# SSL/TLS and OSINT tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    sslscan sslyze theharvester amass subfinder \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Forensics and analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    binwalk foremost exiftool steghide \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Programming tools
RUN apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=3 --fix-missing \
    golang nodejs npm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Go tools (optional - non-fatal)
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true && \
    cp /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

WORKDIR /app
COPY . /app/

# Create working directories
RUN mkdir -p /app/loot /app/sessions /app/reports /app/downloads /opt/custom_wordlists /app/data/knowledge /app/logs /app/metrics

# Configure passwordless sudo
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    chmod 440 /etc/sudoers

# Create and activate virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:/root/go/bin:/usr/local/bin:$PATH"

# Install package manager and dependencies
RUN pip install --no-cache-dir -v uv && \
    pip install --no-cache-dir -v -r requirements.txt && \
    pip install --no-cache-dir pwntools droopescan dnsgen

# Install strategic engine dependencies
RUN pip install --no-cache-dir -v \
    networkx>=3.0 \
    numpy>=1.24.0 \
    scipy>=1.10.0 \
    xmltodict>=0.13.0 \
    psutil>=5.9.0 \
    PyJWT>=2.8.0 \
    cryptography>=41.0.0 \
    prometheus-client>=0.17.0

# Ensure output file exists
RUN touch /app/command_output.txt && chmod 666 /app/command_output.txt

# Decompress rockyou wordlist
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Health check — uses integrated diagnostics module
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 \
    CMD python -m bjhunt_alpha.healthcheck --quick --json || exit 1

EXPOSE 8000

# Run BJHunt Alpha server
CMD ["python", "-m", "bjhunt_alpha.server", "--transport", "sse", "--port", "8000"]