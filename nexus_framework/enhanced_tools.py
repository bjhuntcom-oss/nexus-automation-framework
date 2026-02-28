"""
Nexus Automation Framework - Enhanced Tool Wrappers

Hardened tool execution with:
- Smart retry logic with exponential backoff
- Output normalization using NexusResponse
- Security validation before execution
- Error classification and recovery suggestions
- Resource monitoring and timeout handling
- Session-aware execution with evidence tagging
"""

import asyncio
import json
import logging
import os
import time
import traceback
from typing import Any, Dict, List, Optional, Sequence, Union
from datetime import datetime

import mcp.types as types

# Import our enhanced modules
from nexus_framework.output_normalizer import (
    NexusResponse, OutputStatus, classify_error, auto_parse, Finding, Severity, NexusError, ErrorCategory
)
from nexus_framework.container_security import security_engine, SecurityAction
from nexus_framework.tools import (
    # Core tools
    fetch_website,
    list_system_resources,
    run_command,
    sudo_command,
    # Scanning & Enumeration
    vulnerability_scan,
    web_enumeration,
    network_discovery,
    exploit_search,
    # File management
    save_output,
    create_report,
    file_analysis,
    download_file,
    # Session management
    session_create,
    session_list,
    session_switch,
    session_status,
    session_delete,
    session_history,
    # Web tools
    spider_website,
    form_analysis,
    header_analysis,
    ssl_analysis,
    subdomain_enum,
    web_audit,
    # Proxy tools
    start_mitmdump,
    start_proxify,
    # Process management
    list_processes,
    stop_process,
    # Advanced offensive tools
    msfvenom_payload,
    metasploit_handler,
    impacket_attack,
    netexec_attack,
    responder_start,
    bloodhound_collect,
    reverse_shell_listener,
    chisel_tunnel,
    wifi_scan,
    hash_crack,
)

logger = logging.getLogger("nexus.enhanced_tools")


# ══════════════════════════════════════════════════════════════════════════════
# ENHANCED TOOL WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

class EnhancedToolWrapper:
    """
    Enhanced tool execution wrapper with security, retry logic, and normalized output.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("enhanced_tools")
        self.max_retries = 3
        self.base_delay = 1.0
        self.max_delay = 30.0
        self.timeout_multiplier = 2.0
        
    async def execute_tool(
        self,
        tool_name: str,
        tool_func: callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        target: str = "",
        session_id: str = "",
        validate_security: bool = True
    ) -> List[types.TextContent]:
        """
        Execute a tool with enhanced security, retry logic, and output normalization.
        """
        # Work on a copy so we never mutate the caller's dict
        kwargs = dict(kwargs) if kwargs else {}
        start_time = time.time()

        # Create response wrapper
        response = NexusResponse(tool_name, target)
        response.set_command(f"{tool_name}({', '.join(f'{k}={v}' for k, v in kwargs.items())})")
        
        # Security validation for commands
        if validate_security and tool_name in ["run", "sudo"]:
            command = kwargs.get("command", "")
            security_action = security_engine.validate_process(command)
            if security_action == SecurityAction.KILL:
                response.set_status(OutputStatus.BLOCKED)
                response.add_error(NexusError(
                    category=ErrorCategory.INTERNAL,
                    message="Command blocked by security policy",
                    recovery_hint="This command appears to be a container escape attempt or dangerous operation"
                ))
                return response.to_mcp()
            elif security_action == SecurityAction.BLOCK:
                response.set_status(OutputStatus.BLOCKED)
                response.add_error(NexusError(
                    category=ErrorCategory.INTERNAL,
                    message="Command blocked by security policy",
                    recovery_hint="This command violates security policies"
                ))
                return response.to_mcp()
        
        # Execute with retry logic
        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                # Calculate timeout
                base_timeout = kwargs.get("timeout", 300)
                timeout = base_timeout * (self.timeout_multiplier if attempt > 0 else 1)
                kwargs["timeout"] = timeout
                
                # Execute the tool
                if asyncio.iscoroutinefunction(tool_func):
                    result = await tool_func(*args, **kwargs)
                else:
                    result = tool_func(*args, **kwargs)
                
                # Process successful result
                response.set_status(OutputStatus.SUCCESS)
                response.set_exit_code(0)
                
                # Parse and normalize output
                if isinstance(result, list) and result:
                    # Extract text content
                    content = ""
                    for item in result:
                        if hasattr(item, 'text'):
                            content += item.text
                        elif isinstance(item, str):
                            content += item
                    
                    response.set_raw_output(content)
                    
                    # Auto-parse findings
                    findings = auto_parse(content, tool_name)
                    for finding in findings:
                        response.add_finding(finding)
                    
                    # Set title and summary
                    response.set_title(f"{tool_name.title()} Results")
                    response.set_summary(f"Executed {tool_name} with {len(findings)} findings identified")
                    
                    # Add execution details
                    response.add_section("Execution Details", f"""
**Tool:** {tool_name}
**Target:** {target or 'N/A'}
**Duration:** {time.time() - start_time:.2f}s
**Attempts:** {attempt + 1}
**Timeout:** {timeout}s
**Session:** {session_id or 'default'}
""")
                    
                return response.to_mcp()
                
            except asyncio.TimeoutError as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    self.logger.warning(f"Tool {tool_name} timed out, retrying in {delay}s (attempt {attempt + 1})")
                    await asyncio.sleep(delay)
                    continue
                else:
                    response.set_status(OutputStatus.TIMEOUT)
                    response.add_error(NexusError(
                        category=ErrorCategory.TIMEOUT,
                        message=f"Tool {tool_name} timed out after {timeout}s",
                        recovery_hint="Try increasing timeout or reducing scan scope"
                    ))
                    return response.to_mcp()
                    
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    self.logger.warning(f"Tool {tool_name} failed, retrying in {delay}s (attempt {attempt + 1}): {e}")
                    await asyncio.sleep(delay)
                    continue
                else:
                    # Classify and add error
                    error = classify_error(e, kwargs.get("command", ""), "")
                    response.add_error(error)
                    response.set_status(OutputStatus.ERROR)
                    response.set_exit_code(1)
                    return response.to_mcp()
        
        # This should not be reached
        response.set_status(OutputStatus.ERROR)
        response.add_error(NexusError(
            category=ErrorCategory.UNKNOWN,
            message=f"Unexpected error after {self.max_retries} retries",
            recovery_hint="Check logs for details"
        ))
        return response.to_mcp()


# ══════════════════════════════════════════════════════════════════════════════
# ENHANCED TOOL FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# Global wrapper instance
enhanced_wrapper = EnhancedToolWrapper()

# Enhanced versions of all tools with security and retry logic
async def enhanced_run_command(command: str, background: bool = False, timeout: int = 300) -> Sequence[types.TextContent]:
    """Enhanced run_command with security validation and retry logic."""
    return await enhanced_wrapper.execute_tool(
        "run", run_command, kwargs={"command": command, "background": background, "timeout": timeout}
    )

async def enhanced_sudo_command(command: str, timeout: int = 300) -> Sequence[types.TextContent]:
    """Enhanced sudo_command with security validation and retry logic."""
    return await enhanced_wrapper.execute_tool(
        "sudo", sudo_command, kwargs={"command": command, "timeout": timeout}
    )

async def enhanced_vulnerability_scan(target: str, scan_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """Enhanced vulnerability scan with retry logic and output normalization."""
    return await enhanced_wrapper.execute_tool(
        "vulnerability_scan", vulnerability_scan,
        kwargs={"target": target, "scan_type": scan_type},
        target=target
    )

async def enhanced_web_enumeration(target: str, enumeration_type: str = "full") -> Sequence[types.TextContent]:
    """Enhanced web enumeration with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "web_enumeration", web_enumeration,
        kwargs={"target": target, "enumeration_type": enumeration_type},
        target=target
    )

async def enhanced_network_discovery(target: str, discovery_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """Enhanced network discovery with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "network_discovery", network_discovery,
        kwargs={"target": target, "discovery_type": discovery_type},
        target=target
    )

async def enhanced_exploit_search(search_term: str, search_type: str = "all") -> Sequence[types.TextContent]:
    """Enhanced exploit search with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "exploit_search", exploit_search,
        kwargs={"search_term": search_term, "search_type": search_type}
    )

async def enhanced_fetch_website(url: str) -> Sequence[types.TextContent]:
    """Enhanced website fetch with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "fetch", fetch_website, kwargs={"url": url}, target=url
    )

async def enhanced_file_analysis(filepath: str) -> Sequence[types.TextContent]:
    """Enhanced file analysis with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "file_analysis", file_analysis, kwargs={"filepath": filepath}, target=filepath
    )

async def enhanced_spider_website(url: str, depth: int = 2, threads: int = 10) -> Sequence[types.TextContent]:
    """Enhanced website spidering with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "spider_website", spider_website,
        kwargs={"url": url, "depth": depth, "threads": threads},
        target=url
    )

async def enhanced_form_analysis(url: str, scan_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """Enhanced form analysis with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "form_analysis", form_analysis,
        kwargs={"url": url, "scan_type": scan_type},
        target=url
    )

async def enhanced_header_analysis(url: str, include_security: bool = True) -> Sequence[types.TextContent]:
    """Enhanced header analysis with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "header_analysis", header_analysis,
        kwargs={"url": url, "include_security": include_security},
        target=url
    )

async def enhanced_ssl_analysis(url: str, port: int = 443) -> Sequence[types.TextContent]:
    """Enhanced SSL analysis with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "ssl_analysis", ssl_analysis,
        kwargs={"url": url, "port": port},
        target=url
    )

async def enhanced_subdomain_enum(url: str, enum_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """Enhanced subdomain enumeration with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "subdomain_enum", subdomain_enum,
        kwargs={"url": url, "enum_type": enum_type},
        target=url
    )

async def enhanced_web_audit(url: str, audit_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """Enhanced web audit with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "web_audit", web_audit,
        kwargs={"url": url, "audit_type": audit_type},
        target=url
    )

# Enhanced offensive tools
async def enhanced_msfvenom_payload(
    payload_type: str, lhost: str, lport: int,
    output_format: str = "raw", output_file: str = None
) -> Sequence[types.TextContent]:
    """Enhanced msfvenom payload generation with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "msfvenom_payload", msfvenom_payload,
        kwargs={
            "payload_type": payload_type, "lhost": lhost, "lport": lport,
            "output_format": output_format, "output_file": output_file
        }
    )

async def enhanced_metasploit_handler(
    payload_type: str, lhost: str, lport: int
) -> Sequence[types.TextContent]:
    """Enhanced metasploit handler with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "metasploit_handler", metasploit_handler,
        kwargs={"payload_type": payload_type, "lhost": lhost, "lport": lport}
    )

async def enhanced_impacket_attack(
    attack_type: str, target: str, username: str = "", password: str = "",
    domain: str = "", hashes: str = "", extra_args: str = ""
) -> Sequence[types.TextContent]:
    """Enhanced impacket attack with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "impacket_attack", impacket_attack,
        kwargs={
            "attack_type": attack_type, "target": target, "username": username,
            "password": password, "domain": domain, "hashes": hashes, "extra_args": extra_args
        },
        target=target
    )

async def enhanced_netexec_attack(
    protocol: str, target: str, username: str = "", password: str = "",
    domain: str = "", hashes: str = "", module: str = "", extra_args: str = ""
) -> Sequence[types.TextContent]:
    """Enhanced netexec attack with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "netexec_attack", netexec_attack,
        kwargs={
            "protocol": protocol, "target": target, "username": username,
            "password": password, "domain": domain, "hashes": hashes,
            "module": module, "extra_args": extra_args
        },
        target=target
    )

async def enhanced_hash_crack(
    hash_value: str, hash_type: str = "auto",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    tool: str = "hashcat"
) -> Sequence[types.TextContent]:
    """Enhanced hash cracking with retry logic."""
    return await enhanced_wrapper.execute_tool(
        "hash_crack", hash_crack,
        kwargs={"hash_value": hash_value, "hash_type": hash_type, "wordlist": wordlist, "tool": tool}
    )

# Enhanced session management
async def enhanced_session_create(
    session_name: str, description: str = "", target: str = ""
) -> Sequence[types.TextContent]:
    """Enhanced session creation with validation."""
    return await enhanced_wrapper.execute_tool(
        "session_create", session_create,
        kwargs={"session_name": session_name, "description": description, "target": target}
    )

# ══════════════════════════════════════════════════════════════════════════════
# TOOL MAPPING FOR SERVER INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

# Map of enhanced tools for easy integration
ENHANCED_TOOLS = {
    # Core tools
    "run": enhanced_run_command,
    "sudo": enhanced_sudo_command,
    "fetch": enhanced_fetch_website,
    
    # Scanning & Enumeration
    "vulnerability_scan": enhanced_vulnerability_scan,
    "web_enumeration": enhanced_web_enumeration,
    "network_discovery": enhanced_network_discovery,
    "exploit_search": enhanced_exploit_search,
    
    # Web tools
    "spider_website": enhanced_spider_website,
    "form_analysis": enhanced_form_analysis,
    "header_analysis": enhanced_header_analysis,
    "ssl_analysis": enhanced_ssl_analysis,
    "subdomain_enum": enhanced_subdomain_enum,
    "web_audit": enhanced_web_audit,
    
    # File management
    "file_analysis": enhanced_file_analysis,
    
    # Offensive tools
    "msfvenom_payload": enhanced_msfvenom_payload,
    "metasploit_handler": enhanced_metasploit_handler,
    "impacket_attack": enhanced_impacket_attack,
    "netexec_attack": enhanced_netexec_attack,
    "hash_crack": enhanced_hash_crack,
    
    # Session management
    "session_create": enhanced_session_create,
}

def get_enhanced_tool(tool_name: str):
    """Get the enhanced version of a tool if available."""
    return ENHANCED_TOOLS.get(tool_name)
