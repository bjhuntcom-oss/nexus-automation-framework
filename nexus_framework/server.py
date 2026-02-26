"""
BJHunt Alpha - MCP Server Implementation

Core server providing AI assistants with access to an extensive offensive
security toolkit via the Model Context Protocol (MCP). Supports SSE and
stdio transports for integration with Claude Desktop and CLI clients.

Enhanced with Strategic Engine for autonomous decision-making and orchestration.
"""

from typing import Any, Dict, List, Sequence, Union
import os
import asyncio
import logging

import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server

# Import strategic engine components
from bjhunt_alpha.strategic import (
    initialize_strategic_components, shutdown_strategic_components,
    brain_engine, attack_graph_engine, correlation_engine,
    knowledge_database, execution_engine, orchestrator,
    opsec_manager, governance_manager, observability_manager,
    TaskDefinition, TaskPriority, TaskType
)

from bjhunt_alpha.tools import (
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

# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIC TOOL IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════════════════

async def strategic_init(target_scope: List[str], objectives: List[str], stealth: float) -> List[types.TextContent]:
    """Initialize a new strategic operation."""
    op_id = await brain_engine.initialize_operation({
        "target_scope": target_scope,
        "objectives": objectives,
        "stealth_requirement": stealth
    })
    return [types.TextContent(type="text", text=f"🚀 Strategic operation initialized successfully.\n\n**Operation ID:** `{op_id}`\n**Targets:** {', '.join(target_scope)}\n**Objectives:** {', '.join(objectives) if objectives else 'General assessment'}\n**Stealth Level:** {stealth}\n\nUse `strategic_step` with the Operation ID to launch the first phase.")]

async def strategic_step(operation_id: str) -> List[types.TextContent]:
    """Execute the next iteration of the strategic loop."""
    try:
        tasks = await brain_engine.execute_strategic_loop(operation_id, orchestrator)
        if not tasks:
            status = await brain_engine.get_operation_status(operation_id)
            state = status['current_state'] if status else "unknown"
            return [types.TextContent(type="text", text=f"🧠 **Brain Decision:** No new actions recommended for operation `{operation_id}` at this stage (Current state: {state.upper()}).")]
        
        output = f"🧠 **Strategic Loop Executed**\n\nSubmitted {len(tasks)} tasks to the orchestrator for operation `{operation_id}`:\n\n"
        for i, tid in enumerate(tasks, 1):
            output += f"{i}. Task ID: `{tid}`\n"
        
        output += f"\nMonitor progress using `strategic_status` or check results in a few moments."
        return [types.TextContent(type="text", text=output)]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ **Error during strategic step:** {str(e)}")]

async def strategic_status(operation_id: str) -> List[types.TextContent]:
    """Get detailed status of a strategic operation."""
    status = await brain_engine.get_operation_status(operation_id)
    if not status:
        return [types.TextContent(type="text", text=f"❌ Operation `{operation_id}` not found.")]
    
    # Filter active tasks from orchestrator
    active_op_tasks = []
    for tid, task in orchestrator.active_tasks.items():
        if task.metadata.get('operation_id') == operation_id:
            active_op_tasks.append(task)
            
    res = f"📊 **Strategic Status: {operation_id}**\n\n"
    res += f"**Current State:** `{status['current_state'].upper()}`\n"
    res += f"**Discovered Assets:** {status['discovered_assets_count']}\n"
    res += f"**Completed Steps:** {status['execution_history_count']}\n"
    res += f"**Active Tasks:** {len(active_op_tasks)}\n"
    
    if active_op_tasks:
        res += "\n**Running Tasks:**\n"
        for task in active_op_tasks:
            res += f"- {task.task_name} (Priority: {task.priority.name})\n"
            
    # Add brain analytics summary
    res += "\n**Brain Analytics:**\n"
    res += f"- Risk Tolerance: {status.get('risk_tolerance', 'N/A')}\n"
    res += f"- Stealth Priority: {status.get('stealth_requirement', 'N/A')}\n"
    
    return [types.TextContent(type="text", text=res)]

# ══════════════════════════════════════════════════════════════════════════════
# SERVER INSTANCE
# ══════════════════════════════════════════════════════════════════════════════

bjhunt_server = Server("bjhunt-alpha")

# ══════════════════════════════════════════════════════════════════════════════
# MCP TOOL HANDLER
# ══════════════════════════════════════════════════════════════════════════════
# TOOL REQUEST HANDLER
# ══════════════════════════════════════════════════════════════════════════════

@bjhunt_server.call_tool()
async def handle_tool_request(
    name: str, arguments: Dict[str, Any]
) -> Sequence[Union[types.TextContent, types.ImageContent, types.EmbeddedResource]]:
    """
    Route MCP tool requests to the appropriate handler function.

    Args:
        name: The name of the tool being called.
        arguments: Dictionary of arguments for the tool.

    Returns:
        Sequence of content items returned by the tool.

    Raises:
        ValueError: If the tool name is unknown or required arguments are missing.
    """
    if name == "fetch":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        return await fetch_website(arguments["url"])

    elif name == "run":
        if "command" not in arguments:
            raise ValueError("Missing required argument 'command'")
        background = arguments.get("background", False)
        timeout = arguments.get("timeout", 300)
        return await run_command(arguments["command"], background=background, timeout=timeout)

    elif name == "resources":
        return await list_system_resources()

    elif name == "vulnerability_scan":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        scan_type = arguments.get("scan_type", "comprehensive")
        return await vulnerability_scan(arguments["target"], scan_type)

    elif name == "web_enumeration":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        enum_type = arguments.get("enumeration_type", "full")
        return await web_enumeration(arguments["target"], enum_type)

    elif name == "network_discovery":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        discovery_type = arguments.get("discovery_type", "comprehensive")
        return await network_discovery(arguments["target"], discovery_type)

    elif name == "exploit_search":
        if "search_term" not in arguments:
            raise ValueError("Missing required argument 'search_term'")
        search_type = arguments.get("search_type", "all")
        return await exploit_search(arguments["search_term"], search_type)

    elif name == "save_output":
        if "content" not in arguments:
            raise ValueError("Missing required argument 'content'")
        filename = arguments.get("filename")
        category = arguments.get("category", "general")
        return await save_output(arguments["content"], filename if filename else None, category)

    elif name == "create_report":
        if "title" not in arguments:
            raise ValueError("Missing required argument 'title'")
        if "findings" not in arguments:
            raise ValueError("Missing required argument 'findings'")
        report_type = arguments.get("report_type", "markdown")
        return await create_report(arguments["title"], arguments["findings"], report_type)

    elif name == "file_analysis":
        if "filepath" not in arguments:
            raise ValueError("Missing required argument 'filepath'")
        return await file_analysis(arguments["filepath"])

    elif name == "download_file":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        filename = arguments.get("filename")
        return await download_file(arguments["url"], filename if filename else None)

    elif name == "session_create":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        description = arguments.get("description", "")
        target = arguments.get("target", "")
        return await session_create(arguments["session_name"], description, target)

    elif name == "session_list":
        return await session_list()

    elif name == "session_switch":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        return await session_switch(arguments["session_name"])

    elif name == "session_status":
        return await session_status()

    elif name == "session_delete":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        return await session_delete(arguments["session_name"])

    elif name == "session_history":
        return await session_history()

    elif name == "strategic_init":
        if "target_scope" not in arguments:
            raise ValueError("Missing required argument 'target_scope'")
        return await strategic_init(arguments["target_scope"], arguments.get("objectives", []), arguments.get("stealth_requirement", 0.5))

    elif name == "strategic_step":
        if "operation_id" not in arguments:
            raise ValueError("Missing required argument 'operation_id'")
        return await strategic_step(arguments["operation_id"])

    elif name == "strategic_status":
        if "operation_id" not in arguments:
            raise ValueError("Missing required argument 'operation_id'")
        return await strategic_status(arguments["operation_id"])

    elif name == "spider_website":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        depth = arguments.get("depth", 2)
        threads = arguments.get("threads", 10)
        return await spider_website(arguments["url"], depth, threads)

    elif name == "form_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        scan_type = arguments.get("scan_type", "comprehensive")
        return await form_analysis(arguments["url"], scan_type)

    elif name == "header_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        include_security = arguments.get("include_security", True)
        return await header_analysis(arguments["url"], include_security)

    elif name == "ssl_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        port = arguments.get("port", 443)
        return await ssl_analysis(arguments["url"], port)

    elif name == "subdomain_enum":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        enum_type = arguments.get("enum_type", "comprehensive")
        return await subdomain_enum(arguments["url"], enum_type)

    elif name == "web_audit":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        audit_type = arguments.get("audit_type", "comprehensive")
        return await web_audit(arguments["url"], audit_type)

    elif name == "start_mitmdump":
        listen_port = arguments.get("listen_port", 8081)
        flows_file = arguments.get("flows_file")
        extra_args = arguments.get("extra_args", "")
        return await start_mitmdump(listen_port, flows_file, extra_args)

    elif name == "start_proxify":
        listen_address = arguments.get("listen_address", "127.0.0.1:8080")
        upstream = arguments.get("upstream")
        extra_args = arguments.get("extra_args", "")
        return await start_proxify(listen_address, upstream, extra_args)

    elif name == "list_processes":
        pattern = arguments.get("pattern", "")
        return await list_processes(pattern)

    elif name == "stop_process":
        if "pattern" not in arguments:
            raise ValueError("Missing required argument 'pattern'")
        return await stop_process(arguments["pattern"])

    # --- Advanced Offensive Tools ---

    elif name == "sudo":
        if "command" not in arguments:
            raise ValueError("Missing required argument 'command'")
        timeout = arguments.get("timeout", 300)
        return await sudo_command(arguments["command"], timeout)

    elif name == "msfvenom_payload":
        if "payload_type" not in arguments:
            raise ValueError("Missing required argument 'payload_type'")
        if "lhost" not in arguments:
            raise ValueError("Missing required argument 'lhost'")
        if "lport" not in arguments:
            raise ValueError("Missing required argument 'lport'")
        return await msfvenom_payload(
            arguments["payload_type"],
            arguments["lhost"],
            arguments["lport"],
            arguments.get("output_format", "raw"),
            arguments.get("output_file"),
        )

    elif name == "metasploit_handler":
        if "payload_type" not in arguments:
            raise ValueError("Missing required argument 'payload_type'")
        if "lhost" not in arguments:
            raise ValueError("Missing required argument 'lhost'")
        if "lport" not in arguments:
            raise ValueError("Missing required argument 'lport'")
        return await metasploit_handler(
            arguments["payload_type"],
            arguments["lhost"],
            arguments["lport"],
        )

    elif name == "impacket_attack":
        if "attack_type" not in arguments:
            raise ValueError("Missing required argument 'attack_type'")
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        return await impacket_attack(
            arguments["attack_type"],
            arguments["target"],
            arguments.get("username", ""),
            arguments.get("password", ""),
            arguments.get("domain", ""),
            arguments.get("hashes", ""),
            arguments.get("extra_args", ""),
        )

    elif name == "netexec_attack":
        if "protocol" not in arguments:
            raise ValueError("Missing required argument 'protocol'")
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        return await netexec_attack(
            arguments["protocol"],
            arguments["target"],
            arguments.get("username", ""),
            arguments.get("password", ""),
            arguments.get("domain", ""),
            arguments.get("hashes", ""),
            arguments.get("module", ""),
            arguments.get("extra_args", ""),
        )

    elif name == "responder_start":
        return await responder_start(
            arguments.get("interface", "eth0"),
            arguments.get("analyze", False),
            arguments.get("extra_args", ""),
        )

    elif name == "bloodhound_collect":
        if "domain" not in arguments:
            raise ValueError("Missing required argument 'domain'")
        if "username" not in arguments:
            raise ValueError("Missing required argument 'username'")
        if "password" not in arguments:
            raise ValueError("Missing required argument 'password'")
        if "dc_ip" not in arguments:
            raise ValueError("Missing required argument 'dc_ip'")
        return await bloodhound_collect(
            arguments["domain"],
            arguments["username"],
            arguments["password"],
            arguments["dc_ip"],
            arguments.get("collection", "all"),
        )

    elif name == "reverse_shell_listener":
        if "port" not in arguments:
            raise ValueError("Missing required argument 'port'")
        return await reverse_shell_listener(
            arguments["port"],
            arguments.get("shell_type", "nc"),
        )

    elif name == "chisel_tunnel":
        if "mode" not in arguments:
            raise ValueError("Missing required argument 'mode'")
        return await chisel_tunnel(
            arguments["mode"],
            arguments.get("server", ""),
            arguments.get("port", 8080),
            arguments.get("remote", ""),
        )

    elif name == "wifi_scan":
        return await wifi_scan(arguments.get("interface", "wlan0"))

    elif name == "hash_crack":
        if "hash_value" not in arguments:
            raise ValueError("Missing required argument 'hash_value'")
        return await hash_crack(
            arguments["hash_value"],
            arguments.get("hash_type", "auto"),
            arguments.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
            arguments.get("tool", "hashcat"),
        )

    elif name == "health_check":
        quick = arguments.get("quick", False)
        output_format = arguments.get("format", "text")
        from bjhunt_alpha.healthcheck import run_health_check, format_report_text
        import json as _json
        report = run_health_check(quick=quick)
        if output_format == "json":
            text = _json.dumps(report.to_dict(), indent=2)
        else:
            text = format_report_text(report)
        return [types.TextContent(type="text", text=text)]

    else:
        raise ValueError(f"Unknown tool: {name}")


# ══════════════════════════════════════════════════════════════════════════════
# MCP RESOURCES
# ══════════════════════════════════════════════════════════════════════════════

@bjhunt_server.list_resources()
async def list_resources() -> List[types.Resource]:
    """List all available resources (output files, wordlists, sessions, downloads)."""
    import glob

    resources = []

    # 1. Output files
    for pattern in ["*.txt", "*.log", "*.out", "*.err", "*_output_*.txt", "cmd_output_*.txt"]:
        for filepath in glob.glob(pattern):
            abs_path = os.path.abspath(filepath)
            resources.append(types.Resource(
                uri=f"file:///{abs_path}",
                name=os.path.basename(filepath),
                description=f"Output file: {os.path.basename(filepath)}",
                mimeType="text/plain",
            ))

    # 2. Wordlists
    wordlist_dir = "/usr/share/wordlists"
    if os.path.exists(wordlist_dir):
        for root, dirs, files in os.walk(wordlist_dir):
            for f in files[:50]:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, wordlist_dir)
                resources.append(types.Resource(
                    uri=f"wordlist:///{rel_path}",
                    name=f,
                    description=f"Wordlist: {rel_path}",
                    mimeType="text/plain",
                ))

    # 3. Session files
    from bjhunt_alpha.tools import list_sessions as _list_sessions, get_session_path
    for session in _list_sessions():
        session_dir = get_session_path(session)
        if os.path.exists(session_dir):
            for f in os.listdir(session_dir):
                if f != "metadata.json":
                    resources.append(types.Resource(
                        uri=f"session://{session}/{f}",
                        name=f,
                        description=f"Session {session}: {f}",
                        mimeType="text/plain",
                    ))

    # 4. Downloads
    downloads_dir = "downloads"
    if os.path.exists(downloads_dir):
        for f in os.listdir(downloads_dir):
            filepath = os.path.join(downloads_dir, f)
            if os.path.isfile(filepath):
                resources.append(types.Resource(
                    uri=f"download:///{f}",
                    name=f,
                    description=f"Downloaded file: {f}",
                    mimeType="application/octet-stream",
                ))

    return resources


@bjhunt_server.read_resource()
async def read_resource(uri: str) -> str:
    """Read the content of a resource by its URI."""
    from bjhunt_alpha.tools import get_session_path

    try:
        if uri.startswith("file:///"):
            filepath = uri[8:]
            with open(filepath, "r", errors="replace") as f:
                return f.read()

        elif uri.startswith("wordlist:///"):
            rel_path = uri[12:]
            filepath = os.path.join("/usr/share/wordlists", rel_path)
            file_size = os.path.getsize(filepath)
            if file_size > 10 * 1024 * 1024:
                with open(filepath, "r", errors="replace") as f:
                    content = f.read(10 * 1024 * 1024)
                    return content + f"\n\n... [TRUNCATED - File is {file_size / (1024*1024):.2f}MB]"
            else:
                with open(filepath, "r", errors="replace") as f:
                    return f.read()

        elif uri.startswith("session://"):
            parts = uri[10:].split("/")
            session_name = parts[0]
            filename = parts[1] if len(parts) > 1 else "metadata.json"
            filepath = os.path.join(get_session_path(session_name), filename)
            with open(filepath, "r", errors="replace") as f:
                return f.read()

        elif uri.startswith("download:///"):
            filename = uri[12:]
            filepath = os.path.join("downloads", filename)
            with open(filepath, "rb") as f:
                import base64
                content = f.read()
                if len(content) > 1024 * 1024:
                    return f"[Binary file - {len(content)} bytes - too large to display]"
                try:
                    return content.decode("utf-8", errors="replace")
                except Exception:
                    return base64.b64encode(content).decode("ascii")

        else:
            raise ValueError(f"Unknown URI scheme: {uri}")

    except FileNotFoundError:
        raise ValueError(f"Resource not found: {uri}")
    except PermissionError:
        raise ValueError(f"Permission denied reading resource: {uri}")
    except Exception as e:
        raise ValueError(f"Error reading resource {uri}: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# TOOL DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

@bjhunt_server.list_tools()
async def list_available_tools() -> List[types.Tool]:
    """Register and list all available MCP tools."""
    return [
        types.Tool(
            name="fetch",
            description="Fetches a website and returns its content",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                },
            },
        ),
        types.Tool(
            name="run",
            description="Execute ANY shell command - UNRESTRICTED. Long-running commands auto-detected for background execution.",
            inputSchema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute (ANY command allowed)"},
                    "background": {"type": "boolean", "description": "Force background execution", "default": False},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default 300)", "default": 300},
                },
            },
        ),
        types.Tool(
            name="resources",
            description="Lists available system resources and command examples",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="vulnerability_scan",
            description="Perform automated vulnerability assessment with multiple tools",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {"type": "string", "description": "Target IP address or hostname"},
                    "scan_type": {"type": "string", "description": "Type of scan (quick, comprehensive, web, network)", "enum": ["quick", "comprehensive", "web", "network"], "default": "comprehensive"},
                },
            },
        ),
        types.Tool(
            name="web_enumeration",
            description="Perform comprehensive web application discovery and enumeration",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {"type": "string", "description": "Target URL (e.g., http://example.com)"},
                    "enumeration_type": {"type": "string", "description": "Type of enumeration (basic, full, aggressive)", "enum": ["basic", "full", "aggressive"], "default": "full"},
                },
            },
        ),
        types.Tool(
            name="network_discovery",
            description="Perform multi-stage network reconnaissance and discovery",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {"type": "string", "description": "Target network (e.g., 192.168.1.0/24) or host"},
                    "discovery_type": {"type": "string", "description": "Type of discovery (quick, comprehensive, stealth)", "enum": ["quick", "comprehensive", "stealth"], "default": "comprehensive"},
                },
            },
        ),
        types.Tool(
            name="exploit_search",
            description="Search for exploits using searchsploit and other exploit databases",
            inputSchema={
                "type": "object",
                "required": ["search_term"],
                "properties": {
                    "search_term": {"type": "string", "description": "Term to search for (e.g., 'apache', 'ssh', 'CVE-2021-44228')"},
                    "search_type": {"type": "string", "description": "Type of search (all, web, remote, local, dos)", "enum": ["all", "web", "remote", "local", "dos"], "default": "all"},
                },
            },
        ),
        types.Tool(
            name="save_output",
            description="Save content to a timestamped file for evidence collection",
            inputSchema={
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": {"type": "string", "description": "Content to save"},
                    "filename": {"type": "string", "description": "Optional custom filename (without extension)"},
                    "category": {"type": "string", "description": "Category for organizing files (e.g., 'scan', 'enum', 'evidence')", "default": "general"},
                },
            },
        ),
        types.Tool(
            name="create_report",
            description="Generate a structured report from findings",
            inputSchema={
                "type": "object",
                "required": ["title", "findings"],
                "properties": {
                    "title": {"type": "string", "description": "Report title"},
                    "findings": {"type": "string", "description": "Findings content"},
                    "report_type": {"type": "string", "description": "Type of report (markdown, text, json)", "enum": ["markdown", "text", "json"], "default": "markdown"},
                },
            },
        ),
        types.Tool(
            name="strategic_init",
            description="Initialize a new autonomous strategic security operation",
            inputSchema={
                "type": "object",
                "required": ["target_scope"],
                "properties": {
                    "target_scope": {"type": "array", "items": {"type": "string"}, "description": "List of target IPs or domains"},
                    "objectives": {"type": "array", "items": {"type": "string"}, "description": "Specific goals (e.g., 'initial_access', 'data_exfiltration')"},
                    "stealth_requirement": {"type": "number", "description": "Stealth requirement 0-1 (higher = slower, more stealthy)", "default": 0.5},
                },
            },
        ),
        types.Tool(
            name="strategic_step",
            description="Execute the next phase of an autonomous strategic operation",
            inputSchema={
                "type": "object",
                "required": ["operation_id"],
                "properties": {
                    "operation_id": {"type": "string", "description": "ID of the operation to step"},
                },
            },
        ),
        types.Tool(
            name="strategic_status",
            description="Get the current status and brain analytics of a strategic operation",
            inputSchema={
                "type": "object",
                "required": ["operation_id"],
                "properties": {
                    "operation_id": {"type": "string", "description": "ID of the operation"},
                },
            },
        ),
        types.Tool(
            name="file_analysis",
            description="Analyze a file using various tools (file type, strings, hash)",
            inputSchema={
                "type": "object",
                "required": ["filepath"],
                "properties": {
                    "filepath": {"type": "string", "description": "Path to the file to analyze"},
                },
            },
        ),
        types.Tool(
            name="download_file",
            description="Download a file from a URL and save it locally",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL to download from"},
                    "filename": {"type": "string", "description": "Optional custom filename"},
                },
            },
        ),
        types.Tool(
            name="session_create",
            description="Create a new pentest session (name, description, target)",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {"type": "string", "description": "Name of the session"},
                    "description": {"type": "string", "description": "Description of the session"},
                    "target": {"type": "string", "description": "Target for the session"},
                },
            },
        ),
        types.Tool(
            name="session_list",
            description="List all pentest sessions with metadata",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="session_switch",
            description="Switch to a different pentest session",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {"type": "string", "description": "Name of the session to switch to"},
                },
            },
        ),
        types.Tool(
            name="session_status",
            description="Show current session status and summary",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="session_delete",
            description="Delete a pentest session and all its evidence",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {"type": "string", "description": "Name of the session to delete"},
                },
            },
        ),
        types.Tool(
            name="session_history",
            description="Show command/evidence history for the current session",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="spider_website",
            description="Spider a website to find all links and resources",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL of the website to spider"},
                    "depth": {"type": "integer", "description": "Maximum depth of the spider", "default": 2},
                    "threads": {"type": "integer", "description": "Number of concurrent threads", "default": 10},
                },
            },
        ),
        types.Tool(
            name="form_analysis",
            description="Analyze a web form for vulnerabilities",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL of the web form to analyze"},
                    "scan_type": {"type": "string", "description": "Type of scan (comprehensive, quick)", "enum": ["comprehensive", "quick"], "default": "comprehensive"},
                },
            },
        ),
        types.Tool(
            name="header_analysis",
            description="Analyze HTTP headers for security issues",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL of the website to analyze"},
                    "include_security": {"type": "boolean", "description": "Include security-related headers", "default": True},
                },
            },
        ),
        types.Tool(
            name="ssl_analysis",
            description="Analyze SSL/TLS configuration of a website",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL of the website to analyze"},
                    "port": {"type": "integer", "description": "Port to connect to", "default": 443},
                },
            },
        ),
        types.Tool(
            name="subdomain_enum",
            description="Enumerate subdomains of a target website",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL of the target website"},
                    "enum_type": {"type": "string", "description": "Type of enumeration (comprehensive, quick)", "enum": ["comprehensive", "quick"], "default": "comprehensive"},
                },
            },
        ),
        types.Tool(
            name="web_audit",
            description="Perform a comprehensive web application audit",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "URL of the website to audit"},
                    "audit_type": {"type": "string", "description": "Type of audit (comprehensive, quick)", "enum": ["comprehensive", "quick"], "default": "comprehensive"},
                },
            },
        ),
        # Proxy & Process Management
        types.Tool(
            name="start_mitmdump",
            description="Start mitmdump HTTP(S) interception proxy in background",
            inputSchema={
                "type": "object",
                "properties": {
                    "listen_port": {"type": "integer", "description": "Port to listen on", "default": 8081},
                    "flows_file": {"type": "string", "description": "File to save flows (optional)"},
                    "extra_args": {"type": "string", "description": "Additional arguments"},
                },
            },
        ),
        types.Tool(
            name="start_proxify",
            description="Start ProjectDiscovery proxify proxy in background",
            inputSchema={
                "type": "object",
                "properties": {
                    "listen_address": {"type": "string", "description": "Listen address", "default": "127.0.0.1:8080"},
                    "upstream": {"type": "string", "description": "Upstream proxy (optional)"},
                    "extra_args": {"type": "string", "description": "Additional arguments"},
                },
            },
        ),
        types.Tool(
            name="list_processes",
            description="List running processes, optionally filtered by pattern",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Pattern to filter processes (optional)"},
                },
            },
        ),
        types.Tool(
            name="stop_process",
            description="Stop processes matching a pattern using pkill",
            inputSchema={
                "type": "object",
                "required": ["pattern"],
                "properties": {
                    "pattern": {"type": "string", "description": "Pattern to match processes to stop"},
                },
            },
        ),
        # Advanced Offensive Tools
        types.Tool(
            name="sudo",
            description="Execute command with sudo privileges (UNRESTRICTED)",
            inputSchema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {"type": "string", "description": "Command to run with sudo"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
                },
            },
        ),
        types.Tool(
            name="msfvenom_payload",
            description="Generate Metasploit payloads (exe, elf, ps1, py, etc.)",
            inputSchema={
                "type": "object",
                "required": ["payload_type", "lhost", "lport"],
                "properties": {
                    "payload_type": {"type": "string", "description": "Payload (e.g., windows/meterpreter/reverse_tcp)"},
                    "lhost": {"type": "string", "description": "Listener host IP"},
                    "lport": {"type": "integer", "description": "Listener port"},
                    "output_format": {"type": "string", "description": "Format (raw, exe, elf, py, ps1)", "default": "raw"},
                    "output_file": {"type": "string", "description": "Output filename (optional)"},
                },
            },
        ),
        types.Tool(
            name="metasploit_handler",
            description="Start Metasploit multi/handler for reverse connections",
            inputSchema={
                "type": "object",
                "required": ["payload_type", "lhost", "lport"],
                "properties": {
                    "payload_type": {"type": "string", "description": "Payload type to handle"},
                    "lhost": {"type": "string", "description": "Listener host"},
                    "lport": {"type": "integer", "description": "Listener port"},
                },
            },
        ),
        types.Tool(
            name="impacket_attack",
            description="Execute Impacket AD/Windows attacks (psexec, wmiexec, secretsdump, etc.)",
            inputSchema={
                "type": "object",
                "required": ["attack_type", "target"],
                "properties": {
                    "attack_type": {"type": "string", "description": "Attack type (psexec, wmiexec, smbexec, secretsdump, GetNPUsers, GetUserSPNs)"},
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "username": {"type": "string", "description": "Username"},
                    "password": {"type": "string", "description": "Password"},
                    "domain": {"type": "string", "description": "Domain name"},
                    "hashes": {"type": "string", "description": "NTLM hashes (LM:NT)"},
                    "extra_args": {"type": "string", "description": "Additional arguments"},
                },
            },
        ),
        types.Tool(
            name="netexec_attack",
            description="Execute NetExec (CrackMapExec) attacks for network pentesting",
            inputSchema={
                "type": "object",
                "required": ["protocol", "target"],
                "properties": {
                    "protocol": {"type": "string", "description": "Protocol (smb, ldap, winrm, ssh, mssql, rdp)"},
                    "target": {"type": "string", "description": "Target IP, range, or CIDR"},
                    "username": {"type": "string", "description": "Username"},
                    "password": {"type": "string", "description": "Password"},
                    "domain": {"type": "string", "description": "Domain"},
                    "hashes": {"type": "string", "description": "NTLM hash"},
                    "module": {"type": "string", "description": "Module to run (-M)"},
                    "extra_args": {"type": "string", "description": "Additional arguments"},
                },
            },
        ),
        types.Tool(
            name="responder_start",
            description="Start Responder for LLMNR/NBT-NS/MDNS poisoning",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Network interface", "default": "eth0"},
                    "analyze": {"type": "boolean", "description": "Analyze mode only (no poisoning)", "default": False},
                    "extra_args": {"type": "string", "description": "Additional arguments"},
                },
            },
        ),
        types.Tool(
            name="bloodhound_collect",
            description="Collect Active Directory data for BloodHound analysis",
            inputSchema={
                "type": "object",
                "required": ["domain", "username", "password", "dc_ip"],
                "properties": {
                    "domain": {"type": "string", "description": "Domain name"},
                    "username": {"type": "string", "description": "Username"},
                    "password": {"type": "string", "description": "Password"},
                    "dc_ip": {"type": "string", "description": "Domain Controller IP"},
                    "collection": {"type": "string", "description": "Collection method (all, group, session, acl)", "default": "all"},
                },
            },
        ),
        types.Tool(
            name="reverse_shell_listener",
            description="Start reverse shell listener with payload hints",
            inputSchema={
                "type": "object",
                "required": ["port"],
                "properties": {
                    "port": {"type": "integer", "description": "Port to listen on"},
                    "shell_type": {"type": "string", "description": "Listener type (nc, ncat, socat, pwncat)", "default": "nc"},
                },
            },
        ),
        types.Tool(
            name="chisel_tunnel",
            description="Setup Chisel tunneling for pivoting",
            inputSchema={
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {"type": "string", "description": "Mode (server, client)"},
                    "server": {"type": "string", "description": "Server address (for client mode)"},
                    "port": {"type": "integer", "description": "Port", "default": 8080},
                    "remote": {"type": "string", "description": "Remote forwarding (e.g., R:8080:127.0.0.1:80)"},
                },
            },
        ),
        types.Tool(
            name="wifi_scan",
            description="Scan WiFi networks using aircrack-ng suite",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Wireless interface", "default": "wlan0"},
                },
            },
        ),
        types.Tool(
            name="hash_crack",
            description="Crack password hashes with hashcat or john",
            inputSchema={
                "type": "object",
                "required": ["hash_value"],
                "properties": {
                    "hash_value": {"type": "string", "description": "Hash or file containing hashes"},
                    "hash_type": {"type": "string", "description": "Hash type (auto, md5, sha1, ntlm, etc.)", "default": "auto"},
                    "wordlist": {"type": "string", "description": "Wordlist path", "default": "/usr/share/wordlists/rockyou.txt"},
                    "tool": {"type": "string", "description": "Tool (hashcat, john)", "default": "hashcat"},
                },
            },
        ),
        # Health Check & Diagnostics
        types.Tool(
            name="health_check",
            description="Run comprehensive health check on all BJHunt Alpha services, tools, and dependencies",
            inputSchema={
                "type": "object",
                "properties": {
                    "quick": {"type": "boolean", "description": "Quick check (core only) vs full check", "default": False},
                    "format": {"type": "string", "description": "Output format (text, json)", "enum": ["text", "json"], "default": "text"},
                },
            },
        ),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVER STARTUP
# ══════════════════════════════════════════════════════════════════════════════

@click.command()
@click.option("--port", default=8000, help="Port to listen on for HTTP/SSE connections")
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="sse", help="Transport type (stdio for CLI, sse for Claude Desktop)")
@click.option("--debug", is_flag=True, default=False, help="Enable debug mode")
def main(port: int, transport: str, debug: bool) -> int:
    """Start the BJHunt Alpha MCP Server."""
    if transport == "sse":
        return start_sse_server(port, debug)
    else:
        return start_stdio_server(debug)


def start_sse_server(port: int, debug: bool) -> int:
    """Start the server with SSE transport for web/Claude Desktop usage."""
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.responses import Response
    from starlette.routing import Mount, Route

    # Initialize strategic components
    logger = logging.getLogger(__name__)
    logger.info("Initializing BJHunt Alpha Strategic Engine components...")
    
    try:
        initialize_strategic_components()
        logger.info("Strategic Engine components initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Strategic Engine: {e}")
        return 1

    sse_transport = SseServerTransport("/messages/")

    async def handle_sse(request):
        """Handle incoming SSE connections."""
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await bjhunt_server.run(
                streams[0], streams[1], bjhunt_server.create_initialization_options()
            )
        return Response()

    starlette_app = Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

    print(f"Starting BJHunt Alpha MCP Server with SSE transport on port {port}")
    print(f"Connect to this server using: http://localhost:{port}/sse")
    print("Strategic Engine components: ENABLED")
    
    try:
        uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    finally:
        # Cleanup strategic components
        try:
            shutdown_strategic_components()
            logger.info("Strategic Engine components shutdown successfully")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    return 0


def start_stdio_server(debug: bool) -> int:
    """Start the server with stdio transport for command-line usage."""
    from mcp.server.stdio import stdio_server

    # Initialize strategic components
    logger = logging.getLogger(__name__)
    logger.info("Initializing BJHunt Alpha Strategic Engine components...")
    
    try:
        initialize_strategic_components()
        logger.info("Strategic Engine components initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Strategic Engine: {e}")
        return 1

    async def start_stdio_connection():
        """Initialize and run the stdio server."""
        print("Starting BJHunt Alpha MCP Server with stdio transport")
        print("Strategic Engine components: ENABLED")
        
        try:
            async with stdio_server() as streams:
                await bjhunt_server.run(
                    streams[0], streams[1], bjhunt_server.create_initialization_options()
                )
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
        finally:
            # Cleanup strategic components
            try:
                shutdown_strategic_components()
                logger.info("Strategic Engine components shutdown successfully")
            except Exception as e:
                logger.error(f"Error during shutdown: {e}")

    try:
        anyio.run(start_stdio_connection)
    except Exception as e:
        logger.error(f"Server error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    main()
