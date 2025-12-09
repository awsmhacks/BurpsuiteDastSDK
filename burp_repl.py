#!/usr/bin/env python3
"""
Burp Suite DAST SDK Interactive REPL

A tab-complete command-line interface for interacting with the Burp Suite DAST API.

Usage:
    python burp_repl.py --url https://burpsuite.example.com/graphql/v1 --api-key YOUR_API_KEY
    python burp_repl.py --url https://burpsuite.example.com/graphql/v1  # Uses BURPSUITE_API_KEY env var

Or start without arguments and use 'connect' command:
    python burp_repl.py
    burp> connect https://burpsuite.example.com/graphql/v1 YOUR_API_KEY
"""

import cmd
import json
import os
import sys
import readline
import argparse
import shlex
from typing import Optional, List, Dict, Any
from datetime import datetime

try:
    from burpsuite_sdk import (
        BurpSuiteClient,
        BurpSuiteError,
        AuthenticationError,
        GraphQLError,
        NetworkError,
        # Enums
        ScanStatus,
        ScansSortColumn,
        SortOrder,
        SortBy,
        Severity,
        Confidence,
        Novelty,
        PropagationMode,
        ScanReportType,
        TagColor,
        BCheckSortColumn,
        ScopeProtocolOptions,
        ForwardPropagationMode,
    )
except ImportError:
    print("Error: burpsuite_sdk not found. Make sure it's installed or in PYTHONPATH.")
    print("Try: pip install -e . or PYTHONPATH=. python burp_repl.py")
    sys.exit(1)


# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def format_json(data: Any, indent: int = 2) -> str:
    """Format data as pretty JSON."""
    return json.dumps(data, indent=indent, default=str)


def format_table(headers: List[str], rows: List[List[str]], max_width: int = 40) -> str:
    """Format data as a table."""
    if not rows:
        return "No data"
    
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], min(len(str(cell)), max_width))
    
    # Build table
    lines = []
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    lines.append(colorize(header_line, Colors.BOLD))
    lines.append("-+-".join("-" * w for w in widths))
    
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cell_str = str(cell)[:max_width]
            if i < len(widths):
                cells.append(cell_str.ljust(widths[i]))
        lines.append(" | ".join(cells))
    
    return "\n".join(lines)


def truncate(text: str, max_len: int = 50) -> str:
    """Truncate text with ellipsis."""
    if not text:
        return ""
    text = str(text)
    return text[:max_len-3] + "..." if len(text) > max_len else text


class BurpREPL(cmd.Cmd):
    """Interactive REPL for Burp Suite DAST SDK."""
    
    intro = colorize("""
╔══════════════════════════════════════════════════════════════════╗
║           Burp Suite DAST SDK Interactive REPL                   ║
║                                                                  ║
║  Type 'help' for available commands, 'help <command>' for details║
║  Tab completion is available for commands and arguments          ║
║  Type 'quit' or 'exit' to leave                                  ║
╚══════════════════════════════════════════════════════════════════╝
""", Colors.CYAN)
    
    prompt = colorize("burp> ", Colors.GREEN)
    
    def __init__(self, client: Optional[BurpSuiteClient] = None):
        super().__init__()
        self.client = client
        self._last_result = None
        self._sites_cache: List[Dict] = []
        self._scans_cache: List[Dict] = []
        self._agents_cache: List[Dict] = []
        self._configs_cache: List[Dict] = []
        self._tags_cache: List[Dict] = []
        self._schedule_cache: List[Dict] = []
        self._debug_mode: bool = False
        
        # Configure readline for history
        self.history_file = os.path.expanduser("~/.burp_repl_history")
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)
    
    def postcmd(self, stop, line):
        """Save history after each command."""
        try:
            readline.write_history_file(self.history_file)
        except Exception:
            pass
        return stop
    
    def _check_connected(self) -> bool:
        """Check if client is connected."""
        if not self.client:
            print(colorize("Not connected. Use 'connect <url> [api_key]' first.", Colors.RED))
            return False
        return True
    
    def _handle_error(self, e: Exception):
        """Handle and display errors."""
        if isinstance(e, AuthenticationError):
            print(colorize(f"Authentication Error: {e}", Colors.RED))
        elif isinstance(e, GraphQLError):
            print(colorize(f"GraphQL Error: {e}", Colors.RED))
        elif isinstance(e, NetworkError):
            print(colorize(f"Network Error: {e}", Colors.RED))
        elif isinstance(e, BurpSuiteError):
            print(colorize(f"Burp Suite Error: {e}", Colors.RED))
        else:
            print(colorize(f"Error: {e}", Colors.RED))
    
    def _print_result(self, data: Any, as_json: bool = False):
        """Print result data."""
        self._last_result = data
        if as_json or not isinstance(data, (list, dict)):
            print(format_json(data))
        else:
            print(format_json(data))
    
    def _refresh_sites_cache(self):
        """Refresh the sites cache from the API."""
        try:
            tree = self.client.get_site_tree()
            self._sites_cache = tree.get("sites", [])
        except:
            pass
    
    def _resolve_site_id(self, site_ref: str) -> Optional[str]:
        """
        Resolve a site reference (ID or name) to a site ID.
        
        Args:
            site_ref: Either a site ID or a site name
            
        Returns:
            The site ID, or None if not found
        """
        if not site_ref:
            return None
        
        site_ref = site_ref.strip()
        
        # First, check if it's already a valid site ID in the cache
        if not self._sites_cache:
            self._refresh_sites_cache()
        
        # Check by ID first
        for site in self._sites_cache:
            if site.get("id") == site_ref:
                return site_ref
        
        # Check by name (case-insensitive)
        for site in self._sites_cache:
            if site.get("name", "").lower() == site_ref.lower():
                return site.get("id")
        
        # If not found in cache, refresh and try again
        self._refresh_sites_cache()
        
        for site in self._sites_cache:
            if site.get("id") == site_ref:
                return site_ref
        
        for site in self._sites_cache:
            if site.get("name", "").lower() == site_ref.lower():
                return site.get("id")
        
        # Not found - return the original (might be a valid ID not in cache)
        return site_ref
    
    def _get_site_name(self, site_id: str) -> Optional[str]:
        """Get the site name for a given site ID."""
        if not self._sites_cache:
            self._refresh_sites_cache()
        
        for site in self._sites_cache:
            if site.get("id") == site_id:
                return site.get("name")
        return None
    
    # =========================================================================
    # CONNECTION COMMANDS
    # =========================================================================
    
    def do_connect(self, arg):
        """
        Connect to Burp Suite DAST API.
        
        Usage: connect <url> [api_key]
        
        If api_key is not provided, will use BURPSUITE_API_KEY environment variable.
        
        Examples:
            connect https://burpsuite.example.com/graphql/v1
            connect https://burpsuite.example.com/graphql/v1 my-api-key
        """
        args = shlex.split(arg)
        if not args:
            print("Usage: connect <url> [api_key]")
            return
        
        url = args[0]
        api_key = args[1] if len(args) > 1 else None
        
        try:
            self.client = BurpSuiteClient(url=url, api_key=api_key)
            # Apply debug mode if enabled
            if self._debug_mode:
                self.client.debug = True
                self.client.set_debug_callback(self._debug_output)
            # Test connection
            self.client.get_capabilities()
            print(colorize(f"Connected to {url}", Colors.GREEN))
        except Exception as e:
            self.client = None
            self._handle_error(e)
    
    def do_disconnect(self, arg):
        """Disconnect from the API."""
        self.client = None
        self._sites_cache = []
        self._scans_cache = []
        print(colorize("Disconnected", Colors.YELLOW))
    
    def do_status(self, arg):
        """Show connection status and capabilities."""
        if not self._check_connected():
            return
        
        try:
            caps = self.client.get_capabilities()
            settings = self.client.get_settings()
            warnings = self.client.get_system_warnings()
            
            print(colorize("\n=== Connection Status ===", Colors.BOLD))
            print(f"URL: {self.client.url}")
            print(f"Scans Enabled: {settings.get('global_scans_enabled', 'N/A')}")
            
            print(colorize("\n=== Capabilities ===", Colors.BOLD))
            for cap, enabled in caps.items():
                status = colorize("✓", Colors.GREEN) if enabled else colorize("✗", Colors.RED)
                print(f"  {cap}: {status}")
            
            if warnings:
                print(colorize("\n=== Warnings ===", Colors.YELLOW))
                for w in warnings:
                    print(f"  [{w.get('type')}] {w.get('message')}")
            
        except Exception as e:
            self._handle_error(e)
    
    # =========================================================================
    # SITE COMMANDS
    # =========================================================================
    
    def do_sites(self, arg):
        """
        List all sites.
        
        Usage: sites [--json]
        
        Options:
            --json    Output as raw JSON
        """
        if not self._check_connected():
            return
        
        try:
            tree = self.client.get_site_tree()
            sites = tree.get("sites", [])
            self._sites_cache = sites
            
            if "--json" in arg:
                self._print_result(sites, as_json=True)
                return
            
            if not sites:
                print("No sites found")
                return
            
            headers = ["ID", "Name", "Parent", "URLs", "Tags"]
            rows = []
            for site in sites:
                scope = site.get("scope_v2", {})
                urls = ", ".join(scope.get("start_urls", [])[:2])
                tags = ", ".join(t.get("name", "") for t in site.get("tags", [])[:3])
                rows.append([
                    site.get("id", ""),
                    truncate(site.get("name", ""), 30),
                    site.get("parent_id", ""),
                    truncate(urls, 40),
                    truncate(tags, 20),
                ])
            
            print(format_table(headers, rows))
            print(f"\nTotal: {len(sites)} sites")
            
        except Exception as e:
            self._handle_error(e)
    
    def complete_site(self, text, line, begidx, endidx):
        """Tab completion for site IDs and names."""
        if not self._sites_cache:
            self._refresh_sites_cache()
        
        # Include both IDs and names for completion
        completions = []
        for s in self._sites_cache:
            site_id = s.get("id", "")
            site_name = s.get("name", "")
            if site_id.startswith(text):
                completions.append(site_id)
            # Quote names with spaces for shell compatibility
            if site_name.lower().startswith(text.lower()):
                if " " in site_name:
                    completions.append(f'"{site_name}"')
                else:
                    completions.append(site_name)
        return completions
    
    def _strip_quotes(self, value: str) -> str:
        """Strip surrounding quotes from a value."""
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]
        return value
    
    def do_site(self, arg):
        """
        Get details of a specific site.
        
        Usage: site <site_id_or_name>
        
        You can use either the site ID or site name.
        Tab completion available for both.
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: site <site_id_or_name>")
            return
        
        try:
            site_ref = self._strip_quotes(arg)
            site_id = self._resolve_site_id(site_ref)
            site = self.client.get_site(site_id)
            if site:
                self._print_result(site)
            else:
                print(f"Site '{arg}' not found")
        except Exception as e:
            self._handle_error(e)
    
    complete_site = complete_site
    
    def do_create_site(self, arg):
        """
        Create a new site.
        
        Usage: create_site <name> <url> [parent_id]
        
        Examples:
            create_site "My Site" https://example.com
            create_site "Sub Site" https://test.com 1
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if len(args) < 2:
            print("Usage: create_site <name> <url> [parent_id]")
            return
        
        name = args[0]
        url = args[1]
        parent_id = args[2] if len(args) > 2 else "0"
        
        try:
            result = self.client.create_site(
                name=name,
                start_urls=[url],
                parent_id=parent_id
            )
            print(colorize("Site created:", Colors.GREEN))
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    def do_delete_site(self, arg):
        """
        Delete a site.
        
        Usage: delete_site <site_id_or_name>
        
        You can use either the site ID or site name.
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: delete_site <site_id_or_name>")
            return
        
        try:
            site_ref = self._strip_quotes(arg)
            site_id = self._resolve_site_id(site_ref)
            site_name = self._get_site_name(site_id) or site_ref
            result = self.client.delete_site(site_id)
            print(colorize(f"Site '{site_name}' ({result}) deleted", Colors.GREEN))
            # Clear the cache since we deleted a site
            self._sites_cache = []
        except Exception as e:
            self._handle_error(e)
    
    complete_delete_site = complete_site
    
    # =========================================================================
    # FOLDER COMMANDS
    # =========================================================================
    
    def do_folders(self, arg):
        """
        List all folders.
        
        Usage: folders [--json]
        """
        if not self._check_connected():
            return
        
        try:
            tree = self.client.get_site_tree()
            folders = tree.get("folders", [])
            
            if "--json" in arg:
                self._print_result(folders, as_json=True)
                return
            
            if not folders:
                print("No folders found")
                return
            
            headers = ["ID", "Name", "Parent", "Description"]
            rows = []
            for folder in folders:
                rows.append([
                    folder.get("id", ""),
                    truncate(folder.get("name", ""), 30),
                    folder.get("parent_id", ""),
                    truncate(folder.get("description", ""), 40),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def do_create_folder(self, arg):
        """
        Create a new folder.
        
        Usage: create_folder <name> [parent_id] [description]
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if not args:
            print("Usage: create_folder <name> [parent_id] [description]")
            return
        
        name = args[0]
        parent_id = args[1] if len(args) > 1 else "0"
        description = args[2] if len(args) > 2 else None
        
        try:
            result = self.client.create_folder(
                name=name,
                parent_id=parent_id,
                description=description
            )
            print(colorize("Folder created:", Colors.GREEN))
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    # =========================================================================
    # SCAN COMMANDS
    # =========================================================================
    
    def do_scans(self, arg):
        """
        List scans.
        
        Usage: scans [--limit N] [--status STATUS] [--json]
        
        Options:
            --limit N       Maximum number of scans (default: 20)
            --status STATUS Filter by status (queued, running, succeeded, cancelled, failed, paused)
            --json          Output as raw JSON
        
        Examples:
            scans
            scans --limit 50
            scans --status running
            scans --status succeeded --limit 10
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        limit = 20
        status_filter = None
        as_json = "--json" in args
        
        i = 0
        while i < len(args):
            if args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 2
            elif args[i] == "--status" and i + 1 < len(args):
                try:
                    status_filter = [ScanStatus(args[i + 1].lower())]
                except ValueError:
                    print(f"Invalid status: {args[i + 1]}")
                    return
                i += 2
            else:
                i += 1
        
        try:
            scans = self.client.get_scans(limit=limit, scan_status=status_filter)
            self._scans_cache = scans
            
            if as_json:
                self._print_result(scans, as_json=True)
                return
            
            if not scans:
                print("No scans found")
                return
            
            headers = ["ID", "Status", "Start Time", "Duration", "Issues"]
            rows = []
            for scan in scans:
                status = scan.get("status", "")
                status_color = {
                    "running": Colors.BLUE,
                    "succeeded": Colors.GREEN,
                    "failed": Colors.RED,
                    "cancelled": Colors.YELLOW,
                    "queued": Colors.CYAN,
                    "paused": Colors.YELLOW,
                }.get(status, Colors.RESET)
                
                issue_counts = scan.get("issue_counts", {})
                issues = f"H:{issue_counts.get('high', {}).get('total', 0)} M:{issue_counts.get('medium', {}).get('total', 0)} L:{issue_counts.get('low', {}).get('total', 0)}"
                
                duration = scan.get("duration_in_seconds")
                if duration:
                    duration = f"{duration // 60}m {duration % 60}s"
                else:
                    duration = "-"
                
                rows.append([
                    scan.get("id", ""),
                    colorize(status, status_color),
                    truncate(scan.get("start_time", "-"), 20),
                    duration,
                    issues,
                ])
            
            print(format_table(headers, rows))
            print(f"\nShowing {len(scans)} scans")
            
        except Exception as e:
            self._handle_error(e)
    
    def complete_scan(self, text, line, begidx, endidx):
        """Tab completion for scan IDs."""
        if not self._scans_cache:
            try:
                self._scans_cache = self.client.get_scans(limit=50)
            except:
                pass
        
        scan_ids = [s.get("id", "") for s in self._scans_cache]
        return [sid for sid in scan_ids if sid.startswith(text)]
    
    def do_scan(self, arg):
        """
        Get details of a specific scan.
        
        Usage: scan <scan_id>
        
        Tab completion available for scan IDs.
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: scan <scan_id>")
            return
        
        try:
            scan = self.client.get_scan(arg.strip())
            if scan:
                self._print_result(scan)
            else:
                print(f"Scan {arg} not found")
        except Exception as e:
            self._handle_error(e)
    
    complete_scan = complete_scan
    
    def do_cancel_scan(self, arg):
        """
        Cancel a running or scheduled scan.
        
        Usage: cancel_scan <scan_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: cancel_scan <scan_id>")
            return
        
        try:
            result = self.client.cancel_scan(arg.strip())
            print(colorize(f"Scan {result} cancelled", Colors.GREEN))
        except Exception as e:
            self._handle_error(e)
    
    complete_cancel_scan = complete_scan
    
    def do_pause_scan(self, arg):
        """
        Pause a running scan.
        
        Usage: pause_scan <scan_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: pause_scan <scan_id>")
            return
        
        try:
            result = self.client.pause_scan(arg.strip())
            print(colorize(f"Scan {result} paused", Colors.GREEN))
        except Exception as e:
            self._handle_error(e)
    
    complete_pause_scan = complete_scan
    
    def do_resume_scan(self, arg):
        """
        Resume a paused scan.
        
        Usage: resume_scan <scan_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: resume_scan <scan_id>")
            return
        
        try:
            result = self.client.resume_scan(arg.strip())
            print(colorize(f"Scan {result} resumed", Colors.GREEN))
        except Exception as e:
            self._handle_error(e)
    
    complete_resume_scan = complete_scan
    
    def do_delete_scan(self, arg):
        """
        Delete a scan.
        
        Usage: delete_scan <scan_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: delete_scan <scan_id>")
            return
        
        try:
            result = self.client.delete_scan(arg.strip())
            print(colorize(f"Scan {result} deleted", Colors.GREEN))
        except Exception as e:
            self._handle_error(e)
    
    complete_delete_scan = complete_scan
    
    def do_create_scan(self, arg):
        """
        Create and start a scan for a site (alias for create_schedule).
        
        Usage: create_scan <site_id_or_name> [options]
        
        You can use either the site ID or site name.
        
        Options:
            --name NAME         Name for the scan
            --time TIME         Initial run time (ISO 8601, e.g., 2024-01-15T10:00:00Z)
                               If not specified, scan starts immediately
            --rrule RRULE       Recurrence rule for recurring scans
            --config CONFIG_ID  Scan configuration ID to use
        
        Examples:
            create_scan abc123
            create_scan "My Site" --name "Security Scan"
            create_scan abc123 --name "Daily Scan" --rrule "FREQ=DAILY;INTERVAL=1"
        
        This is an alias for 'create_schedule'. See 'help create_schedule' for more details.
        """
        self.do_create_schedule(arg)
    
    complete_create_scan = complete_site
    
    # =========================================================================
    # ISSUE COMMANDS
    # =========================================================================
    
    def do_issues(self, arg):
        """
        List issues for a scan.
        
        Usage: issues <scan_id> [--limit N] [--severity SEVERITY] [--json]
        
        Options:
            --limit N           Limit to N issues (default: fetch ALL)
            --severity SEVERITY Filter by severity (high, medium, low, info)
            --json              Output as raw JSON
        
        Examples:
            issues 123
            issues 123 --severity high
            issues 123 --limit 50 --severity medium
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if not args:
            print("Usage: issues <scan_id> [--limit N] [--severity SEVERITY]")
            return
        
        scan_id = args[0]
        limit = None  # None means fetch all
        severity_filter = None
        as_json = "--json" in args
        
        i = 1
        while i < len(args):
            if args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 2
            elif args[i] == "--count" and i + 1 < len(args):
                # Keep --count as alias for backwards compatibility
                limit = int(args[i + 1])
                i += 2
            elif args[i] == "--severity" and i + 1 < len(args):
                try:
                    severity_filter = [Severity(args[i + 1].lower())]
                except ValueError:
                    print(f"Invalid severity: {args[i + 1]}")
                    return
                i += 2
            else:
                i += 1
        
        try:
            if limit is None:
                # Fetch all issues using pagination (default)
                all_issues = []
                start = 0
                batch_size = 500
                print("Fetching all issues...", end="", flush=True)
                while True:
                    batch = self.client.get_scan_issues(
                        scan_id=scan_id,
                        start=start,
                        count=batch_size,
                        severities=severity_filter
                    )
                    if not batch:
                        break
                    all_issues.extend(batch)
                    start += len(batch)
                    print(f"\rFetching all issues... {len(all_issues)} found", end="", flush=True)
                    if len(batch) < batch_size:
                        break
                print()  # Newline after progress
                issues = all_issues
            else:
                issues = self.client.get_scan_issues(
                    scan_id=scan_id,
                    count=limit,
                    severities=severity_filter
                )
            
            if as_json:
                self._print_result(issues, as_json=True)
                return
            
            if not issues:
                print("No issues found")
                return
            
            headers = ["Serial", "Severity", "Confidence", "Type", "Path"]
            rows = []
            for issue in issues:
                severity = issue.get("severity", "")
                sev_color = {
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                    "info": Colors.CYAN,
                }.get(severity, Colors.RESET)
                
                issue_type = issue.get("issue_type", {})
                rows.append([
                    issue.get("serial_number", ""),
                    colorize(severity, sev_color),
                    issue.get("confidence", ""),
                    truncate(issue_type.get("name", ""), 30),
                    truncate(issue.get("path", ""), 40),
                ])
            
            print(format_table(headers, rows))
            print(f"\nTotal: {len(issues)} issues")
            
        except Exception as e:
            self._handle_error(e)
    
    complete_issues = complete_scan
    
    def do_issue(self, arg):
        """
        Get details of a specific issue.
        
        Usage: issue <scan_id> <serial_number>
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if len(args) < 2:
            print("Usage: issue <scan_id> <serial_number>")
            return
        
        try:
            issue = self.client.get_issue(args[0], args[1])
            if issue:
                self._print_result(issue)
            else:
                print(f"Issue not found")
        except Exception as e:
            self._handle_error(e)
    
    def do_site_issues(self, arg):
        """
        Get all issues for a site.
        
        Usage: site_issues <site_id_or_name> [--json]
        
        You can use either the site ID or site name.
        
        Examples:
            site_issues abc123
            site_issues "My Application"
            site_issues abc123 --json
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: site_issues <site_id_or_name> [--json]")
            return
        
        args = shlex.split(arg)
        site_ref = self._strip_quotes(args[0])
        as_json = "--json" in args
        
        try:
            issues = self.client.get_site_issues(site_ref)
            
            if as_json:
                self._print_result(issues, as_json=True)
                return
            
            if not issues:
                print(f"No issues found for site '{site_ref}'")
                return
            
            # Display issues in a table format
            # Handle aggregated_issue_type_summaries format from REST API
            headers = ["Severity", "Confidence", "Type", "Count", "First Seen"]
            rows = []
            for issue in issues:
                # Get severity - try multiple field names
                severity = (issue.get("highest_severity") or 
                           issue.get("severity") or "-")
                
                # Get confidence
                confidence = (issue.get("typical_confidence") or 
                             issue.get("confidence") or "-")
                
                # Get type/name
                issue_type = (issue.get("type_label") or 
                             issue.get("name") or 
                             issue.get("issue_type_name") or "-")
                
                # Get count
                count = issue.get("number_of_children", issue.get("count", "-"))
                
                # Get first seen
                first_seen = (issue.get("first_found_date") or 
                             issue.get("first_seen") or "-")
                if first_seen and first_seen != "-":
                    # Truncate datetime for display
                    first_seen = str(first_seen)[:19]
                
                rows.append([
                    severity,
                    confidence,
                    truncate(str(issue_type), 45),
                    str(count),
                    first_seen,
                ])
            
            print(format_table(headers, rows))
            print(f"\nTotal: {len(issues)} issue types for site")
            print("Use --json for full details")
            
        except Exception as e:
            self._handle_error(e)
    
    complete_site_issues = complete_site
    
    # =========================================================================
    # AGENT COMMANDS
    # =========================================================================
    
    def do_agents(self, arg):
        """
        List all agents.
        
        Usage: agents [--json]
        """
        if not self._check_connected():
            return
        
        try:
            agents = self.client.get_agents()
            self._agents_cache = agents
            
            if "--json" in arg:
                self._print_result(agents, as_json=True)
                return
            
            if not agents:
                print("No agents found")
                return
            
            headers = ["ID", "Name", "State", "IP", "Enabled", "Scans", "Pool"]
            rows = []
            for agent in agents:
                state = agent.get("state", "")
                state_color = Colors.GREEN if state == "online" else Colors.RED
                
                pool = agent.get("agent_pool", {})
                rows.append([
                    agent.get("id", ""),
                    truncate(agent.get("name", ""), 20),
                    colorize(state, state_color),
                    agent.get("ip", ""),
                    "Yes" if agent.get("enabled") else "No",
                    f"{agent.get('current_scan_count', 0)}/{agent.get('max_concurrent_scans', 1)}",
                    truncate(pool.get("name", "-"), 15),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def complete_agent(self, text, line, begidx, endidx):
        """Tab completion for agent IDs."""
        if not self._agents_cache:
            try:
                self._agents_cache = self.client.get_agents()
            except:
                pass
        
        agent_ids = [a.get("id", "") for a in self._agents_cache]
        return [aid for aid in agent_ids if aid.startswith(text)]
    
    def do_unauthorized_agents(self, arg):
        """
        List unauthorized agents waiting for authorization.
        
        Usage: unauthorized_agents
        """
        if not self._check_connected():
            return
        
        try:
            agents = self.client.get_unauthorized_agents()
            if not agents:
                print("No unauthorized agents")
                return
            
            headers = ["Machine ID", "IP"]
            rows = [[a.get("machine_id", ""), a.get("ip", "")] for a in agents]
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def do_authorize_agent(self, arg):
        """
        Authorize an agent.
        
        Usage: authorize_agent <machine_id> [pool_id]
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if not args:
            print("Usage: authorize_agent <machine_id> [pool_id]")
            return
        
        machine_id = args[0]
        pool_id = args[1] if len(args) > 1 else None
        
        try:
            result = self.client.authorize_agent(machine_id, pool_id)
            print(colorize("Agent authorized:", Colors.GREEN))
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    def do_enable_agent(self, arg):
        """
        Enable an agent.
        
        Usage: enable_agent <agent_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: enable_agent <agent_id>")
            return
        
        try:
            result = self.client.enable_agent(arg.strip(), enabled=True)
            print(colorize("Agent enabled:", Colors.GREEN))
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    complete_enable_agent = complete_agent
    
    def do_disable_agent(self, arg):
        """
        Disable an agent.
        
        Usage: disable_agent <agent_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: disable_agent <agent_id>")
            return
        
        try:
            result = self.client.enable_agent(arg.strip(), enabled=False)
            print(colorize("Agent disabled:", Colors.YELLOW))
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    complete_disable_agent = complete_agent
    
    # =========================================================================
    # CONFIGURATION COMMANDS
    # =========================================================================
    
    def do_configs(self, arg):
        """
        List scan configurations.
        
        Usage: configs [--json]
        """
        if not self._check_connected():
            return
        
        try:
            configs = self.client.get_scan_configurations()
            self._configs_cache = configs
            
            if "--json" in arg:
                self._print_result(configs, as_json=True)
                return
            
            if not configs:
                print("No configurations found")
                return
            
            headers = ["ID", "Name", "Built-in", "Modified"]
            rows = []
            for config in configs:
                rows.append([
                    config.get("id", ""),
                    truncate(config.get("name", ""), 40),
                    "Yes" if config.get("built_in") else "No",
                    truncate(config.get("last_modified_time", "-"), 20),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def do_featured_configs(self, arg):
        """
        List featured scan configurations.
        
        Usage: featured_configs
        """
        if not self._check_connected():
            return
        
        try:
            configs = self.client.get_featured_scan_configurations()
            
            if "--json" in arg:
                self._print_result(configs, as_json=True)
                return
            
            if not configs:
                print("No featured configurations found")
                return
            
            headers = ["ID", "Name", "Description"]
            rows = []
            for config in configs:
                rows.append([
                    config.get("id", ""),
                    truncate(config.get("name", ""), 30),
                    truncate(config.get("description", ""), 50),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    # =========================================================================
    # TAG COMMANDS
    # =========================================================================
    
    def do_tags(self, arg):
        """
        List all tags.
        
        Usage: tags [--json]
        """
        if not self._check_connected():
            return
        
        try:
            tags = self.client.get_tags()
            self._tags_cache = tags
            
            if "--json" in arg:
                self._print_result(tags, as_json=True)
                return
            
            if not tags:
                print("No tags found")
                return
            
            headers = ["ID", "Name", "Color", "Description"]
            rows = []
            for tag in tags:
                rows.append([
                    tag.get("id", ""),
                    tag.get("name", ""),
                    tag.get("color", ""),
                    truncate(tag.get("description", ""), 40),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def do_create_tag(self, arg):
        """
        Create a new tag.
        
        Usage: create_tag <name> <color> [description]
        
        Colors: DARK_BLUE, LIGHT_BLUE, NAVY, PURPLE, MAGENTA, 
                DARK_GREEN, LIGHT_GREEN, ORANGE, LIGHT_ORANGE, YELLOW
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if len(args) < 2:
            print("Usage: create_tag <name> <color> [description]")
            print("Colors: DARK_BLUE, LIGHT_BLUE, NAVY, PURPLE, MAGENTA, DARK_GREEN, LIGHT_GREEN, ORANGE, LIGHT_ORANGE, YELLOW")
            return
        
        name = args[0]
        try:
            color = TagColor(args[1].upper())
        except ValueError:
            print(f"Invalid color: {args[1]}")
            return
        
        description = args[2] if len(args) > 2 else None
        
        try:
            result = self.client.create_tag(name=name, color=color, description=description)
            print(colorize("Tag created:", Colors.GREEN))
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    def complete_create_tag(self, text, line, begidx, endidx):
        """Tab completion for tag colors."""
        words = line.split()
        if len(words) == 3 or (len(words) == 2 and not text):
            colors = [c.value for c in TagColor]
            return [c for c in colors if c.startswith(text.upper())]
        return []
    
    # =========================================================================
    # SCHEDULE COMMANDS
    # =========================================================================
    
    def do_schedules(self, arg):
        """
        List schedule items.
        
        Usage: schedules [--json]
        """
        if not self._check_connected():
            return
        
        try:
            schedules = self.client.get_schedule_items()
            self._schedule_cache = schedules
            
            if "--json" in arg:
                self._print_result(schedules, as_json=True)
                return
            
            if not schedules:
                print("No schedules found")
                return
            
            headers = ["ID", "Name", "Next Run", "Sites"]
            rows = []
            for schedule in schedules:
                sched_info = schedule.get("schedule", {})
                sites = schedule.get("sites", [])
                site_names = ", ".join(s.get("name", "") for s in sites[:3])
                rows.append([
                    schedule.get("id", ""),
                    truncate(sched_info.get("name", "-"), 25),
                    truncate(schedule.get("scheduled_run_time", "-"), 20),
                    truncate(site_names, 30),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def complete_schedule(self, text, line, begidx, endidx):
        """Tab completion for schedule IDs."""
        if not self._schedule_cache:
            try:
                self._schedule_cache = self.client.get_schedule_items()
            except:
                pass
        
        schedule_ids = [s.get("id", "") for s in self._schedule_cache]
        return [sid for sid in schedule_ids if sid.startswith(text)]
    
    def do_schedule(self, arg):
        """
        Get details of a specific schedule item.
        
        Usage: schedule <schedule_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: schedule <schedule_id>")
            return
        
        try:
            schedule = self.client.get_schedule_item(arg.strip())
            if schedule:
                self._print_result(schedule)
            else:
                print(f"Schedule {arg} not found")
        except Exception as e:
            self._handle_error(e)
    
    complete_schedule = complete_schedule
    
    def do_delete_schedule(self, arg):
        """
        Delete a schedule item.
        
        Usage: delete_schedule <schedule_id>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: delete_schedule <schedule_id>")
            return
        
        try:
            result = self.client.delete_schedule_item(arg.strip())
            print(colorize(f"Schedule {result} deleted", Colors.GREEN))
        except Exception as e:
            self._handle_error(e)
    
    complete_delete_schedule = complete_schedule
    
    def do_create_schedule(self, arg):
        """
        Create a schedule item to start a scan.
        
        Usage: create_schedule <site_id_or_name> [options]
        
        You can use either the site ID or site name.
        
        Options:
            --name NAME         Name for the schedule
            --time TIME         Initial run time (ISO 8601, e.g., 2024-01-15T10:00:00Z)
                               If not specified, scan starts immediately
            --rrule RRULE       Recurrence rule for recurring scans
            --config CONFIG_ID  Scan configuration ID to use
        
        Examples:
            create_schedule abc123
            create_schedule "My Site" --name "Weekly Scan"
            create_schedule abc123 --name "Daily Scan" --rrule "FREQ=DAILY;INTERVAL=1"
            create_schedule "Production App" --time 2024-12-15T10:00:00Z --name "Scheduled Scan"
        
        Common RRULE patterns:
            FREQ=DAILY;INTERVAL=1           - Every day
            FREQ=WEEKLY;INTERVAL=1;BYDAY=MO - Every Monday
            FREQ=WEEKLY;INTERVAL=2          - Every 2 weeks
            FREQ=MONTHLY;INTERVAL=1;BYMONTHDAY=1 - First of each month
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: create_schedule <site_id_or_name> [--name NAME] [--time TIME] [--rrule RRULE]")
            return
        
        # Parse arguments
        args = shlex.split(arg)
        site_ref = args[0]
        site_id = self._resolve_site_id(site_ref)
        
        name = None
        initial_run_time = None
        rrule = None
        scan_config_ids = None
        
        i = 1
        while i < len(args):
            if args[i] == "--name" and i + 1 < len(args):
                name = args[i + 1]
                i += 2
            elif args[i] == "--time" and i + 1 < len(args):
                initial_run_time = args[i + 1]
                i += 2
            elif args[i] == "--rrule" and i + 1 < len(args):
                rrule = args[i + 1]
                i += 2
            elif args[i] == "--config" and i + 1 < len(args):
                scan_config_ids = [args[i + 1]]
                i += 2
            else:
                i += 1
        
        try:
            result = self.client.create_schedule_item(
                site_ids=[site_id],
                name=name,
                initial_run_time=initial_run_time,
                rrule=rrule,
                scan_configuration_ids=scan_config_ids
            )
            print(colorize("Schedule created:", Colors.GREEN))
            schedule_item = result.get("schedule_item", {})
            print(f"  ID: {schedule_item.get('id', 'N/A')}")
            print(f"  Scheduled run time: {schedule_item.get('scheduled_run_time', 'Immediately')}")
            sites = schedule_item.get("sites", [])
            if sites:
                print(f"  Site: {sites[0].get('name', 'N/A')} ({sites[0].get('id', 'N/A')})")
            if schedule_item.get("schedule"):
                sched = schedule_item["schedule"]
                if sched.get("name"):
                    print(f"  Name: {sched.get('name')}")
                if sched.get("rrule"):
                    print(f"  Recurrence: {sched.get('rrule')}")
            self._last_result = result
        except Exception as e:
            self._handle_error(e)
    
    complete_create_schedule = complete_site
    
    # =========================================================================
    # EXTENSION & BCHECK COMMANDS
    # =========================================================================
    
    def do_extensions(self, arg):
        """
        List extensions.
        
        Usage: extensions [--json]
        """
        if not self._check_connected():
            return
        
        try:
            extensions = self.client.get_extensions()
            
            if "--json" in arg:
                self._print_result(extensions, as_json=True)
                return
            
            if not extensions:
                print("No extensions found")
                return
            
            headers = ["ID", "Name", "Description", "Uploaded"]
            rows = []
            for ext in extensions:
                rows.append([
                    ext.get("id", ""),
                    truncate(ext.get("name", ""), 25),
                    truncate(ext.get("description", ""), 35),
                    truncate(ext.get("uploaded_date", ""), 20),
                ])
            
            print(format_table(headers, rows))
            
        except Exception as e:
            self._handle_error(e)
    
    def do_bchecks(self, arg):
        """
        List BChecks.
        
        Usage: bchecks [--limit N] [--json]
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        limit = 50
        as_json = "--json" in args
        
        for i, a in enumerate(args):
            if a == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
        
        try:
            result = self.client.get_bchecks(limit=limit)
            bchecks = result.get("bchecks", [])
            total = result.get("total_count", 0)
            
            if as_json:
                self._print_result(result, as_json=True)
                return
            
            if not bchecks:
                print("No BChecks found")
                return
            
            headers = ["ID", "Name", "Author", "Tags"]
            rows = []
            for bc in bchecks:
                rows.append([
                    bc.get("id", ""),
                    truncate(bc.get("name", ""), 30),
                    truncate(bc.get("author", ""), 20),
                    truncate(", ".join(bc.get("tags", [])), 25),
                ])
            
            print(format_table(headers, rows))
            print(f"\nShowing {len(bchecks)} of {total} BChecks")
            
        except Exception as e:
            self._handle_error(e)
    
    # =========================================================================
    # REPORT COMMANDS
    # =========================================================================
    
    def do_report(self, arg):
        """
        Generate a scan report.
        
        Usage: report <scan_id> [--type TYPE] [--output FILE]
        
        Options:
            --type TYPE    Report type: detailed or summary (default: detailed)
            --output FILE  Save report to file
        """
        if not self._check_connected():
            return
        
        args = shlex.split(arg)
        if not args:
            print("Usage: report <scan_id> [--type TYPE] [--output FILE]")
            return
        
        scan_id = args[0]
        report_type = ScanReportType.DETAILED
        output_file = None
        
        i = 1
        while i < len(args):
            if args[i] == "--type" and i + 1 < len(args):
                try:
                    report_type = ScanReportType(args[i + 1].lower())
                except ValueError:
                    print(f"Invalid report type: {args[i + 1]}")
                    return
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                output_file = args[i + 1]
                i += 2
            else:
                i += 1
        
        try:
            result = self.client.get_scan_report(scan_id=scan_id, report_type=report_type)
            
            if output_file:
                if result.get("report_html"):
                    with open(output_file, "w") as f:
                        f.write(result["report_html"])
                    print(colorize(f"Report saved to {output_file}", Colors.GREEN))
                else:
                    print(colorize("No HTML report available", Colors.YELLOW))
            else:
                if result.get("warning"):
                    print(colorize(f"Warning: {result['warning']}", Colors.YELLOW))
                print(f"Report generated. Use --output FILE to save.")
                print(f"HTML available: {'Yes' if result.get('report_html') else 'No'}")
                print(f"PDF available: {'Yes' if result.get('report_pdf') else 'No'}")
            
        except Exception as e:
            self._handle_error(e)
    
    complete_report = complete_scan
    
    # =========================================================================
    # RAW QUERY COMMANDS
    # =========================================================================
    
    def do_query(self, arg):
        """
        Execute a raw GraphQL query.
        
        Usage: query <graphql_query>
        
        Example:
            query { agents { id name state } }
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: query <graphql_query>")
            return
        
        try:
            result = self.client.execute_query(arg)
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    def do_mutation(self, arg):
        """
        Execute a raw GraphQL mutation.
        
        Usage: mutation <graphql_mutation>
        """
        if not self._check_connected():
            return
        
        if not arg:
            print("Usage: mutation <graphql_mutation>")
            return
        
        try:
            result = self.client.execute_mutation(arg)
            self._print_result(result)
        except Exception as e:
            self._handle_error(e)
    
    # =========================================================================
    # UTILITY COMMANDS
    # =========================================================================
    
    def _debug_output(self, message: str):
        """Output debug messages with color."""
        print(colorize(message, Colors.YELLOW))
    
    def do_debug(self, arg):
        """
        Toggle debug mode to show HTTP requests and responses.
        
        Usage: debug [on|off]
        
        Examples:
            debug        - Show current debug status
            debug on     - Enable debug mode
            debug off    - Disable debug mode
        """
        arg = arg.strip().lower()
        
        if arg == "on":
            self._debug_mode = True
            if self.client:
                self.client.debug = True
                self.client.set_debug_callback(self._debug_output)
            print(colorize("Debug mode enabled", Colors.GREEN))
        elif arg == "off":
            self._debug_mode = False
            if self.client:
                self.client.debug = False
                self.client.set_debug_callback(None)
            print(colorize("Debug mode disabled", Colors.YELLOW))
        else:
            status = "enabled" if self._debug_mode else "disabled"
            print(f"Debug mode is {status}")
            print("Usage: debug [on|off]")
    
    def do_last(self, arg):
        """
        Show the last result as JSON.
        
        Usage: last
        """
        if self._last_result is not None:
            print(format_json(self._last_result))
        else:
            print("No previous result")
    
    def do_clear(self, arg):
        """Clear the screen."""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def do_exit(self, arg):
        """Exit the REPL."""
        print(colorize("Goodbye!", Colors.CYAN))
        return True
    
    def do_quit(self, arg):
        """Exit the REPL."""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        """Handle Ctrl+D."""
        print()
        return self.do_exit(arg)
    
    def default(self, line):
        """Handle unknown commands."""
        print(colorize(f"Unknown command: {line}", Colors.RED))
        print("Type 'help' for available commands")
    
    def emptyline(self):
        """Do nothing on empty line."""
        pass
    
    def do_help(self, arg):
        """
        Show help for commands.
        
        Usage: help [command]
        """
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            print(colorize("\n=== Available Commands ===\n", Colors.BOLD))
            
            categories = {
                "Connection": ["connect", "disconnect", "status"],
                "Sites": ["sites", "site", "create_site", "delete_site", "folders", "create_folder"],
                "Scans": ["scans", "scan", "create_scan", "cancel_scan", "pause_scan", "resume_scan", "delete_scan"],
                "Issues": ["issues", "issue", "site_issues"],
                "Agents": ["agents", "unauthorized_agents", "authorize_agent", "enable_agent", "disable_agent"],
                "Configuration": ["configs", "featured_configs"],
                "Tags": ["tags", "create_tag"],
                "Schedules": ["schedules", "schedule", "create_schedule", "delete_schedule"],
                "Extensions": ["extensions", "bchecks"],
                "Reports": ["report"],
                "Raw GraphQL": ["query", "mutation"],
                "Utility": ["debug", "last", "clear", "help", "exit", "quit"],
            }
            
            for category, commands in categories.items():
                print(colorize(f"{category}:", Colors.CYAN))
                print(f"  {', '.join(commands)}")
                print()
            
            print("Type 'help <command>' for detailed help on a specific command.")


def main():
    parser = argparse.ArgumentParser(description="Burp Suite DAST SDK Interactive REPL")
    parser.add_argument("--url", help="Burp Suite API URL")
    parser.add_argument("--api-key", help="API key (or set BURPSUITE_API_KEY env var)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()
    
    client = None
    if args.url:
        try:
            client = BurpSuiteClient(
                url=args.url,
                api_key=args.api_key,
                verify_ssl=not args.no_verify_ssl
            )
            print(colorize(f"Connected to {args.url}", Colors.GREEN))
        except Exception as e:
            print(colorize(f"Warning: Could not connect: {e}", Colors.YELLOW))
            print("Use 'connect' command to connect later.")
    
    repl = BurpREPL(client)
    
    try:
        repl.cmdloop()
    except KeyboardInterrupt:
        print(colorize("\nInterrupted. Goodbye!", Colors.CYAN))


if __name__ == "__main__":
    main()

