"""
Burp Suite DAST GraphQL API - Client

This module contains the main BurpSuiteClient class for interacting with the API.
"""

import json
import os
from typing import Optional, List, Dict, Any, Union
from dataclasses import asdict
import requests

from .enums import (
    Confidence, Novelty, PropagationMode, ScanReportType, ScansSortColumn,
    ScanStatus, Severity, SortBy, SortOrder, AuditItemSortColumn, BCheckSortColumn,
    ScopeProtocolOptions, TagColor, ForwardPropagationMode, ScanEventLogType
)
from .types import (
    Agent, AgentPool, UnauthorizedAgent, Site, Folder, CidsSite, SiteTree,
    Scan, ScanConfiguration, ScanReport, BurpReport, ScheduleItem, Issue,
    Extension, BCheck, BChecksContainer, Tag, PreScanCheck, Settings,
    Capabilities, SlackChannels, SlackAppConfiguration, GitLabSettings,
    GitLabProjects, TrelloBoard, TrelloSettings, JiraCredentials, JiraProjects,
    JiraProjectInfo, JiraManualRule, JiraAutomaticRule, JiraTicketSearchResults,
    JiraTicketFieldListResult, SplunkSettings, ForwardPropagationSettings,
    HierarchicalScanSettings, ScimSettings, MachineToken, InstallerLinks,
    UserAccount, UserActivityLogSettings, FeaturedScanConfiguration,
    ScanEventLog, LiveCIDScan, EphemeralAgent, ScheduleItemsContainer,
    ScanSeverityCounts, VulnerabilitySummary, Questionnaire, ScanTarget
)
from .exceptions import (
    BurpSuiteError, AuthenticationError, GraphQLError, NetworkError,
    ValidationError, ResourceNotFoundError
)


class BurpSuiteClient:
    """
    Client for interacting with the Burp Suite DAST GraphQL API.
    
    Usage:
        >>> client = BurpSuiteClient(
        ...     url="https://burpsuite.example.com/graphql/v1",
        ...     api_key="your-api-key"
        ... )
        >>> sites = client.get_site_tree()
        >>> scans = client.get_scans(limit=10)
    """
    
    def __init__(
        self,
        url: str,
        api_key: Optional[str] = None,
        api_key_env_var: str = "BURPSUITE_API_KEY",
        timeout: int = 30,
        verify_ssl: bool = True,
        headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the Burp Suite client.
        
        Args:
            url: The GraphQL API endpoint URL.
            api_key: The API key for authentication. If not provided, will try
                     to read from environment variable.
            api_key_env_var: Environment variable name for the API key.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            headers: Additional headers to include in requests.
        """
        self.url = url.rstrip('/')
        self.api_key = api_key or os.environ.get(api_key_env_var)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            self._headers.update(headers)
        
        if self.api_key:
            self._headers["Authorization"] = self.api_key
    
    def _execute(
        self, 
        query: str, 
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query/mutation.
        
        Args:
            query: The GraphQL query or mutation string.
            variables: Variables for the query.
            operation_name: The operation name (if query contains multiple).
            
        Returns:
            The response data.
            
        Raises:
            GraphQLError: If the GraphQL API returns errors.
            NetworkError: If a network error occurs.
            AuthenticationError: If authentication fails.
        """
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self._headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
        except requests.exceptions.Timeout:
            raise NetworkError("Request timed out", status_code=None)
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection error: {str(e)}", status_code=None)
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {str(e)}", status_code=None)
        
        if response.status_code == 401:
            raise AuthenticationError("Authentication failed. Check your API key.")
        if response.status_code == 403:
            raise AuthenticationError("Access forbidden. Check your permissions.")
        
        if response.status_code >= 400:
            raise NetworkError(
                f"HTTP {response.status_code} error",
                status_code=response.status_code,
                response_body=response.text
            )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            raise NetworkError(
                "Invalid JSON response",
                status_code=response.status_code,
                response_body=response.text
            )
        
        if "errors" in data and data["errors"]:
            raise GraphQLError(
                "GraphQL query failed",
                errors=data["errors"],
                query=query
            )
        
        return data.get("data", {})
    
    # =========================================================================
    # AGENT OPERATIONS
    # =========================================================================
    
    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get an agent by ID (filters from agents list)."""
        agents = self.get_agents()
        for agent in agents:
            if agent.get("id") == agent_id:
                return agent
        return None
    
    def get_agents(self) -> List[Dict[str, Any]]:
        """Get all authorized agents."""
        query = """
        query GetAgents {
            agents {
                id machine_id current_scan_count ip name state
                enabled max_concurrent_scans cpu_cores system_ram_gb
                warning last_used_token_name
                error { code error }
                agent_pool { id name description }
            }
        }
        """
        result = self._execute(query)
        return result.get("agents", [])
    
    def get_unauthorized_agents(self) -> List[Dict[str, Any]]:
        """Get all unauthorized agents."""
        query = """
        query GetUnauthorizedAgents {
            unauthorized_agents {
                machine_id ip
            }
        }
        """
        result = self._execute(query)
        return result.get("unauthorized_agents", [])
    
    def authorize_agent(
        self, 
        machine_id: str, 
        agent_pool_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authorize an agent."""
        mutation = """
        mutation AuthorizeAgent($input: AuthorizeAgentInput!) {
            authorize_agent(input: $input) {
                agent { id name machine_id ip state enabled }
            }
        }
        """
        variables = {"input": {"machine_id": machine_id}}
        if agent_pool_id:
            variables["input"]["agent_pool_id"] = agent_pool_id
        result = self._execute(mutation, variables)
        return result.get("authorize_agent", {})
    
    def deauthorize_agent(self, agent_id: str) -> Optional[str]:
        """Deauthorize an agent."""
        mutation = """
        mutation DeauthorizeAgent($input: DeauthorizeAgentInput!) {
            deauthorize_agent(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": agent_id}})
        return result.get("deauthorize_agent", {}).get("id")
    
    def rename_agent(self, agent_id: str, name: str) -> Dict[str, Any]:
        """Rename an agent."""
        mutation = """
        mutation RenameAgent($input: RenameAgentInput!) {
            rename_agent(input: $input) {
                agent { id name }
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": agent_id, "name": name}})
        return result.get("rename_agent", {})
    
    def enable_agent(self, agent_id: str, enabled: bool = True) -> Dict[str, Any]:
        """Enable or disable an agent."""
        mutation = """
        mutation EnableAgent($input: EnableAgentInput!) {
            enable_agent(input: $input) {
                agent { id name enabled }
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": agent_id, "enabled": enabled}})
        return result.get("enable_agent", {})
    
    def update_agent_max_concurrent_scans(
        self, 
        agent_id: str, 
        max_concurrent_scans: int
    ) -> Dict[str, Any]:
        """Update the maximum concurrent scans for an agent."""
        mutation = """
        mutation UpdateAgentMaxConcurrentScans($input: UpdateAgentMaxConcurrentScansInput!) {
            update_agent_max_concurrent_scans(input: $input) {
                agent { id name max_concurrent_scans }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"id": agent_id, "max_concurrent_scans": max_concurrent_scans}
        })
        return result.get("update_agent_max_concurrent_scans", {})
    
    # =========================================================================
    # AGENT POOL OPERATIONS
    # =========================================================================
    
    def get_agent_pools(self) -> List[Dict[str, Any]]:
        """Get all agent pools (extracted from agents)."""
        agents = self.get_agents()
        pools_dict = {}
        for agent in agents:
            pool = agent.get("agent_pool")
            if pool and pool.get("id"):
                pool_id = pool["id"]
                if pool_id not in pools_dict:
                    pools_dict[pool_id] = pool
        return list(pools_dict.values())
    
    def create_agent_pool(
        self, 
        name: str, 
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create an agent pool."""
        mutation = """
        mutation CreateAgentPool($input: CreateAgentPoolInput!) {
            create_agent_pool(input: $input) {
                agent_pool { id name description }
            }
        }
        """
        variables = {"input": {"name": name}}
        if description:
            variables["input"]["description"] = description
        result = self._execute(mutation, variables)
        return result.get("create_agent_pool", {})
    
    def delete_agent_pool(self, pool_id: str) -> Optional[str]:
        """Delete an agent pool."""
        mutation = """
        mutation DeleteAgentPool($input: DeleteAgentPoolInput!) {
            delete_agent_pool(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": pool_id}})
        return result.get("delete_agent_pool", {}).get("id")
    
    def move_agent_to_pool(
        self, 
        agent_id: str, 
        pool_id: str
    ) -> Dict[str, Any]:
        """Move an agent to a different pool."""
        mutation = """
        mutation MoveAgentPool($input: MoveAgentPoolInput!) {
            move_agent_pool(input: $input) {
                agent { id name agent_pool { id name } }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"agent_id": agent_id, "agent_pool_id": pool_id}
        })
        return result.get("move_agent_pool", {})
    
    # =========================================================================
    # SITE OPERATIONS
    # =========================================================================
    
    def get_site_tree(self) -> Dict[str, Any]:
        """Get the entire site tree."""
        query = """
        query GetSiteTree {
            site_tree {
                folders {
                    id name description parent_id
                    scan_configurations { id }
                    email_recipients { id email }
                }
                sites {
                    id name parent_id ephemeral
                    scope_v2 {
                        start_urls in_scope_url_prefixes
                        out_of_scope_url_prefixes protocol_options
                    }
                    scan_configurations { id }
                    email_recipients { id email }
                    agent_pool { id name }
                    tags { id name color }
                }
                cids_sites {
                    id name parent_id correlation_id
                    tags { id name color }
                }
            }
        }
        """
        result = self._execute(query)
        return result.get("site_tree", {})
    
    def get_site(self, site_id: str) -> Optional[Dict[str, Any]]:
        """Get a site by ID."""
        query = """
        query GetSite($id: ID!) {
            site(id: $id) {
                id name parent_id ephemeral has_missing_api_credentials
                scope_v2 {
                    start_urls in_scope_url_prefixes
                    out_of_scope_url_prefixes protocol_options
                }
                scan_configurations { id }
                extensions { id }
                bchecks { id }
                application_logins {
                    login_credentials { id label username }
                    recorded_logins { id label }
                }
                email_recipients { id email }
                agent_pool { id name }
                slack_channels { id name }
                tags { id name color description }
            }
        }
        """
        result = self._execute(query, {"id": site_id})
        return result.get("site")
    
    def create_site(
        self,
        name: str,
        parent_id: str = "0",
        start_urls: Optional[List[str]] = None,
        in_scope_url_prefixes: Optional[List[str]] = None,
        out_of_scope_url_prefixes: Optional[List[str]] = None,
        protocol_options: ScopeProtocolOptions = ScopeProtocolOptions.USE_SPECIFIED_PROTOCOLS,
        scan_configuration_ids: Optional[List[str]] = None,
        agent_pool_id: Optional[str] = None,
        confirm_permission_to_scan: bool = True
    ) -> Dict[str, Any]:
        """Create a new site."""
        mutation = """
        mutation CreateSite($input: CreateSiteInput!) {
            create_site(input: $input) {
                site {
                    id name parent_id
                    scope_v2 { start_urls in_scope_url_prefixes out_of_scope_url_prefixes }
                }
            }
        }
        """
        variables = {
            "input": {
                "name": name,
                "parent_id": parent_id,
                "confirm_permission_to_scan": confirm_permission_to_scan
            }
        }
        
        if start_urls:
            variables["input"]["scope_v2"] = {
                "start_urls": start_urls,
                "in_scope_url_prefixes": in_scope_url_prefixes or [],
                "out_of_scope_url_prefixes": out_of_scope_url_prefixes or [],
                "protocol_options": protocol_options.value
            }
        
        if scan_configuration_ids:
            variables["input"]["scan_configuration_ids"] = scan_configuration_ids
        if agent_pool_id:
            variables["input"]["agent_pool_id"] = agent_pool_id
        
        result = self._execute(mutation, variables)
        return result.get("create_site", {})
    
    def delete_site(self, site_id: str) -> Optional[str]:
        """Delete a site."""
        mutation = """
        mutation DeleteSite($input: DeleteSiteInput!) {
            delete_site(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": site_id}})
        return result.get("delete_site", {}).get("id")
    
    def rename_site(self, site_id: str, name: str) -> Dict[str, Any]:
        """Rename a site."""
        mutation = """
        mutation RenameSite($input: RenameSiteInput!) {
            rename_site(input: $input) {
                site { id name }
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": site_id, "name": name}})
        return result.get("rename_site", {})
    
    def move_site(self, site_id: str, parent_id: str) -> Dict[str, Any]:
        """Move a site to a different folder."""
        mutation = """
        mutation MoveSite($input: MoveSiteInput!) {
            move_site(input: $input) {
                site { id name parent_id }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"site_id": site_id, "parent_id": parent_id}
        })
        return result.get("move_site", {})
    
    def update_site_scope(
        self,
        site_id: str,
        start_urls: List[str],
        in_scope_url_prefixes: Optional[List[str]] = None,
        out_of_scope_url_prefixes: Optional[List[str]] = None,
        protocol_options: ScopeProtocolOptions = ScopeProtocolOptions.USE_SPECIFIED_PROTOCOLS,
        confirm_permission_to_scan: bool = True
    ) -> Dict[str, Any]:
        """Update a site's scope."""
        mutation = """
        mutation UpdateSiteScopeV2($input: UpdateSiteScopeV2Input!) {
            update_site_scope_v2(input: $input) {
                site {
                    id name
                    scope_v2 { start_urls in_scope_url_prefixes out_of_scope_url_prefixes }
                }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {
                "site_id": site_id,
                "scope_v2": {
                    "start_urls": start_urls,
                    "in_scope_url_prefixes": in_scope_url_prefixes or [],
                    "out_of_scope_url_prefixes": out_of_scope_url_prefixes or [],
                    "protocol_options": protocol_options.value
                },
                "confirm_permission_to_scan": confirm_permission_to_scan
            }
        })
        return result.get("update_site_scope_v2", {})
    
    def update_site_scan_configurations(
        self, 
        site_id: str, 
        scan_configuration_ids: List[str]
    ) -> Dict[str, Any]:
        """Update scan configurations for a site."""
        mutation = """
        mutation UpdateSiteScanConfigurations($input: UpdateSiteScanConfigurationsInput!) {
            update_site_scan_configurations(input: $input) {
                site { id scan_configurations { id name } }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"id": site_id, "scan_configuration_ids": scan_configuration_ids}
        })
        return result.get("update_site_scan_configurations", {})
    
    # =========================================================================
    # FOLDER OPERATIONS
    # =========================================================================
    
    def get_folder(self, folder_id: str) -> Optional[Dict[str, Any]]:
        """Get a folder by ID."""
        query = """
        query GetFolder($id: ID!) {
            folder(id: $id) {
                id name description parent_id
                scan_configurations { id }
                extensions { id }
                bchecks { id }
                email_recipients { id email }
                slack_channels { id name }
                tags { id name color }
            }
        }
        """
        result = self._execute(query, {"id": folder_id})
        return result.get("folder")
    
    def create_folder(
        self,
        name: str,
        parent_id: str = "0",
        description: Optional[str] = None,
        scan_configuration_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a new folder."""
        mutation = """
        mutation CreateFolder($input: CreateFolderInput!) {
            create_folder(input: $input) {
                folder { id name parent_id description }
            }
        }
        """
        variables = {"input": {"name": name, "parent_id": parent_id}}
        if description:
            variables["input"]["description"] = description
        if scan_configuration_ids:
            variables["input"]["scan_configuration_ids"] = scan_configuration_ids
        
        result = self._execute(mutation, variables)
        return result.get("create_folder", {})
    
    def delete_folder(self, folder_id: str) -> Optional[str]:
        """Delete a folder."""
        mutation = """
        mutation DeleteFolder($input: DeleteFolderInput!) {
            delete_folder(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": folder_id}})
        return result.get("delete_folder", {}).get("id")
    
    def rename_folder(self, folder_id: str, name: str) -> Dict[str, Any]:
        """Rename a folder."""
        mutation = """
        mutation RenameFolder($input: RenameFolderInput!) {
            rename_folder(input: $input) {
                folder { id name }
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": folder_id, "name": name}})
        return result.get("rename_folder", {})
    
    def move_folder(self, folder_id: str, parent_id: str) -> Dict[str, Any]:
        """Move a folder to a different location."""
        mutation = """
        mutation MoveFolder($input: MoveFolderInput!) {
            move_folder(input: $input) {
                folder { id name parent_id }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"folder_id": folder_id, "parent_id": parent_id}
        })
        return result.get("move_folder", {})
    
    # =========================================================================
    # SCAN OPERATIONS
    # =========================================================================
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a scan by ID."""
        query = """
        query GetScan($id: ID!) {
            scan(id: $id) {
                id status generated_by
                scan_target { id name type ephemeral }
                scheduled_start_time start_time end_time paused_time
                duration_in_seconds estimated_duration_in_seconds
                scanner_version scanner_build_number
                scan_failure_code scan_failure_message scan_failure_cause scan_failure_remedy
                agent { id name }
                scan_metrics {
                    crawl_request_count unique_location_count audit_request_count
                    audit_queue_items_waiting crawl_and_audit_progress_percentage
                    scan_phase current_url
                }
                scan_delta {
                    new_issue_count repeated_issue_count regressed_issue_count resolved_issue_count
                }
                issue_counts {
                    total
                    high { total firm tentative certain }
                    medium { total firm tentative certain }
                    low { total firm tentative certain }
                    info { total firm tentative certain }
                }
                scan_configurations { id name }
                schedule_item { id }
                scope_v2 { start_urls in_scope_url_prefixes out_of_scope_url_prefixes }
            }
        }
        """
        result = self._execute(query, {"id": scan_id})
        return result.get("scan")
    
    def get_scans(
        self,
        offset: int = 0,
        limit: int = 50,
        sort_column: ScansSortColumn = ScansSortColumn.START,
        sort_order: SortOrder = SortOrder.DESC,
        scan_status: Optional[List[ScanStatus]] = None,
        site_id: Optional[str] = None,
        schedule_item_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get a list of scans."""
        query = """
        query GetScans(
            $offset: Int, $limit: Int, $sort_column: ScansSortColumn, 
            $sort_order: SortOrder, $scan_status: [ScanStatus], 
            $scan_target_id: ID, $schedule_item_id: ID
        ) {
            scans(
                offset: $offset, limit: $limit, sort_column: $sort_column,
                sort_order: $sort_order, scan_status: $scan_status,
                scan_target_id: $scan_target_id, schedule_item_id: $schedule_item_id
            ) {
                id status generated_by
                scheduled_start_time start_time end_time
                duration_in_seconds
                issue_counts { total high { total } medium { total } low { total } info { total } }
            }
        }
        """
        variables = {
            "offset": offset,
            "limit": limit,
            "sort_column": sort_column.value,
            "sort_order": sort_order.value
        }
        if scan_status:
            variables["scan_status"] = [s.value for s in scan_status]
        if site_id:
            variables["scan_target_id"] = site_id
        if schedule_item_id:
            variables["schedule_item_id"] = schedule_item_id
        
        result = self._execute(query, variables)
        return result.get("scans", [])
    
    def delete_scan(self, scan_id: str) -> str:
        """Delete a scan."""
        mutation = """
        mutation DeleteScan($input: DeleteScanInput!) {
            delete_scan(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": scan_id}})
        return result.get("delete_scan", {}).get("id")
    
    def cancel_scan(self, scan_id: str) -> Optional[str]:
        """Cancel a running or scheduled scan."""
        mutation = """
        mutation CancelScan($input: CancelScanInput!) {
            cancel_scan(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": scan_id}})
        return result.get("cancel_scan", {}).get("id")
    
    def pause_scan(self, scan_id: str) -> Optional[str]:
        """Pause a running scan."""
        mutation = """
        mutation PauseScan($input: PauseScanInput!) {
            pause_scan(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": scan_id}})
        return result.get("pause_scan", {}).get("id")
    
    def resume_scan(self, scan_id: str) -> Optional[str]:
        """Resume a paused scan."""
        mutation = """
        mutation ResumeScan($input: ResumeScanInput!) {
            resume_scan(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": scan_id}})
        return result.get("resume_scan", {}).get("id")
    
    def get_scan_report(
        self,
        scan_id: str,
        report_type: ScanReportType = ScanReportType.DETAILED,
        include_false_positives: bool = False,
        severities: Optional[List[Severity]] = None,
        timezone_offset: int = 0
    ) -> Dict[str, Any]:
        """Get a scan report."""
        query = """
        query GetScanReport(
            $scan_id: ID!, $report_type: ScanReportType,
            $include_false_positives: Boolean, $severities: [Severity],
            $timezone_offset: Int
        ) {
            scan_report(
                scan_id: $scan_id, report_type: $report_type,
                include_false_positives: $include_false_positives,
                severities: $severities, timezone_offset: $timezone_offset
            ) {
                report_html report_pdf warning
            }
        }
        """
        variables = {
            "scan_id": scan_id,
            "report_type": report_type.value,
            "include_false_positives": include_false_positives,
            "timezone_offset": timezone_offset
        }
        if severities:
            variables["severities"] = [s.value for s in severities]
        
        result = self._execute(query, variables)
        return result.get("scan_report", {})
    
    def get_burp_xml_report(
        self,
        scan_id: str,
        include_false_positives: bool = False,
        severities: Optional[List[Severity]] = None,
        base64_encode: bool = True,
        timezone_offset: int = 0
    ) -> Optional[str]:
        """Get a Burp XML report."""
        query = """
        query GetBurpXmlReport(
            $scan_id: ID!, $include_false_positives: Boolean,
            $severities: [Severity], $base64_encode: Boolean,
            $timezone_offset: Int
        ) {
            burp_xml_report(
                scan_id: $scan_id, include_false_positives: $include_false_positives,
                severities: $severities, base64_encode_requests_and_responses: $base64_encode,
                timezone_offset: $timezone_offset
            ) {
                report_xml
            }
        }
        """
        variables = {
            "scan_id": scan_id,
            "include_false_positives": include_false_positives,
            "base64_encode": base64_encode,
            "timezone_offset": timezone_offset
        }
        if severities:
            variables["severities"] = [s.value for s in severities]
        
        result = self._execute(query, variables)
        return result.get("burp_xml_report", {}).get("report_xml")
    
    # =========================================================================
    # SCHEDULE OPERATIONS
    # =========================================================================
    
    def get_schedule_item(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Get a schedule item by ID."""
        query = """
        query GetScheduleItem($id: ID!) {
            schedule_item(id: $id) {
                id has_run_more_than_once scheduled_run_time verbose_debug
                sites { id name }
                folders { id name }
                schedule { initial_run_time rrule name description }
            }
        }
        """
        result = self._execute(query, {"id": schedule_id})
        return result.get("schedule_item")
    
    def get_schedule_items(
        self,
        sort_by: SortBy = SortBy.START,
        sort_order: SortOrder = SortOrder.ASC
    ) -> List[Dict[str, Any]]:
        """Get all schedule items."""
        query = """
        query GetScheduleItems($sort_by: SortBy, $sort_order: SortOrder) {
            schedule_items(sort_by: $sort_by, sort_order: $sort_order) {
                id has_run_more_than_once scheduled_run_time
                sites { id name }
                folders { id name }
                schedule { initial_run_time rrule name description }
            }
        }
        """
        result = self._execute(query, {
            "sort_by": sort_by.value,
            "sort_order": sort_order.value
        })
        return result.get("schedule_items", [])
    
    def create_schedule_item(
        self,
        site_ids: Optional[List[str]] = None,
        folder_ids: Optional[List[str]] = None,
        initial_run_time: Optional[str] = None,
        rrule: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        scan_configuration_ids: Optional[List[str]] = None,
        verbose_debug: bool = False
    ) -> Dict[str, Any]:
        """Create a schedule item."""
        mutation = """
        mutation CreateScheduleItem($input: CreateScheduleItemInput!) {
            create_schedule_item(input: $input) {
                schedule_item {
                    id scheduled_run_time
                    sites { id name }
                    schedule { initial_run_time rrule name }
                }
            }
        }
        """
        variables = {"input": {"verbose_debug": verbose_debug}}
        
        if site_ids:
            variables["input"]["site_ids"] = site_ids
        if folder_ids:
            variables["input"]["folder_ids"] = folder_ids
        if scan_configuration_ids:
            variables["input"]["scan_configuration_ids"] = scan_configuration_ids
        
        schedule = {}
        if initial_run_time:
            schedule["initial_run_time"] = initial_run_time
        if rrule:
            schedule["rrule"] = rrule
        if name:
            schedule["name"] = name
        if description:
            schedule["description"] = description
        if schedule:
            variables["input"]["schedule"] = schedule
        
        result = self._execute(mutation, variables)
        return result.get("create_schedule_item", {})
    
    def delete_schedule_item(self, schedule_id: str) -> str:
        """Delete a schedule item."""
        mutation = """
        mutation DeleteScheduleItem($input: DeleteScheduleItemInput!) {
            delete_schedule_item(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": schedule_id}})
        return result.get("delete_schedule_item", {}).get("id")
    
    # =========================================================================
    # ISSUE OPERATIONS
    # =========================================================================
    
    def get_issue(self, scan_id: str, serial_number: str) -> Optional[Dict[str, Any]]:
        """Get an issue by scan ID and serial number."""
        query = """
        query GetIssue($scan_id: ID!, $serial_number: ID!) {
            issue(scan_id: $scan_id, serial_number: $serial_number) {
                serial_number confidence severity original_severity
                accepted_risk path origin novelty fingerprint
                description_html remediation_html
                issue_type {
                    type_index name description_html remediation_html
                    vulnerability_classifications_html references_html
                }
                evidence {
                    ... on Request { request_index request_count }
                    ... on Response { response_index response_count }
                    ... on HttpInteraction { title description_html }
                    ... on DescriptiveEvidence { title description_html }
                }
                tickets {
                    link_url link_id date_added
                    jira_ticket { id external_key ticket_type summary status }
                    gitlab_issue { id project_id }
                    trello_card { id }
                }
                generated_by_extension { name }
                generated_by_bcheck { name }
                change_history { note timestamp username }
            }
        }
        """
        result = self._execute(query, {
            "scan_id": scan_id,
            "serial_number": serial_number
        })
        return result.get("issue")
    
    def get_scan_issues(
        self,
        scan_id: str,
        start: int = 0,
        count: int = 100,
        severities: Optional[List[Severity]] = None,
        confidences: Optional[List[Confidence]] = None,
        novelties: Optional[List[Novelty]] = None,
        type_index: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get issues for a scan."""
        query = """
        query GetScanIssues(
            $scan_id: ID!, $start: Int!, $count: Int!,
            $severities: [Severity], $confidences: [Confidence],
            $novelties: [Novelty], $type_index: ID
        ) {
            scan(id: $scan_id) {
                issues(
                    start: $start, count: $count,
                    severities: $severities, confidences: $confidences,
                    novelties: $novelties, type_index: $type_index
                ) {
                    serial_number confidence severity origin path novelty
                    accepted_risk fingerprint
                    issue_type { type_index name }
                    tickets { link_url }
                }
            }
        }
        """
        variables = {
            "scan_id": scan_id,
            "start": start,
            "count": count
        }
        if severities:
            variables["severities"] = [s.value for s in severities]
        if confidences:
            variables["confidences"] = [c.value for c in confidences]
        if novelties:
            variables["novelties"] = [n.value for n in novelties]
        if type_index:
            variables["type_index"] = type_index
        
        result = self._execute(query, variables)
        return result.get("scan", {}).get("issues", [])
    
    def update_issue(
        self,
        scan_id: str,
        serial_number: str,
        severity: Optional[Severity] = None,
        accepted_risk: Optional[bool] = None,
        propagation_mode: PropagationMode = PropagationMode.NONE,
        note: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update an issue (severity or accepted risk)."""
        mutation = """
        mutation UpdateIssue($input: UpdateIssueInput) {
            update_issue(input: $input) {
                issue {
                    serial_number severity accepted_risk
                }
            }
        }
        """
        variables = {
            "input": {
                "scan_id": scan_id,
                "serial_number": serial_number,
                "propagation_mode": propagation_mode.value
            }
        }
        if severity:
            variables["input"]["severity"] = severity.value
        if accepted_risk is not None:
            variables["input"]["accepted_risk"] = accepted_risk
        if note:
            variables["input"]["note"] = note
        
        result = self._execute(mutation, variables)
        return result.get("update_issue", {})
    
    def mark_false_positive(
        self,
        scan_id: str,
        serial_number: str,
        propagation_mode: PropagationMode = PropagationMode.NONE,
        note: Optional[str] = None,
        share_telemetry: bool = True
    ) -> Dict[str, Any]:
        """Mark an issue as a false positive."""
        mutation = """
        mutation MarkFalsePositive($input: MarkFalsePositiveInput!) {
            mark_false_positive(input: $input) {
                successful
            }
        }
        """
        variables = {
            "input": {
                "scan_id": scan_id,
                "serial_number": serial_number,
                "propagation_mode": propagation_mode.value,
                "share_telemetry": share_telemetry
            }
        }
        if note:
            variables["input"]["note"] = note
        
        result = self._execute(mutation, variables)
        return result.get("mark_false_positive", {})
    
    # =========================================================================
    # SCAN CONFIGURATION OPERATIONS
    # =========================================================================
    
    def get_scan_configurations(self) -> List[Dict[str, Any]]:
        """Get all scan configurations."""
        query = """
        query GetScanConfigurations {
            scan_configurations {
                id name built_in last_modified_time
                last_modified_by { username }
            }
        }
        """
        result = self._execute(query)
        return result.get("scan_configurations", [])
    
    def get_featured_scan_configurations(self) -> List[Dict[str, Any]]:
        """Get featured scan configurations."""
        query = """
        query GetFeaturedScanConfigurations {
            featured_scan_configurations {
                id name description icon_svg
            }
        }
        """
        result = self._execute(query)
        return result.get("featured_scan_configurations", [])
    
    def create_scan_configuration(
        self,
        name: str,
        configuration_json: str
    ) -> Dict[str, Any]:
        """Create a scan configuration."""
        mutation = """
        mutation CreateScanConfiguration($input: CreateScanConfigurationInput!) {
            create_scan_configuration(input: $input) {
                scan_configuration { id name built_in }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {
                "name": name,
                "scan_configuration_fragment_json": configuration_json
            }
        })
        return result.get("create_scan_configuration", {})
    
    def update_scan_configuration(
        self,
        config_id: str,
        name: Optional[str] = None,
        configuration_json: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a scan configuration."""
        mutation = """
        mutation UpdateScanConfiguration($input: UpdateScanConfigurationInput!) {
            update_scan_configuration(input: $input) {
                scan_configuration { id name }
            }
        }
        """
        variables = {"input": {"id": config_id}}
        if name:
            variables["input"]["name"] = name
        if configuration_json:
            variables["input"]["scan_configuration_fragment_json"] = configuration_json
        
        result = self._execute(mutation, variables)
        return result.get("update_scan_configuration", {})
    
    def delete_scan_configuration(
        self, 
        config_id: str, 
        force: bool = False
    ) -> Optional[str]:
        """Delete a scan configuration."""
        mutation = """
        mutation DeleteScanConfiguration($input: DeleteScanConfigurationInput!) {
            delete_scan_configuration(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"id": config_id, "force": force}
        })
        return result.get("delete_scan_configuration", {}).get("id")
    
    # =========================================================================
    # EXTENSION & BCHECK OPERATIONS
    # =========================================================================
    
    def get_extensions(self) -> List[Dict[str, Any]]:
        """Get all extensions."""
        query = """
        query GetExtensions {
            extensions {
                id name description uploaded_filename uploaded_date uploaded_by
                bapp_details { bapp_uuid author version }
            }
        }
        """
        result = self._execute(query)
        return result.get("extensions", [])
    
    def get_bchecks(
        self,
        offset: int = 0,
        limit: int = 50,
        sort_column: BCheckSortColumn = BCheckSortColumn.NAME,
        sort_order: SortOrder = SortOrder.ASC
    ) -> Dict[str, Any]:
        """Get BChecks."""
        query = """
        query GetBChecks($offset: Int, $limit: Int, $sort_column: BCheckSortColumn, $sort_order: SortOrder) {
            bchecks(offset: $offset, limit: $limit, sort_column: $sort_column, sort_order: $sort_order) {
                bchecks {
                    id name description author uploaded_filename uploaded_date uploaded_by tags
                }
                total_count
            }
        }
        """
        result = self._execute(query, {
            "offset": offset,
            "limit": limit,
            "sort_column": sort_column.value,
            "sort_order": sort_order.value
        })
        return result.get("bchecks", {"bchecks": [], "total_count": 0})
    
    def upload_bcheck(self, filename: str, script: str) -> Dict[str, Any]:
        """Upload a BCheck."""
        mutation = """
        mutation UploadBCheck($input: UploadBCheckInput!) {
            upload_bcheck(input: $input) {
                bcheck { id name description author tags }
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"filename": filename, "script": script}
        })
        return result.get("upload_bcheck", {})
    
    def delete_bcheck(self, bcheck_id: str) -> str:
        """Delete a BCheck."""
        mutation = """
        mutation DeleteBCheck($input: DeleteBCheckInput!) {
            delete_bcheck(input: $input) {
                id
            }
        }
        """
        result = self._execute(mutation, {"input": {"id": bcheck_id}})
        return result.get("delete_bcheck", {}).get("id")
    
    # =========================================================================
    # TAG OPERATIONS
    # =========================================================================
    
    def get_tags(self) -> List[Dict[str, Any]]:
        """Get all tags."""
        query = """
        query GetTags {
            tags {
                id name description color
            }
        }
        """
        result = self._execute(query)
        return result.get("tags", [])
    
    def create_tag(
        self,
        name: str,
        color: TagColor,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a tag."""
        mutation = """
        mutation CreateTag($input: CreateTagInput!) {
            create_tag(input: $input) {
                tag { id name description color }
            }
        }
        """
        variables = {"input": {"name": name, "color": color.value}}
        if description:
            variables["input"]["description"] = description
        
        result = self._execute(mutation, variables)
        return result.get("create_tag", {})
    
    def update_tag(
        self,
        tag_id: str,
        name: str,
        color: TagColor,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a tag."""
        mutation = """
        mutation UpdateTag($input: UpdateTagInput!) {
            update_tag(input: $input) {
                tag { id name description color }
            }
        }
        """
        variables = {
            "input": {
                "id": tag_id,
                "name": name,
                "color": color.value
            }
        }
        if description:
            variables["input"]["description"] = description
        
        result = self._execute(mutation, variables)
        return result.get("update_tag", {})
    
    def delete_tag(self, tag_id: str) -> bool:
        """Delete a tag."""
        mutation = """
        mutation DeleteTag($input: DeleteTagInput!) {
            delete_tag(input: $input) {
                successful
            }
        }
        """
        result = self._execute(mutation, {"input": {"tag_id": tag_id}})
        return result.get("delete_tag", {}).get("successful", False)
    
    def add_tags_to_nodes(
        self, 
        tag_ids: List[str], 
        node_ids: List[str]
    ) -> bool:
        """Add tags to sites or folders."""
        mutation = """
        mutation AddTagsToNodes($input: AddTagsToNodesInput!) {
            add_tags_to_nodes(input: $input) {
                successful
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"tag_ids": tag_ids, "node_ids": node_ids}
        })
        return result.get("add_tags_to_nodes", {}).get("successful", False)
    
    def remove_tags_from_nodes(
        self, 
        tag_ids: List[str], 
        node_ids: List[str]
    ) -> bool:
        """Remove tags from sites or folders."""
        mutation = """
        mutation RemoveTagsFromNodes($input: RemoveTagsFromNodesInput!) {
            remove_tags_from_nodes(input: $input) {
                successful
            }
        }
        """
        result = self._execute(mutation, {
            "input": {"tag_ids": tag_ids, "node_ids": node_ids}
        })
        return result.get("remove_tags_from_nodes", {}).get("successful", False)
    
    # =========================================================================
    # SETTINGS & SYSTEM OPERATIONS
    # =========================================================================
    
    def get_settings(self) -> Dict[str, Any]:
        """Get global settings."""
        query = """
        query GetSettings {
            settings {
                global_scans_enabled global_scan_throttle_enabled
                global_max_concurrent_scans project_file_storage_path
            }
        }
        """
        result = self._execute(query)
        return result.get("settings", {})
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get system capabilities."""
        query = """
        query GetCapabilities {
            capabilities {
                email slack jira gitlab scim ldap saml trello splunk mfa
            }
        }
        """
        result = self._execute(query)
        return result.get("capabilities", {})
    
    def get_system_warnings(self) -> List[Dict[str, Any]]:
        """Get system warnings."""
        query = """
        query GetSystemWarnings {
            system_warnings {
                type message
            }
        }
        """
        result = self._execute(query)
        return result.get("system_warnings", [])
    
    def get_forward_propagation_settings(self) -> Dict[str, Any]:
        """Get forward propagation settings."""
        query = """
        query GetForwardPropagationSettings {
            forward_propagation_settings {
                false_positive severity accepted_risk
            }
        }
        """
        result = self._execute(query)
        return result.get("forward_propagation_settings", {})
    
    def update_forward_propagation_settings(
        self,
        false_positive: Optional[ForwardPropagationMode] = None,
        severity: Optional[ForwardPropagationMode] = None,
        accepted_risk: Optional[ForwardPropagationMode] = None
    ) -> Dict[str, Any]:
        """Update forward propagation settings."""
        mutation = """
        mutation UpdateForwardPropagationSettings($input: UpdateForwardPropagationSettingsInput!) {
            update_forward_propagation_settings(input: $input) {
                false_positive severity accepted_risk
            }
        }
        """
        variables = {"input": {}}
        if false_positive:
            variables["input"]["false_positive"] = false_positive.value
        if severity:
            variables["input"]["severity"] = severity.value
        if accepted_risk:
            variables["input"]["accepted_risk"] = accepted_risk.value
        
        result = self._execute(mutation, variables)
        return result.get("update_forward_propagation_settings", {})
    
    # =========================================================================
    # PRE-SCAN CHECK OPERATIONS
    # =========================================================================
    
    def get_pre_scan_check(self, site_id: str) -> Optional[Dict[str, Any]]:
        """Get pre-scan check results for a site."""
        query = """
        query GetPreScanCheck($site_id: ID!) {
            pre_scan_check(site_id: $site_id) {
                id status created_time start_time end_time
                scan_failure_code scan_failure_message
                results { result_json }
                recorded_logins {
                    images_available
                    results { label failure_code failure_message }
                }
            }
        }
        """
        result = self._execute(query, {"site_id": site_id})
        return result.get("pre_scan_check")
    
    def create_pre_scan_check(self, site_id: str) -> Dict[str, Any]:
        """Create a pre-scan check for a site."""
        mutation = """
        mutation CreatePreScanCheck($input: ManagePreScanCheckInput!) {
            create_pre_scan_check(input: $input) {
                site_id error
            }
        }
        """
        result = self._execute(mutation, {"input": {"site_id": site_id}})
        return result.get("create_pre_scan_check", {})
    
    def cancel_pre_scan_check(self, site_id: str) -> Optional[bool]:
        """Cancel a pre-scan check."""
        mutation = """
        mutation CancelPreScanCheck($input: ManagePreScanCheckInput!) {
            cancel_pre_scan_check(input: $input)
        }
        """
        result = self._execute(mutation, {"input": {"site_id": site_id}})
        return result.get("cancel_pre_scan_check")
    
    # =========================================================================
    # RAW QUERY EXECUTION
    # =========================================================================
    
    def execute_query(
        self, 
        query: str, 
        variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a raw GraphQL query.
        
        Args:
            query: The GraphQL query string.
            variables: Optional variables for the query.
            
        Returns:
            The response data.
        """
        return self._execute(query, variables)
    
    def execute_mutation(
        self, 
        mutation: str, 
        variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a raw GraphQL mutation.
        
        Args:
            mutation: The GraphQL mutation string.
            variables: Optional variables for the mutation.
            
        Returns:
            The response data.
        """
        return self._execute(mutation, variables)

