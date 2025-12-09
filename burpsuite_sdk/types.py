"""
Burp Suite DAST GraphQL API - Type Definitions

This module contains dataclass definitions for all GraphQL types.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict, Union
from datetime import datetime

from .enums import (
    AgentWarningType, ApiAuthenticationTokenDestination, ApiAuthenticationType,
    ApiDynamicAuthenticationTokenRequestMethod, Confidence, ErrorType, 
    ForwardPropagationMode, GeneratedBy, GitLabIssueState, GitLabIssueType,
    Novelty, PlatformAuthenticationType, PreScanCheckStatus, PropagationMode,
    ProxyAuthenticationType, ScanEventLogType, ScanPhase, ScanStatus,
    ScanTargetType, ScopeProtocolOptions, Severity, TagColor
)


# =============================================================================
# SCALAR TYPES
# =============================================================================

# Long: A 64-bit signed integer (use int in Python)
# Timestamp: Timestamp scalar (use datetime or str)
# ID: GraphQL ID type (use str)


# =============================================================================
# BASIC TYPES
# =============================================================================

@dataclass
class User:
    """A registered user of Burp Suite DAST."""
    username: str


@dataclass
class BackupCode:
    """MFA backup code."""
    code: str
    used: bool


@dataclass
class UserAccount:
    """User account information."""
    totp_backup_codes: List[BackupCode] = field(default_factory=list)


# =============================================================================
# AGENT TYPES
# =============================================================================

@dataclass
class AgentError:
    """An error that has occurred on the agent machine."""
    code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class AgentPool:
    """A pool to which agents can be assigned."""
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    agents: Optional[List['Agent']] = None
    sites: Optional[List['Site']] = None


@dataclass
class Agent:
    """A virtual or physical machine configured as an agent machine."""
    id: Optional[str] = None
    machine_id: Optional[str] = None
    current_scan_count: Optional[int] = None
    ip: Optional[str] = None
    name: Optional[str] = None
    state: Optional[str] = None
    error: Optional[AgentError] = None
    enabled: Optional[bool] = None
    max_concurrent_scans: Optional[int] = None
    cpu_cores: Optional[int] = None
    system_ram_gb: Optional[int] = None
    agent_pool: Optional[AgentPool] = None
    warning: Optional[AgentWarningType] = None
    last_used_token_name: Optional[str] = None


@dataclass
class UnauthorizedAgent:
    """An agent machine not yet authorized."""
    machine_id: str
    ip: str


@dataclass
class MachineToken:
    """Self-hosted scanning machine authentication token."""
    id: Optional[str] = None
    name: str = ""
    timestamp: Optional[str] = None
    token_hash: Optional[str] = None
    machine_count: Optional[int] = None
    has_running_scans: Optional[bool] = None


@dataclass
class EphemeralAgent:
    """Ephemeral agent information."""
    id: str
    name: Optional[str] = None
    node_name: Optional[str] = None
    job_status: Optional[str] = None
    pod_status: Optional[str] = None
    scan_id: Optional[str] = None
    start_time: Optional[str] = None
    site_name: Optional[str] = None
    scan_status: Optional[ScanStatus] = None


# =============================================================================
# SCOPE & API DEFINITION TYPES
# =============================================================================

@dataclass
class ScopeV2:
    """The URLs that Burp Scanner is allowed to crawl and audit."""
    start_urls: List[str] = field(default_factory=list)
    in_scope_url_prefixes: List[str] = field(default_factory=list)
    out_of_scope_url_prefixes: List[str] = field(default_factory=list)
    protocol_options: Optional[ScopeProtocolOptions] = None


@dataclass
class ApiDynamicAuthenticationTokenRequestHeader:
    """API dynamic authentication token request header."""
    name: str
    value: str


@dataclass
class ApiDynamicAuthenticationTokenConfig:
    """API dynamic authentication token configuration."""
    request_url: str
    request_method: ApiDynamicAuthenticationTokenRequestMethod
    extract_path: str
    refresh_interval_seconds: int
    request_headers: Optional[List[ApiDynamicAuthenticationTokenRequestHeader]] = None
    request_body: Optional[str] = None


@dataclass
class ApiBasicAuthentication:
    """Basic authentication scheme."""
    type: ApiAuthenticationType
    label: str
    has_missing_credentials: bool
    username: Optional[str] = None
    password: Optional[str] = None
    was_detected: Optional[bool] = None


@dataclass
class ApiBearerTokenAuthentication:
    """Bearer token authentication scheme."""
    type: ApiAuthenticationType
    label: str
    has_missing_credentials: bool
    token: Optional[str] = None
    dynamic_token_config: Optional[ApiDynamicAuthenticationTokenConfig] = None
    was_detected: Optional[bool] = None


@dataclass
class ApiKeyAuthentication:
    """API key authentication scheme."""
    type: ApiAuthenticationType
    label: str
    api_key_destination: ApiAuthenticationTokenDestination
    parameter_name: str
    has_missing_credentials: bool
    key: Optional[str] = None
    dynamic_token_config: Optional[ApiDynamicAuthenticationTokenConfig] = None
    was_detected: Optional[bool] = None


@dataclass
class ApiUnsupportedAuthentication:
    """Unsupported authentication scheme."""
    type: ApiAuthenticationType
    label: str
    authentication_type: str


@dataclass
class EnabledEndpoint:
    """An enabled endpoint."""
    id: str


@dataclass
class OpenApiEndpoint:
    """An OpenAPI endpoint."""
    id: str
    host: str
    path: str
    method: str
    content_type: Optional[str] = None


@dataclass
class SoapEndpoint:
    """A SOAP endpoint."""
    id: str
    host: str
    path: str
    name: str
    content_type: Optional[str] = None


@dataclass
class PostmanRequest:
    """A request imported from Postman."""
    id: str
    method: str
    interpolated_host: str
    name: str
    interpolated_path: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class UrlBasedApiDefinition:
    """URL-based API definition."""
    url: str
    authentications: List[Any] = field(default_factory=list)


@dataclass
class FileBasedApiDefinition:
    """File-based API definition."""
    filename: str
    parsed_api_definition: Any = None
    authentications: List[Any] = field(default_factory=list)
    enabled_endpoints: List[EnabledEndpoint] = field(default_factory=list)
    environment_filename: Optional[str] = None


@dataclass
class ApiDefinition:
    """API definition for a site."""
    id: str
    url_based_api_definition: Optional[UrlBasedApiDefinition] = None
    file_based_api_definition: Optional[FileBasedApiDefinition] = None


# =============================================================================
# APPLICATION LOGIN TYPES
# =============================================================================

@dataclass
class LoginCredential:
    """A set of login credentials associated with a site."""
    id: str
    label: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class AuthenticationStatusCheck:
    """Authentication status check configuration."""
    url: str
    confirmationText: str


@dataclass
class RecordedLogin:
    """A recorded login sequence associated with a site."""
    id: str
    label: Optional[str] = None
    script: Optional[str] = None
    authenticationStatusCheck: Optional[AuthenticationStatusCheck] = None


@dataclass
class ApplicationLogins:
    """Collection of application logins for a site."""
    login_credentials: List[LoginCredential] = field(default_factory=list)
    recorded_logins: List[RecordedLogin] = field(default_factory=list)


# =============================================================================
# SITE & FOLDER TYPES
# =============================================================================

@dataclass
class Tag:
    """Tags for categorizing sites and folders."""
    id: str
    name: str
    color: TagColor
    description: Optional[str] = None


@dataclass
class EmailRecipient:
    """An email address that receives scan reports."""
    id: str
    email: str


@dataclass
class SlackChannel:
    """A Slack channel."""
    id: str
    name: str


@dataclass
class RequestHeader:
    """A request header configuration."""
    name: str
    value: str
    id: Optional[str] = None
    scope_prefix: Optional[str] = None


@dataclass
class RequestCookie:
    """A request cookie configuration."""
    name: str
    value: str
    id: Optional[str] = None
    scope_prefix: Optional[str] = None


@dataclass
class PlatformAuthentication:
    """Platform authentication configuration."""
    id: str
    destination_host: str
    type: PlatformAuthenticationType
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    domain_hostname: Optional[str] = None


@dataclass
class Proxy:
    """Proxy configuration."""
    id: str
    destination_host: str
    proxy_host: str
    proxy_port: int
    authentication_type: ProxyAuthenticationType
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    domain_hostname: Optional[str] = None


@dataclass
class SiteSettings:
    """Settings for a site."""
    request_headers: Optional[List[RequestHeader]] = None
    request_cookies: Optional[List[RequestHeader]] = None
    platform_authentication: Optional[List[PlatformAuthentication]] = None
    proxies: Optional[List[Proxy]] = None


@dataclass
class FolderSettings:
    """Settings for a folder."""
    request_headers: Optional[List[RequestHeader]] = None
    request_cookies: Optional[List[RequestHeader]] = None
    platform_authentication: Optional[List[PlatformAuthentication]] = None
    proxies: Optional[List[Proxy]] = None


@dataclass
class Site:
    """A website or web application to scan."""
    id: str
    parent_id: str
    application_logins: ApplicationLogins = field(default_factory=ApplicationLogins)
    has_missing_api_credentials: bool = False
    name: Optional[str] = None
    scope_v2: Optional[ScopeV2] = None
    api_definitions: Optional[List[ApiDefinition]] = None
    scan_configurations: Optional[List['ScanConfiguration']] = None
    extensions: Optional[List['Extension']] = None
    bchecks: Optional[List['BCheck']] = None
    ephemeral: Optional[bool] = None
    email_recipients: Optional[List[EmailRecipient]] = None
    agent_pool: Optional[AgentPool] = None
    slack_channels: Optional[List[SlackChannel]] = None
    settings: Optional[SiteSettings] = None
    tags: Optional[List[Tag]] = None


@dataclass
class Folder:
    """A folder in the site tree."""
    id: str
    name: str
    parent_id: Optional[str] = None
    description: Optional[str] = None
    scan_configurations: Optional[List['ScanConfiguration']] = None
    extensions: Optional[List['Extension']] = None
    bchecks: Optional[List['BCheck']] = None
    email_recipients: Optional[List[EmailRecipient]] = None
    slack_channels: Optional[List[SlackChannel]] = None
    settings: Optional[FolderSettings] = None
    tags: Optional[List[Tag]] = None


@dataclass
class CidsSite:
    """A site created by a CI-driven scan."""
    id: str
    name: str
    parent_id: str
    ephemeral: Optional[bool] = None
    correlation_id: Optional[str] = None
    tags: Optional[List[Tag]] = None


@dataclass
class SiteTree:
    """The site tree containing all sites and folders."""
    folders: List[Folder] = field(default_factory=list)
    sites: List[Site] = field(default_factory=list)
    cids_sites: List[CidsSite] = field(default_factory=list)


# =============================================================================
# SCAN CONFIGURATION TYPES
# =============================================================================

@dataclass
class ScanConfiguration:
    """A scan configuration controlling scan settings."""
    id: str
    name: Optional[str] = None
    scan_configuration_fragment_json: Optional[str] = None
    built_in: Optional[bool] = None
    last_modified_time: Optional[str] = None
    last_modified_by: Optional[User] = None


@dataclass
class FeaturedScanConfiguration:
    """A featured scan configuration."""
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    icon_svg: Optional[str] = None


@dataclass
class Extension:
    """A Burp extension (custom or BApp)."""
    uploaded_filename: str
    name: str
    description: str
    uploaded_date: str
    id: Optional[str] = None
    uploaded_by: Optional[str] = None
    bapp_details: Optional['BappDetails'] = None


@dataclass
class BappDetails:
    """Details for a BApp extension."""
    bapp_uuid: str
    author: str
    version: str


@dataclass
class BCheck:
    """A BCheck script."""
    id: str
    uploaded_filename: str
    name: str
    uploaded_date: str
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    author: Optional[str] = None
    uploaded_by: Optional[str] = None


@dataclass
class BChecksContainer:
    """Container for BChecks with pagination."""
    bchecks: List[BCheck] = field(default_factory=list)
    total_count: int = 0


# =============================================================================
# SCHEDULE TYPES
# =============================================================================

@dataclass
class Schedule:
    """Scheduling information for a schedule item."""
    initial_run_time: str
    rrule: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ScheduleItem:
    """A scheduled scan configuration."""
    id: str
    schedule: Schedule = None
    sites: List[Site] = field(default_factory=list)
    folders: List[Folder] = field(default_factory=list)
    scan_configurations: List[ScanConfiguration] = field(default_factory=list)
    site: Optional[Site] = None  # Deprecated
    has_run_more_than_once: Optional[bool] = None
    scheduled_run_time: Optional[str] = None
    verbose_debug: Optional[bool] = None


@dataclass
class ScheduleItemsContainer:
    """Container for schedule items with pagination."""
    items: Optional[List[ScheduleItem]] = None
    total_count: int = 0


# =============================================================================
# ISSUE TYPES
# =============================================================================

@dataclass
class IssueType:
    """Basic information about an issue type."""
    type_index: str
    name: Optional[str] = None
    description_html: Optional[str] = None
    remediation_html: Optional[str] = None
    vulnerability_classifications_html: Optional[str] = None
    references_html: Optional[str] = None


@dataclass
class CountsByConfidence:
    """Issue counts by confidence level."""
    total: int
    firm: int
    tentative: int
    certain: int


@dataclass
class IssueCounts:
    """Issue counts sorted by severity level."""
    total: int
    high: CountsByConfidence
    medium: CountsByConfidence
    low: CountsByConfidence
    info: CountsByConfidence


@dataclass
class DataSegment:
    """Part of a request/response not highlighted by Burp Scanner."""
    data_html: Optional[str] = None


@dataclass
class HighlightSegment:
    """Part of a request/response highlighted by Burp Scanner."""
    highlight_html: Optional[str] = None


@dataclass
class SnipSegment:
    """An extracted segment of an HTTP message."""
    snip_length: Optional[int] = None


@dataclass
class Request:
    """An HTTP request in which an issue was identified."""
    request_index: Optional[int] = None
    request_count: Optional[int] = None
    request_segments: Optional[List[Any]] = None


@dataclass
class Response:
    """An HTTP response in which an issue was identified."""
    response_index: Optional[int] = None
    response_count: Optional[int] = None
    response_segments: Optional[List[Any]] = None


@dataclass
class HttpInteraction:
    """An HTTP interaction with Burp Collaborator."""
    title: str
    description_html: Optional[str] = None
    request: Optional[List[Any]] = None
    response: Optional[List[Any]] = None


@dataclass
class DescriptiveEvidence:
    """Textual description of evidence for an issue."""
    title: str
    description_html: Optional[str] = None


@dataclass
class GeneratedByExtension:
    """An extension that generated an issue."""
    name: str


@dataclass
class GeneratedByBCheck:
    """A BCheck that generated an issue."""
    name: str


@dataclass
class JiraTicket:
    """A Jira ticket linked to an issue."""
    id: str
    external_key: Optional[str] = None
    ticket_type: Optional[str] = None
    summary: Optional[str] = None
    project: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None


@dataclass
class GitLabIssueDetails:
    """GitLab issue details."""
    title: Optional[str] = None
    state: Optional[GitLabIssueState] = None


@dataclass
class GitLabIssue:
    """A GitLab issue linked to a scan issue."""
    id: str
    project_id: str
    issue_details: Optional[GitLabIssueDetails] = None


@dataclass
class TrelloCardDetails:
    """Trello card details."""
    title: Optional[str] = None
    board_name: Optional[str] = None
    list_name: Optional[str] = None


@dataclass
class TrelloCard:
    """A Trello card linked to an issue."""
    id: str
    card_details: Optional[TrelloCardDetails] = None


@dataclass
class Ticket:
    """A ticket created from a scan issue."""
    jira_ticket: Optional[JiraTicket] = None
    gitlab_issue: Optional[GitLabIssue] = None
    trello_card: Optional[TrelloCard] = None
    link_url: Optional[str] = None
    link_id: Optional[str] = None
    date_added: Optional[str] = None


@dataclass
class SeverityIssueChange:
    """A change to the severity of an issue."""
    severity: Optional[Severity] = None


@dataclass
class FalsePositiveIssueChange:
    """A change to the false positive status of an issue."""
    false_positive: Optional[bool] = None


@dataclass
class AcceptedRiskIssueChange:
    """A change to the accepted risk status of an issue."""
    accepted_risk: Optional[bool] = None


@dataclass
class IssueChangeHistory:
    """Details of a change to an issue."""
    note: Optional[str] = None
    timestamp: Optional[str] = None
    username: Optional[str] = None
    issue_change: Optional[Any] = None


@dataclass
class Issue:
    """A potential security vulnerability found by a scan."""
    confidence: Confidence
    serial_number: str
    severity: Severity
    original_severity: Severity
    accepted_risk: bool
    path: str
    origin: str
    issue_type: Optional[IssueType] = None
    original_confidence: Optional[Confidence] = None
    description_html: Optional[str] = None
    remediation_html: Optional[str] = None
    novelty: Optional[Novelty] = None
    evidence: Optional[List[Any]] = None
    tickets: Optional[List[Ticket]] = None
    generated_by_extension: Optional[GeneratedByExtension] = None
    generated_by_bcheck: Optional[GeneratedByBCheck] = None
    fingerprint: Optional[str] = None
    change_history: Optional[List[IssueChangeHistory]] = None


@dataclass
class IssueTypeGroup:
    """Information about instances of an issue type."""
    confidence: Confidence
    severity: Severity
    accepted_risk: bool
    number_of_children: int
    issue_type: Optional[IssueType] = None
    first_child_serial_number: Optional[str] = None
    novelty: Optional[Novelty] = None
    jira_ticket_count: Optional[int] = None
    gitlab_issue_count: Optional[int] = None
    trello_card_count: Optional[int] = None


# =============================================================================
# AUDIT ITEM TYPES
# =============================================================================

@dataclass
class AuditItem:
    """An item representing a location to audit."""
    id: str
    host: str
    path: str
    issue_counts: IssueCounts
    number_of_requests: int
    number_of_errors: int
    number_of_insertion_points: int
    method: Optional[str] = None
    error_types: Optional[List[ErrorType]] = None
    issue_type_groups: Optional[List[IssueTypeGroup]] = None


@dataclass
class CrawlItem:
    """A crawl item found during scanning."""
    id: str
    host: str
    path: str
    status: Optional[str] = None


# =============================================================================
# SCAN TYPES
# =============================================================================

@dataclass
class ScanTarget:
    """A scan target (site or CIDS site)."""
    id: str
    name: str
    type: ScanTargetType
    ephemeral: bool


@dataclass
class ScanProgressMetrics:
    """Metrics providing details of scan progress."""
    crawl_request_count: int
    unique_location_count: int
    audit_request_count: int
    audit_queue_items_waiting: int
    crawl_and_audit_progress_percentage: int
    scan_phase: Optional[ScanPhase] = None
    audit_start_time: Optional[str] = None
    current_url: Optional[str] = None


@dataclass
class ScanDelta:
    """Information about how issue counts changed from previous scan."""
    new_issue_count: int
    repeated_issue_count: int
    regressed_issue_count: int
    resolved_issue_count: int


@dataclass
class ScanWarnings:
    """Scan warnings."""
    primary_warning: Optional[str] = None


@dataclass
class ScanDebugInfo:
    """Scan debug information."""
    project_file_available: Optional[bool] = None


@dataclass
class ScanEventLogEntry:
    """A scan event log entry."""
    type: ScanEventLogType
    message: str
    timestamp: str
    duplicate_count: int
    scanner_message_id: Optional[int] = None
    cause: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class ScanEventLog:
    """Scan event log."""
    entries: List[ScanEventLogEntry] = field(default_factory=list)


@dataclass
class Scan:
    """A scan of a site using Burp Scanner."""
    id: str
    scan_target: ScanTarget
    schedule_item: Optional[ScheduleItem] = None
    scheduled_start_time: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    paused_time: Optional[str] = None
    duration_in_seconds: Optional[int] = None
    estimated_duration_in_seconds: Optional[int] = None
    status: Optional[ScanStatus] = None
    agent: Optional[Agent] = None
    scan_metrics: Optional[ScanProgressMetrics] = None
    scan_failure_code: Optional[int] = None
    scan_failure_message: Optional[str] = None
    scan_failure_cause: Optional[str] = None
    scan_failure_remedy: Optional[str] = None
    generated_by: Optional[GeneratedBy] = None
    scanner_version: Optional[str] = None
    scanner_build_number: Optional[int] = None
    scan_configurations: Optional[List[ScanConfiguration]] = None
    extensions: Optional[List[Extension]] = None
    bchecks: Optional[List[BCheck]] = None
    scan_delta: Optional[ScanDelta] = None
    jira_ticket_count: Optional[int] = None
    gitlab_issue_count: Optional[int] = None
    trello_card_count: Optional[int] = None
    issue_type_groups: Optional[List[IssueTypeGroup]] = None
    issue_counts: Optional[IssueCounts] = None
    audit_items: Optional[List[AuditItem]] = None
    scope_v2: Optional[ScopeV2] = None
    api_definitions: Optional[List[Any]] = None
    site_application_logins: Optional[ApplicationLogins] = None
    schedule_item_application_logins: Optional[ApplicationLogins] = None
    issues: Optional[List[Issue]] = None
    warnings: Optional[ScanWarnings] = None
    debug: Optional[ScanDebugInfo] = None
    settings: Optional[SiteSettings] = None


@dataclass
class ScanReport:
    """A downloadable scan report."""
    report_html: Optional[str] = None
    report_pdf: Optional[str] = None
    warning: Optional[str] = None


@dataclass
class BurpReport:
    """Issue data in XML format."""
    report_xml: Optional[str] = None


@dataclass
class ScanCountsByStatus:
    """Scan counts by status."""
    scheduled: int
    queued: int
    running: int
    succeeded: int
    cancelled: int
    failed: int


@dataclass
class ScanSeverityCounts:
    """Scan severity counts."""
    scan_id: str
    end_time: str
    high: int
    info: int
    low: int
    medium: int


@dataclass
class VulnerabilitySummary:
    """Vulnerability summary."""
    issue_name: str
    severity: Severity
    high_count: int
    medium_count: int
    low_count: int
    info_count: int


# =============================================================================
# PRE-SCAN CHECK TYPES
# =============================================================================

@dataclass
class PreScanCheckResult:
    """Results of a pre-scan check."""
    result_json: str


@dataclass
class RecordedLoginReplayImage:
    """Recorded login replay image."""
    index: int
    timestamp: str
    url: str


@dataclass
class RequestResult:
    """Request result."""
    request_url: Optional[str] = None
    http_response_code: Optional[str] = None
    http_response_message: Optional[str] = None
    http_request: Optional[str] = None
    http_response: Optional[str] = None


@dataclass
class RecordedLoginReplayResult:
    """Recorded login replay result."""
    label: str
    failure_code: int
    images: List[RecordedLoginReplayImage] = field(default_factory=list)
    failure_message: Optional[str] = None
    status_check_responses: Optional[List[RequestResult]] = None
    status_check_screenshot: Optional[str] = None


@dataclass
class RecordedLoginReplayResults:
    """Recorded login replay results."""
    images_available: bool
    results: List[RecordedLoginReplayResult] = field(default_factory=list)


@dataclass
class PreScanCheck:
    """A pre-scan check of a site."""
    id: str
    created_time: str
    status: PreScanCheckStatus
    results: List[PreScanCheckResult] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    recorded_logins: Optional[RecordedLoginReplayResults] = None
    scan_failure_code: Optional[int] = None
    scan_failure_message: Optional[str] = None


# =============================================================================
# INTEGRATION TYPES
# =============================================================================

@dataclass
class SlackApiChannel:
    """A channel from the Slack API."""
    id: str
    name: str


@dataclass
class SlackAppConfiguration:
    """Slack app configuration."""
    ok: bool
    channels: List[SlackApiChannel] = field(default_factory=list)
    error: Optional[str] = None
    app_name: Optional[str] = None


@dataclass
class SlackChannels:
    """Slack channels configured in Burp Suite DAST."""
    channels: List[SlackChannel] = field(default_factory=list)


@dataclass
class GitLabProject:
    """A GitLab project."""
    id: str
    name: str


@dataclass
class GitLabProjectLink:
    """A GitLab project link."""
    project: GitLabProject
    issue_type: GitLabIssueType


@dataclass
class AutomaticGitLabSettings:
    """Automatic GitLab settings."""
    min_severity: Severity
    min_confidence: Confidence
    project_link: Optional[GitLabProjectLink] = None


@dataclass
class GitLabSettings:
    """GitLab settings."""
    url: str
    auto_create_enabled: bool
    project_links: List[GitLabProjectLink] = field(default_factory=list)
    auto_gitlab_settings: Optional[AutomaticGitLabSettings] = None


@dataclass
class GitLabProjects:
    """GitLab projects."""
    projects: List[GitLabProject] = field(default_factory=list)


@dataclass
class TrelloList:
    """A Trello list."""
    id: str
    name: str


@dataclass
class TrelloBoard:
    """A Trello board."""
    id: str
    name: str
    lists: Optional[List[TrelloList]] = None


@dataclass
class TrelloBoardLink:
    """A Trello board link."""
    board_id: str
    board_name: str
    list_id: str
    list_name: str


@dataclass
class AutomaticTrelloSettings:
    """Automatic Trello settings."""
    min_severity: Severity
    min_confidence: Confidence
    board_link: Optional[TrelloBoardLink] = None


@dataclass
class TrelloSettings:
    """Trello settings."""
    api_key: str
    auto_create_enabled: bool
    board_links: Optional[List[TrelloBoardLink]] = None
    auto_trello_settings: Optional[AutomaticTrelloSettings] = None


@dataclass
class JiraCredentials:
    """Jira credentials."""
    url: str
    username: str


@dataclass
class JiraProject:
    """A Jira project."""
    id: str
    name: str


@dataclass
class JiraProjectDetails:
    """Jira project details."""
    id: str
    name: str


@dataclass
class JiraTicketType:
    """A Jira ticket type."""
    id: str
    name: str


@dataclass
class JiraTicketTypeWithHierarchy:
    """A Jira ticket type with hierarchy level."""
    id: str
    name: str
    hierarchy_level: int


@dataclass
class JiraProjectInfo:
    """Jira project info."""
    ticket_types: List[JiraTicketTypeWithHierarchy] = field(default_factory=list)


@dataclass
class JiraProjects:
    """Jira projects."""
    projects: List[JiraProjectDetails] = field(default_factory=list)


@dataclass
class JiraParent:
    """Jira parent issue."""
    id: str
    name: str


@dataclass
class JiraCustomField:
    """Jira custom field."""
    id: str
    type: str
    value: str


@dataclass
class JiraManualRule:
    """Jira manual rule."""
    id: str
    name: str
    project: JiraProject
    ticket_type: JiraTicketType
    description: Optional[str] = None
    parent: Optional[JiraParent] = None
    custom_fields: Optional[List[JiraCustomField]] = None


@dataclass
class JiraAutomaticRule:
    """Jira automatic rule."""
    id: str
    name: str
    project: JiraProject
    ticket_type: JiraTicketType
    severities: List[Severity] = field(default_factory=list)
    confidences: List[Confidence] = field(default_factory=list)
    site_ids: List[str] = field(default_factory=list)
    folder_ids: List[str] = field(default_factory=list)
    description: Optional[str] = None
    parent: Optional[JiraParent] = None
    custom_fields: Optional[List[JiraCustomField]] = None


@dataclass
class JiraTicketFieldAllowedValue:
    """Jira ticket field allowed value."""
    id: str
    value: str


@dataclass
class JiraTicketField:
    """A Jira ticket field."""
    id: str
    name: str
    type: str
    array: bool
    required: bool
    supported: bool
    allowed_values: List[JiraTicketFieldAllowedValue] = field(default_factory=list)


@dataclass
class JiraTicketFieldListResult:
    """Jira ticket field list result."""
    fields: List[JiraTicketField] = field(default_factory=list)


@dataclass
class JiraTicketSearchResult:
    """Jira ticket search result."""
    key: str
    summary: str


@dataclass
class JiraTicketSearchResults:
    """Jira ticket search results."""
    tickets: List[JiraTicketSearchResult] = field(default_factory=list)


@dataclass
class SplunkSettings:
    """Splunk integration settings."""
    url: str


# =============================================================================
# SETTINGS TYPES
# =============================================================================

@dataclass
class Settings:
    """Global settings."""
    project_file_storage_path: str
    global_scans_enabled: Optional[bool] = None
    global_scan_throttle_enabled: Optional[bool] = None
    global_max_concurrent_scans: Optional[int] = None


@dataclass
class ScimSettings:
    """SCIM settings."""
    enabled: bool
    port: int
    use_tls: bool
    certificate_name: Optional[str] = None
    token: Optional[str] = None


@dataclass
class ForwardPropagationSettings:
    """Forward propagation settings."""
    false_positive: Optional[ForwardPropagationMode] = None
    severity: Optional[ForwardPropagationMode] = None
    accepted_risk: Optional[ForwardPropagationMode] = None


@dataclass
class Capabilities:
    """System capabilities."""
    email: bool
    slack: bool
    jira: bool
    gitlab: bool
    scim: bool
    ldap: bool
    saml: bool
    trello: bool
    splunk: bool
    mfa: bool


@dataclass
class SystemWarning:
    """System warning."""
    type: Optional[str] = None
    message: Optional[str] = None


@dataclass
class UserActivityLogSettings:
    """User activity log settings."""
    enabled: Optional[bool] = None
    retention_period: Optional[int] = None


@dataclass
class InstallerLinks:
    """Installer download links."""
    windows: str
    linux: str


@dataclass
class Questionnaire:
    """Questionnaire."""
    questionnaire_id: Optional[int] = None
    questions: Optional[str] = None


@dataclass
class LiveCIDScan:
    """Live CI/CD scan."""
    agent_id: str
    scan_id: str
    scan_status: ScanStatus
    start_time: str
    site_name: str


@dataclass
class ScanSettings:
    """Scan settings for a site or folder."""
    site_or_folder_id: str
    site_or_folder_name: str
    scan_configurations: List[ScanConfiguration] = field(default_factory=list)
    extensions: List[Extension] = field(default_factory=list)
    bchecks: List[BCheck] = field(default_factory=list)
    email_recipients: List[EmailRecipient] = field(default_factory=list)
    slack_channels: List[SlackChannel] = field(default_factory=list)
    platform_authentication: List[PlatformAuthentication] = field(default_factory=list)
    request_headers: List[RequestHeader] = field(default_factory=list)
    request_cookies: List[RequestHeader] = field(default_factory=list)
    proxies: List[Proxy] = field(default_factory=list)


@dataclass
class HierarchicalScanSettings:
    """Hierarchical scan settings including inherited settings."""
    settings: List[ScanSettings] = field(default_factory=list)

