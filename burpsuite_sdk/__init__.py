"""
Burp Suite DAST GraphQL API SDK

A Python SDK for interacting with the Burp Suite DAST GraphQL API.

Usage:
    >>> from burpsuite_sdk import BurpSuiteClient
    >>> client = BurpSuiteClient(
    ...     url="https://burpsuite.example.com/graphql/v1",
    ...     api_key="your-api-key"
    ... )
    >>> # Get all sites
    >>> site_tree = client.get_site_tree()
    >>> # Get scans
    >>> scans = client.get_scans(limit=10)
    >>> # Create a site
    >>> site = client.create_site(
    ...     name="My Site",
    ...     start_urls=["https://example.com"]
    ... )
"""

__version__ = "1.0.0"
__author__ = "Generated from Burp Suite DAST GraphQL Schema"

# Client
from .client import BurpSuiteClient

# Exceptions
from .exceptions import (
    BurpSuiteError,
    AuthenticationError,
    GraphQLError,
    NetworkError,
    ValidationError,
    ResourceNotFoundError,
    RateLimitError,
    ScanError,
    ConfigurationError,
    TimeoutError,
)

# Enums
from .enums import (
    AgentWarningType,
    ApiAuthenticationTokenDestination,
    ApiAuthenticationType,
    ApiDynamicAuthenticationTokenRequestMethod,
    AuditItemSortColumn,
    BCheckSortColumn,
    Confidence,
    Counter,
    CreatePreScanCheckError,
    ErrorType,
    FeedbackRatingType,
    ForwardPropagationMode,
    GeneratedBy,
    GitLabIssueState,
    GitLabIssueType,
    GitLabStateType,
    Novelty,
    PlatformAuthenticationType,
    PreScanCheckStatus,
    PropagationMode,
    ProxyAuthenticationType,
    ScanEventLogType,
    ScanPhase,
    ScanReportType,
    ScanStatus,
    ScanTargetType,
    ScansSortColumn,
    ScopeProtocolOptions,
    Severity,
    SortBy,
    SortOrder,
    SystemWarningType,
    TagColor,
)

# Types
from .types import (
    # Basic types
    User,
    BackupCode,
    UserAccount,
    # Agent types
    Agent,
    AgentError,
    AgentPool,
    UnauthorizedAgent,
    MachineToken,
    EphemeralAgent,
    # Scope & API types
    ScopeV2,
    ApiDefinition,
    UrlBasedApiDefinition,
    FileBasedApiDefinition,
    OpenApiEndpoint,
    SoapEndpoint,
    PostmanRequest,
    EnabledEndpoint,
    ApiBasicAuthentication,
    ApiBearerTokenAuthentication,
    ApiKeyAuthentication,
    ApiUnsupportedAuthentication,
    ApiDynamicAuthenticationTokenConfig,
    ApiDynamicAuthenticationTokenRequestHeader,
    # Login types
    LoginCredential,
    RecordedLogin,
    ApplicationLogins,
    AuthenticationStatusCheck,
    # Site & Folder types
    Site,
    Folder,
    CidsSite,
    SiteTree,
    Tag,
    EmailRecipient,
    SlackChannel,
    RequestHeader,
    RequestCookie,
    PlatformAuthentication,
    Proxy,
    SiteSettings,
    FolderSettings,
    # Scan configuration types
    ScanConfiguration,
    FeaturedScanConfiguration,
    Extension,
    BappDetails,
    BCheck,
    BChecksContainer,
    # Schedule types
    Schedule,
    ScheduleItem,
    ScheduleItemsContainer,
    # Issue types
    Issue,
    IssueType,
    IssueTypeGroup,
    IssueCounts,
    CountsByConfidence,
    IssueChangeHistory,
    SeverityIssueChange,
    FalsePositiveIssueChange,
    AcceptedRiskIssueChange,
    # Evidence types
    Request,
    Response,
    HttpInteraction,
    DescriptiveEvidence,
    DataSegment,
    HighlightSegment,
    SnipSegment,
    GeneratedByExtension,
    GeneratedByBCheck,
    # Audit types
    AuditItem,
    CrawlItem,
    # Scan types
    Scan,
    ScanTarget,
    ScanProgressMetrics,
    ScanDelta,
    ScanWarnings,
    ScanDebugInfo,
    ScanReport,
    BurpReport,
    ScanCountsByStatus,
    ScanSeverityCounts,
    ScanEventLog,
    ScanEventLogEntry,
    VulnerabilitySummary,
    # Pre-scan check types
    PreScanCheck,
    PreScanCheckResult,
    RecordedLoginReplayResults,
    RecordedLoginReplayResult,
    RecordedLoginReplayImage,
    RequestResult,
    # Ticket types
    Ticket,
    JiraTicket,
    GitLabIssue,
    GitLabIssueDetails,
    TrelloCard,
    TrelloCardDetails,
    # Integration types
    SlackApiChannel,
    SlackAppConfiguration,
    SlackChannels,
    GitLabProject,
    GitLabProjectLink,
    GitLabSettings,
    GitLabProjects,
    AutomaticGitLabSettings,
    TrelloList,
    TrelloBoard,
    TrelloBoardLink,
    TrelloSettings,
    AutomaticTrelloSettings,
    JiraCredentials,
    JiraProject,
    JiraProjectDetails,
    JiraProjectInfo,
    JiraTicketType,
    JiraTicketTypeWithHierarchy,
    JiraProjects,
    JiraParent,
    JiraCustomField,
    JiraManualRule,
    JiraAutomaticRule,
    JiraTicketField,
    JiraTicketFieldAllowedValue,
    JiraTicketFieldListResult,
    JiraTicketSearchResult,
    JiraTicketSearchResults,
    SplunkSettings,
    # Settings types
    Settings,
    ScimSettings,
    ForwardPropagationSettings,
    Capabilities,
    SystemWarning,
    UserActivityLogSettings,
    InstallerLinks,
    Questionnaire,
    LiveCIDScan,
    ScanSettings,
    HierarchicalScanSettings,
)

__all__ = [
    # Version
    "__version__",
    # Client
    "BurpSuiteClient",
    # Exceptions
    "BurpSuiteError",
    "AuthenticationError",
    "GraphQLError",
    "NetworkError",
    "ValidationError",
    "ResourceNotFoundError",
    "RateLimitError",
    "ScanError",
    "ConfigurationError",
    "TimeoutError",
    # Enums
    "AgentWarningType",
    "ApiAuthenticationTokenDestination",
    "ApiAuthenticationType",
    "ApiDynamicAuthenticationTokenRequestMethod",
    "AuditItemSortColumn",
    "BCheckSortColumn",
    "Confidence",
    "Counter",
    "CreatePreScanCheckError",
    "ErrorType",
    "FeedbackRatingType",
    "ForwardPropagationMode",
    "GeneratedBy",
    "GitLabIssueState",
    "GitLabIssueType",
    "GitLabStateType",
    "Novelty",
    "PlatformAuthenticationType",
    "PreScanCheckStatus",
    "PropagationMode",
    "ProxyAuthenticationType",
    "ScanEventLogType",
    "ScanPhase",
    "ScanReportType",
    "ScanStatus",
    "ScanTargetType",
    "ScansSortColumn",
    "ScopeProtocolOptions",
    "Severity",
    "SortBy",
    "SortOrder",
    "SystemWarningType",
    "TagColor",
    # Types (abbreviated list for clarity)
    "User",
    "Agent",
    "AgentPool",
    "Site",
    "Folder",
    "Scan",
    "ScanConfiguration",
    "ScheduleItem",
    "Issue",
    "IssueType",
    "Tag",
    "Extension",
    "BCheck",
]

