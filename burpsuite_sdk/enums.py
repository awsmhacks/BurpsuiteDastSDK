"""
Burp Suite DAST GraphQL API - Enum Types

This module contains all enum types from the GraphQL schema.
"""

from enum import Enum


class AgentWarningType(str, Enum):
    """Agent warning types."""
    AGENT_OVERALLOCATED = "agent_overallocated"
    AGENT_UNDER_SPEC = "agent_under_spec"


class ApiAuthenticationTokenDestination(str, Enum):
    """API authentication token destination."""
    HEADER = "header"
    COOKIE = "cookie"
    QUERY = "query"


class ApiAuthenticationType(str, Enum):
    """API authentication type."""
    BASIC = "basic"
    APIKEY = "apikey"
    BEARER = "bearer"
    UNSUPPORTED = "unsupported"


class ApiDynamicAuthenticationTokenRequestMethod(str, Enum):
    """API dynamic authentication token request method."""
    GET = "get"
    POST = "post"


class AuditItemSortColumn(str, Enum):
    """Indicates the column to sort audit items by."""
    HOST = "host"
    PATH = "path"
    NUMBER_OF_REQUESTS = "number_of_requests"
    NUMBER_OF_ERRORS = "number_of_errors"
    NUMBER_OF_INSERTION_POINTS = "number_of_insertion_points"


class BCheckSortColumn(str, Enum):
    """Indicates the column to sort BChecks by."""
    NAME = "name"
    DATE_ADDED = "date_added"


class Confidence(str, Enum):
    """
    The level of confidence that an identified issue is a genuine vulnerability.
    """
    TENTATIVE = "tentative"
    FIRM = "firm"
    CERTAIN = "certain"
    FALSE_POSITIVE = "false_positive"


class Counter(str, Enum):
    """Counter types."""
    NO_PERM_TO_VIEW_APP_LOGINS_MODAL_DISPLAYED = "NO_PERM_TO_VIEW_APP_LOGINS_MODAL_DISPLAYED"
    CREATE_PERM_TO_VIEW_APP_LOGINS = "CREATE_PERM_TO_VIEW_APP_LOGINS"
    RECORDED_LOGIN_REPLAY_BUTTON_PERMITTED = "RECORDED_LOGIN_REPLAY_BUTTON_PERMITTED"
    DISPLAY_APP_LOGIN_ERROR = "DISPLAY_APP_LOGIN_ERROR"


class CreatePreScanCheckError(str, Enum):
    """Error state of a new pre-scan check."""
    SCANNING_DISABLED = "scanning_disabled"
    NO_AUTHORIZED_SCANNING_MACHINES = "no_authorized_scanning_machines"
    EMPTY_SCANNING_POOL = "empty_scanning_pool"
    NO_ENABLED_MACHINES_IN_POOL = "no_enabled_machines_in_pool"


class ErrorType(str, Enum):
    """Indicates the type of error that occurred during the auditing phase."""
    UNKNOWN_HOST = "unknown_host"
    REQUEST_TIMEOUT = "request_timeout"
    BLOCKED_DOORWAY = "blocked_doorway"
    TOO_MANY_CONSECUTIVE = "too_many_consecutive"
    INSERTION_POINT_NOT_FOUND = "insertion_point_not_found"
    STREAMING_RESPONSE = "streaming_response"
    BROWSER_CRASH = "browser_crash"
    REPLAYER_ERROR = "replayer_error"
    UNKNOWN = "unknown"


class FeedbackRatingType(str, Enum):
    """Feedback rating types."""
    SCAN = "scan"


class ForwardPropagationMode(str, Enum):
    """Forward propagation mode for issues."""
    NONE = "none"
    ISSUE_TYPE_ONLY = "issue_type_only"
    ISSUE_TYPE_AND_URL = "issue_type_and_url"


class GeneratedBy(str, Enum):
    """Indicates the method in which the scan was initiated."""
    WEB_INTERFACE = "web_interface"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    EXTERNAL = "external"
    SCHEDULED = "scheduled"


class GitLabIssueState(str, Enum):
    """The state of the GitLab issue."""
    OPENED = "opened"
    CLOSED = "closed"


class GitLabIssueType(str, Enum):
    """A GitLab issue type."""
    ISSUE = "issue"
    INCIDENT = "incident"


class GitLabStateType(str, Enum):
    """A GitLab state type."""
    OPENED = "opened"
    CLOSED = "closed"


class Novelty(str, Enum):
    """
    Indicates the issue's relationship to the results of the previous scan.
    """
    REPEATED = "repeated"
    NEW = "new"
    REGRESSION = "regression"
    FIRST = "first"


class PlatformAuthenticationType(str, Enum):
    """Platform authentication type."""
    BASIC = "basic"
    NTLM_V1 = "ntlm_v1"
    NTLM_V2 = "ntlm_v2"


class PreScanCheckStatus(str, Enum):
    """The current status of a pre-scan check."""
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"
    FAILED = "failed"


class PropagationMode(str, Enum):
    """Determines whether to also mark or unmark other issues as false positives."""
    NONE = "none"
    ISSUE_TYPE_ONLY = "issue_type_only"
    ISSUE_TYPE_AND_URL = "issue_type_and_url"
    ISSUE_TYPE_AND_CURRENT_SCAN = "issue_type_and_current_scan"


class ProxyAuthenticationType(str, Enum):
    """Proxy authentication type."""
    NONE = "none"
    BASIC = "basic"
    NTLM_V1 = "ntlm_v1"
    NTLM_V2 = "ntlm_v2"


class ScanEventLogType(str, Enum):
    """Scan event log type."""
    CRITICAL = "critical"
    ERROR = "error"
    INFORMATION = "information"
    DEBUG = "debug"


class ScanPhase(str, Enum):
    """Scan phase."""
    CRAWLING = "crawling"
    AUDITING = "auditing"


class ScanReportType(str, Enum):
    """Indicates whether the scan report should be detailed or summary."""
    DETAILED = "detailed"
    SUMMARY = "summary"


class ScanStatus(str, Enum):
    """The current status of a scan."""
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"
    FAILED = "failed"
    PAUSED = "paused"


class ScanTargetType(str, Enum):
    """The type of a scan target."""
    SITE = "site"
    CIDS_SITE = "cids_site"


class ScansSortColumn(str, Enum):
    """Indicates the column to sort scans by."""
    START = "start"
    END = "end"
    STATUS = "status"
    SITE = "site"
    ID = "id"


class ScopeProtocolOptions(str, Enum):
    """Options to determine which protocols are used when scanning."""
    USE_SPECIFIED_PROTOCOLS = "USE_SPECIFIED_PROTOCOLS"
    USE_HTTP_AND_HTTPS = "USE_HTTP_AND_HTTPS"


class Severity(str, Enum):
    """The level of severity for an issue found by a scan."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SortBy(str, Enum):
    """Determines which column is used to sort schedule items."""
    START = "start"
    SITE = "site"


class SortOrder(str, Enum):
    """Determines whether sorted column is ascending or descending."""
    ASC = "asc"
    DESC = "desc"


class SystemWarningType(str, Enum):
    """System warning types."""
    METERED_BILLING = "metered_billing"
    ENTERPRISE_SERVER_UNDER_SPEC = "enterprise_server_under_spec"
    WEB_SERVER_UNDER_SPEC = "web_server_under_spec"
    AGENT_PROBLEM = "agent_problem"


class TagColor(str, Enum):
    """Available colors for tags."""
    DARK_BLUE = "DARK_BLUE"
    LIGHT_BLUE = "LIGHT_BLUE"
    NAVY = "NAVY"
    PURPLE = "PURPLE"
    MAGENTA = "MAGENTA"
    DARK_GREEN = "DARK_GREEN"
    LIGHT_GREEN = "LIGHT_GREEN"
    ORANGE = "ORANGE"
    LIGHT_ORANGE = "LIGHT_ORANGE"
    YELLOW = "YELLOW"

