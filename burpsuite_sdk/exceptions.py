"""
Burp Suite DAST GraphQL API - Exceptions

This module contains custom exception classes for the SDK.
"""

from typing import Optional, List, Dict, Any


class BurpSuiteError(Exception):
    """Base exception for all Burp Suite SDK errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(BurpSuiteError):
    """Raised when authentication fails."""
    pass


class GraphQLError(BurpSuiteError):
    """Raised when the GraphQL API returns an error."""
    
    def __init__(
        self, 
        message: str, 
        errors: Optional[List[Dict[str, Any]]] = None,
        query: Optional[str] = None
    ):
        self.errors = errors or []
        self.query = query
        super().__init__(message, {"errors": self.errors, "query": self.query})
    
    def __str__(self) -> str:
        if self.errors:
            error_messages = [e.get("message", str(e)) for e in self.errors]
            return f"{self.message}: {'; '.join(error_messages)}"
        return self.message


class NetworkError(BurpSuiteError):
    """Raised when a network error occurs."""
    
    def __init__(
        self, 
        message: str, 
        status_code: Optional[int] = None,
        response_body: Optional[str] = None
    ):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(
            message, 
            {"status_code": status_code, "response_body": response_body}
        )


class ValidationError(BurpSuiteError):
    """Raised when input validation fails."""
    pass


class ResourceNotFoundError(BurpSuiteError):
    """Raised when a requested resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(
            f"{resource_type} with ID '{resource_id}' not found",
            {"resource_type": resource_type, "resource_id": resource_id}
        )


class RateLimitError(BurpSuiteError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, retry_after: Optional[int] = None):
        self.retry_after = retry_after
        message = "Rate limit exceeded"
        if retry_after:
            message += f". Retry after {retry_after} seconds"
        super().__init__(message, {"retry_after": retry_after})


class ScanError(BurpSuiteError):
    """Raised when a scan operation fails."""
    
    def __init__(
        self, 
        message: str, 
        scan_id: Optional[str] = None,
        failure_code: Optional[int] = None,
        failure_message: Optional[str] = None
    ):
        self.scan_id = scan_id
        self.failure_code = failure_code
        self.failure_message = failure_message
        super().__init__(
            message,
            {
                "scan_id": scan_id,
                "failure_code": failure_code,
                "failure_message": failure_message
            }
        )


class ConfigurationError(BurpSuiteError):
    """Raised when there's a configuration error."""
    pass


class TimeoutError(BurpSuiteError):
    """Raised when an operation times out."""
    
    def __init__(self, operation: str, timeout_seconds: float):
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Operation '{operation}' timed out after {timeout_seconds} seconds",
            {"operation": operation, "timeout_seconds": timeout_seconds}
        )

