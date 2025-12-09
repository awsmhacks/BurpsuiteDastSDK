# Burp Suite DAST GraphQL API SDK

A Python SDK for interacting with the Burp Suite DAST (Dynamic Application Security Testing) GraphQL API.

## Installation

```bash
# Install from local directory
pip install -e .

# Or install dependencies directly
pip install requests>=2.28.0
```

## Quick Start

### Environment Variables

Set the required environment variables:

```bash
export BURPSUITE_URL="https://your-burpsuite-server/graphql/v1"
export BURPSUITE_API_KEY="your-api-key"
```

### Basic Usage

```python
import os
from burpsuite_sdk import BurpSuiteClient, Severity, ScanStatus

# Initialize the client using environment variables
client = BurpSuiteClient(
    url=os.environ.get("BURPSUITE_URL"),
    api_key=os.environ.get("BURPSUITE_API_KEY")
)

# Or let the SDK read the API key from an environment variable
client = BurpSuiteClient(
    url=os.environ.get("BURPSUITE_URL"),
    api_key_env_var="BURPSUITE_API_KEY"
)

# Get the site tree
site_tree = client.get_site_tree()
print(f"Found {len(site_tree['sites'])} sites")

# Get all scans
scans = client.get_scans(limit=10)
for scan in scans:
    print(f"Scan {scan['id']}: {scan['status']}")
```

## Running Tests

The SDK includes a comprehensive test suite:

```bash
# Set environment variables
export BURPSUITE_URL="https://your-burpsuite-server/graphql/v1"
export BURPSUITE_API_KEY_PROD="your-api-key"

# Run tests
python3 test_sdk.py
```

## Features

### Agent Management

```python
# Get all agents
agents = client.get_agents()

# Get a specific agent by ID
agent = client.get_agent(agent_id="agent-id")

# Authorize a new agent
client.authorize_agent(machine_id="agent-machine-id")

# Enable/disable an agent
client.enable_agent(agent_id="agent-id", enabled=True)

# Update max concurrent scans
client.update_agent_max_concurrent_scans(agent_id="agent-id", max_concurrent_scans=3)

# Get agent pools
pools = client.get_agent_pools()
```

### Site Management

All site operations accept either a site ID or site name. Site names are resolved automatically (case-insensitive).

```python
from burpsuite_sdk import ScopeProtocolOptions

# Create a new site
site = client.create_site(
    name="My Application",
    start_urls=["https://example.com"],
    in_scope_url_prefixes=["https://example.com/app/"],
    out_of_scope_url_prefixes=["https://example.com/logout"],
    protocol_options=ScopeProtocolOptions.USE_SPECIFIED_PROTOCOLS
)

# Get site details - by ID or name
site = client.get_site(site_id="site-id")
site = client.get_site(site_id="My Application")  # Also works!

# Update site scope - by ID or name
client.update_site_scope(
    site_id="My Application",
    start_urls=["https://example.com"],
    in_scope_url_prefixes=["https://example.com/"]
)

# Rename a site
client.rename_site(site_id="My Application", name="New Name")

# Move a site to a folder
client.move_site(site_id="New Name", parent_id="folder-id")

# Delete a site
client.delete_site(site_id="New Name")
```

### Folder Management

```python
# Create a folder
folder = client.create_folder(
    name="Production Sites",
    description="All production environment sites"
)

# Get folder details
folder = client.get_folder(folder_id="folder-id")

# Rename a folder
client.rename_folder(folder_id="folder-id", name="New Name")

# Move a folder
client.move_folder(folder_id="folder-id", parent_id="new-parent-id")

# Delete a folder
client.delete_folder(folder_id="folder-id")
```

### Scan Operations

```python
from burpsuite_sdk import ScanStatus, ScansSortColumn, SortOrder, ScanReportType

# Get scans with filtering
scans = client.get_scans(
    limit=50,
    sort_column=ScansSortColumn.START,
    sort_order=SortOrder.DESC,
    scan_status=[ScanStatus.RUNNING, ScanStatus.SUCCEEDED]
)

# Get a specific scan
scan = client.get_scan(scan_id="scan-id")

# Cancel a scan
client.cancel_scan(scan_id="scan-id")

# Pause/resume a scan
client.pause_scan(scan_id="scan-id")
client.resume_scan(scan_id="scan-id")

# Delete a scan
client.delete_scan(scan_id="scan-id")

# Get scan report (HTML/PDF)
report = client.get_scan_report(
    scan_id="scan-id",
    report_type=ScanReportType.DETAILED
)

# Get Burp XML report
xml_report = client.get_burp_xml_report(scan_id="scan-id")
```

### Schedule Management

```python
from burpsuite_sdk import SortBy, SortOrder

# Get all schedules
schedules = client.get_schedule_items(
    sort_by=SortBy.START,
    sort_order=SortOrder.DESC
)

# Get a specific schedule
schedule = client.get_schedule_item(schedule_id="schedule-id")

# Create a scheduled scan - use site IDs or site names
schedule = client.create_schedule_item(
    site_ids=["My Application"],  # Site names work!
    initial_run_time="2024-01-15T10:00:00Z",
    rrule="FREQ=WEEKLY;INTERVAL=1;BYDAY=MO",
    name="Weekly Security Scan"
)

# Delete a schedule
client.delete_schedule_item(schedule_id="schedule-id")
```

### Issue Management

```python
from burpsuite_sdk import Severity, Confidence, Novelty, PropagationMode

# Get ALL issues for a site (uses REST API) - by ID or name
issues = client.get_site_issues(site_id="My Application")

# Get issues from a specific scan (paginated, default 100)
issues = client.get_scan_issues(
    scan_id="scan-id",
    count=200,
    severities=[Severity.HIGH, Severity.MEDIUM],
    confidences=[Confidence.CERTAIN, Confidence.FIRM]
)

# Get ALL issues from a scan (automatically handles pagination)
all_issues = client.get_all_scan_issues(
    scan_id="scan-id",
    severities=[Severity.HIGH, Severity.MEDIUM]
)

# Get detailed issue information
issue = client.get_issue(scan_id="scan-id", serial_number="issue-serial")

# Mark issue as false positive
client.mark_false_positive(
    scan_id="scan-id",
    serial_number="issue-serial",
    propagation_mode=PropagationMode.ISSUE_TYPE_AND_URL,
    note="Verified as false positive"
)

# Update issue severity
client.update_issue(
    scan_id="scan-id",
    serial_number="issue-serial",
    severity=Severity.LOW,
    note="Downgraded due to mitigating controls"
)
```

### Tag Management

```python
from burpsuite_sdk import TagColor

# Get all tags
tags = client.get_tags()

# Create a tag
tag = client.create_tag(
    name="Critical",
    color=TagColor.MAGENTA,
    description="High-priority applications"
)

# Update a tag
client.update_tag(
    tag_id="tag-id",
    name="Updated Name",
    color=TagColor.PURPLE,
    description="Updated description"
)

# Add tags to sites/folders
client.add_tags_to_nodes(
    tag_ids=["tag-id"],
    node_ids=["site-id", "folder-id"]
)

# Remove tags
client.remove_tags_from_nodes(
    tag_ids=["tag-id"],
    node_ids=["site-id"]
)

# Delete a tag
client.delete_tag(tag_id="tag-id")
```

### Scan Configurations

```python
# Get all scan configurations
configs = client.get_scan_configurations()

# Get featured scan configurations
featured = client.get_featured_scan_configurations()

# Create a custom scan configuration
config = client.create_scan_configuration(
    name="My Custom Config",
    configuration_json='{"crawl_config": {"max_link_depth": 10}}'
)

# Update a scan configuration
client.update_scan_configuration(
    config_id="config-id",
    name="Updated Name"
)

# Update site scan configurations
client.update_site_scan_configurations(
    site_id="site-id",
    scan_configuration_ids=["config-id-1", "config-id-2"]
)

# Delete a scan configuration
client.delete_scan_configuration(config_id="config-id", force=True)
```

### BChecks

```python
from burpsuite_sdk import BCheckSortColumn, SortOrder

# Get all BChecks
bchecks = client.get_bchecks(
    limit=50,
    sort_column=BCheckSortColumn.NAME,
    sort_order=SortOrder.ASC
)

# Upload a BCheck
bcheck = client.upload_bcheck(
    filename="custom-check.bcheck",
    script='metadata { ... } given request then ... end'
)

# Delete a BCheck
client.delete_bcheck(bcheck_id="bcheck-id")
```

### Extensions

```python
# Get all extensions
extensions = client.get_extensions()
```

### Pre-Scan Checks

```python
# Run a pre-scan check
result = client.create_pre_scan_check(site_id="site-id")

# Get pre-scan check results
check = client.get_pre_scan_check(site_id="site-id")

# Cancel pre-scan check
client.cancel_pre_scan_check(site_id="site-id")
```

### Settings & System

```python
# Get global settings
settings = client.get_settings()

# Get system capabilities
capabilities = client.get_capabilities()

# Get system warnings
warnings = client.get_system_warnings()

# Get forward propagation settings
fp_settings = client.get_forward_propagation_settings()

# Update forward propagation settings
from burpsuite_sdk import ForwardPropagationMode
client.update_forward_propagation_settings(
    false_positive=ForwardPropagationMode.ISSUE_TYPE_AND_URL
)
```

### Raw Query Execution

For operations not covered by the SDK methods:

```python
# Execute a custom query
result = client.execute_query("""
    query {
        agents {
            id
            name
            current_scan_count
        }
    }
""")

# Execute a custom mutation
result = client.execute_mutation("""
    mutation($input: CreateSiteInput!) {
        create_site(input: $input) {
            site { id name }
        }
    }
""", variables={"input": {"name": "Test Site", "parent_id": "0"}})
```

## Error Handling

```python
from burpsuite_sdk import (
    BurpSuiteError,
    AuthenticationError,
    GraphQLError,
    NetworkError,
    ResourceNotFoundError
)

try:
    scan = client.get_scan(scan_id="invalid-id")
except AuthenticationError:
    print("Invalid API key")
except GraphQLError as e:
    print(f"GraphQL error: {e.errors}")
except NetworkError as e:
    print(f"Network error: {e.status_code}")
except BurpSuiteError as e:
    print(f"General error: {e.message}")
```

## Configuration Options

```python
import os

client = BurpSuiteClient(
    url=os.environ.get("BURPSUITE_URL"),
    api_key=os.environ.get("BURPSUITE_API_KEY"),
    timeout=60,              # Request timeout in seconds
    verify_ssl=True,         # Verify SSL certificates
    headers={                # Additional headers
        "X-Custom-Header": "value"
    }
)
```

## Type Hints

The SDK is fully typed. All methods include type hints for better IDE support:

```python
from burpsuite_sdk import BurpSuiteClient, Severity
from typing import List, Dict, Any

client: BurpSuiteClient = BurpSuiteClient(...)
scans: List[Dict[str, Any]] = client.get_scans()
```

## Available Enums

| Enum | Values |
|------|--------|
| `Severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH` |
| `Confidence` | `TENTATIVE`, `FIRM`, `CERTAIN`, `FALSE_POSITIVE` |
| `ScanStatus` | `QUEUED`, `RUNNING`, `SUCCEEDED`, `CANCELLED`, `FAILED`, `PAUSED` |
| `Novelty` | `REPEATED`, `NEW`, `REGRESSION`, `FIRST` |
| `PropagationMode` | `NONE`, `ISSUE_TYPE_ONLY`, `ISSUE_TYPE_AND_URL`, `ISSUE_TYPE_AND_CURRENT_SCAN` |
| `SortOrder` | `ASC`, `DESC` |
| `SortBy` | `START`, `SITE` |
| `ScansSortColumn` | `START`, `END`, `STATUS`, `SITE`, `ID` |
| `BCheckSortColumn` | `NAME`, `DATE_ADDED` |
| `TagColor` | `DARK_BLUE`, `LIGHT_BLUE`, `NAVY`, `PURPLE`, `MAGENTA`, `DARK_GREEN`, `LIGHT_GREEN`, `ORANGE`, `LIGHT_ORANGE`, `YELLOW` |
| `ScanReportType` | `DETAILED`, `SUMMARY` |
| `ScopeProtocolOptions` | `USE_SPECIFIED_PROTOCOLS`, `USE_HTTP_AND_HTTPS` |
| `ForwardPropagationMode` | `NONE`, `ISSUE_TYPE_ONLY`, `ISSUE_TYPE_AND_URL` |

## License

MIT License
