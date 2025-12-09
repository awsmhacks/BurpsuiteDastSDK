#!/usr/bin/env python3
"""
Burp Suite SDK Test Script

This script tests all SDK methods in a non-destructive manner.
- Creates temporary objects before testing update/delete operations
- Cleans up all temporary resources after tests
- Reports pass/fail status for each test
"""

import os
import sys
import time
import traceback
from typing import Optional, List, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from burpsuite_sdk import (
    BurpSuiteClient,
    Severity,
    ScanStatus,
    ScansSortColumn,
    SortOrder,
    SortBy,
    TagColor,
    Confidence,
    PropagationMode,
    ScanReportType,
    BCheckSortColumn,
    BurpSuiteError,
    GraphQLError,
    AuthenticationError,
)


@dataclass
class TestResult:
    """Result of a single test."""
    name: str
    passed: bool
    message: str
    duration: float


class SDKTester:
    """Comprehensive SDK tester."""
    
    def __init__(self, client: BurpSuiteClient):
        self.client = client
        self.results: List[TestResult] = []
        self.created_resources: dict = {
            "sites": [],
            "folders": [],
            "tags": [],
            "scan_configurations": [],
            "schedule_items": [],
        }
        
    def run_test(self, name: str, test_func: Callable) -> TestResult:
        """Run a single test and record the result."""
        start_time = time.time()
        try:
            test_func()
            duration = time.time() - start_time
            result = TestResult(name, True, "OK", duration)
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"{type(e).__name__}: {str(e)}"
            result = TestResult(name, False, error_msg, duration)
        
        self.results.append(result)
        status = "✓" if result.passed else "✗"
        print(f"  {status} {name}: {result.message} ({result.duration:.2f}s)")
        return result
    
    def cleanup(self):
        """Clean up all created resources."""
        print("\n🧹 Cleaning up temporary resources...")
        
        # Delete schedule items first (they reference sites)
        for schedule_id in self.created_resources["schedule_items"]:
            try:
                self.client.delete_schedule_item(schedule_id)
                print(f"  Deleted schedule item: {schedule_id}")
            except Exception as e:
                print(f"  Failed to delete schedule item {schedule_id}: {e}")
        
        # Delete sites
        for site_id in self.created_resources["sites"]:
            try:
                self.client.delete_site(site_id)
                print(f"  Deleted site: {site_id}")
            except Exception as e:
                print(f"  Failed to delete site {site_id}: {e}")
        
        # Delete folders
        for folder_id in self.created_resources["folders"]:
            try:
                self.client.delete_folder(folder_id)
                print(f"  Deleted folder: {folder_id}")
            except Exception as e:
                print(f"  Failed to delete folder {folder_id}: {e}")
        
        # Delete tags
        for tag_id in self.created_resources["tags"]:
            try:
                self.client.delete_tag(tag_id)
                print(f"  Deleted tag: {tag_id}")
            except Exception as e:
                print(f"  Failed to delete tag {tag_id}: {e}")
        
        # Delete scan configurations
        for config_id in self.created_resources["scan_configurations"]:
            try:
                self.client.delete_scan_configuration(config_id, force=True)
                print(f"  Deleted scan configuration: {config_id}")
            except Exception as e:
                print(f"  Failed to delete scan config {config_id}: {e}")
    
    def run_all_tests(self):
        """Run all tests."""
        print("=" * 60)
        print("Burp Suite SDK Test Suite")
        print("=" * 60)
        
        try:
            self.test_agent_operations()
            self.test_agent_pool_operations()
            self.test_site_operations()
            self.test_folder_operations()
            self.test_scan_operations()
            self.test_schedule_operations()
            self.test_scan_configuration_operations()
            self.test_tag_operations()
            self.test_bcheck_operations()
            self.test_settings_operations()
            self.test_integration_operations()
        finally:
            self.cleanup()
        
        self.print_summary()
    
    # =========================================================================
    # AGENT TESTS
    # =========================================================================
    
    def test_agent_operations(self):
        """Test agent-related operations."""
        print("\n📦 Testing Agent Operations...")
        
        def test_get_agents():
            agents = self.client.get_agents()
            assert isinstance(agents, list), "Expected list of agents"
        
        def test_get_unauthorized_agents():
            agents = self.client.get_unauthorized_agents()
            assert isinstance(agents, list), "Expected list of unauthorized agents"
        
        def test_get_agent():
            agents = self.client.get_agents()
            if agents:
                agent = self.client.get_agent(agents[0]["id"])
                assert agent is not None, "Expected agent data"
                assert "id" in agent, "Agent should have id"
        
        self.run_test("get_agents", test_get_agents)
        self.run_test("get_unauthorized_agents", test_get_unauthorized_agents)
        self.run_test("get_agent (if agents exist)", test_get_agent)
    
    # =========================================================================
    # AGENT POOL TESTS
    # =========================================================================
    
    def test_agent_pool_operations(self):
        """Test agent pool operations."""
        print("\n🏊 Testing Agent Pool Operations...")
        
        def test_get_agent_pools():
            pools = self.client.get_agent_pools()
            assert isinstance(pools, list), "Expected list of agent pools"
        
        self.run_test("get_agent_pools", test_get_agent_pools)
    
    # =========================================================================
    # SITE TESTS
    # =========================================================================
    
    def test_site_operations(self):
        """Test site-related operations."""
        print("\n🌐 Testing Site Operations...")
        
        created_site_id = None
        
        def test_get_site_tree():
            tree = self.client.get_site_tree()
            assert isinstance(tree, dict), "Expected dict for site tree"
            assert "sites" in tree or "folders" in tree, "Site tree should have sites or folders"
        
        def test_create_site():
            nonlocal created_site_id
            result = self.client.create_site(
                name=f"SDK_Test_Site_{int(time.time())}",
                start_urls=["https://example.com"],
                confirm_permission_to_scan=True
            )
            assert "site" in result, "Expected site in response"
            created_site_id = result["site"]["id"]
            self.created_resources["sites"].append(created_site_id)
        
        def test_get_site():
            if created_site_id:
                site = self.client.get_site(created_site_id)
                assert site is not None, "Expected site data"
                assert site["id"] == created_site_id, "Site ID should match"
        
        def test_rename_site():
            if created_site_id:
                new_name = f"SDK_Test_Site_Renamed_{int(time.time())}"
                result = self.client.rename_site(created_site_id, new_name)
                assert "site" in result, "Expected site in response"
        
        def test_update_site_scope():
            if created_site_id:
                result = self.client.update_site_scope(
                    site_id=created_site_id,
                    start_urls=["https://example.com", "https://example.com/api"],
                    confirm_permission_to_scan=True
                )
                assert "site" in result, "Expected site in response"
        
        self.run_test("get_site_tree", test_get_site_tree)
        self.run_test("create_site", test_create_site)
        self.run_test("get_site", test_get_site)
        self.run_test("rename_site", test_rename_site)
        self.run_test("update_site_scope", test_update_site_scope)
    
    # =========================================================================
    # FOLDER TESTS
    # =========================================================================
    
    def test_folder_operations(self):
        """Test folder-related operations."""
        print("\n📁 Testing Folder Operations...")
        
        created_folder_id = None
        
        def test_create_folder():
            nonlocal created_folder_id
            result = self.client.create_folder(
                name=f"SDK_Test_Folder_{int(time.time())}",
                description="Test folder created by SDK test script"
            )
            assert "folder" in result, "Expected folder in response"
            created_folder_id = result["folder"]["id"]
            self.created_resources["folders"].append(created_folder_id)
        
        def test_get_folder():
            if created_folder_id:
                folder = self.client.get_folder(created_folder_id)
                assert folder is not None, "Expected folder data"
                assert folder["id"] == created_folder_id, "Folder ID should match"
        
        def test_rename_folder():
            if created_folder_id:
                new_name = f"SDK_Test_Folder_Renamed_{int(time.time())}"
                result = self.client.rename_folder(created_folder_id, new_name)
                assert "folder" in result, "Expected folder in response"
        
        self.run_test("create_folder", test_create_folder)
        self.run_test("get_folder", test_get_folder)
        self.run_test("rename_folder", test_rename_folder)
    
    # =========================================================================
    # SCAN TESTS
    # =========================================================================
    
    def test_scan_operations(self):
        """Test scan-related operations."""
        print("\n🔍 Testing Scan Operations...")
        
        def test_get_scans():
            scans = self.client.get_scans(limit=5)
            assert isinstance(scans, list), "Expected list of scans"
        
        def test_get_scans_with_filters():
            scans = self.client.get_scans(
                limit=5,
                sort_column=ScansSortColumn.START,
                sort_order=SortOrder.DESC
            )
            assert isinstance(scans, list), "Expected list of scans"
        
        def test_get_scans_by_status():
            scans = self.client.get_scans(
                limit=5,
                scan_status=[ScanStatus.SUCCEEDED]
            )
            assert isinstance(scans, list), "Expected list of scans"
        
        def test_get_scan():
            scans = self.client.get_scans(limit=1)
            if scans:
                scan = self.client.get_scan(scans[0]["id"])
                assert scan is not None, "Expected scan data"
                assert "id" in scan, "Scan should have id"
        
        def test_get_scan_report():
            scans = self.client.get_scans(limit=1, scan_status=[ScanStatus.SUCCEEDED])
            if scans:
                try:
                    report = self.client.get_scan_report(
                        scan_id=scans[0]["id"],
                        report_type=ScanReportType.SUMMARY
                    )
                    assert isinstance(report, dict), "Expected report dict"
                except GraphQLError as e:
                    # Some scans might not have reports available
                    if "not available" not in str(e).lower():
                        raise
        
        self.run_test("get_scans", test_get_scans)
        self.run_test("get_scans_with_filters", test_get_scans_with_filters)
        self.run_test("get_scans_by_status", test_get_scans_by_status)
        self.run_test("get_scan (if scans exist)", test_get_scan)
        self.run_test("get_scan_report (if completed scans exist)", test_get_scan_report)
    
    # =========================================================================
    # SCHEDULE TESTS
    # =========================================================================
    
    def test_schedule_operations(self):
        """Test schedule-related operations."""
        print("\n📅 Testing Schedule Operations...")
        
        def test_get_schedule_items():
            items = self.client.get_schedule_items()
            assert isinstance(items, list), "Expected list of schedule items"
        
        def test_get_schedule_items_sorted():
            items = self.client.get_schedule_items(
                sort_by=SortBy.START,
                sort_order=SortOrder.DESC
            )
            assert isinstance(items, list), "Expected list of schedule items"
        
        def test_get_schedule_item():
            items = self.client.get_schedule_items()
            if items:
                item = self.client.get_schedule_item(items[0]["id"])
                assert item is not None, "Expected schedule item data"
        
        self.run_test("get_schedule_items", test_get_schedule_items)
        self.run_test("get_schedule_items_sorted", test_get_schedule_items_sorted)
        self.run_test("get_schedule_item (if schedules exist)", test_get_schedule_item)
    
    # =========================================================================
    # SCAN CONFIGURATION TESTS
    # =========================================================================
    
    def test_scan_configuration_operations(self):
        """Test scan configuration operations."""
        print("\n⚙️ Testing Scan Configuration Operations...")
        
        def test_get_scan_configurations():
            configs = self.client.get_scan_configurations()
            assert isinstance(configs, list), "Expected list of scan configurations"
            assert len(configs) > 0, "Expected at least one scan configuration"
        
        def test_get_featured_scan_configurations():
            configs = self.client.get_featured_scan_configurations()
            assert isinstance(configs, list), "Expected list of featured configurations"
        
        self.run_test("get_scan_configurations", test_get_scan_configurations)
        self.run_test("get_featured_scan_configurations", test_get_featured_scan_configurations)
    
    # =========================================================================
    # TAG TESTS
    # =========================================================================
    
    def test_tag_operations(self):
        """Test tag operations."""
        print("\n🏷️ Testing Tag Operations...")
        
        created_tag_id = None
        
        def test_get_tags():
            tags = self.client.get_tags()
            assert isinstance(tags, list), "Expected list of tags"
        
        def test_create_tag():
            nonlocal created_tag_id
            result = self.client.create_tag(
                name=f"SDK_Test_Tag_{int(time.time())}",
                color=TagColor.LIGHT_BLUE,
                description="Test tag created by SDK test script"
            )
            assert "tag" in result, "Expected tag in response"
            created_tag_id = result["tag"]["id"]
            self.created_resources["tags"].append(created_tag_id)
        
        def test_update_tag():
            if created_tag_id:
                result = self.client.update_tag(
                    tag_id=created_tag_id,
                    name=f"SDK_Test_Tag_Updated_{int(time.time())}",
                    color=TagColor.PURPLE,
                    description="Updated test tag"
                )
                assert "tag" in result, "Expected tag in response"
        
        self.run_test("get_tags", test_get_tags)
        self.run_test("create_tag", test_create_tag)
        self.run_test("update_tag", test_update_tag)
    
    # =========================================================================
    # BCHECK TESTS
    # =========================================================================
    
    def test_bcheck_operations(self):
        """Test BCheck operations."""
        print("\n✅ Testing BCheck Operations...")
        
        def test_get_bchecks():
            result = self.client.get_bchecks(limit=10)
            assert isinstance(result, dict), "Expected dict result"
            assert "bchecks" in result, "Expected bchecks in response"
            assert "total_count" in result, "Expected total_count in response"
        
        def test_get_bchecks_sorted():
            result = self.client.get_bchecks(
                limit=10,
                sort_column=BCheckSortColumn.NAME,
                sort_order=SortOrder.ASC
            )
            assert isinstance(result, dict), "Expected dict result"
        
        self.run_test("get_bchecks", test_get_bchecks)
        self.run_test("get_bchecks_sorted", test_get_bchecks_sorted)
    
    # =========================================================================
    # SETTINGS TESTS
    # =========================================================================
    
    def test_settings_operations(self):
        """Test settings and system operations."""
        print("\n🔧 Testing Settings Operations...")
        
        def test_get_settings():
            settings = self.client.get_settings()
            assert isinstance(settings, dict), "Expected dict for settings"
        
        def test_get_capabilities():
            caps = self.client.get_capabilities()
            assert isinstance(caps, dict), "Expected dict for capabilities"
        
        def test_get_system_warnings():
            warnings = self.client.get_system_warnings()
            assert isinstance(warnings, list), "Expected list of warnings"
        
        def test_get_forward_propagation_settings():
            settings = self.client.get_forward_propagation_settings()
            assert isinstance(settings, dict), "Expected dict for settings"
        
        self.run_test("get_settings", test_get_settings)
        self.run_test("get_capabilities", test_get_capabilities)
        self.run_test("get_system_warnings", test_get_system_warnings)
        self.run_test("get_forward_propagation_settings", test_get_forward_propagation_settings)
    
    # =========================================================================
    # INTEGRATION TESTS
    # =========================================================================
    
    def test_integration_operations(self):
        """Test integration operations (read-only)."""
        print("\n🔗 Testing Integration Operations (read-only)...")
        
        def test_get_extensions():
            extensions = self.client.get_extensions()
            assert isinstance(extensions, list), "Expected list of extensions"
        
        def test_raw_query():
            result = self.client.execute_query("""
                query {
                    scan_configurations {
                        id
                        name
                    }
                }
            """)
            assert "scan_configurations" in result, "Expected scan_configurations in result"
        
        self.run_test("get_extensions", test_get_extensions)
        self.run_test("execute_query (raw)", test_raw_query)
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)
        total_time = sum(r.duration for r in self.results)
        
        print(f"\nTotal Tests: {total}")
        print(f"Passed: {passed} ✓")
        print(f"Failed: {failed} ✗")
        print(f"Total Time: {total_time:.2f}s")
        print(f"Success Rate: {(passed/total*100):.1f}%")
        
        if failed > 0:
            print("\n❌ FAILED TESTS:")
            for r in self.results:
                if not r.passed:
                    print(f"  • {r.name}: {r.message}")
        
        print("\n" + "=" * 60)
        
        return failed == 0


def main():
    """Main entry point."""
    # Check for API key
    api_key = os.environ.get("BURPSUITE_API_KEY_PROD")
    if not api_key:
        print("❌ Error: BURPSUITE_API_KEY_PROD environment variable not set")
        print("Please set it with: export BURPSUITE_API_KEY_PROD='your-api-key'")
        sys.exit(1)
    
    # Get URL from environment
    url = os.environ.get("BURPSUITE_URL")
    if not url:
        print("❌ Error: BURPSUITE_URL environment variable not set")
        print("Please set it with: export BURPSUITE_URL='https://your-burpsuite-server/graphql/v1'")
        sys.exit(1)
    
    print(f"🚀 Connecting to: {url}")
    print(f"🔑 API Key: {api_key[:8]}...{api_key[-4:]}")
    
    try:
        client = BurpSuiteClient(
            url=url,
            api_key=api_key,
            timeout=60,
            verify_ssl=True
        )
        
        # Quick connectivity test
        print("\n🔌 Testing connection...")
        try:
            client.get_scan_configurations()
            print("✓ Connection successful!\n")
        except AuthenticationError:
            print("❌ Authentication failed. Check your API key.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            sys.exit(1)
        
        # Run tests
        tester = SDKTester(client)
        success = tester.run_all_tests()
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

