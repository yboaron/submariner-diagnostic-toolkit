#!/usr/bin/env python3
"""
Submariner Basic Diagnostic Analyzer
Automated pattern-matching analysis of Submariner diagnostics data
"""

import sys
import os
import tarfile
import yaml
import re
import ipaddress
from pathlib import Path
from datetime import datetime

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SubmarinerAnalyzer:
    def __init__(self, tarball_path):
        self.tarball_path = tarball_path
        self.diagnostics_dir = None
        self.findings = []
        self.issues = []
        self.recommendations = []
        self.faulty_states = []  # Track faulty states found
        self.tunnel_status = {}  # Store tunnel status for later analysis
        self.verify_tests_run = False  # Track if verify tests were executed
        self.verify_tests_passed = False  # Track if verify tests passed
        self.routeagent_data = {}  # Store RouteAgent analysis data
        self.network_topology = {}  # Store network topology analysis

    def extract_tarball(self):
        """Extract tarball to temporary directory"""
        print(f"Extracting {self.tarball_path}...")

        if not os.path.exists(self.tarball_path):
            print(f"{Colors.FAIL}ERROR: File not found: {self.tarball_path}{Colors.ENDC}")
            return False

        try:
            with tarfile.open(self.tarball_path, 'r:gz') as tar:
                # Get the root directory name from tarball
                members = tar.getmembers()
                if not members:
                    print(f"{Colors.FAIL}ERROR: Empty tarball{Colors.ENDC}")
                    return False

                root_dir = members[0].name.split('/')[0]
                self.diagnostics_dir = root_dir

                # Extract if not already extracted
                if not os.path.exists(root_dir):
                    tar.extractall()
                    print(f"{Colors.OKGREEN}✓{Colors.ENDC} Extracted to {root_dir}/")
                else:
                    print(f"{Colors.OKGREEN}✓{Colors.ENDC} Using existing directory {root_dir}/")

            return True
        except Exception as e:
            print(f"{Colors.FAIL}ERROR: Failed to extract tarball: {e}{Colors.ENDC}")
            return False

    def read_file(self, relative_path):
        """Read file content from diagnostics directory"""
        full_path = os.path.join(self.diagnostics_dir, relative_path)
        if not os.path.exists(full_path):
            return None
        try:
            with open(full_path, 'r') as f:
                return f.read()
        except:
            return None

    def read_yaml(self, relative_path):
        """Read and parse YAML file"""
        content = self.read_file(relative_path)
        if not content:
            return None
        try:
            return yaml.safe_load(content)
        except:
            return None

    def analyze_manifest(self):
        """Read manifest for metadata"""
        content = self.read_file("manifest.txt")
        if not content:
            return None

        manifest = {}
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                manifest[key.strip()] = value.strip()
        return manifest

    def detect_cni(self, cluster):
        """Detect CNI plugin from summary.html"""
        summary_html = self.read_file(f"{cluster}/gather/{cluster}/summary.html")
        if not summary_html:
            return "unknown"

        # Look for CNI Plugin in HTML table
        import re
        match = re.search(r'<td>CNI Plugin:</td>\s*<td>([^<]+)</td>', summary_html)
        if match:
            return match.group(1).strip()
        return "unknown"

    def check_version_compatibility(self):
        """Check for version mismatches between subctl and Submariner"""
        manifest_content = self.read_file("manifest.txt")
        if not manifest_content:
            return

        # Extract version information from manifest
        subctl_version = None
        cluster1_version = None
        cluster2_version = None
        version_mismatch_detected = False
        different_cluster_versions = False

        for line in manifest_content.split('\n'):
            if 'subctl version:' in line:
                match = re.search(r'v([0-9]+\.[0-9]+)', line)
                if match:
                    subctl_version = match.group(1)
            elif 'Cluster1 Submariner version:' in line:
                match = re.search(r'release-([0-9]+\.[0-9]+)', line)
                if match:
                    cluster1_version = match.group(1)
            elif 'Cluster2 Submariner version:' in line:
                match = re.search(r'release-([0-9]+\.[0-9]+)', line)
                if match:
                    cluster2_version = match.group(1)
            elif 'VERSION MISMATCH DETECTED!' in line:
                version_mismatch_detected = True
            elif 'Different Submariner versions between clusters' in line:
                different_cluster_versions = True

        # Display version information and warnings
        if subctl_version or cluster1_version or cluster2_version:
            print(f"\n{Colors.BOLD}=== Version Compatibility ==={Colors.ENDC}")
            if subctl_version:
                print(f"  subctl version: v{subctl_version}")
            if cluster1_version:
                print(f"  Cluster1 Submariner: release-{cluster1_version}")
            if cluster2_version:
                print(f"  Cluster2 Submariner: release-{cluster2_version}")

            # Check for mismatches
            if version_mismatch_detected:
                self.faulty_states.append("Version mismatch: subctl and Submariner versions don't match")
                print(f"\n  {Colors.FAIL}✗ VERSION MISMATCH DETECTED{Colors.ENDC}")

                if subctl_version and cluster1_version and subctl_version != cluster1_version:
                    print(f"    Cluster1: subctl v{subctl_version} vs Submariner release-{cluster1_version}")
                    self.recommendations.append(f"Update subctl to version v{cluster1_version} to match Submariner deployment")

                if subctl_version and cluster2_version and subctl_version != cluster2_version:
                    print(f"    Cluster2: subctl v{subctl_version} vs Submariner release-{cluster2_version}")
                    if not (subctl_version and cluster1_version and subctl_version != cluster1_version):
                        self.recommendations.append(f"Update subctl to version v{cluster2_version} to match Submariner deployment")

                self.recommendations.append("Version mismatches can cause unexpected behavior and test failures")

                # Display prominent warning about incorrect results
                print(f"\n  {Colors.FAIL}{'='*60}{Colors.ENDC}")
                print(f"  {Colors.FAIL}WARNING: Version mismatch could lead to INCORRECT RESULTS{Colors.ENDC}")
                print(f"  {Colors.FAIL}{'='*60}{Colors.ENDC}")
                print(f"  {Colors.WARNING}The diagnostic analysis below may be misleading or inaccurate due to{Colors.ENDC}")
                print(f"  {Colors.WARNING}incompatibility between subctl CLI and deployed Submariner components.{Colors.ENDC}")
                print(f"  {Colors.WARNING}Recommend fixing version mismatch before trusting analysis results.{Colors.ENDC}")
                print(f"  {Colors.FAIL}{'='*60}{Colors.ENDC}")

            if different_cluster_versions:
                self.faulty_states.append("Different Submariner versions between clusters")
                print(f"\n  {Colors.WARNING}⚠ Different Submariner versions between clusters{Colors.ENDC}")
                print(f"    Cluster1: release-{cluster1_version}")
                print(f"    Cluster2: release-{cluster2_version}")
                print(f"    This is NOT recommended and may cause compatibility issues")
                self.recommendations.append("Update both clusters to use the same Submariner version")

                # Display warning about potential issues
                print(f"\n  {Colors.WARNING}{'='*60}{Colors.ENDC}")
                print(f"  {Colors.WARNING}WARNING: Different cluster versions may cause issues{Colors.ENDC}")
                print(f"  {Colors.WARNING}{'='*60}{Colors.ENDC}")
                print(f"  {Colors.WARNING}Running different Submariner versions between clusters is NOT{Colors.ENDC}")
                print(f"  {Colors.WARNING}recommended and may lead to tunnel negotiation or compatibility issues.{Colors.ENDC}")
                print(f"  {Colors.WARNING}{'='*60}{Colors.ENDC}")

            if not version_mismatch_detected and not different_cluster_versions:
                if cluster1_version and cluster2_version and cluster1_version == cluster2_version:
                    if subctl_version and subctl_version == cluster1_version:
                        print(f"  {Colors.OKGREEN}✓ All versions compatible (v{subctl_version}){Colors.ENDC}")

    def check_faulty_states(self):
        """Check for faulty states before starting deep analysis"""
        print(f"\n{Colors.BOLD}=== Checking for Faulty States ==={Colors.ENDC}")

        # Check version compatibility first
        self.check_version_compatibility()

        # Check tunnel status
        cluster1_show = self.read_file("cluster1/subctl-show-all.txt")
        cluster2_show = self.read_file("cluster2/subctl-show-all.txt")

        if cluster1_show and cluster2_show:
            status1 = self.extract_tunnel_status(cluster1_show, "cluster1")
            status2 = self.extract_tunnel_status(cluster2_show, "cluster2")

            if status1 and status2:
                self.tunnel_status = {
                    'cluster1': status1,
                    'cluster2': status2
                }

                if status1['status'] != 'connected':
                    self.faulty_states.append(f"Cluster1 tunnel: {status1['status']}")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Cluster1 → Cluster2: {status1['status']}")
                else:
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Cluster1 → Cluster2: connected")

                if status2['status'] != 'connected':
                    self.faulty_states.append(f"Cluster2 tunnel: {status2['status']}")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Cluster2 → Cluster1: {status2['status']}")
                else:
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Cluster2 → Cluster1: connected")

        # Check verify tests
        self.check_verify_tests()

        # Check firewall diagnostics
        self.check_firewall_diagnostics()

        if not self.faulty_states:
            print(f"\n{Colors.OKGREEN}✓ No faulty states detected - Submariner deployment appears healthy{Colors.ENDC}")
            return False
        else:
            print(f"\n{Colors.WARNING}Found {len(self.faulty_states)} faulty state(s) - starting deep analysis...{Colors.ENDC}")
            return True

    def check_verify_tests(self):
        """Check subctl verify test results"""
        verify_dir = os.path.join(self.diagnostics_dir, "verify")
        if not os.path.exists(verify_dir):
            return

        connectivity_passed = False
        connectivity_failed = False
        small_packet_passed = False
        small_packet_failed = False
        svc_discovery_passed = False
        svc_discovery_failed = False
        tests_found = False

        # Check connectivity tests
        connectivity = self.read_file("verify/connectivity.txt")
        if connectivity and "SKIPPED" not in connectivity:
            tests_found = True
            self.verify_tests_run = True

            # Check if tests were stopped early
            early_stop_match = re.search(r'stopped early after (\d+) consecutive test failures', connectivity)

            # Check for Ginkgo test output (SUCCESS! or failures)
            # Look for pattern like "SUCCESS! -- X Passed | 0 Failed" or "X Failed"
            if "SUCCESS!" in connectivity or (re.search(r'\d+\s+Passed.*0\s+Failed', connectivity)):
                connectivity_passed = True
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Connectivity verification: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', connectivity) or "FAILURE" in connectivity:
                connectivity_failed = True
                if early_stop_match:
                    num_tests = early_stop_match.group(1)
                    self.faulty_states.append(f"Connectivity verification failed (stopped early after {num_tests} failures)")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED (stopped early after {num_tests} failures)")
                else:
                    self.faulty_states.append("Connectivity verification failed")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED")
            else:
                # Fallback for older format or errors
                if "FAIL" in connectivity or "error" in connectivity.lower():
                    connectivity_failed = True
                    if early_stop_match:
                        num_tests = early_stop_match.group(1)
                        self.faulty_states.append(f"Connectivity verification failed (stopped early after {num_tests} failures)")
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED (stopped early after {num_tests} failures)")
                    else:
                        self.faulty_states.append("Connectivity verification failed")
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED")
                elif "PASS" in connectivity:
                    connectivity_passed = True
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Connectivity verification: PASSED")
                else:
                    # Test file exists but no clear result
                    connectivity_failed = True
                    self.faulty_states.append("Connectivity verification inconclusive")
                    print(f"  {Colors.WARNING}⚠{Colors.ENDC} Connectivity verification: INCONCLUSIVE")

        # Check small packet tests (MTU testing)
        small_packet = self.read_file("verify/connectivity-small-packet.txt")
        if small_packet and "SMALL PACKET TEST SKIPPED" in small_packet:
            # Check why it was skipped
            if "regular connectivity test passed" in small_packet.lower():
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Small packet verification: SKIPPED (regular test passed, no MTU issue)")
            else:
                print(f"  {Colors.WARNING}⚠{Colors.ENDC} Small packet verification: SKIPPED")
        elif small_packet and "SKIPPED" not in small_packet:
            tests_found = True
            self.verify_tests_run = True

            # Check if tests were stopped early
            early_stop_match = re.search(r'stopped early after (\d+) consecutive test failures', small_packet)

            # Check for Ginkgo test output (SUCCESS! or failures)
            if "SUCCESS!" in small_packet or (re.search(r'\d+\s+Passed.*0\s+Failed', small_packet)):
                small_packet_passed = True
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Small packet verification: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', small_packet) or "FAILURE" in small_packet:
                small_packet_failed = True
                if early_stop_match:
                    num_tests = early_stop_match.group(1)
                    self.faulty_states.append(f"Small packet verification failed (stopped early after {num_tests} failures)")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED (stopped early after {num_tests} failures)")
                else:
                    self.faulty_states.append("Small packet verification failed")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED")
            else:
                # Fallback for older format or errors
                if "FAIL" in small_packet or "error" in small_packet.lower():
                    small_packet_failed = True
                    if early_stop_match:
                        num_tests = early_stop_match.group(1)
                        self.faulty_states.append(f"Small packet verification failed (stopped early after {num_tests} failures)")
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED (stopped early after {num_tests} failures)")
                    else:
                        self.faulty_states.append("Small packet verification failed")
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED")
                elif "PASS" in small_packet:
                    small_packet_passed = True
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Small packet verification: PASSED")
                else:
                    # Test file exists but no clear result
                    small_packet_failed = True
                    self.faulty_states.append("Small packet verification inconclusive")
                    print(f"  {Colors.WARNING}⚠{Colors.ENDC} Small packet verification: INCONCLUSIVE")

        # Check for MTU issue pattern: regular packets fail, small packets pass
        if connectivity_failed and small_packet_passed:
            print(f"\n  {Colors.FAIL}✗ MTU ISSUE DETECTED:{Colors.ENDC}")
            print(f"    Regular packets (default size): FAILED")
            print(f"    Small packets (400 bytes): PASSED")
            print(f"    → This indicates an MTU/fragmentation issue caused by Submariner's encapsulation overhead")
            self.faulty_states.append("MTU issue detected (regular packets fail, small packets pass)")
            self.issues.append("MTU/fragmentation issue preventing large packet transmission")
            self.recommendations.insert(0, "Apply TCP MSS clamping: kubectl annotate node <gateway-node> submariner.io/tcp-clamp-mss=<mss-clamp-value>")
            self.recommendations.insert(1, "Restart routeagent pods to apply the changes: kubectl delete pod -n submariner-operator -l app=submariner-routeagent")
            self.recommendations.insert(2, "Recommended MSS value: 1300 (conservative value for most networks)")
            self.recommendations.insert(3, "See official documentation: https://submariner.io/getting-started/architecture/gateway-engine/ (Customize TCP MSS Clamping)")

        # Check service discovery
        svc_discovery = self.read_file("verify/service-discovery.txt")
        if svc_discovery and "SKIPPED" not in svc_discovery:
            tests_found = True
            self.verify_tests_run = True

            # Check if tests were stopped early
            early_stop_match = re.search(r'stopped early after (\d+) consecutive test failures', svc_discovery)

            # Check for Ginkgo test output (SUCCESS! or failures)
            if "SUCCESS!" in svc_discovery or (re.search(r'\d+\s+Passed.*0\s+Failed', svc_discovery)):
                svc_discovery_passed = True
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Service discovery verification: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', svc_discovery) or "FAILURE" in svc_discovery:
                svc_discovery_failed = True
                if early_stop_match:
                    num_tests = early_stop_match.group(1)
                    self.faulty_states.append(f"Service discovery verification failed (stopped early after {num_tests} failures)")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED (stopped early after {num_tests} failures)")
                else:
                    self.faulty_states.append("Service discovery verification failed")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED")
            else:
                # Fallback for older format or errors
                if "FAIL" in svc_discovery or "error" in svc_discovery.lower():
                    svc_discovery_failed = True
                    if early_stop_match:
                        num_tests = early_stop_match.group(1)
                        self.faulty_states.append(f"Service discovery verification failed (stopped early after {num_tests} failures)")
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED (stopped early after {num_tests} failures)")
                    else:
                        self.faulty_states.append("Service discovery verification failed")
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED")
                elif "PASS" in svc_discovery:
                    svc_discovery_passed = True
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Service discovery verification: PASSED")
                else:
                    # Test file exists but no clear result
                    svc_discovery_failed = True
                    self.faulty_states.append("Service discovery verification inconclusive")
                    print(f"  {Colors.WARNING}⚠{Colors.ENDC} Service discovery verification: INCONCLUSIVE")

        # Check for OVNK SNAT issue pattern
        skip_src_ip_check = self.read_file("verify/connectivity-skip-src-ip-check.txt")
        if skip_src_ip_check:
            skip_src_ip_passed = False
            skip_src_ip_failed = False

            # Check if skip-src-ip-check test passed
            if "SUCCESS!" in skip_src_ip_check or (re.search(r'\d+\s+Passed.*0\s+Failed', skip_src_ip_check)):
                skip_src_ip_passed = True
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Connectivity with --skip-src-ip-check: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', skip_src_ip_check) or "FAILURE" in skip_src_ip_check or "FAIL" in skip_src_ip_check:
                skip_src_ip_failed = True
                print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity with --skip-src-ip-check: FAILED")

            # Detect OVNK SNAT issue: regular connectivity failed but skip-src-ip-check passed
            if connectivity_failed and skip_src_ip_passed:
                # Detect CNI to confirm OVNK
                cni_cluster1 = self.detect_cni("cluster1")
                cni_cluster2 = self.detect_cni("cluster2")

                print(f"\n  {Colors.FAIL}✗ OVNK SNAT ISSUE DETECTED:{Colors.ENDC}")
                print(f"    Regular connectivity tests: FAILED")
                print(f"    Connectivity with --skip-src-ip-check: PASSED")
                print(f"    CNI detected: Cluster1={cni_cluster1}, Cluster2={cni_cluster2}")
                print(f"    → This indicates OVNK SNAT is breaking Submariner connectivity")
                self.faulty_states.append("OVNK SNAT issue detected (regular connectivity fails, --skip-src-ip-check passes)")
                self.issues.append(f"OVNK CNI SNAT prevents Submariner cross-cluster connectivity (CNI: {cni_cluster1}/{cni_cluster2})")
                self.recommendations.insert(0, "OVNK SNAT Issue: Apply the OVNK fix for Submariner compatibility")
                self.recommendations.insert(1, "Check if your OVNK version has the Submariner SNAT fix available")
                self.recommendations.insert(2, "See: https://github.com/ovn-org/ovn-kubernetes/pull/XXXXX (OVNK fix for Submariner)")
                self.recommendations.insert(3, "Workaround: Use --skip-src-ip-check flag for testing (not recommended for production)")

        # Set verify_tests_passed only if ALL tests that ran passed
        if tests_found:
            # All tests must pass for verify_tests_passed to be True
            all_passed = True
            if connectivity and "SKIPPED" not in connectivity and not connectivity_passed:
                all_passed = False
            if small_packet and "SKIPPED" not in small_packet and not small_packet_passed:
                all_passed = False
            if svc_discovery and "SKIPPED" not in svc_discovery and not svc_discovery_passed:
                all_passed = False

            self.verify_tests_passed = all_passed

    def check_firewall_diagnostics(self):
        """
        Check firewall diagnostics results (inter-cluster and intra-cluster)

        Inter-cluster: Only runs when at least one tunnel is NOT connected AND using UDP encapsulation (VxLAN or IPSec NAT-T)
        Intra-cluster: Only runs when CNI is NOT OVN-Kubernetes (checked per cluster)

        Also cross-references:
        - tcpdump data (for UDP traffic patterns)
        - IPsec counters from gather data (for IPsec tunnel analysis)
        """
        firewall_dir = os.path.join(self.diagnostics_dir, "firewall")
        if not os.path.exists(firewall_dir):
            return

        firewall_issues_found = False

        # Detect NAT-T port from Submariner CR (default 4500)
        natt_port = 4500  # default
        submariner_yaml = self.read_yaml("cluster1/gather/cluster1/submariners_submariner-operator_submariner.yaml")
        if submariner_yaml and 'spec' in submariner_yaml and 'ceIPSecNATTPort' in submariner_yaml['spec']:
            natt_port = submariner_yaml['spec']['ceIPSecNATTPort']

        # Check inter-cluster firewall diagnostics
        # Prerequisites: At least one tunnel NOT connected + UDP encapsulation (VxLAN or IPSec NAT-T)
        inter_cluster = self.read_file("firewall/firewall-inter-cluster.txt")
        if inter_cluster:
            print(f"\n{Colors.BOLD}=== Firewall Inter-Cluster Diagnostics ==={Colors.ENDC}")
            print(f"  Prerequisites: Tunnel not connected + UDP encapsulation (VxLAN/IPSec NAT-T)")

            # Check for successful completion
            if "Tunnels can be established" in inter_cluster and "✓" in inter_cluster:
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Inter-cluster firewall: PASSED")
                print(f"    UDP ports are open - firewall is NOT blocking tunnel traffic")
                self.recommendations.append("Firewall is OK - investigate other tunnel issues: routing, IPsec config, or endpoint reachability")

                # Cross-reference with IPsec counters if available
                self.recommendations.append("Check IPsec counters in gather data (ipsec-trafficstatus.log) to verify traffic flow")
            elif "CONTEXT: This test was run because:" in inter_cluster:
                # Test ran - check for failures
                if "error" in inter_cluster.lower() or "fail" in inter_cluster.lower() or "cannot" in inter_cluster.lower() or "timed out" in inter_cluster.lower():
                    firewall_issues_found = True
                    self.faulty_states.append("Inter-cluster firewall blocking UDP traffic")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Inter-cluster firewall: FAILED")
                    print(f"    UDP ports blocked by firewall/security groups")

                    # Cross-reference with tcpdump data
                    tcpdump_dir = os.path.join(self.diagnostics_dir, "tcpdump")
                    if os.path.exists(tcpdump_dir):
                        print(f"    {Colors.WARNING}Additional data:{Colors.ENDC} Check tcpdump/ for UDP traffic patterns")
                        print(f"      - Look for outbound UDP packets on port {natt_port} (NAT-T)")
                        print(f"      - Check if UDP packets are egressing but not ingressing")

                    # Reference IPsec counters
                    print(f"    {Colors.WARNING}Additional data:{Colors.ENDC} Check IPsec counters in gather/")
                    print(f"      - cluster*/gather/cluster*/ipsec-trafficstatus.log")
                    print(f"      - Look for 0 bytes in/out indicating no traffic flow")

                    self.recommendations.append(f"Fix inter-cluster firewall: allow UDP traffic on NAT-T port {natt_port} between gateway nodes")
                    self.recommendations.append("Cloud environments: Check security group rules between gateway node IPs")
                    self.recommendations.append(f"On-premise: Verify firewall allows UDP {natt_port} or ESP (protocol 50) depending on cable driver config")
                    self.recommendations.append(f"Cross-check tcpdump data: verify UDP packets on port {natt_port} are flowing in both directions")
                    self.recommendations.append("Check IPsec traffic counters: ipsec-trafficstatus.log should show non-zero bytes if traffic flowing")

                    # Extract specific error
                    error_match = re.search(r'(error|Error|ERROR|FAILED|timeout)[^\n]*', inter_cluster)
                    if error_match:
                        print(f"    Error: {error_match.group(0)}")
                else:
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Inter-cluster firewall: PASSED")
                    self.recommendations.append("Firewall OK - check other tunnel issues (routing, IPsec, endpoints)")
                    self.recommendations.append("Verify IPsec counters in ipsec-trafficstatus.log show traffic flowing")

        # Check intra-cluster firewall diagnostics for cluster1
        # Prerequisites: CNI is NOT OVN-Kubernetes
        # Expected symptoms if failed: RouteAgent failures + verify test failures from non-gateway pods
        intra_cluster1 = self.read_file("firewall/firewall-intra-cluster-cluster1.txt")
        if intra_cluster1:
            print(f"\n{Colors.BOLD}=== Firewall Intra-Cluster Diagnostics (Cluster1) ==={Colors.ENDC}")
            print(f"  Prerequisites: CNI is NOT OVN-Kubernetes")

            # Check for successful completion
            if "firewall configuration allows intra-cluster VXLAN traffic" in intra_cluster1 and "✓" in intra_cluster1:
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Intra-cluster firewall (cluster1): PASSED")

                # Check tcpdump packet count
                packet_match = re.search(r'(\d+)\s+packets captured', intra_cluster1)
                if packet_match:
                    packet_count = int(packet_match.group(1))
                    if packet_count > 0:
                        print(f"    {packet_count} packets on vx-submariner - VXLAN traffic flowing")
                    else:
                        print(f"    {Colors.WARNING}⚠{Colors.ENDC} 0 packets captured (might be low traffic, not necessarily firewall issue)")
            elif "CONTEXT: This test was run because:" in intra_cluster1:
                # Test ran - check for failures
                if "error" in intra_cluster1.lower() or "fail" in intra_cluster1.lower():
                    firewall_issues_found = True
                    self.faulty_states.append("Intra-cluster firewall blocking VXLAN on cluster1")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Intra-cluster firewall (cluster1): FAILED")
                    print(f"    VXLAN traffic blocked on vx-submariner interface")
                    print(f"    {Colors.WARNING}Expected symptoms:{Colors.ENDC}")
                    print(f"      • RouteAgent failures on cluster1")
                    print(f"      • subctl verify tests fail when pods scheduled on non-gateway nodes")
                    self.recommendations.append("Fix intra-cluster firewall on cluster1: allow VXLAN traffic on vx-submariner interface")
                    self.recommendations.append("Verify RouteAgent status on cluster1")
                    self.recommendations.append("Check verify tests: failures from non-gateway pods indicate intra-cluster firewall issues")

        # Check intra-cluster firewall diagnostics for cluster2
        # Prerequisites: CNI is NOT OVN-Kubernetes
        intra_cluster2 = self.read_file("firewall/firewall-intra-cluster-cluster2.txt")
        if intra_cluster2:
            print(f"\n{Colors.BOLD}=== Firewall Intra-Cluster Diagnostics (Cluster2) ==={Colors.ENDC}")
            print(f"  Prerequisites: CNI is NOT OVN-Kubernetes")

            # Check for successful completion
            if "firewall configuration allows intra-cluster VXLAN traffic" in intra_cluster2 and "✓" in intra_cluster2:
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Intra-cluster firewall (cluster2): PASSED")

                # Check tcpdump packet count
                packet_match = re.search(r'(\d+)\s+packets captured', intra_cluster2)
                if packet_match:
                    packet_count = int(packet_match.group(1))
                    if packet_count > 0:
                        print(f"    {packet_count} packets on vx-submariner - VXLAN traffic flowing")
                    else:
                        print(f"    {Colors.WARNING}⚠{Colors.ENDC} 0 packets captured (might be low traffic, not necessarily firewall issue)")
            elif "CONTEXT: This test was run because:" in intra_cluster2:
                # Test ran - check for failures
                if "error" in intra_cluster2.lower() or "fail" in intra_cluster2.lower():
                    firewall_issues_found = True
                    self.faulty_states.append("Intra-cluster firewall blocking VXLAN on cluster2")
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} Intra-cluster firewall (cluster2): FAILED")
                    print(f"    VXLAN traffic blocked on vx-submariner interface")
                    print(f"    {Colors.WARNING}Expected symptoms:{Colors.ENDC}")
                    print(f"      • RouteAgent failures on cluster2")
                    print(f"      • subctl verify tests fail when pods scheduled on non-gateway nodes")
                    self.recommendations.append("Fix intra-cluster firewall on cluster2: allow VXLAN traffic on vx-submariner interface")
                    self.recommendations.append("Verify RouteAgent status on cluster2")
                    self.recommendations.append("Check verify tests: failures from non-gateway pods indicate intra-cluster firewall issues")

    def analyze_tunnel_status(self):
        """Analyze tunnel connectivity status in detail"""
        print(f"\n{Colors.BOLD}=== Analyzing Tunnel Status ==={Colors.ENDC}")

        if not self.tunnel_status:
            cluster1_show = self.read_file("cluster1/subctl-show-all.txt")
            cluster2_show = self.read_file("cluster2/subctl-show-all.txt")

            if not cluster1_show or not cluster2_show:
                self.issues.append("Missing subctl show output files")
                return

            # Parse tunnel status from cluster1
            status1 = self.extract_tunnel_status(cluster1_show, "cluster1")
            status2 = self.extract_tunnel_status(cluster2_show, "cluster2")

            if not status1 or not status2:
                self.issues.append("Could not parse tunnel status")
                return

            self.tunnel_status = {
                'cluster1': status1,
                'cluster2': status2
            }

        status1 = self.tunnel_status['cluster1']
        status2 = self.tunnel_status['cluster2']

        print(f"  Cluster1 → Cluster2: {self.colorize_status(status1['status'])}")
        print(f"  Cluster2 → Cluster1: {self.colorize_status(status2['status'])}")

        self.findings.append(f"Cluster1 status: {status1['status']}")
        self.findings.append(f"Cluster2 status: {status2['status']}")

        # Analyze tunnel issues
        if status1['status'] == 'connected' and status2['status'] == 'connected':
            print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Tunnels connected on both clusters")
        else:
            if status1['status'] != 'connected':
                self.issues.append(f"Cluster1 tunnel status: {status1['status']}")
            if status2['status'] != 'connected':
                self.issues.append(f"Cluster2 tunnel status: {status2['status']}")

            # Detect blocking type
            self.detect_blocking_type()

    def extract_tunnel_status(self, show_output, cluster_name):
        """Extract tunnel status from subctl show output"""
        lines = show_output.split('\n')
        for i, line in enumerate(lines):
            if 'Showing Connections' in line:
                # Look for the connection line (skip header)
                for j in range(i+1, min(i+5, len(lines))):
                    if lines[j].strip() and not lines[j].startswith('GATEWAY'):
                        parts = lines[j].split()
                        if len(parts) >= 7:
                            return {
                                'gateway': parts[0],
                                'cluster': parts[1],
                                'remote_ip': parts[2],
                                'nat': parts[3],
                                'cable_driver': parts[4],
                                'status': parts[-2]  # Second to last field is STATUS
                            }
        return None

    def detect_blocking_type(self):
        """Detect if ESP or UDP is being blocked"""
        print(f"\n{Colors.BOLD}=== Detecting Blocking Type ==={Colors.ENDC}")

        # Read Gateway CRs
        gateway1 = self.find_and_read_gateway_cr("cluster1")
        gateway2 = self.find_and_read_gateway_cr("cluster2")

        if not gateway1 and not gateway2:
            print(f"  {Colors.WARNING}⚠{Colors.ENDC} Could not read Gateway CRs")
            return

        # Analyze cluster1
        if gateway1:
            self.analyze_gateway_blocking(gateway1, "cluster1")

        # Analyze cluster2
        if gateway2:
            self.analyze_gateway_blocking(gateway2, "cluster2")

    def find_and_read_gateway_cr(self, cluster):
        """Find and read the Gateway CR YAML"""
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
        if not os.path.exists(gather_dir):
            return None

        # Find cluster subdirectory
        for subdir in os.listdir(gather_dir):
            subdir_path = os.path.join(gather_dir, subdir)
            if os.path.isdir(subdir_path):
                # Look for submariner CR YAML
                for file in os.listdir(subdir_path):
                    if file.startswith("submariners_") and file.endswith(".yaml"):
                        return self.read_yaml(os.path.join(cluster, "gather", subdir, file))
        return None

    def analyze_gateway_blocking(self, gateway_cr, cluster_name):
        """Analyze Gateway CR for blocking patterns"""
        if not gateway_cr or 'status' not in gateway_cr:
            return

        status = gateway_cr.get('status', {})
        gateways = status.get('gateways', [])

        for gw in gateways:
            connections = gw.get('connections', [])
            for conn in connections:
                endpoint = conn.get('endpoint', {})
                backend = endpoint.get('backend', '')
                private_ip = endpoint.get('private_ip', '')
                public_ip = endpoint.get('public_ip', '')
                using_ip = conn.get('usingIP', '')
                conn_status = conn.get('status', '')
                status_msg = conn.get('statusMessage', '')

                if conn_status != 'connected' and backend == 'libreswan':
                    # ESP blocking pattern
                    if using_ip == private_ip:
                        self.issues.append(f"{cluster_name}: Appears to be infrastructure/firewall issue preventing IPsec tunnel")
                        self.recommendations.append(
                            f"{cluster_name}: Verify infrastructure configuration, consider UDP encapsulation as alternative"
                        )
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster_name}: It seems like infrastructure/firewall is preventing Submariner IPsec tunnel")
                        print(f"    Using IP: {using_ip} (private IP - suggests ESP protocol (IP protocol 50))")
                        print(f"    → Verify all required Submariner ports/protocols are allowed in your infrastructure")
                        print(f"    → Alternative: Enable UDP encapsulation if ESP is blocked")

                    # UDP blocking pattern
                    elif using_ip == public_ip:
                        self.issues.append(f"{cluster_name}: Appears to be UDP port blocking at infrastructure level")
                        self.recommendations.append(
                            f"{cluster_name}: Verify firewall allows UDP ports 500/4500, consider VxLAN as alternative"
                        )
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster_name}: It seems like UDP ports may be blocked at infrastructure level")
                        print(f"    Using IP: {using_ip} (public IP - UDP encapsulation)")
                        print(f"    → Verify UDP ports 500 and 4500 are allowed in firewall/security groups")
                        print(f"    → Alternative: Consider VxLAN cable driver if UDP is blocked")

    def analyze_tcpdump(self):
        """Analyze tcpdump data if available"""
        tcpdump_dir = os.path.join(self.diagnostics_dir, "tcpdump")
        if not os.path.exists(tcpdump_dir):
            return

        print(f"\n{Colors.BOLD}=== Analyzing Packet Captures ==={Colors.ENDC}")

        # Find analysis files with glob pattern
        import glob
        cluster1_files = glob.glob(os.path.join(tcpdump_dir, "cluster1-gateway-*-analysis.txt"))
        cluster2_files = glob.glob(os.path.join(tcpdump_dir, "cluster2-gateway-*-analysis.txt"))

        cluster1_analysis = None
        cluster2_analysis = None

        if cluster1_files:
            cluster1_analysis = self.read_file(os.path.relpath(cluster1_files[0], self.diagnostics_dir))
        if cluster2_files:
            cluster2_analysis = self.read_file(os.path.relpath(cluster2_files[0], self.diagnostics_dir))

        if not cluster1_analysis and not cluster2_analysis:
            print(f"  {Colors.WARNING}⚠{Colors.ENDC} No tcpdump analysis files found")
            return

        # Detect protocol from capture filter
        protocol_info = self.detect_protocol_from_tcpdump(cluster1_analysis or cluster2_analysis)

        # Extract packet counts and directions
        packets1_total = self.extract_packet_count(cluster1_analysis) if cluster1_analysis else 0
        packets2_total = self.extract_packet_count(cluster2_analysis) if cluster2_analysis else 0

        # Check for bidirectional traffic (presence of "In" direction packets)
        packets1_in = self.check_packet_direction(cluster1_analysis, "In") if cluster1_analysis else False
        packets1_out = self.check_packet_direction(cluster1_analysis, "Out") if cluster1_analysis else False
        packets2_in = self.check_packet_direction(cluster2_analysis, "In") if cluster2_analysis else False
        packets2_out = self.check_packet_direction(cluster2_analysis, "Out") if cluster2_analysis else False

        print(f"  Cluster1 gateway: {packets1_total} packets captured")
        if packets1_total > 0:
            direction = []
            if packets1_out: direction.append("Out")
            if packets1_in: direction.append("In")
            print(f"    Direction: {', '.join(direction) if direction else 'Unknown'}")

        print(f"  Cluster2 gateway: {packets2_total} packets captured")
        if packets2_total > 0:
            direction = []
            if packets2_out: direction.append("Out")
            if packets2_in: direction.append("In")
            print(f"    Direction: {', '.join(direction) if direction else 'Unknown'}")

        # Analyze bidirectional traffic patterns
        if packets1_total > 0 and packets2_total > 0:
            # Both clusters sending packets
            if packets1_out and not packets1_in and packets2_out and not packets2_in:
                # Both sending, neither receiving (bidirectional blocking)
                self.issues.append(f"CRITICAL: Both clusters sending tunnel packets but neither receiving → Appears to be infrastructure blocking {protocol_info['description']} in both directions")

                # Build recommendations based on protocol type
                if protocol_info['type'] == 'esp':
                    self.recommendations.append(f"Verify Submariner prerequisites - ensure {protocol_info['description']} is allowed between gateway nodes")
                    self.recommendations.append("Enable UDP encapsulation (ceIPSecForceUDPEncaps: true) as workaround if ESP is blocked but UDP port 4500 is allowed")
                elif protocol_info['type'] == 'udp':
                    self.recommendations.append(f"Verify Submariner prerequisites - ensure {protocol_info['description']} is allowed between gateway nodes")
                else:
                    self.recommendations.append("Verify Submariner prerequisites - ensure required protocols are allowed between gateway nodes")

                print(f"\n  {Colors.FAIL}✗ CRITICAL FINDING:{Colors.ENDC}")
                print(f"    Both clusters sending packets but NEITHER receiving")
                print(f"    → It seems that infrastructure is blocking {protocol_info['description']} in BOTH directions")
                print(f"    → Packets appear to leave source but not arrive at destination")
                print(f"\n  {Colors.BOLD}Recommended Investigation:{Colors.ENDC}")
                print(f"    1. Verify infrastructure allows {protocol_info['description']} between gateway nodes")
                print(f"    2. Check firewall/security groups/network policies")
                if protocol_info['type'] == 'esp':
                    print(f"    3. Try UDP encapsulation as workaround if ESP is blocked")
                print(f"    📖 Submariner Prerequisites: https://submariner.io/operations/deployment/prerequisites/")
            elif packets1_in and packets1_out and packets2_in and packets2_out:
                # Bidirectional traffic working
                print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Bidirectional packet flow detected")
                self.findings.append("Bidirectional tunnel traffic flowing correctly")
        elif packets1_total > 0 and packets2_total == 0:
            # Cluster1 sending, cluster2 not
            self.issues.append(f"Cluster1 sending packets but Cluster2 not receiving → Appears to be unidirectional infrastructure blocking {protocol_info['description']}")
            self.recommendations.append(f"Verify firewall allows {protocol_info['description']} from Cluster1 to Cluster2")
            print(f"  {Colors.FAIL}✗{Colors.ENDC} Packets leaving cluster1 but NOT reaching cluster2")
            print(f"    → Appears to be unidirectional infrastructure blocking {protocol_info['description']} (cluster1 → cluster2)")
        elif packets1_total == 0 and packets2_total > 0:
            # Cluster2 sending, cluster1 not
            self.issues.append(f"Cluster2 sending packets but Cluster1 not receiving → Appears to be unidirectional infrastructure blocking {protocol_info['description']}")
            self.recommendations.append(f"Verify firewall allows {protocol_info['description']} from Cluster2 to Cluster1")
            print(f"  {Colors.FAIL}✗{Colors.ENDC} Packets leaving cluster2 but NOT reaching cluster1")
            print(f"    → Appears to be unidirectional infrastructure blocking {protocol_info['description']} (cluster2 → cluster1)")
        elif packets1_total == 0 and packets2_total == 0:
            # No packets at all
            self.issues.append("No tunnel packets captured on either cluster → Gateway not sending traffic")
            self.recommendations.append("Review gateway pod logs for cable driver initialization errors")
            print(f"  {Colors.FAIL}✗{Colors.ENDC} No packets captured on either cluster")
            print(f"    → Gateways not sending tunnel traffic - check gateway logs")

    def detect_protocol_from_tcpdump(self, analysis_content):
        """Detect protocol from tcpdump capture filter"""
        if not analysis_content:
            return {'type': 'unknown', 'description': 'tunnel traffic'}

        # Look for capture filter line
        filter_match = re.search(r'Capture Filter:\s*(.+)', analysis_content)
        if not filter_match:
            return {'type': 'unknown', 'description': 'tunnel traffic'}

        filter_str = filter_match.group(1).strip()

        if 'proto 50' in filter_str:
            return {'type': 'esp', 'description': 'ESP (IP protocol 50)'}
        elif 'udp port' in filter_str:
            port_match = re.search(r'udp port (\d+)', filter_str)
            port = port_match.group(1) if port_match else '4500'
            return {'type': 'udp', 'description': f'UDP port {port}'}
        else:
            return {'type': 'unknown', 'description': 'tunnel traffic'}

    def check_packet_direction(self, analysis_content, direction):
        """Check if packets in a specific direction (In/Out) exist"""
        if not analysis_content:
            return False
        # Look for direction indicator in packet details
        return f" {direction} " in analysis_content or f"wlp0s20f3 {direction}" in analysis_content

    def extract_packet_count(self, analysis_content):
        """Extract total packet count from tcpdump analysis"""
        if not analysis_content:
            return 0
        match = re.search(r'Total packets captured:\s+(\d+)', analysis_content)
        if match:
            return int(match.group(1))
        return 0

    def analyze_pod_health(self):
        """Check pod status"""
        print(f"\n{Colors.BOLD}=== Analyzing Pod Health ==={Colors.ENDC}")

        for cluster in ['cluster1', 'cluster2']:
            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
            if not os.path.exists(gather_dir):
                continue

            # Find pods YAML
            for subdir in os.listdir(gather_dir):
                subdir_path = os.path.join(gather_dir, subdir)
                if os.path.isdir(subdir_path):
                    for file in os.listdir(subdir_path):
                        if file.startswith("pods_") and file.endswith(".yaml"):
                            pods_yaml = self.read_yaml(os.path.join(cluster, "gather", subdir, file))
                            if pods_yaml and 'items' in pods_yaml:
                                self.check_pod_status(pods_yaml['items'], cluster)

    def check_pod_status(self, pods, cluster_name):
        """Check status of individual pods"""
        unhealthy = []
        for pod in pods:
            metadata = pod.get('metadata', {})
            status = pod.get('status', {})

            pod_name = metadata.get('name', 'unknown')
            phase = status.get('phase', 'Unknown')

            if phase not in ['Running', 'Succeeded']:
                unhealthy.append(f"{pod_name}: {phase}")

            # Check container status
            container_statuses = status.get('containerStatuses', [])
            for cs in container_statuses:
                if not cs.get('ready', False):
                    state = cs.get('state', {})
                    if 'waiting' in state:
                        reason = state['waiting'].get('reason', 'Unknown')
                        unhealthy.append(f"{pod_name}: Container not ready ({reason})")

        if unhealthy:
            print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster_name}: Unhealthy pods found:")
            for issue in unhealthy:
                print(f"    - {issue}")
            self.issues.extend([f"{cluster_name}: {issue}" for issue in unhealthy])
        else:
            print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster_name}: All pods healthy")

    def get_gateway_status(self, cluster, actual_cluster_name):
        """Get gateway-to-gateway connectivity status from Submariner CR"""
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
        if not os.path.exists(gather_dir):
            return None

        # Look for submariner CR YAML
        for file in os.listdir(gather_dir):
            if file.startswith("submariners_submariner-operator_submariner") and file.endswith(".yaml"):
                submariner_cr = self.read_yaml(os.path.join(cluster, "gather", actual_cluster_name, file))
                if submariner_cr:
                    # Get gateway status from CR
                    gateways = submariner_cr.get('status', {}).get('gateways', [])
                    if gateways:
                        # Look for active gateway
                        for gw in gateways:
                            if gw.get('haStatus') == 'active':
                                connections = gw.get('connections', [])
                                if connections:
                                    # Return first connection status
                                    return {
                                        'status': connections[0].get('status', 'unknown'),
                                        'gateway_node': gw.get('localEndpoint', {}).get('hostname', 'unknown'),
                                        'remote_ip': connections[0].get('endpoint', {}).get('private_ip', 'unknown')
                                    }
        return None

    def analyze_routeagents(self):
        """Analyze RouteAgent resources to detect connectivity issues"""
        print(f"\n{Colors.BOLD}=== Analyzing RouteAgent Resources ==={Colors.ENDC}")

        # Get cluster subdirectory mapping
        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            print(f"  {Colors.WARNING}Could not determine cluster subdirectories{Colors.ENDC}")
            return

        for cluster in ['cluster1', 'cluster2']:
            # Get the actual cluster name (e.g., sitea-mgmt1, siteb-mgmt1)
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                print(f"  {cluster}: {Colors.WARNING}Could not determine cluster name{Colors.ENDC}")
                continue

            # Get gateway status first (gateway-to-gateway connectivity)
            gateway_status = self.get_gateway_status(cluster, actual_cluster_name)

            # Read RouteAgent CRs from gather subdirectory
            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                print(f"  {cluster}: {Colors.WARNING}No gather data for {actual_cluster_name}{Colors.ENDC}")
                continue

            # Collect all RouteAgent YAML files
            agents = []
            for file in os.listdir(gather_dir):
                if file.startswith("routeagents_submariner-operator_") and file.endswith(".yaml"):
                    agent_yaml = self.read_yaml(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if agent_yaml:
                        agents.append(agent_yaml)

            if not agents:
                print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: No RouteAgent resources")
                continue

            # Analyze each RouteAgent
            error_agents = []
            connected_agents = []
            gateway_agents = []
            pattern_detected = False
            control_plane_failures = []

            for agent in agents:
                # Each agent is a single RouteAgent CR, not wrapped in items list
                name = agent.get('metadata', {}).get('name', 'unknown')
                status_obj = agent.get('status', {})
                remote_endpoints = status_obj.get('remoteEndpoints', [])

                if not remote_endpoints:
                    continue

                # Check first remote endpoint status
                endpoint_status = remote_endpoints[0].get('status', '')
                status_msg = remote_endpoints[0].get('statusMessage', '')

                if endpoint_status == 'connected':
                    connected_agents.append(name)
                elif endpoint_status == 'none':
                    # Gateway nodes don't perform health checks
                    gateway_agents.append(name)
                elif endpoint_status == 'error':
                    error_agents.append((name, status_msg))

                    # Detect if it's a control plane node by checking common naming patterns
                    if any(pattern in name.lower() for pattern in ['cp-', 'control', 'master']):
                        control_plane_failures.append((name, status_msg))

            # Store data for later use
            self.routeagent_data[cluster] = {
                'total': len(agents),
                'connected': len(connected_agents),
                'errors': len(error_agents),
                'gateways': len(gateway_agents)
            }

            # Report findings
            print(f"  {cluster}: {len(agents)} RouteAgents found")
            print(f"    Connected: {len(connected_agents)}")
            print(f"    Gateway nodes: {len(gateway_agents)} (health check not performed)")

            if error_agents:
                print(f"    {Colors.FAIL}Errors: {len(error_agents)}{Colors.ENDC}")

                # Check gateway-to-gateway connectivity status
                if gateway_status:
                    gw_status = gateway_status.get('status', 'unknown')
                    gw_node = gateway_status.get('gateway_node', 'unknown')
                    print(f"\n    Gateway-to-Gateway connectivity: {self.colorize_status(gw_status)}")
                    print(f"    Gateway node: {gw_node}")

                    # Correlate gateway status with RouteAgent failures
                    if gw_status == 'connected' and error_agents:
                        print(f"\n  {Colors.BOLD}🔍 ROOT CAUSE IDENTIFIED:{Colors.ENDC}")
                        print(f"    ✓ Gateway → Remote Gateway: {Colors.OKGREEN}CONNECTED{Colors.ENDC}")
                        print(f"    ✗ Non-gateway nodes → Remote Gateway: {Colors.FAIL}FAILED{Colors.ENDC}")
                        print(f"\n    {Colors.WARNING}Diagnosis:{Colors.ENDC} This is an INTRA-cluster routing issue")
                        print(f"    - Inter-cluster connectivity is working (gateway tunnel connected)")
                        print(f"    - Problem: Non-gateway nodes cannot reach the remote gateway IP")
                        print(f"    - This indicates the faulty segment is within the LOCAL cluster:")
                        print(f"      Non-gateway nodes → Local gateway node's selected IP")

                # Detect pattern: all control plane nodes failing
                if control_plane_failures and len(control_plane_failures) >= 2:
                    pattern_detected = True
                    print(f"\n  {Colors.WARNING}⚠ PATTERN DETECTED:{Colors.ENDC} Multiple control plane nodes failing")

                    for node_name, msg in control_plane_failures[:3]:  # Show first 3
                        print(f"    - {node_name}")
                        if "ping" in msg.lower():
                            # Extract IP being pinged
                            import re
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', msg)
                            if ip_match:
                                failed_ip = ip_match.group(1)
                                print(f"      Cannot ping: {failed_ip}")

                    # Only add generic recommendations if we didn't already identify root cause
                    if not gateway_status or gateway_status.get('status') != 'connected':
                        self.faulty_states.append(f"{cluster}: Control plane nodes cannot reach remote gateway")
                        self.recommendations.append(
                            f"{cluster}: Check network connectivity from control plane to gateway nodes"
                        )
                        self.recommendations.append(
                            f"{cluster}: Verify routing rules allow traffic from control planes to gateway IP"
                        )
                    else:
                        self.faulty_states.append(f"{cluster}: Control planes cannot reach gateway IP (intra-cluster routing issue)")
                        self.recommendations.append(
                            f"{cluster}: INTRA-CLUSTER ISSUE - Verify control planes can reach local gateway node's IP"
                        )
                        self.recommendations.append(
                            f"{cluster}: Check routing tables on control plane nodes to gateway subnet"
                        )
                        self.recommendations.append(
                            f"{cluster}: Verify firewall rules allow control plane → gateway node traffic"
                        )

                # Show sample errors if pattern not detected
                if not pattern_detected:
                    for node_name, msg in error_agents[:2]:
                        print(f"    - {node_name}: {msg[:80]}")
                    if len(error_agents) > 2:
                        print(f"    ... and {len(error_agents) - 2} more")

                self.issues.append(f"{cluster}: {len(error_agents)} RouteAgent(s) with errors")

    def get_cluster_subdirs(self):
        """Get sorted list of cluster subdirectories from gather/

        Since subctl gather collects from both clusters, we map:
        - cluster1 -> first subdirectory alphabetically
        - cluster2 -> second subdirectory alphabetically
        """
        # Check cluster1/gather for subdirectories
        gather_dir = os.path.join(self.diagnostics_dir, "cluster1", "gather")
        if not os.path.exists(gather_dir):
            return {}

        subdirs = sorted([d for d in os.listdir(gather_dir)
                         if os.path.isdir(os.path.join(gather_dir, d))])

        if len(subdirs) >= 2:
            return {
                'cluster1': subdirs[0],
                'cluster2': subdirs[1]
            }
        elif len(subdirs) == 1:
            # Only one subdirectory - use it for both
            return {
                'cluster1': subdirs[0],
                'cluster2': subdirs[0]
            }
        return {}

    def analyze_network_topology(self):
        """Analyze network topology to detect flat vs non-flat networking

        Only runs if RouteAgent errors were detected, as topology analysis
        is only relevant when there are connectivity issues.
        """
        # Check if any RouteAgent errors were detected
        has_errors = False
        for cluster_data in self.routeagent_data.values():
            if cluster_data.get('errors', 0) > 0:
                has_errors = True
                break

        if not has_errors:
            # Skip topology analysis if no RouteAgent errors
            return

        print(f"\n{Colors.BOLD}=== Analyzing Network Topology ==={Colors.ENDC}")
        print(f"  (Running due to RouteAgent connectivity failures detected)")

        # Get cluster subdirectory mapping
        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            print(f"  {Colors.WARNING}Could not determine cluster subdirectories{Colors.ENDC}")
            return

        for cluster in ['cluster1', 'cluster2']:
            # Get the actual cluster name (e.g., sitea-mgmt1, siteb-mgmt1)
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                print(f"  {cluster}: {Colors.WARNING}Could not determine cluster name{Colors.ENDC}")
                continue

            # Collect node IPs from pod YAML files (status.hostIP)
            cluster_ips = set()
            node_to_ip = {}

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
            if not os.path.exists(gather_dir):
                print(f"  {cluster}: {Colors.WARNING}No gather data found{Colors.ENDC}")
                continue

            # Only look in the subdirectory matching this cluster's name
            cluster_gather_dir = os.path.join(gather_dir, actual_cluster_name)
            if not os.path.exists(cluster_gather_dir):
                print(f"  {cluster}: {Colors.WARNING}No gather data for {actual_cluster_name}{Colors.ENDC}")
                continue

            # Look for pod YAML files which contain hostIP information
            for file in os.listdir(cluster_gather_dir):
                if file.startswith("pods_") and file.endswith(".yaml"):
                    pods_yaml = self.read_yaml(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if pods_yaml and isinstance(pods_yaml, dict):
                        # Handle both single pod and list of pods
                        pod_list = pods_yaml.get('items', [pods_yaml]) if 'items' in pods_yaml else [pods_yaml]

                        for pod in pod_list:
                            if not isinstance(pod, dict):
                                continue

                            # Get hostIP from pod status
                            host_ip = pod.get('status', {}).get('hostIP')
                            node_name = pod.get('spec', {}).get('nodeName')

                            if host_ip:
                                cluster_ips.add(host_ip)
                                if node_name:
                                    node_to_ip[node_name] = host_ip

            if not cluster_ips:
                print(f"  {cluster}: {Colors.WARNING}No node IP information found{Colors.ENDC}")
                continue

            # Auto-detect network topology by trying common subnet masks
            # Try masks in order: /24 (most common), /22, /20, /16
            common_masks = [24, 22, 20, 16]
            topology_detected = False

            for subnet_mask in common_masks:
                ip_subnets = set()
                subnet_to_ips = {}

                for ip in cluster_ips:
                    try:
                        # Calculate network prefix based on subnet mask
                        ip_obj = ipaddress.ip_address(ip)
                        network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
                        network_str = str(network)

                        ip_subnets.add(network_str)
                        if network_str not in subnet_to_ips:
                            subnet_to_ips[network_str] = []
                        subnet_to_ips[network_str].append(ip)
                    except ValueError:
                        # Skip invalid IPs
                        continue

                # Report findings if multiple subnets detected at this mask
                if len(ip_subnets) > 1 and not topology_detected:
                    topology_detected = True
                    print(f"  {cluster}: {Colors.WARNING}Multiple subnets detected{Colors.ENDC}")
                    print(f"    Node IPs span {len(ip_subnets)} different /{subnet_mask} subnets:")
                    for subnet in sorted(ip_subnets):
                        num_ips = len(subnet_to_ips[subnet])
                        print(f"    - {subnet} ({num_ips} node{'s' if num_ips > 1 else ''})")

                    print(f"\n    {Colors.BOLD}Note:{Colors.ENDC} This indicates non-flat networking (nodes in different /{subnet_mask} networks).")
                    print(f"    Investigate network topology and routing between these subnets.")

                    # Only add as issue if we also detected RouteAgent failures
                    if self.routeagent_data.get(cluster, {}).get('errors', 0) > 0:
                        self.issues.append(f"{cluster}: Multiple /{subnet_mask} subnets with RouteAgent connectivity errors")
                        self.recommendations.append(
                            f"{cluster}: Non-flat networking detected - verify routing between /{subnet_mask} subnets"
                        )
                        self.recommendations.append(
                            f"{cluster}: Ensure nodes can route traffic between: {', '.join(sorted(ip_subnets))}"
                        )

                    self.network_topology[cluster] = {
                        'total_ips': len(cluster_ips),
                        'total_nodes': len(node_to_ip),
                        'subnets': len(ip_subnets),
                        'subnet_mask': subnet_mask,
                        'is_flat': False
                    }
                    break

            # If all masks show single subnet, it's flat networking
            if not topology_detected:
                print(f"  {cluster}: {Colors.OKGREEN}Flat networking detected{Colors.ENDC}")
                # Show at /24 level for reference
                network = ipaddress.ip_network(f"{list(cluster_ips)[0]}/24", strict=False)
                print(f"    All node IPs within same network scope")

                self.network_topology[cluster] = {
                    'total_ips': len(cluster_ips),
                    'total_nodes': len(node_to_ip),
                    'subnets': 1,
                    'is_flat': True
                }

    def analyze_logs(self):
        """Analyze pod logs for errors and warnings"""
        print(f"\n{Colors.BOLD}=== Analyzing Pod Logs ==={Colors.ENDC}")

        for cluster in ['cluster1', 'cluster2']:
            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
            if not os.path.exists(gather_dir):
                continue

            # Find log files
            for subdir in os.listdir(gather_dir):
                subdir_path = os.path.join(gather_dir, subdir)
                if os.path.isdir(subdir_path):
                    # Look for gateway and routeagent logs
                    gateway_logs = []
                    routeagent_logs = []

                    for file in os.listdir(subdir_path):
                        if 'submariner-gateway' in file and file.endswith('.log'):
                            gateway_logs.append(os.path.join(cluster, "gather", subdir, file))
                        elif 'submariner-routeagent' in file and file.endswith('.log'):
                            routeagent_logs.append(os.path.join(cluster, "gather", subdir, file))

                    # Analyze gateway logs
                    for log_path in gateway_logs:
                        self.analyze_log_file(log_path, cluster, "gateway")

                    # Analyze routeagent logs
                    for log_path in routeagent_logs:
                        self.analyze_log_file(log_path, cluster, "routeagent")

    def analyze_log_file(self, log_path, cluster_name, component):
        """Analyze a single log file for significant errors"""
        content = self.read_file(log_path)
        if not content:
            return

        errors = []

        # Skip health check ping failures as they're symptoms not root causes
        skip_patterns = [
            'Failed to successfully ping',
            'healthChecker timed out',
            'health check.*timeout',
            'ping.*timeout'
        ]

        # Significant error patterns to look for
        significant_patterns = [
            (r'CREATE_CHILD_SA failed', 'IPsec tunnel negotiation failed'),
            (r'TS_UNACCEPTABLE', 'Traffic selector negotiation failed'),
            (r'IKE.*failed', 'IKE negotiation failed'),
            (r'route.*failed', 'Route installation failed'),
            (r'iptables.*failed', 'Iptables rule installation failed'),
            (r'Failed to.*cable', 'Cable driver error'),
            (r'NAT.*discovery.*timeout', 'NAT discovery timeout'),
            (r'connection.*refused', 'Connection refused'),
            (r'authentication failed', 'Authentication failed'),
        ]

        # Search for significant errors
        for line in content.split('\n'):
            # Skip if it matches a skip pattern
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in skip_patterns):
                continue

            # Check for significant error patterns
            for pattern, description in significant_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append((description, line.strip()))
                    break

        # Report significant errors (limit to first 3 to avoid spam)
        if errors:
            print(f"  {Colors.FAIL}⚠{Colors.ENDC} {cluster_name}/{component}: Found significant errors in logs:")
            for i, (description, line) in enumerate(errors[:3]):
                # Truncate very long lines
                if len(line) > 120:
                    line = line[:117] + "..."
                print(f"    {i+1}. {description}")
                print(f"       {line}")
            if len(errors) > 3:
                print(f"    ... and {len(errors) - 3} more errors")

            self.issues.append(f"{cluster_name}/{component}: Found {len(errors)} significant error(s) in logs")
            self.recommendations.append(
                f"{cluster_name}/{component}: Review pod logs for detailed error messages"
            )

    def colorize_status(self, status):
        """Add color to status based on value"""
        if status == 'connected':
            return f"{Colors.OKGREEN}{status}{Colors.ENDC}"
        elif status == 'error':
            return f"{Colors.FAIL}{status}{Colors.ENDC}"
        else:
            return f"{Colors.WARNING}{status}{Colors.ENDC}"

    def generate_report(self):
        """Generate final analysis report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}ANALYSIS SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")

        # Check for version issues and display prominent warning at top
        has_version_mismatch = any("version mismatch" in fault.lower() for fault in self.faulty_states)
        has_different_versions = any("different submariner versions" in fault.lower() for fault in self.faulty_states)

        if has_version_mismatch:
            print(f"\n{Colors.FAIL}╔{'═'*58}╗{Colors.ENDC}")
            print(f"{Colors.FAIL}║  ⚠ WARNING: VERSION MISMATCH DETECTED                   ║{Colors.ENDC}")
            print(f"{Colors.FAIL}║  Analysis results below may be INCORRECT or MISLEADING  ║{Colors.ENDC}")
            print(f"{Colors.FAIL}╚{'═'*58}╝{Colors.ENDC}")
            print(f"{Colors.WARNING}Recommend fixing version compatibility before trusting this analysis.{Colors.ENDC}\n")

        if not self.faulty_states and not self.issues:
            # Healthy state (only possible if verify tests weren't run or if they passed)
            print(f"\n{Colors.OKGREEN}{'✓'*3} SUBMARINER DEPLOYMENT APPEARS HEALTHY {'✓'*3}{Colors.ENDC}")
            print(f"\n{Colors.OKGREEN}No faulty states detected:{Colors.ENDC}")
            print(f"  ✓ All tunnels in 'connected' state")

            # Provide detailed verify test status
            if self.verify_tests_run and self.verify_tests_passed:
                print(f"  ✓ Verification tests passed - comprehensive datapath validated")
                print(f"    (Tests cover all connectivity paths: local pod ↔ remote pod on gateway/non-gateway nodes)")
            else:
                # Tests not run
                print(f"  • Verification tests not run (tunnels healthy but datapath not fully validated)")

            print(f"  ✓ No significant errors in pod logs")

            if self.verify_tests_run and self.verify_tests_passed:
                print(f"\n{Colors.BOLD}Status:{Colors.ENDC} Submariner is functioning correctly - tunnels connected and datapath validated")
            else:
                print(f"\n{Colors.BOLD}Status:{Colors.ENDC} Submariner tunnels appear healthy")
                print(f"{Colors.BOLD}Note:{Colors.ENDC} Run 'subctl verify' for comprehensive datapath validation")
        elif not self.issues:
            # Faulty states found but no specific issues identified
            print(f"\n{Colors.WARNING}Faulty States Detected ({len(self.faulty_states)}):{Colors.ENDC}")
            for fault in self.faulty_states:
                print(f"  • {fault}")
            print(f"\n{Colors.WARNING}Note: Could not identify specific root causes.{Colors.ENDC}")
            print(f"Consider using advanced AI analysis for deeper investigation.")
        else:
            # Issues found
            print(f"\n{Colors.FAIL}Issues Detected ({len(self.issues)}):{Colors.ENDC}")
            for issue in self.issues:
                print(f"  • {issue}")

        if self.recommendations:
            print(f"\n{Colors.BOLD}Recommendations:{Colors.ENDC}")
            # Remove duplicates while preserving order
            seen = set()
            unique_recs = []
            for rec in self.recommendations:
                if rec not in seen:
                    seen.add(rec)
                    unique_recs.append(rec)

            for i, rec in enumerate(unique_recs, 1):
                # Highlight kubectl commands in cyan
                formatted_rec = re.sub(
                    r'(kubectl [^"\n]+)',
                    f'{Colors.OKCYAN}\\1{Colors.ENDC}',
                    rec
                )
                print(f"  {i}. {formatted_rec}")

        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")

        if self.faulty_states or self.issues:
            print(f"\n{Colors.WARNING}IMPORTANT NOTE:{Colors.ENDC}")
            print(f"  📖 Verify Submariner Prerequisites:")
            print(f"     https://submariner.io/operations/deployment/prerequisites/")
            print(f"")
            print(f"  • Try the recommended solutions in order")
            print(f"  • If issues persist, contact Submariner community:")
            print(f"    - Submariner Slack: https://kubernetes.slack.com/archives/C010RJV694M")
            print(f"    - GitHub Issues: https://github.com/submariner-io/submariner/issues")

        print(f"\n{Colors.BOLD}For deeper AI-powered analysis:{Colors.ENDC}")
        print(f"  See README.md for instructions on setting up advanced AI analysis")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

    def run(self):
        """Run full analysis"""
        print(f"\n{Colors.BOLD}Submariner Basic Diagnostic Analyzer{Colors.ENDC}")
        print(f"{'='*60}\n")

        # Extract tarball
        if not self.extract_tarball():
            return False

        # Read manifest
        manifest = self.analyze_manifest()
        if manifest:
            print(f"\n{Colors.BOLD}Diagnostic Information:{Colors.ENDC}")
            print(f"  Timestamp: {manifest.get('Timestamp', 'unknown')}")
            print(f"  Issue: {manifest.get('Complaint', 'unknown')}")

        # Check for faulty states first
        has_faults = self.check_faulty_states()

        # Only run deep analysis if faulty states were found
        if has_faults:
            print(f"\n{Colors.BOLD}=== Starting Deep Analysis ==={Colors.ENDC}")

            # Analyze RouteAgent resources first (key diagnostic info)
            self.analyze_routeagents()

            # Analyze network topology
            self.analyze_network_topology()

            # Analyze logs for significant errors
            self.analyze_logs()

            # Analyze tunnel details
            self.analyze_tunnel_status()

            # Analyze tcpdump for tunnel issues
            if any('tunnel' in fault.lower() for fault in self.faulty_states):
                self.analyze_tcpdump()

            # Analyze pod health
            self.analyze_pod_health()

        # Generate report
        self.generate_report()

        return True

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <submariner-diagnostics.tar.gz>")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} submariner-diagnostics-20251230-171124.tar.gz")
        sys.exit(1)

    tarball = sys.argv[1]
    analyzer = SubmarinerAnalyzer(tarball)

    success = analyzer.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
