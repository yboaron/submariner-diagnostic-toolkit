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

    def check_faulty_states(self):
        """Check for faulty states before starting deep analysis"""
        print(f"\n{Colors.BOLD}=== Checking for Faulty States ==={Colors.ENDC}")

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
        if small_packet and "SKIPPED" not in small_packet:
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

            # Analyze logs for significant errors first
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
