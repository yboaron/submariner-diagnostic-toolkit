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

    def analyze_tunnel_status(self):
        """Analyze tunnel connectivity status"""
        print(f"\n{Colors.BOLD}=== Analyzing Tunnel Status ==={Colors.ENDC}")

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
                        print(f"    Using IP: {using_ip} (private IP - suggests ESP protocol)")
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

        # Look for analysis files
        cluster1_analysis = self.read_file("tcpdump/cluster1-gateway-*-analysis.txt")
        cluster2_analysis = self.read_file("tcpdump/cluster2-gateway-*-analysis.txt")

        # Find analysis files with glob pattern
        import glob
        cluster1_files = glob.glob(os.path.join(tcpdump_dir, "cluster1-gateway-*-analysis.txt"))
        cluster2_files = glob.glob(os.path.join(tcpdump_dir, "cluster2-gateway-*-analysis.txt"))

        if cluster1_files:
            cluster1_analysis = self.read_file(os.path.relpath(cluster1_files[0], self.diagnostics_dir))
        if cluster2_files:
            cluster2_analysis = self.read_file(os.path.relpath(cluster2_files[0], self.diagnostics_dir))

        if not cluster1_analysis and not cluster2_analysis:
            print(f"  {Colors.WARNING}⚠{Colors.ENDC} No tcpdump analysis files found")
            return

        # Extract packet counts
        packets1 = self.extract_packet_count(cluster1_analysis) if cluster1_analysis else 0
        packets2 = self.extract_packet_count(cluster2_analysis) if cluster2_analysis else 0

        print(f"  Cluster1 gateway: {packets1} packets captured")
        print(f"  Cluster2 gateway: {packets2} packets captured")

        # Analyze patterns
        if packets1 > 0 and packets2 == 0:
            self.issues.append("Pattern suggests: Cluster1 sending but Cluster2 not receiving → Possible infrastructure blocking")
            self.recommendations.append("Verify firewall/network configuration between clusters allows required protocols")
            print(f"  {Colors.FAIL}✗{Colors.ENDC} It appears packets are leaving cluster1 but not reaching cluster2")
            print(f"    → This suggests infrastructure-level blocking (firewall/router/security groups)")
        elif packets1 == 0 and packets2 > 0:
            self.issues.append("Pattern suggests: Cluster2 sending but Cluster1 not receiving → Possible infrastructure blocking")
            self.recommendations.append("Verify firewall/network configuration between clusters allows required protocols")
            print(f"  {Colors.FAIL}✗{Colors.ENDC} It appears packets are leaving cluster2 but not reaching cluster1")
            print(f"    → This suggests infrastructure-level blocking (firewall/router/security groups)")
        elif packets1 == 0 and packets2 == 0:
            self.issues.append("Pattern suggests: No packets captured → Possible gateway initialization issue")
            self.recommendations.append("Review gateway pod logs for IPsec/configuration errors")
            print(f"  {Colors.FAIL}✗{Colors.ENDC} It appears gateways are not sending tunnel traffic")
            print(f"    → Review gateway logs for initialization or configuration issues")
        elif packets1 > 10 and packets2 > 10:
            print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Both clusters appear to be sending/receiving packets")
            self.findings.append("Packet flow detected on both clusters")

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
        """Analyze a single log file for errors and warnings"""
        content = self.read_file(log_path)
        if not content:
            return

        errors = []
        warnings = []

        # Skip health check ping failures as they're symptoms not root causes
        skip_patterns = [
            'Failed to successfully ping',
            'healthChecker timed out',
            'health check.*timeout',
            'ping.*timeout'
        ]

        # Search for errors and warnings
        for line in content.split('\n'):
            # Skip if it matches a skip pattern
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in skip_patterns):
                continue

            # Look for ERROR patterns
            if re.search(r'\bERROR\b|\bFAIL\b|\berror\b.*\bfailed\b', line, re.IGNORECASE):
                # Extract meaningful part of the log line
                if 'ERROR' in line or 'error' in line:
                    errors.append(line.strip())

            # Look for WARNING patterns
            elif re.search(r'\bWARN\b|\bwarning\b', line, re.IGNORECASE):
                warnings.append(line.strip())

        # Report significant errors (limit to first 3 to avoid spam)
        if errors:
            print(f"  {Colors.FAIL}⚠{Colors.ENDC} {cluster_name}/{component}: Found errors in logs")
            for error in errors[:3]:
                # Truncate very long lines
                if len(error) > 100:
                    error = error[:97] + "..."
                print(f"    - {error}")
            if len(errors) > 3:
                print(f"    ... and {len(errors) - 3} more errors")

            self.issues.append(f"{cluster_name}/{component}: Log contains {len(errors)} error(s)")
            self.recommendations.append(
                f"{cluster_name}/{component}: Review pod logs for configuration or initialization issues"
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

        if not self.issues:
            print(f"\n{Colors.OKGREEN}✓ No major issues detected{Colors.ENDC}")
            print(f"\nKey Findings:")
            for finding in self.findings:
                print(f"  • {finding}")
        else:
            print(f"\n{Colors.FAIL}Issues Detected ({len(self.issues)}):{Colors.ENDC}")
            for issue in self.issues:
                print(f"  • {issue}")

        if self.recommendations:
            print(f"\n{Colors.BOLD}Recommendations:{Colors.ENDC}")
            for i, rec in enumerate(self.recommendations, 1):
                print(f"  {i}. {rec}")

        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"\n{Colors.WARNING}IMPORTANT NOTE:{Colors.ENDC}")
        print(f"  This is automated pattern-matching analysis based on known issues.")
        print(f"  Results use cautious language (\"appears to be\", \"seems like\") because")
        print(f"  the actual root cause may vary based on your specific environment.")
        print(f"")
        print(f"  • Verify all Submariner prerequisites are configured correctly in your infrastructure")
        print(f"  • Try the recommended alternatives if initial solutions don't work")
        print(f"  • If issues persist, contact Submariner experts with these findings:")
        print(f"    - Submariner Slack: https://kubernetes.slack.com/archives/C010RJV694M")
        print(f"    - GitHub Issues: https://github.com/submariner-io/submariner/issues")
        print(f"\n{Colors.BOLD}For deeper AI-powered analysis:{Colors.ENDC}")
        print(f"  /analyze-offline {self.tarball_path}")
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

        # Run analyses
        self.analyze_tunnel_status()
        self.analyze_tcpdump()
        self.analyze_pod_health()
        self.analyze_logs()

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
