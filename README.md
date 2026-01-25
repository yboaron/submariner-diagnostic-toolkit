# Submariner Diagnostic Toolkit

Comprehensive toolkit for collecting and analyzing Submariner diagnostics. Collect diagnostics once from live clusters, then analyze **offline** anytime - no cluster access needed for analysis.

## Features

- **Automated Collection**: Gather complete diagnostic data from both clusters
- **Basic Analysis** (Python): Fast pattern-matching for common issues - no AI required
- **Advanced Analysis** (Claude Code): Deep AI-powered root cause analysis

## Getting Started

### Installation

**1. Clone the repository:**
```bash
git clone https://github.com/yboaron/submariner-diagnostic-toolkit.git
cd submariner-diagnostic-toolkit
```

**2. Verify prerequisites:**
```bash
# Required for collection
kubectl version --client
subctl version

# Required for basic analysis (optional)
python3 --version
pip install pyyaml
```

**Prerequisites:**
- `kubectl` - [Installation Guide](https://kubernetes.io/docs/tasks/tools/)
- `subctl` - [Installation Guide](https://github.com/submariner-io/subctl)
- `python3` and `pyyaml` - Only needed for basic analysis (optional)
- Access to both Submariner clusters with valid kubeconfig files

## Quick Start

### 1. Collect Diagnostics

```bash
./collect-full-diagnostics.sh <cluster1-context> <cluster1-kubeconfig> <cluster2-context> <cluster2-kubeconfig> [issue-description]
```

**Parameters:**
- `cluster1-context`: Context name for cluster 1 (from kubeconfig)
- `cluster1-kubeconfig`: Path to kubeconfig file for cluster 1
- `cluster2-context`: Context name for cluster 2 (from kubeconfig)
- `cluster2-kubeconfig`: Path to kubeconfig file for cluster 2
- `issue-description`: Optional description of the issue

**Examples:**
```bash
# Separate kubeconfig files
./collect-full-diagnostics.sh \
  prod-east /path/to/kubeconfig-east \
  prod-west /path/to/kubeconfig-west \
  "tunnel not connected"

# Single kubeconfig with multiple contexts
./collect-full-diagnostics.sh \
  context-cluster1 /path/to/merged-kubeconfig \
  context-cluster2 /path/to/merged-kubeconfig \
  "connectivity issues"

# Without issue description (defaults to "undefined")
./collect-full-diagnostics.sh \
  prod-east /path/to/kubeconfig-east \
  prod-west /path/to/kubeconfig-west
```

**Output:** `submariner-diagnostics-TIMESTAMP.tar.gz`

### 2. Analyze (Basic - No AI)

```bash
./analyze-basic.py submariner-diagnostics-TIMESTAMP.tar.gz
```

**What it detects:**
- Version compatibility issues (subctl vs Submariner)
- **Submariner software bugs (e.g., libreswan version incompatibility)**
- Tunnel connectivity status
- ESP/UDP protocol blocking
- Firewall blocking (inter-cluster and intra-cluster)
- MTU/fragmentation issues
- Pod health issues
- Packet flow patterns (from tcpdump)
- RouteAgent connectivity with gateway correlation
  - Distinguishes intra-cluster vs inter-cluster issues
  - Detects control plane connectivity patterns
  - Identifies root cause segment (local routing vs inter-cluster)
- Network topology analysis (when RouteAgent errors detected)
  - Detects potential non-flat networking scenarios
  - Analyzes node subnet distribution
- Common misconfigurations

**No setup required** - just Python 3 with PyYAML:
```bash
pip install pyyaml
```

### 3. Analyze (Advanced - AI-Powered)

For deeper analysis with Claude AI:

**Installation:**
```bash
# Install the Claude Code skill (creates /submariner:analyze-offline command)
mkdir -p ~/.claude/commands/submariner
cp analyze-offline.md ~/.claude/commands/submariner/analyze-offline.md
```

**Restart Claude Code**, then verify the command is available:
```
/submariner:analyze-offline
```

**Note:** The command will appear as `/submariner:analyze-offline` in Claude Code.

**Usage:**
```
/submariner:analyze-offline submariner-diagnostics-TIMESTAMP.tar.gz

# Or with specific issue description
/submariner:analyze-offline submariner-diagnostics-TIMESTAMP.tar.gz "tunnel not connected"
```

**Prerequisites:**
- [Claude Code](https://claude.com/claude-code) installed
- Claude subscription

**What it detects (in addition to basic analysis):**
- **MTU/fragmentation issues** (classic pattern: small packets pass, large packets fail)
- **Submariner software bugs** requiring expert attention (e.g., libreswan incompatibility)
- Infrastructure-level blocking patterns from tcpdump analysis
- All issues detected by basic analysis

**What it provides:**
- Deep root cause analysis with context
- Probabilistic reasoning ("most likely", "appears to be")
- Step-by-step solutions with deployment-specific commands (ACM vs Standalone)
- Official documentation references
- Further investigation steps if initial solution fails
- Guidance on contacting Submariner experts for software bugs

## What Gets Collected

### Always Collected
- `subctl gather` - Comprehensive cluster data including:
  - Submariner CRs (Gateway, Endpoints, RouteAgents)
  - Pod logs and status
  - IPsec status and traffic counters
  - Network configuration (routes, iptables, XFRM policies)
- `subctl show` - Connection status overview
- `subctl show versions` - Component version information
- `subctl diagnose` - Health check results
- Gateway and RouteAgent status
- ACM resources (if present)
- Version compatibility check (in manifest.txt)

### Conditional Collection

#### When Tunnels NOT Connected
**tcpdump packet captures** from gateway nodes (80-second capture)
- Automatically captured if either tunnel shows `status != connected`
- Helps diagnose infrastructure-level blocking (ESP/UDP)
- Includes text analysis summaries for offline review
- **Benefit**: Identifies *where* packets are being dropped

**Firewall inter-cluster diagnostics** (`subctl diagnose firewall inter-cluster`)
- Runs when: Tunnel not connected + UDP encapsulation (VxLAN or IPSec NAT-T)
- Skipped when: Using ESP (protocol 50) - test only checks UDP ports
- **Benefit**: Verifies if UDP ports are open between gateway nodes
- **Cross-referenced with**: tcpdump data (UDP traffic) + IPsec counters (ipsec-trafficstatus.log)

#### When Tunnels Connected
**subctl verify connectivity tests**
- Default packet size tests
- Small packet size tests (MTU detection)
- Service discovery tests (if enabled)
- **Benefit**: Validates end-to-end connectivity

#### When CNI is NOT OVN-Kubernetes
**Firewall intra-cluster diagnostics** (`subctl diagnose firewall intra-cluster`)
- Runs per cluster when CNI is not OVNK (checked independently)
- Runs regardless of tunnel status
- **Benefit**: Verifies VXLAN traffic allowed on vx-submariner interface
- **Expected failures**: RouteAgent issues + verify test failures from non-gateway pods

## Collection Script Features

### Intelligent Decision Making
- ✅ **Skip verify when tunnels broken** - Saves 15-20 minutes
- ✅ **Auto tcpdump when needed** - Captures packet-level diagnostics
- ✅ **Parallel collection** - Faster data gathering from both clusters
- ✅ **Comprehensive timing** - Track collection duration per phase

### Validation
- ✅ Verifies kubeconfigs exist and clusters are accessible
- ✅ Validates context names are different
- ✅ Checks for required tools (subctl, kubectl, tcpdump)
- ✅ Validates parameters before starting collection
- ✅ **Version compatibility check** - Verifies subctl and Submariner versions match
  - Checks both clusters separately
  - Warns if versions mismatch
  - Warns if clusters have different Submariner versions
  - Prompts user to continue or cancel if mismatch detected
  - Documents all version info in manifest

### Smart Exit Behavior
- Exits on validation failures (missing prereqs)
- Continues through all collection steps even if some commands fail
- **Never closes your terminal** on error

## Analysis Comparison

| Feature | Basic Analysis | Advanced Analysis (AI) |
|---------|---------------|----------------------|
| **Setup** | None (just Python) | Claude Code + subscription |
| **Speed** | Fast (~5 seconds) | Medium (~1-2 minutes) |
| **Cost** | Free | Claude subscription required |
| **Detection** | Pattern matching | Deep contextual analysis |
| **Accuracy** | Good for common issues | Excellent for all issues |
| **Use Case** | Quick initial check | Deep investigation |

## Example Workflow

### Scenario: Tunnel Not Connected

**Step 1: Collect**
```bash
./collect-full-diagnostics.sh \
  cluster1-context /path/to/kubeconfig1 \
  cluster2-context /path/to/kubeconfig2 \
  "tunnel not connected"
```
*Result: tcpdump captures collected automatically (tunnel status ≠ connected)*

**Step 2: Basic Analysis**
```bash
./analyze-basic.py submariner-diagnostics-*.tar.gz
```
*Output:*
```
Issues Detected (2):
  • Cluster2 tunnel status: error
  • cluster2: Likely ESP protocol blocking

Recommendations:
  1. cluster2: Enable UDP encapsulation (set ceIPSecForceUDPEncaps: true)
```

**Step 3: (Optional) Advanced Analysis**
```
/submariner:analyze-offline submariner-diagnostics-*.tar.gz
```
*Provides:*
- Detailed tcpdump pattern analysis
- Confirms ESP blocking with packet-level evidence
- Alternative solutions if UDP encapsulation doesn't work
- Infrastructure-level investigation steps

## Common Issues Detected

### 1. ESP Protocol Blocking
**Symptoms:** Tunnel status = error, using private IP
**Basic Analysis:** ✅ Detects
**Recommendation:** Enable UDP encapsulation

### 2. UDP Port Blocking
**Symptoms:** Tunnel status = error, using public IP
**Basic Analysis:** ✅ Detects
**Recommendation:** Allow UDP ports 500/4500

### 3. MTU Issues
**Symptoms:** Large packets fail, small packets succeed
**Basic Analysis:** ✅ Detects
**Recommendation:** Apply TCP MSS clamping

### 4. Pod Health Issues
**Symptoms:** Pods in CrashLoopBackOff, ImagePullBackOff
**Basic Analysis:** ✅ Detects
**Recommendation:** Fix pod-specific issues

### 5. Infrastructure Packet Dropping
**Symptoms:** tcpdump shows egress but no ingress
**Basic Analysis:** ✅ Detects
**Recommendation:** Check firewall/network between nodes

### 6. Inter-Cluster Firewall Blocking
**Symptoms:** Tunnel not connected, firewall inter-cluster test fails
**Basic Analysis:** ✅ Detects (auto-detects NAT-T port from config)
**Recommendation:** Allow UDP NAT-T port (default 4500, configurable) between gateway nodes
**Cross-checked with:** tcpdump (UDP traffic patterns) + IPsec counters

### 7. Intra-Cluster Firewall Blocking
**Symptoms:** RouteAgent failures, verify tests fail from non-gateway pods
**Basic Analysis:** ✅ Detects
**Recommendation:** Allow VXLAN traffic on vx-submariner interface

### 8. Intra-Cluster Routing Issues
**Symptoms:** Gateway tunnel connected, but RouteAgent errors on non-gateway nodes
**Basic Analysis:** ✅ Detects via gateway/RouteAgent correlation
**Diagnosis:** Non-gateway nodes cannot reach local gateway node's IP
**Recommendation:** Investigate local cluster routing, especially in non-flat networking scenarios
**Pattern Detection:** Control plane nodes failing indicates subnet routing issues

## Output Structure

```
submariner-diagnostics-TIMESTAMP.tar.gz
└── submariner-diagnostics-TIMESTAMP/
    ├── manifest.txt                  # Collection metadata
    ├── cluster1/                     # Cluster 1 diagnostics
    │   ├── gather/                   # subctl gather output
    │   │   └── cluster1/
    │   │       ├── submariners_*.yaml       # Gateway CR
    │   │       ├── *_ipsec-status.log       # IPsec state
    │   │       ├── *_ipsec-trafficstatus.log# Traffic counters
    │   │       ├── *_ip-xfrm-policy.log     # XFRM policies
    │   │       ├── *_ip-routes.log          # Routing tables
    │   │       ├── submariner-gateway-*.log # Gateway logs
    │   │       └── pods_*.yaml              # Pod status
    │   ├── subctl-show-all.txt
    │   ├── subctl-show-versions.txt  # Version information
    │   ├── subctl-diagnose-all.txt
    │   └── routeagents.yaml
    ├── cluster2/                     # Cluster 2 (same structure)
    ├── tcpdump/                      # Packet captures (if tunnels down)
    │   ├── cluster1-gateway-node-analysis.txt  # Text summary
    │   ├── cluster1-gateway-node.pcap          # Binary capture
    │   └── cluster2-gateway-...
    ├── firewall/                     # Firewall diagnostics (conditional)
    │   ├── firewall-inter-cluster.txt          # Inter-cluster firewall test
    │   ├── firewall-intra-cluster-cluster1.txt # Intra-cluster (cluster1)
    │   └── firewall-intra-cluster-cluster2.txt # Intra-cluster (cluster2)
    └── verify/                       # Connectivity tests (if tunnels up)
        ├── connectivity.txt
        ├── connectivity-small-packet.txt
        └── service-discovery.txt
```

## Requirements

### Collection Script
- `bash`
- `kubectl`
- `subctl` - [Installation Guide](https://github.com/submariner-io/subctl)
- Access to both Submariner clusters

**Note:** Packet captures are performed inside the cluster using containers - no local `tcpdump` installation required.

### Basic Analysis
- `python3` (3.6+)
- `pyyaml` - Install: `pip install pyyaml`

### Advanced Analysis
- [Claude Code](https://claude.com/claude-code)
- Claude subscription

## Troubleshooting

### Collection Issues

**Error: Cannot connect to cluster**
```bash
# Verify kubeconfig is correct and cluster is accessible
kubectl cluster-info --kubeconfig /path/to/kubeconfig
```

**Error: Context not found**
```bash
# List available contexts
kubectl config get-contexts --kubeconfig /path/to/kubeconfig
```

**tcpdump collection takes long time**
- Normal - waits 80 seconds for packet capture
- Both clusters collected in parallel
- Total tcpdump time: ~85-90 seconds

**Version mismatch warning**
- Collection script checks if subctl and Submariner versions match
- If mismatch detected:
  - Script shows warning with versions
  - Prompts to continue or cancel
  - Documents mismatch in manifest.txt
- **Recommended:** Update subctl to match Submariner version

### Analysis Issues

**Basic analysis: "Module not found: yaml"**
```bash
pip install pyyaml
```

**Advanced analysis: Command not found**
- Verify `analyze-offline.md` is copied to `~/.claude/commands/submariner/analyze-offline.md`
- Restart Claude Code
- Verify installation: `ls ~/.claude/commands/submariner/`
- Make sure there's NO file at `~/.claude/commands/analyze-offline.md` (would create duplicate command)

## Contributing

Contributions welcome! Please submit issues or PRs to:
https://github.com/yboaron/submariner-diagnostic-toolkit

## Support

- **Collection/Analysis Issues**: [GitHub Issues](https://github.com/yboaron/submariner-diagnostic-toolkit/issues)
- **Submariner Bugs**: [Submariner GitHub](https://github.com/submariner-io/submariner/issues)
- **Community Help**: [Submariner Slack](https://kubernetes.slack.com/archives/C010RJV694M)

## License

Apache 2.0
