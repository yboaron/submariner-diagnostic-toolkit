# Submariner Diagnostic Toolkit

Comprehensive toolkit for collecting and analyzing Submariner diagnostics **offline** - no live cluster access required for analysis.

## Features

- **Automated Collection**: Gather complete diagnostic data from both clusters
- **Basic Analysis** (Python): Fast pattern-matching for common issues - no AI required
- **Advanced Analysis** (Claude Code): Deep AI-powered root cause analysis

## Quick Start

### 1. Collect Diagnostics

```bash
./collect-full-diagnostics.sh <cluster1-name> <cluster1-kubeconfig> <cluster2-name> <cluster2-kubeconfig> <issue-description>
```

**Example:**
```bash
./collect-full-diagnostics.sh \
  cluster1 /path/to/kubeconfig1 \
  cluster2 /path/to/kubeconfig2 \
  "tunnel not connected"
```

**Output:** `submariner-diagnostics-TIMESTAMP.tar.gz`

### 2. Analyze (Basic - No AI)

```bash
./analyze-basic.py submariner-diagnostics-TIMESTAMP.tar.gz
```

**What it detects:**
- Tunnel connectivity status
- ESP/UDP protocol blocking
- Pod health issues
- Packet flow patterns (from tcpdump)
- Common misconfigurations

**No setup required** - just Python 3 with PyYAML:
```bash
pip install pyyaml
```

### 3. Analyze (Advanced - AI-Powered)

For deeper analysis with Claude AI:

**Installation:**
```bash
# Copy the analysis skill to Claude Code
mkdir -p ~/.config/claude-code/skills
cp submariner-analyze-offline.md ~/.config/claude-code/skills/
```

**Usage:**
Open Claude Code and run:
```
/submariner:analyze-offline submariner-diagnostics-TIMESTAMP.tar.gz
```

**Prerequisites:**
- [Claude Code](https://claude.com/claude-code) installed
- Claude subscription

**What it provides:**
- Deep root cause analysis with context
- Probabilistic reasoning ("most likely", "appears to be")
- Step-by-step solutions
- Official documentation references
- Further investigation steps if initial solution fails

## What Gets Collected

### Always Collected
- `subctl gather` - Comprehensive cluster data including:
  - Submariner CRs (Gateway, Endpoints, RouteAgents)
  - Pod logs and status
  - IPsec status and traffic counters
  - Network configuration (routes, iptables, XFRM policies)
- `subctl show` - Connection status overview
- `subctl diagnose` - Health check results
- Gateway and RouteAgent status
- ACM resources (if present)

### Conditional Collection

#### When Tunnels NOT Connected
**tcpdump packet captures** from gateway nodes (80-second capture)
- Automatically captured if either tunnel shows `status != connected`
- Helps diagnose infrastructure-level blocking (ESP/UDP)
- Includes text analysis summaries for offline review
- **Benefit**: Identifies *where* packets are being dropped

#### When Tunnels Connected
**subctl verify connectivity tests**
- Default packet size tests
- Small packet size tests (MTU detection)
- Service discovery tests (if enabled)
- **Benefit**: Validates end-to-end connectivity

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
./collect-full-diagnostics.sh cluster1 kubeconfig1 cluster2 kubeconfig2 "tunnel not connected"
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
**Basic Analysis:** ❌ Use advanced analysis
**Recommendation:** Apply TCP MSS clamping

### 4. Pod Health Issues
**Symptoms:** Pods in CrashLoopBackOff, ImagePullBackOff
**Basic Analysis:** ✅ Detects
**Recommendation:** Fix pod-specific issues

### 5. Infrastructure Packet Dropping
**Symptoms:** tcpdump shows egress but no ingress
**Basic Analysis:** ✅ Detects
**Recommendation:** Check firewall/network between nodes

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
    │   ├── subctl-diagnose-all.txt
    │   └── routeagents.yaml
    ├── cluster2/                     # Cluster 2 (same structure)
    ├── tcpdump/                      # Packet captures (if tunnels down)
    │   ├── cluster1-gateway-node-analysis.txt  # Text summary
    │   ├── cluster1-gateway-node.pcap          # Binary capture
    │   └── cluster2-gateway-...
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
- `tcpdump` (for packet capture when tunnels are down)
- Access to both Submariner clusters

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

### Analysis Issues

**Basic analysis: "Module not found: yaml"**
```bash
pip install pyyaml
```

**Advanced analysis: Skill not found**
- Verify `submariner-analyze-offline.md` copied to `~/.config/claude-code/skills/`
- Restart Claude Code
- Try: `ls ~/.config/claude-code/skills/`

## Contributing

Contributions welcome! Please submit issues or PRs to:
https://github.com/yboaron/submariner-diagnostic-toolkit

## Support

- **Collection/Analysis Issues**: [GitHub Issues](https://github.com/yboaron/submariner-diagnostic-toolkit/issues)
- **Submariner Bugs**: [Submariner GitHub](https://github.com/submariner-io/submariner/issues)
- **Community Help**: [Submariner Slack](https://kubernetes.slack.com/archives/C010RJV694M)

## License

Apache 2.0
