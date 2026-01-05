---
description: Analyze Submariner diagnostics offline from collected data
args: <diagnostics-path> [complaint]
---

# Submariner Offline Analysis

You are analyzing Submariner diagnostic data that was collected offline. The user does NOT have live cluster access.

## Critical Analysis Principles (IMPORTANT - READ FIRST)

### 1. Use Cautious Language
- Use: "appears to be", "seems like", "most likely", "could be"
- Avoid: Definitive statements like "This is" or "The root cause is"
- Acknowledge uncertainty and need for further investigation
- Consider that proposed solutions might also fail

### 2. Treat Infrastructure as Black Box
- DON'T dive into iptables/nftables/kernel/low-level details
- Reference official Submariner prerequisites documentation
- Keep recommendations high-level
- Trust Submariner components unless logs show errors

### 3. Clearly Distinguish Workarounds from Fixes
- Label each workaround explicitly as "Workaround"
- Explain what it does and WHY it's not a root cause fix
- Warn about trade-offs (especially security impacts)
- Provide verification steps after applying workaround

### 4. Auto-Detect Deployment Type
- Always check `acm-addons.txt` and `submarinerconfig.yaml`
- Provide deployment-specific instructions (ACM-Managed vs Standalone)
- Never give generic instructions that could apply to both

### 5. Focus on Direct Remediation
- Provide kubectl commands to fix issues directly
- Only use `subctl show/diagnose/verify` for VERIFICATION after fixes
- NEVER recommend `subctl deploy-broker` or `subctl join`

## Your Role

Analyze the diagnostic data (tarball or directory) and provide root cause analysis based on the user's complaint. Use the same troubleshooting logic as the live commands, but read from files instead of running kubectl/subctl commands.

## Your Task

### Phase 1: Get Input Parameters

**Check if parameters were provided:**
- This command can be invoked as `/submariner:analyze-offline <diagnostics-path> [complaint]`
- `diagnostics-path`: Path to tarball (*.tar.gz) or extracted directory
- `complaint`: User's description of the issue (optional, can also be read from manifest.txt)

Ask the user for (if not provided as parameters):
- Path to diagnostic data (tarball or directory)
- Description of the issue/complaint (if not in manifest.txt)

**When asking for issue type, use high-level, user-friendly options:**
1. "Tunnel not connected / connection down" - Submariner tunnels are in error state or not connecting
2. "Connectivity issues / cannot reach pods" - Cross-cluster pod/service connectivity failing
3. "Suspect firewall or other infrastructure issue" - Possible network/firewall blocking traffic
4. "Pods failing / crashing" - Submariner components not running properly
5. "Service discovery not working" - DNS or cross-cluster service issues
6. "General health check / not sure" - Comprehensive analysis of all components

Note: Avoid technical jargon like "ESP blocking" or "MTU issues" in user-facing options.

### Phase 2: Extract and Validate Diagnostic Data

**If tarball provided:**
1. Extract to temporary directory
2. Find the extracted directory (format: `submariner-diagnostics-TIMESTAMP/`)

**Validate data structure:**
```
diagnostics-dir/
├── manifest.txt (contains timestamp, complaint, kubeconfig info)
├── cluster1/
│   ├── gather/ (subctl gather output)
│   │   └── cluster*/ (cluster-specific data)
│   │       ├── submariners_submariner-operator_submariner.yaml (Gateway CR)
│   │       ├── <nodename>_ipsec-status.log (IPsec control plane status)
│   │       ├── <nodename>_ipsec-trafficstatus.log (IPsec traffic counters)
│   │       ├── <nodename>_ip-xfrm-policy.log (XFRM policies)
│   │       ├── <nodename>_ip-xfrm-state.log (XFRM state)
│   │       ├── <nodename>_ip-routes.log (Routing table)
│   │       ├── <nodename>_ip-routes-table150.log (Submariner routing table)
│   │       ├── <nodename>_ip-rules.log (IP rules)
│   │       ├── <nodename>_ip-a.log (IP addresses)
│   │       ├── <nodename>_iptables-save.log (iptables rules)
│   │       ├── submariner-gateway-*-submariner-gateway.log (Gateway pod logs)
│   │       ├── submariner-routeagent-*-submariner-routeagent.log (RouteAgent pod logs)
│   │       └── pods_*.yaml (Pod status)
│   ├── subctl-show-all.txt
│   ├── subctl-diagnose-all.txt
│   ├── routeagents.yaml
│   ├── acm-addons.txt
│   └── submarinerconfig.yaml
├── cluster2/ (optional, same structure)
├── verify/ (optional, if contexts were provided)
│   ├── connectivity.txt
│   ├── connectivity-small-packet.txt
│   └── service-discovery.txt
└── tcpdump/ (optional, if tunnel was down during collection)
    ├── cluster1-gateway-<nodename>-analysis.txt (TEXT - packet analysis)
    ├── cluster1-gateway-<nodename>.pcap (BINARY - raw capture)
    ├── cluster2-gateway-<nodename>-analysis.txt (TEXT - packet analysis)
    └── cluster2-gateway-<nodename>.pcap (BINARY - raw capture)
```

**Read manifest.txt:**
- Extract timestamp
- Extract complaint (if not provided by user)
- Note which clusters were collected

**Detect Deployment Type (CRITICAL):**

Read both files from cluster1:
- `cluster1/acm-addons.txt`
- `cluster1/submarinerconfig.yaml`

**If EITHER file contains actual resources (not "No ... resources found"):**
  → **Deployment Type: ACM-Managed**
  → All configuration changes must be made to SubmarinerConfig CR on ACM hub cluster
  → DO NOT modify Submariner CR directly (ACM addon will override it)
  → In workaround instructions, provide ACM-specific commands

**If BOTH files say "No ... resources found":**
  → **Deployment Type: Standalone Submariner**
  → Configuration changes made to Submariner CR in each managed cluster
  → In workaround instructions, provide Standalone-specific commands

### Phase 3: Determine Analysis Focus Based on Complaint

Based on the complaint, route to appropriate analysis:

**Common complaints and their focus areas:**

1. **"tunnel not connected"** / **"tunnel error"** / **"connection down"**
   → Focus: Gateway-to-gateway tunnel analysis

2. **"pods failing"** / **"gateway crash"** / **"pods not running"**
   → Focus: Pod health analysis

3. **"connectivity issues"** / **"cannot reach pods"** / **"ping fails"**
   → Focus: Datapath analysis (both tunnel and local routing)
   → **PRIORITY CHECK:** Compare verify tests - if regular packets fail but small packets pass, this is MTU issue!

4. **"suspect firewall or other infrastructure issue"** / **"firewall"**
   → Focus: IPsec datapath analysis, check tcpdump data if available

5. **"service discovery"** / **"service discovery not working"** / **"DNS not working"**
   → Focus: Service discovery analysis

6. **"general health check"** / **"not sure"** / **Generic / No specific complaint**
   → Perform comprehensive health check
   → **ALWAYS check MTU pattern** if verify tests exist (compare regular vs small packet results)

### Phase 4: Read Diagnostic Files

**Key files to read based on complaint:**

#### A. Always Read (for all complaints):
1. `cluster1/subctl-show-all.txt` - Connection status overview
2. `cluster2/subctl-show-all.txt` - Connection status overview (if exists)
3. `manifest.txt` - Metadata

#### B. For Tunnel Issues - IPsec Control Plane:
1. `cluster1/gather/cluster*/submariners_submariner-operator_submariner.yaml` - Gateway CR (authoritative source for tunnel status)
2. `cluster2/gather/cluster*/submariners_submariner-operator_submariner.yaml` - Gateway CR
3. `cluster1/gather/cluster*/<gateway-node>_ipsec-status.log` - IPsec tunnel state (STATE_V2_ESTABLISHED_*)
4. `cluster2/gather/cluster*/<gateway-node>_ipsec-status.log` - IPsec tunnel state
5. `cluster1/gather/cluster*/<gateway-node>_ipsec-trafficstatus.log` - Traffic counters (ESPin/ESPout)
6. `cluster2/gather/cluster*/<gateway-node>_ipsec-trafficstatus.log` - Traffic counters

#### C. For Tunnel Issues - IPsec Datapath:
1. `cluster1/gather/cluster*/<gateway-node>_ip-xfrm-policy.log` - XFRM policies
2. `cluster2/gather/cluster*/<gateway-node>_ip-xfrm-policy.log` - XFRM policies
3. `cluster1/gather/cluster*/<gateway-node>_ip-routes-table150.log` - Submariner routes
4. `cluster2/gather/cluster*/<gateway-node>_ip-routes-table150.log` - Submariner routes
5. `cluster1/gather/cluster*/<gateway-node>_ip-a.log` - Verify health check IPs exist
6. `cluster2/gather/cluster*/<gateway-node>_ip-a.log` - Verify health check IPs exist
7. `tcpdump/cluster1-gateway-*-analysis.txt` - Packet capture analysis (TEXT - read this)
8. `tcpdump/cluster2-gateway-*-analysis.txt` - Packet capture analysis (TEXT - read this)
9. `tcpdump/cluster1-gateway-*.pcap` - Raw packet capture (BINARY - for reference only)
10. `tcpdump/cluster2-gateway-*.pcap` - Raw packet capture (BINARY - for reference only)

#### D. For Tunnel Issues - Logs:
1. `cluster1/gather/cluster*/submariner-gateway-*-submariner-gateway.log` - Gateway logs (check for errors)
2. `cluster2/gather/cluster*/submariner-gateway-*-submariner-gateway.log` - Gateway logs (check for errors)
3. `cluster1/gather/cluster*/submariner-routeagent-*-submariner-routeagent.log` - RouteAgent logs (check for errors)
4. `cluster2/gather/cluster*/submariner-routeagent-*-submariner-routeagent.log` - RouteAgent logs (check for errors)

#### E. For Pod Health Issues:
1. `cluster1/gather/cluster*/pods_*.yaml` - Pod status
2. `cluster1/gather/cluster*/*-submariner-*.log` - Pod logs

#### F. For Connectivity Issues:
1. `verify/connectivity.txt` - Default packet size results
2. `verify/connectivity-small-packet.txt` - Small packet size results (for MTU issues)
3. Gateway CR and logs (same as tunnel issues)

Note: The verify files contain the actual command executed at the top. Check if:
- The same context was used for both --context and --tocontext (common mistake)
- Correct packet sizes were specified
- Proper kubeconfig was used
- **Early stop detection:** Tests may have stopped early to save time
  - Look for: "Verification stopped early after N consecutive test failures"
  - This indicates systemic connectivity issues (first 6 tests failed)
  - Failed test details are captured before the stop
  - Treat early-stopped tests as failed - they indicate connectivity problems

#### G. For RouteAgent Issues:
1. `cluster1/routeagents.yaml` - RouteAgent status
2. `cluster2/routeagents.yaml` - RouteAgent status
3. `cluster1/gather/cluster*/submariner-routeagent-*.log` - RouteAgent logs

#### H. For Service Discovery Issues:
1. `verify/service-discovery.txt` - Service discovery verification
2. Lighthouse/CoreDNS logs (if present)

### Phase 5: Perform Analysis

Apply the same logic as live troubleshooting commands, but read from files:

#### **Analysis 1: Tunnel Health**

**Step 1: Read Gateway CR for Tunnel Status**

File: `cluster*/gather/cluster*/submariners_submariner-operator_submariner.yaml`

In the Gateway CR YAML, check `status.gateways[].connections[]`:

```yaml
status:
  gateways:
  - connections:
    - endpoint:
        backend: libreswan           # Cable driver type
        private_ip: 172.18.0.4
        public_ip: 1.2.3.4
      usingIP: 172.18.0.4            # IP actually being used
      status: error                   # Connection status
      statusMessage: "Failed to successfully ping the remote endpoint IP..."
```

**Important Fields:**
- `backend`: Cable driver (libreswan, wireguard, vxlan)
- `usingIP`: IP address being used for tunnel (private or public)
- `status`: Tunnel status (connected, error, connecting)
- `statusMessage`: Error details if status != connected
- `healthCheckIP`: Remote cluster's health check IP target

**Step 2: Verify IPsec Control Plane (if backend=libreswan)**

File: `cluster*/gather/cluster*/<gateway-node>_ipsec-status.log`

Look for tunnel state lines like:
```
#222: "submariner-cable-..." STATE_V2_ESTABLISHED_IKE_SA
#224: "submariner-cable-..." STATE_V2_ESTABLISHED_CHILD_SA
```

**Expected:** All tunnels should show STATE_V2_ESTABLISHED_CHILD_SA

**Step 3: Check IPsec Datapath Traffic**

File: `cluster*/gather/cluster*/<gateway-node>_ipsec-trafficstatus.log`

Look for traffic counters:
```
#224: "submariner-cable-...", inBytes=0, outBytes=0
```

**Expected:** If tunnel is "connected", inBytes and outBytes should be > 0
**Problem:** inBytes=0 and outBytes=0 indicates datapath failure despite control plane being up

**Step 4: Verify XFRM Policies**

File: `cluster*/gather/cluster*/<gateway-node>_ip-xfrm-policy.log`

Check for policies like:
```
src 10.130.0.0/16 dst 10.131.0.0/16
	dir out priority 1761505 ptype main
	tmpl src 172.18.0.5 dst 172.18.0.4
		proto esp reqid 16401 mode tunnel
```

**Expected:** Policies should exist for both directions (in/out) for pod and service CIDRs

**Step 5: Verify Routing**

File: `cluster*/gather/cluster*/<gateway-node>_ip-routes-table150.log`

Check for routes to remote cluster CIDRs:
```
10.131.0.0/16 dev eth0 proto static scope link src 10.130.1.1
```

**Expected:** Routes should exist for remote cluster's pod and service CIDRs

**Step 6: Verify Health Check IPs**

**IMPORTANT:** You can verify health check IP existence from collected data - no live cluster access needed!

File: `cluster*/gather/cluster*/<gateway-node>_ip-a.log`

Search for the health check IP (from Gateway CR) in the ip-a.log file:
```bash
# Example: If healthCheckIP is 10.130.1.1, search for it:
grep "10.130.1.1" cluster1/gather/cluster1/cluster1-worker_ip-a.log
```

Look for health check IP on veth interfaces:
```
inet 10.130.1.1/32 scope global veth...
```

**Expected:** Health check IP should exist on the gateway node on one or more veth interfaces

**Analysis:**
- **If health check IP exists:** The issue is most likely NOT health check IP configuration - focus on datapath/infrastructure blocking
- **If health check IP is missing:** This could indicate a configuration issue that needs further investigation

**Step 7: Check Gateway and RouteAgent Logs**

Files:
- `submariner-gateway-*-submariner-gateway.log`
- `submariner-routeagent-*-submariner-routeagent.log`

Search for ERROR, WARN, or FAIL messages. Key patterns:
- "Failed to successfully ping" - Health check ping failures (symptom, not root cause)
- "error" or "failed" related to configuration - Actual configuration problems
- "nat-discovery" or "NAT-T discovery" with "timeout" or "failed" - NAT discovery issues

**Important:**
- Health check ping failures are SYMPTOMS of datapath issues
- Look for errors related to route installation, iptables, or IPsec configuration
- If no configuration errors exist, the issue is likely infrastructure-level

**Special Case - OpenShift on OpenStack:**

If BOTH conditions are met:
1. Tunnel is NOT connected on one or both clusters, OR NAT discovery failed in gateway logs
2. Environment is OpenShift on OpenStack (check for "openshift" + "openstack"/"nova" indicators)

Then check gateway logs for NAT discovery timeout:
```
grep -i "nat.*discovery.*timeout\|nat.*discovery.*failed" gateway.log
```

If NAT discovery timeout is found:
→ Add a note in "ADDITIONAL RECOMMENDATIONS" section about potential UDP port conflict
→ This is a known issue in OpenShift on OpenStack environments
→ OpenStack infrastructure may use UDP ports 4490-4510 conflicting with Submariner defaults

**Step 8: Analyze tcpdump Data (if available)**

Files:
- `tcpdump/cluster*-gateway-*-analysis.txt` - Text summary (ALWAYS read this)
- `tcpdump/cluster*-gateway-*.pcap` - Binary capture (for advanced analysis)

If tunnel status is "error" and tcpdump was collected, the collection script automatically
generates text summaries that can be read directly.

**Read the analysis files:**

File: `tcpdump/cluster1-gateway-<nodename>-analysis.txt`
File: `tcpdump/cluster2-gateway-<nodename>-analysis.txt`

These files contain:
- Total packet count
- First 50 packets with details
- Source/destination IP pairs
- Automatic interpretation

**Analyze the pattern:**

Compare both clusters' analysis files:

**Pattern 1: No Egress Traffic**
```
Cluster1 analysis: "Total packets captured: 0"
Cluster2 analysis: "Total packets captured: 0"

→ Gateway pods are NOT sending tunnel traffic
→ Root cause: IPsec tunnel not properly initialized at kernel level
→ Check: ipsec-status.log for STATE_V2_ESTABLISHED_CHILD_SA
```

**Pattern 2: Egress but No Ingress (Infrastructure Blocking)**

**CRITICAL:** tcpdump captures BOTH incoming and outgoing packets. If you only see "Out" packets with NO "In" packets, it means packets are NOT arriving.

**Note:** The tcpdump capture filter is set based on the cable driver and configuration:
- libreswan with ESP: `proto 50`
- libreswan with UDP encapsulation: `udp port 4500` (or ceIPSecNATTPort)
- vxlan: `udp port 4500` (or ceIPSecNATTPort)

The analysis checks for packet direction (In/Out) regardless of the underlying protocol.

```
Example A - Unidirectional blocking:
Cluster1 analysis: "Total packets captured: 150" (all "Out" direction)
Cluster2 analysis: "Total packets captured: 0"

→ Packets leaving cluster1 but NOT arriving at cluster2
→ Infrastructure blocking cluster1→cluster2 direction

Example B - Bidirectional blocking:
Cluster1 analysis: "Total packets captured: 150" (all "Out", no "In")
Cluster2 analysis: "Total packets captured: 94" (all "Out", no "In")

→ Both clusters sending packets, but NEITHER receiving
→ Infrastructure blocking tunnel traffic in BOTH directions
→ This is the most common infrastructure blocking pattern

Root cause: INFRASTRUCTURE BLOCKING (firewall/network blocking tunnel traffic)
→ Check what protocol is being used (ESP proto 50 or UDP port)
→ If ESP (proto 50): Recommend UDP encapsulation
→ If UDP already: Verify firewall allows the UDP port
```

**Pattern 3: Both Sending but Tunnel Still Error**
```
Cluster1 analysis: "Total packets captured: 150"
Cluster2 analysis: "Total packets captured: 150"

→ Packets flowing in both directions
→ But tunnel status still shows "error"
→ Root cause: Health check IP issue or packet corruption
→ Check: Are packets reaching the right destination IPs?
→ Review: Source/destination pairs in analysis file
```

**Diagnosis Pattern:**
```
If tunnels are ESTABLISHED (ipsec-status shows STATE_V2_ESTABLISHED_CHILD_SA):
  AND traffic counters show inBytes=0, outBytes=0:
    → IPsec control plane is working, but datapath is broken

    If gateway/routeagent logs show NO configuration errors:
      → Root cause is INFRASTRUCTURE LEVEL (firewall/network blocking)

      Read tcpdump analysis files:
        If cluster1 analysis shows packets (Out direction) BUT cluster2 analysis shows 0:
          → Packets leaving cluster1 but not reaching cluster2
          → Tunnel traffic being blocked between nodes
          → Check cable driver and protocol being used:
            - libreswan with ESP: Try UDP encapsulation
            - libreswan with UDP or vxlan: Verify firewall allows UDP port

        If both analysis files show 0 packets:
          → Gateway not sending packets
          → Check gateway pod logs for cable driver initialization errors
```

#### **Analysis 2: MTU Issues**

**CRITICAL:** Always compare both verify test results to detect MTU issues

Read:
- `verify/connectivity.txt` - Default packet size (~3000 bytes)
- `verify/connectivity-small-packet.txt` - Small packet size (400 bytes)

**MTU Issue Pattern (DEFINITIVE):**
- Default packet test FAILS (may have stopped early after 6 failures)
- Small packet test SUCCEEDS

→ **ROOT CAUSE: MTU/fragmentation issue** (high confidence)

**This is THE classic MTU pattern - do NOT ignore it!**

**Why this indicates MTU:**
- Large packets (~3KB) cannot traverse the network path due to MTU restrictions
- Small packets (400 bytes) fit within MTU limits and succeed
- If tunnels are connected but large packets fail, the issue is NOT at tunnel level
- The infrastructure allows the tunnel protocol (ESP/UDP) but fragments/drops large packets

**Solution: TCP MSS Clamping**

In network topologies where MTU issues are observed, the encapsulation overhead added by Submariner can cause packet drops. This happens when nodes along the path don't adjust the path MTU value correctly to account for the encapsulation overhead.

To resolve this, you can force a specific MSS clamping value by adding an annotation to the Gateway nodes, which instructs Submariner to rewrite the TCP Maximum Segment Size.

Apply TCP MSS clamping by annotating gateway nodes:

```bash
# Annotate gateway nodes with MSS value
kubectl annotate node <gateway-node-name> submariner.io/tcp-clamp-mss=<value>

# Restart routeagent pods to pick up the change
kubectl delete pod -n submariner-operator -l app=submariner-routeagent
```

Recommended MSS value: **1300** (accounts for encapsulation overhead in standard networks)

Adjust based on your network MTU if needed.

**Important Notes:**
- Health check pings use small ICMP packets, so if health checks fail, MTU is NOT the root cause
- MTU issues only appear with large data transfers, not control plane
- Tunnels may show "connected" status even with MTU issues (health checks still work)

#### **Analysis 3: RouteAgent Health**

**Read RouteAgent CR:**
```
cluster*/routeagents.yaml
```

**Check each RouteAgent's `status.remoteEndpoints[].status` field:**

**Rules:**
- **Gateway nodes:** `status: none` = OK (expected - gateway doesn't check itself)
- **Non-gateway nodes:** `status: connected` = OK (can route through gateway)
- **Non-gateway nodes:** `status != connected` = Problem (local routing issue)

**Important Distinction:**
- If tunnel status is "error" on gateway AND non-gateway nodes also show errors:
  → Focus on gateway-to-gateway issue FIRST
  → Non-gateway errors are likely downstream effect of tunnel failure
  → Don't conclude "local routing issue" when gateway tunnel is broken

- If tunnel status is "connected" on gateway BUT non-gateway nodes show errors:
  → This IS a local routing issue (nodes can't route through their gateway)

#### **Analysis 4: Pod Health**

**Read pod status from:**
```
cluster*/gather/cluster*/pods_*.yaml
```

**Check:**
- Are all pods in Running state?
- Any pods in CrashLoopBackOff, Error, or Pending?
- Check `status.conditions[]` for issues

**Read pod logs for errors:**
```
cluster*/gather/cluster*/*-submariner-*.log
```

#### **Analysis 5: Service Discovery**

**Read:**
```
verify/service-discovery.txt
```

**Check if:**
- Service discovery tests passed
- DNS resolution working
- Cross-cluster service access working

### Phase 6: Provide Analysis Report

**OUTPUT FORMAT: Provide Brief Analysis (DEFAULT)**

**IMPORTANT:** Always provide a **brief, actionable report** as the default output format. Only provide the detailed report if the user explicitly requests it.

**Brief report should include:**
1. **Key Findings** (3-5 bullet points) - What's working, what's broken
2. **Root Cause** (1-2 paragraphs) - Most likely issue based on evidence
3. **Recommended Next Steps** (3 steps with correct priority order):
   - **Step 1: Verify Prerequisites FIRST**
   - **Step 2: Apply workaround if needed**
   - **Step 3: Alternative workaround if Step 2 fails**
4. **Reference to detailed files analyzed** - For transparency

**DO NOT provide:**
- Massive detailed reports with 10+ sections
- Extensive workaround options (pick top 2 most likely solutions)
- Speculative deep-dives into all possible causes
- Workarounds before verifying prerequisites

**IMPORTANT: Use Cautious Language and Acknowledge Uncertainty**

When analyzing offline diagnostic data, you are working with a snapshot in time without live cluster access. Therefore:

- **Use probabilistic language:** "seems like", "most probably", "could be", "appears to be" instead of definitive statements like "This is" or "The root cause is"
- **Present most likely scenario first**, but acknowledge other possibilities
- **Recommend further investigation steps** - offline analysis can identify the most probable cause, but deeper investigation may be needed to confirm
- **Consider that proposed solutions might also fail** - For example, if you suspect ESP is blocked and recommend UDP encapsulation, acknowledge that UDP port 4500 might also be blocked by the firewall
- **Be humble about conclusions** - You're providing educated analysis based on evidence, not absolute truth

**Example of Good vs Bad Language:**

❌ **Bad (too definitive):**
"This is a gateway-to-gateway datapath failure. ESP protocol packets are being blocked by network infrastructure. The solution is to enable UDP encapsulation."

✅ **Good (appropriately cautious):**
"Based on the evidence, this **appears to be** a gateway-to-gateway datapath failure, **most likely caused by** ESP protocol packets being blocked at the infrastructure level. **Recommended first step** is to try UDP encapsulation, though further investigation may be needed if UDP port 4500 is also restricted."

**IMPORTANT: Keep Recommendations Simple and Focused**

When providing solutions:
- Focus on the KEY next steps (3-4 steps maximum)
- Don't overwhelm with too many possibilities
- Prioritize most likely root cause based on evidence
- Reference official Submariner documentation for details
- Avoid deep technical investigations that users can't easily perform
- **Always include "Further Investigation Steps"** section for deeper analysis if initial solution doesn't work

**IMPORTANT: Trust Submariner Components**

- Submariner routeagent manages iptables/nftables rules
- If routeagent logs show NO errors, don't recommend manual iptables investigation
- Treat routing/iptables as a black box unless routeagent logs indicate problems

---

**BRIEF REPORT FORMAT (USE THIS)**

Provide a brief report following this template:

```
## SUBMARINER OFFLINE ANALYSIS - BRIEF REPORT

**Diagnostic:** <diagnostics-path>
**Issue:** <complaint from manifest>
**Deployment:** <Standalone Submariner / ACM-Managed>

### Key Findings

✓/✗ **Finding 1** - Brief description with file reference
✓/✗ **Finding 2** - Brief description with file reference
✓/✗ **Finding 3** - Brief description with file reference
✓/✗ **Finding 4** - Brief description with file reference

### Root Cause

<1-2 paragraph explanation using cautious language like "appears to be", "most likely", "seems to indicate">

Key evidence:
- Evidence point 1 (file:line reference)
- Evidence point 2 (file:line reference)
- Evidence point 3 (file:line reference)

### Recommended Next Steps

**IMPORTANT: For MTU Issues ONLY - Do NOT include the "Verify Prerequisites" section**

When MTU issue is detected (small packets pass, large packets fail), provide ONLY the TCP MSS clamping solution:

**Apply TCP MSS Clamping**

**What it does:** Adjusts the TCP Maximum Segment Size to account for Submariner's encapsulation overhead.

**Why this is needed:** Submariner encapsulation adds overhead to packets, and most probably some nodes along the path don't adjust the path MTU value correctly, so we need to force MSS clamping value.

**Security Impact:** ✓ Maintains encryption - only adjusts TCP packet sizes

**Steps:**

1. **Annotate gateway nodes:**

```bash
kubectl --context cluster1 annotate node <gateway-node> \
  submariner.io/tcp-clamp-mss=<value>

kubectl --context cluster2 annotate node <gateway-node> \
  submariner.io/tcp-clamp-mss=<value>
```

Recommended starting value: **1300** (accounts for encapsulation overhead in standard networks)

2. **Restart routeagent pods to apply changes:**

```bash
kubectl --context cluster1 delete pod -n submariner-operator -l app=submariner-routeagent
kubectl --context cluster2 delete pod -n submariner-operator -l app=submariner-routeagent
```

3. **Verify the fix:**

Re-run the default packet size test that initially failed:

```bash
subctl verify --context cluster1 --tocontext cluster2 --only connectivity --verbose
```

Expected outcome: Default packet size tests (~3KB) that previously failed should now pass with MSS clamping enabled.

---

**For Other Issues (Tunnel Not Connected, Firewall Blocking, etc.):**

**1. Verify Submariner Prerequisites (FIRST PRIORITY)**

Check if required protocols are allowed between gateway nodes:
- **ESP (IP protocol 50)** OR **UDP port 4500**
- Provide specific verification commands for the environment (KIND/cloud/etc.)

📖 [Submariner Prerequisites](https://submariner.io/operations/deployment/prerequisites/)

**2. <Workaround Name> (If Prerequisites Cannot Be Met)**

<Brief explanation of workaround - what it does and why it's a workaround>

**Security Impact:** <✓ Maintains encryption / ❌ Removes encryption>

```bash
<Concrete commands to apply workaround>
```

### Files Analyzed
- List key files examined for transparency

**Priority:** <HIGH/MEDIUM/LOW> - <reason>
**Confidence:** <HIGH/MEDIUM/LOW> - <reason>
```

---

**DETAILED REPORT FORMAT (OPTIONAL - Only if user requests detailed analysis)**

Create a comprehensive report following this format:

```
========================================
SUBMARINER OFFLINE ANALYSIS REPORT
========================================

DIAGNOSTIC DATA:
  Timestamp: <from manifest>
  Complaint: <user complaint>
  Clusters Analyzed: cluster1, cluster2
  Deployment Type: <Standalone Submariner / ACM-Managed>

========================================
EXECUTIVE SUMMARY
========================================

<One-paragraph summary of findings using cautious language like "appears to be", "most likely", "seems to indicate">
<Focus on whether it appears to be a configuration issue or infrastructure issue>
<Which segment seems to have the problem (gateway-to-gateway vs local routing)>
<Use probabilistic language, not definitive statements>
<Acknowledge this is offline analysis and may need confirmation>

========================================
DETAILED FINDINGS
========================================

1. TUNNEL STATUS (Submariner Control Plane)

   Cluster1 → Cluster2:
     Status: <connected/error/connecting>
     Cable Driver: <libreswan/wireguard/vxlan>
     Using IP: <IP address> (<private/public>)
     Health Check Target: <remote cluster health check IP>
     Error Message: <if status=error>

   Cluster2 → Cluster1:
     <same structure>

   Finding: <Symmetric or asymmetric status, interpretation>

2. IPSEC CONTROL PLANE STATUS (Kernel Level)

   Cluster1 Gateway (<node-name>):
     IKE SA: <STATE_V2_ESTABLISHED_IKE_SA or status>
     ESP SAs: <number> tunnels, all STATE_V2_ESTABLISHED_CHILD_SA

   Cluster2 Gateway (<node-name>):
     <same structure>

   Finding: <Whether IPsec control plane is established>

3. DATAPATH STATUS

   Traffic Statistics:
     Cluster1 → Cluster2: ESPout=<bytes>, ESPin=<bytes>
     Cluster2 → Cluster1: ESPout=<bytes>, ESPin=<bytes>

   XFRM Policies:
     ✓/✗ Outbound policies configured
     ✓/✗ Inbound policies configured

   Routing (Table 150):
     ✓/✗ Routes to remote cluster CIDRs

   Health Check IPs:
     ✓/✗ Present on gateway nodes

   Finding: <Whether datapath infrastructure is correctly configured>

4. POD HEALTH

   Cluster1:
     ✓/✗ Gateway DaemonSet: <status>
     ✓/✗ RouteAgent DaemonSet: <status>
     ✓/✗ Operator: <status>

   Cluster2:
     <same structure>

5. COMPONENT LOGS ANALYSIS

   Gateway Logs:
     ✓/✗ No configuration errors
     ✓/✗ No routing errors
     ✗ Health check ping failures: <message>

   RouteAgent Logs:
     ✓/✗ No route installation errors
     ✓/✗ No iptables errors

   Finding: <Whether Submariner components have configuration issues>

6. TCPDUMP ANALYSIS (if available)

   Read from: tcpdump/cluster*-gateway-*-analysis.txt

   Cluster1 Gateway (tcpdump/cluster1-gateway-<node>-analysis.txt):
     Total packets: <number> packets
     Protocol: <ESP proto 50 / UDP port XXXX>
     Status: <✓ Traffic detected / ✗ NO PACKETS CAPTURED>

   Cluster2 Gateway (tcpdump/cluster2-gateway-<node>-analysis.txt):
     Total packets: <number> packets
     Protocol: <ESP proto 50 / UDP port XXXX>
     Status: <✓ Traffic detected / ✗ NO PACKETS CAPTURED>

   Pattern Analysis:
     <Pattern 1/2/3 as described in Step 8>

   Finding: <Where packets are being dropped - be specific>

   Examples:
     - "Cluster1 sending 150 packets, Cluster2 receiving 0 → Infrastructure blocking ESP"
     - "Both clusters sending 0 packets → IPsec not initialized"
     - "Both sending packets but tunnel error → Health check IP issue"

7. CONNECTIVITY VERIFICATION (if available)

   Default packet size: <PASS/FAIL>
   Small packet size: <PASS/FAIL>
   Service discovery: <PASS/FAIL>

========================================
ROOT CAUSE ANALYSIS
========================================

Issue Type: <Gateway-to-Gateway Datapath Failure / Local Routing Issue / Configuration Error / etc.>

**What IS Working:**
  ✓ <List working components>

**What IS NOT Working:**
  ✗ <List failing components>

**Key Evidence:**
  1. <Evidence 1 with file reference>
  2. <Evidence 2 with file reference>
  3. <Evidence 3 with file reference>

**Most Likely Root Cause:**

<Use cautious language: "appears to be", "most probably", "seems like", "could be">
<Present the most likely root cause based on evidence>
<Acknowledge that this is based on offline analysis and may need confirmation>

**Technical Explanation:**

<Technical explanation of why this is happening - use probabilistic language>

<Important: Don't speculate about ICMP being blocked by infrastructure - ICMP
is encapsulated inside the IPsec tunnel, so infrastructure only sees ESP/UDP packets>

**Alternative Possibilities:**

<Briefly mention 1-2 other possible causes if the evidence is not 100% conclusive>

**Next Steps for Investigation:**

1. **Verify Submariner Prerequisites:**
   Ensure all infrastructure and datapath prerequisites are properly configured:

   📖 [Submariner Prerequisites Documentation](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_management_for_kubernetes/2.15/html/networking/networking#submariner-prereqs)

2. **Confirm Network Path Requirements:**
   - Verify required protocols are allowed between gateway nodes
   - Review security policies or filtering rules that might affect traffic

**Possible Root Causes:**
<List 2-3 possible causes based on evidence - e.g., ESP protocol blocking, UDP port blocking, etc.>

**What we know is NOT the issue:**
<List ruled-out causes with reasoning - e.g., "Pre-shared key mismatch (IKE negotiation succeeded)">

========================================
RECOMMENDED SOLUTION
========================================

**IMPORTANT INSTRUCTIONS:**

**For MTU Issues:** Skip Step 1 (Verify Prerequisites) entirely. Provide ONLY the TCP MSS clamping solution as shown below. MTU issues are not related to protocol blocking or prerequisites.

**For Other Issues (Tunnel Not Connected, ESP Blocking, etc.):** Follow Steps 1-3 in order - verify prerequisites first, then apply workarounds if needed.

**Deployment Type Detected: <Standalone Submariner / ACM-Managed>**

---

**For MTU Issues ONLY - TCP MSS Clamping:**

**What it does:** Adjusts the TCP Maximum Segment Size to account for Submariner's encapsulation overhead.

**Why this is needed:** Submariner encapsulation adds overhead to packets, and most probably some nodes along the path don't adjust the path MTU value correctly, so we need to force MSS clamping value.

**Security Impact:** ✓ Maintains encryption - only adjusts TCP packet sizes

**How to apply:**

1. **Annotate gateway nodes:**

```bash
kubectl --context cluster1 annotate node <gateway-node> \
  submariner.io/tcp-clamp-mss=1300

kubectl --context cluster2 annotate node <gateway-node> \
  submariner.io/tcp-clamp-mss=1300
```

2. **Restart routeagent pods to pick up the change:**

```bash
kubectl --context cluster1 delete pod -n submariner-operator -l app=submariner-routeagent
kubectl --context cluster2 delete pod -n submariner-operator -l app=submariner-routeagent
```

3. **Verify the fix:**

Re-run the default packet size test that initially failed:

```bash
subctl verify --context cluster1 --tocontext cluster2 --only connectivity --verbose
```

Expected outcome: Default packet size tests (~3KB) that previously failed should now pass with MSS clamping enabled.

---

**For Other Issues (NOT MTU) - Step 1: Verify Submariner Prerequisites (FIRST PRIORITY)**

Before applying any workarounds, verify that the infrastructure meets Submariner's network requirements.

**Required for Submariner:**
- **ESP (IP protocol 50)** between gateway nodes, OR
- **UDP port 4500** between gateway nodes (for UDP encapsulation mode)

**How to verify:**

<Provide specific commands to check if ESP or UDP port 4500 is allowed between the gateway nodes>
<For KIND environments: Check Docker networking and host iptables>
<For cloud environments: Check security groups, network policies, firewall rules>

📖 [Submariner Prerequisites Documentation](https://submariner.io/operations/deployment/prerequisites/)

**If ESP (protocol 50) is blocked but UDP port 4500 is allowed:**
→ Proceed to Step 2 (UDP Encapsulation workaround)

**If both ESP and UDP port 4500 are blocked:**
→ Fix the infrastructure/firewall rules first before proceeding

---

**Step 2: Enable UDP Encapsulation (WORKAROUND if ESP is blocked)**

**What it does:** Forces IPsec payload to be encapsulated inside UDP packets (port 4500), **regardless of whether NAT was detected**. Even when Submariner NAT discovery selects private IP addresses (meaning no NAT is present), setting `ceIPSecForceUDPEncaps: true` will still use UDP encapsulation instead of native ESP.

**Why it's a workaround:** Doesn't fix the infrastructure blocking of ESP protocol - works around it by forcing UDP transport. This helps when:
- ESP (IP protocol 50) is blocked by firewall/network infrastructure
- BUT UDP port 4500 is allowed

**Security Impact:** ✓ Maintains encryption - IPsec payload is still encrypted, just transported over UDP instead of ESP

**How to apply:**

**For Standalone Submariner:**
```bash
kubectl patch submariner -n submariner-operator submariner \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

kubectl delete pods -n submariner-operator -l app=submariner-gateway
```

**For ACM-Managed Submariner:**
```bash
# On the ACM hub cluster
kubectl patch submarinerconfig -n <managed-cluster-namespace> <submarinerconfig-name> \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

# ACM will propagate changes automatically to managed clusters
```

**Verify the fix:**
```bash
# Wait ~30 seconds for changes to propagate, then check:
subctl show connections
# Expected: STATUS should change from "error" to "connected"

subctl diagnose all
# Expected: Gateway connection checks should pass
```

**Expected outcome:** Tunnel should establish using UDP port 4500 instead of ESP protocol 50

---

**Step 3: Switch to VXLAN Cable Driver (LAST RESORT)**

**What it does:** Uses VXLAN (UDP-based tunneling) instead of IPsec.

**Why it's a workaround:** Avoids IPsec/ESP entirely - doesn't fix infrastructure blocking.

**⚠️ CRITICAL SECURITY IMPACT:**
**VXLAN does NOT encrypt traffic between clusters.** All pod-to-pod communication will be sent in **CLEAR TEXT**.

Only use this if:
- Your clusters are on a trusted private network
- You have other encryption (service mesh with mTLS)
- You accept the security risk for testing/lab environments

**How to apply:**

**For Standalone Submariner:**
```bash
kubectl patch submariner -n submariner-operator submariner \
  --type merge \
  -p '{"spec": {"cableDriver": "vxlan"}}'

kubectl delete pods -n submariner-operator -l app=submariner-routeagent
# Gateway pods will restart automatically
```

**For ACM-Managed Submariner:**
```bash
# On the ACM hub cluster
kubectl patch submarinerconfig -n <managed-cluster-namespace> <submarinerconfig-name> \
  --type merge \
  -p '{"spec": {"cableDriver": "vxlan"}}'

# ACM will propagate changes automatically
```

**Verify the fix:**
```bash
# Wait ~30 seconds, then check:
subctl show connections
# Expected: CABLE DRIVER: vxlan, STATUS: connected

subctl verify --only connectivity --verbose
```

**Trade-offs:**
- ❌ **No encryption** - all inter-cluster traffic in clear text
- ❌ **Will NOT work if UDP encapsulation failed** - Both use same UDP port (4500)
- ✓ Simpler protocol, might bypass ESP-specific packet inspection

**Critical Note:**

**If UDP encapsulation (Workaround 1) fails**, VXLAN will **definitely also fail** because both use the exact same UDP port (4500).

**Only consider VXLAN if:**
- UDP encapsulation **works** but you want to avoid IPsec for other reasons
- You accept **unencrypted traffic**
- You understand the security implications

**Bottom line:** VXLAN is **not a workaround for UDP port blocking** - it's only an alternative if you want to avoid IPsec while keeping the same network requirements.

========================================
FURTHER INVESTIGATION STEPS
========================================

**If the recommended solution doesn't resolve the issue**, consider these deeper investigation steps:

**1. Verify Infrastructure Connectivity**

<Provide specific steps to test infrastructure-level connectivity>
<For example: Test if ESP/UDP packets can traverse the network path>
<How to check firewall rules, security groups, network policies>

**2. Collect Live Packet Captures**

<How to run tcpdump on gateway nodes to see if packets are egressing/ingressing>
<What to look for in the packet captures>

**3. Check for Additional Blocking**

<If UDP encapsulation was recommended, test if UDP 4500 is also blocked>
<How to verify with tcpdump or manual testing>

**4. Alternative Cable Drivers**

<If all network-level fixes fail, mention VxLAN as last resort>
<Acknowledge trade-offs (no encryption with VxLAN)>

**5. Engage Submariner Community**

If the issue persists after these investigations:
- Share the diagnostic tarball on Submariner Slack: https://kubernetes.slack.com/archives/C010RJV694M
- Open a GitHub issue: https://github.com/submariner-io/submariner/issues
- Include the complete diagnostic tarball and investigation results

========================================
ADDITIONAL RECOMMENDATIONS
========================================

<Any other findings or suggestions - keep brief>

<If OpenShift on OpenStack with NAT discovery timeout detected, include:>

**HEADS-UP: Potential UDP Port Conflict (OpenShift on OpenStack)**

Your environment appears to be OpenShift running on OpenStack, and we detected NAT
discovery timeout failures in the gateway logs. This could indicate a UDP port conflict
between Submariner and OpenStack infrastructure services.

**Known Issue:**
OpenStack infrastructure sometimes uses UDP ports in the 4490-4510 range, which conflicts
with Submariner's default ports:
  - ceIPSecNATTPort: 4500 (IPsec NAT-T)
  - nattDiscoveryPort: 4490 (NAT discovery)

**Evidence:**
  - Environment: OpenShift on OpenStack
  - NAT discovery timeout in gateway logs: <file:line>
  - Tunnel status: <error/connecting/not connected>

**Recommended Investigation:**

This could be the root cause of your tunnel connectivity issues. Consider investigating
in this direction:

1. **Check if using ACM for Submariner deployment:**

   Look for SubmarinerConfig CR in gathered data (acm-addons.txt or submarinerconfig.yaml).

   If ACM deployment (SubmarinerConfig exists):
   → Changes must be made to **SubmarinerConfig CR on ACM hub cluster**
   → DO NOT modify Submariner CR directly (ACM addon will override it)

   If standalone deployment (no SubmarinerConfig):
   → Changes should be made to **Submariner CR** in each cluster

2. **Suggested port changes:**

   Use non-conflicting UDP ports outside the 4490-4510 range, for example:
   - ceIPSecNATTPort: 4501 → change to 4520
   - nattDiscoveryPort: 4490 → change to 4480

3. **Further investigation:**

   - Verify which UDP ports OpenStack is using in your environment
   - Test connectivity with different port combinations
   - Monitor gateway logs after port changes for NAT discovery success

**Documentation:**
Refer to Submariner documentation for updating these settings based on your deployment method.

========================================
FILES ANALYZED
========================================

<List of key files that were examined with their purposes>

========================================
SUMMARY
========================================

<2-3 paragraph summary using cautious language>
- Use phrases like "appears to be", "most likely", "seems to indicate"
- Acknowledge this is based on offline analysis of static diagnostic data
- Whether it appears to be a Submariner configuration issue or infrastructure issue
- Which segment seems to have the problem (gateway-to-gateway vs local routing)
- Priority level and confidence level
- Recommended immediate next steps
- Note that further investigation may be needed to confirm root cause

Priority: <HIGH/MEDIUM/LOW> - <reason>
Confidence: <HIGH/MEDIUM/LOW> - <reason based on evidence quality and certainty>

**Note:** This analysis is based on offline diagnostic data. Live cluster testing may reveal additional factors not visible in the collected snapshots.
```

### Phase 7: Answer Follow-up Questions

After providing the report, be ready to:
- Dive deeper into specific findings
- Explain technical details
- Provide alternative solutions
- Analyze additional files if needed

## Important Guidelines

1. **Use cautious, probabilistic language** - You're analyzing offline static data without live cluster access
   - Use "appears to be", "most likely", "seems like", "could be" instead of "is" or "the root cause is"
   - Acknowledge uncertainty and recommend further investigation if needed
   - Consider that proposed solutions might also fail (e.g., UDP 4500 could also be blocked)
   - Always include "Further Investigation Steps" section for deeper analysis

2. **Read from files, never run commands** - All data is static, no live cluster access

3. **Gateway CR is authoritative** - For tunnel status, always trust the Gateway CR over logs

4. **Check IPsec at multiple levels:**
   - Control plane: ipsec-status.log (are tunnels established?)
   - Datapath: ipsec-trafficstatus.log (is traffic flowing?)
   - Policies: ip-xfrm-policy.log (are XFRM policies configured?)
   - Routing: ip-routes-table150.log (are routes installed?)

5. **Distinguish tunnel vs local routing:**
   - If gateway tunnel status = "error" → Focus on gateway-to-gateway segment
   - If gateway tunnel status = "connected" but non-gateway nodes fail → Local routing issue
   - Don't conclude "local routing issue" when gateway tunnel is broken

6. **Trust Submariner components:**
   - If routeagent/gateway logs show NO configuration errors → Configuration is correct
   - Don't recommend manual iptables/nftables investigation
   - The issue is likely infrastructure-level

7. **ICMP is encapsulated:**
   - Health check pings are INSIDE the IPsec tunnel
   - Infrastructure only sees ESP (proto 50) or UDP packets
   - Don't mention "ICMP blocked by firewall" - it's incorrect

8. **Health check ping size:**
   - Health checks use default small ICMP packets
   - If health checks fail, MTU is NOT the root cause
   - MTU issues only appear with large data transfers

9. **Use tcpdump data if available:**
   - If tcpdump files exist, analyze them to determine where packets are dropped
   - Egress but no ingress → Infrastructure blocking
   - No egress → Gateway not sending (local issue)

10. **Keep recommendations simple:**
    - 3-4 focused steps maximum
    - Don't provide too many alternatives
    - Prioritize most likely solution based on evidence
    - Always include "Further Investigation Steps" section

11. **Reference official documentation:**
    - Always point to https://submariner.io/ for detailed solutions
    - Provide specific section and search terms
    - Let official docs provide implementation details

12. **OpenShift on OpenStack UDP port conflicts:**
    - ONLY check if: (tunnel not connected OR NAT discovery timeout) AND OpenShift on OpenStack
    - If NAT discovery timeout found → Add heads-up in ADDITIONAL RECOMMENDATIONS
    - Mention ACM vs standalone deployment difference (SubmarinerConfig vs Submariner CR)
    - This is a potential root cause, recommend further investigation
    - Don't conclusively diagnose without evidence

## File Reading Strategy

**For YAML files:**
- Use Read tool to read the YAML
- Parse the structure to find relevant fields
- Look for Gateway CR, Pod status, RouteAgent status

**For log files:**
- Use Read tool or Grep for searching
- Search for "error", "ERROR", "fail", "FAIL", "warn", "WARN"
- Look for specific error patterns
- Distinguish between symptoms (ping failures) and root causes (configuration errors)

**For tcpdump files:**
- **ALWAYS read the text analysis files first:** `tcpdump/*-analysis.txt`
- These contain pre-generated packet counts and interpretations
- Compare analysis from both clusters to identify the pattern
- Binary pcap files are kept for reference but analysis is already done

**For text output files:**
- Read subctl-show-all.txt to get connection status
- Read subctl-diagnose-all.txt for health check results
- Read verify/*.txt for connectivity test results
- Check command headers to validate test parameters

## Example Workflow

1. User provides: `/submariner:analyze-offline submariner-diagnostics-20251229-152608.tar.gz`
2. Read manifest.txt - complaint: "general health check"
3. Read cluster1/subctl-show-all.txt - tunnel status = "connected" from cluster1 view
4. Read cluster2/subctl-show-all.txt - tunnel status = "error" from cluster2 view
5. Read Gateway CR - confirm asymmetric status, usingIP=private_ip, backend=libreswan
6. Read ipsec-status.log - tunnels show STATE_V2_ESTABLISHED_CHILD_SA (control plane OK)
7. Read ipsec-trafficstatus.log - ESPin=0B, ESPout=0B (no traffic flowing)
8. Check gateway/routeagent logs - NO configuration errors
9. Read tcpdump analysis files:
   - cluster1-gateway-worker-analysis.txt: "✓ Packets detected: 150"
   - cluster2-gateway-worker-analysis.txt: "✗ NO PACKETS CAPTURED"
10. Conclude: Pattern 2 (Egress but No Ingress) → ESP protocol blocked by infrastructure
11. Recommend: Try UDP encapsulation, reference official docs
12. Provide focused 3-step solution with documentation links

Example of what offline analysis will see in tcpdump files:

**cluster1-gateway-worker-analysis.txt:**
```
TCPDUMP CAPTURE SUMMARY: cluster1 Gateway
Node: cluster1-worker
Capture Filter: proto 50  # or "udp port 4500" depending on cable driver/config
Capture Duration: 80 seconds

CAPTURE STATISTICS:
  Total packets captured: 150

UNIQUE SOURCE -> DESTINATION PAIRS:
  150 172.18.0.4 -> 172.18.0.5
```

**cluster2-gateway-worker-analysis.txt:**
```
TCPDUMP CAPTURE SUMMARY: cluster2 Gateway
Node: cluster2-worker
Capture Filter: proto 50  # or "udp port 4500" depending on cable driver/config
Capture Duration: 80 seconds

CAPTURE STATISTICS:
  Total packets captured: 0

Capture filter: proto 50
File size: 24 bytes (empty or too small)
```

Analysis: Compare packet counts and direction:
- Cluster1: 150 packets (all "Out" direction - sending to 172.18.0.5)
- Cluster2: 0 packets (not receiving from 172.18.0.4)

Conclusion: Pattern 2 (Egress but No Ingress) → Infrastructure blocking tunnel traffic (ESP proto 50 or UDP depending on cable driver)

You are the offline diagnostic expert that analyzes collected data and finds the root cause!
