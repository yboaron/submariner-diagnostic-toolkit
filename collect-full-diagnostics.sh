#!/bin/bash
# Submariner Full Diagnostic Data Collector
# Uses subctl and kubectl to gather comprehensive troubleshooting data

# Don't use 'set -e' to avoid closing the shell on errors
# Instead, we'll handle errors explicitly

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="submariner-diagnostics-${TIMESTAMP}"
CLUSTER1_NAME="$1"
KUBECONFIG1="$2"
CLUSTER2_NAME="$3"
KUBECONFIG2="$4"
COMPLAINT="$5"

show_usage() {
    echo "Usage: $0 <cluster1-name> <cluster1-kubeconfig> <cluster2-name> <cluster2-kubeconfig> <issue-description>"
    echo ""
    echo "Arguments:"
    echo "  cluster1-name        - Name/context for cluster 1 (required)"
    echo "  cluster1-kubeconfig  - Path to kubeconfig for cluster 1 (required)"
    echo "  cluster2-name        - Name/context for cluster 2 (required)"
    echo "  cluster2-kubeconfig  - Path to kubeconfig for cluster 2 (required)"
    echo "  issue-description    - Description of the issue (required)"
    echo ""
    echo "Example:"
    echo "  $0 cluster1 /path/to/kubeconfig1 cluster2 /path/to/kubeconfig2 'tunnel not connected'"
    echo ""
    return 1 2>/dev/null || exit 1
}

# Function to collect diagnostics from a single cluster
collect_cluster_diagnostics() {
    local cluster_name="$1"
    local kubeconfig="$2"
    local context="$3"
    local cluster_dir="${OUTPUT_DIR}/${cluster_name}"

    echo "=== Collecting from ${cluster_name} ==="
    mkdir -p "${cluster_dir}"

    # subctl gather (most comprehensive)
    echo "Running subctl gather for ${cluster_name}..."
    subctl gather --kubeconfig "${kubeconfig}" --dir "${cluster_dir}/gather" 2>&1 | tee "${cluster_dir}/gather.log"

    # subctl show (connection status)
    echo "Running subctl show for ${cluster_name}..."
    subctl show all --kubeconfig "${kubeconfig}" > "${cluster_dir}/subctl-show-all.txt" 2>&1

    # subctl diagnose (health checks)
    echo "Running subctl diagnose for ${cluster_name}..."
    subctl diagnose all --kubeconfig "${kubeconfig}" > "${cluster_dir}/subctl-diagnose-all.txt" 2>&1

    # Additional CRs that might not be in gather
    echo "Collecting additional CRs for ${cluster_name}..."
    kubectl get routeagents.submariner.io -n submariner-operator -o yaml --kubeconfig "${kubeconfig}" > "${cluster_dir}/routeagents.yaml" 2>&1 || echo "Failed to get RouteAgents" > "${cluster_dir}/routeagents.yaml"

    # ACM resources (if ACM hub or managed cluster)
    echo "Checking for ACM resources on ${cluster_name}..."
    kubectl get managedclusteraddon -A --kubeconfig "${kubeconfig}" 2>/dev/null | grep submariner > "${cluster_dir}/acm-addons.txt" || echo "No ACM ManagedClusterAddOn resources found" > "${cluster_dir}/acm-addons.txt"
    kubectl get submarinerconfig -A -o yaml --kubeconfig "${kubeconfig}" > "${cluster_dir}/submarinerconfig.yaml" 2>&1 || echo "No SubmarinerConfig resources found" > "${cluster_dir}/submarinerconfig.yaml"
}

# Function to collect tcpdump from gateway nodes
collect_tcpdump_from_cluster() {
    local cluster_name="$1"
    local kubeconfig="$2"
    local tcpdump_dir="$3"
    local capture_duration="${4:-30}"

    echo "=== Collecting tcpdump from ${cluster_name} gateway nodes ==="

    # Get gateway node name
    GATEWAY_NODE=$(kubectl get pods -n submariner-operator -l app=submariner-gateway --kubeconfig="${kubeconfig}" -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)

    if [ -z "$GATEWAY_NODE" ]; then
        echo "  ✗ No gateway node found in ${cluster_name}, skipping tcpdump"
        return
    fi

    echo "  Gateway node: ${GATEWAY_NODE}"

    # Get Submariner configuration to determine capture filter
    USING_IP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" -o jsonpath='{.status.gateways[0].connections[0].usingIP}' 2>/dev/null)
    PRIVATE_IP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" -o jsonpath='{.status.gateways[0].connections[0].endpoint.private_ip}' 2>/dev/null)
    FORCE_UDP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" -o jsonpath='{.spec.ceIPSecForceUDPEncaps}' 2>/dev/null)
    NATT_PORT=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" -o jsonpath='{.spec.ceIPSecNATTPort}' 2>/dev/null)
    NATT_PORT=${NATT_PORT:-4500}  # Default to 4500 if not set

    # Determine capture filter
    if [ "$FORCE_UDP" = "true" ] || [ "$USING_IP" != "$PRIVATE_IP" ]; then
        CAPTURE_FILTER="udp port ${NATT_PORT}"
        echo "  Capture filter: ${CAPTURE_FILTER} (UDP encapsulation detected)"
    else
        CAPTURE_FILTER="proto 50"
        echo "  Capture filter: ${CAPTURE_FILTER} (ESP protocol)"
    fi

    # Create DaemonSet YAML for tcpdump
    cat <<EOF | kubectl apply --kubeconfig="${kubeconfig}" -f - >/dev/null 2>&1
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: submariner-tcpdump-collector
  namespace: submariner-operator
spec:
  selector:
    matchLabels:
      app: submariner-tcpdump-collector
  template:
    metadata:
      labels:
        app: submariner-tcpdump-collector
    spec:
      nodeSelector:
        submariner.io/gateway: "true"
      tolerations:
      - operator: Exists
      containers:
      - name: tcpdump
        image: nicolaka/netshoot:latest
        imagePullPolicy: IfNotPresent
        command:
        - /bin/sh
        - -c
        - |
          echo "Starting tcpdump capture for ${capture_duration} seconds..."
          timeout ${capture_duration} tcpdump -pnni any ${CAPTURE_FILTER} -w /tmp/gateway-traffic.pcap 2>&1
          echo "Capture complete. Waiting for file extraction..."
          sleep 300
        securityContext:
          privileged: true
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
        volumeMounts:
        - name: host-tmp
          mountPath: /tmp
      volumes:
      - name: host-tmp
        emptyDir: {}
      restartPolicy: Always
      hostNetwork: true
      serviceAccount: submariner-routeagent
      serviceAccountName: submariner-routeagent
EOF

    if [ $? -ne 0 ]; then
        echo "  ✗ Failed to deploy tcpdump DaemonSet on ${cluster_name}"
        return
    fi

    echo "  ✓ tcpdump DaemonSet deployed on ${cluster_name}"
    echo "  Waiting for pod to start..."
    sleep 5

    # Wait for pod to be ready
    kubectl wait --for=condition=Ready pod -l app=submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" --timeout=30s >/dev/null 2>&1

    TCPDUMP_POD=$(kubectl get pods -n submariner-operator -l app=submariner-tcpdump-collector --kubeconfig="${kubeconfig}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$TCPDUMP_POD" ]; then
        echo "  ✗ tcpdump pod not found on ${cluster_name}"
        kubectl delete daemonset submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" >/dev/null 2>&1
        return
    fi

    echo "  tcpdump pod: ${TCPDUMP_POD}"
    echo "  Capturing traffic for ${capture_duration} seconds..."

    # Wait for capture to complete
    sleep $((capture_duration + 5))

    # Extract pcap file
    echo "  Extracting pcap file from ${cluster_name}..."
    kubectl cp "submariner-operator/${TCPDUMP_POD}:/tmp/gateway-traffic.pcap" "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" --kubeconfig="${kubeconfig}" 2>/dev/null

    if [ -f "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" ]; then
        PCAP_SIZE=$(stat -f%z "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" 2>/dev/null || stat -c%s "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" 2>/dev/null)
        if [ "$PCAP_SIZE" -gt 100 ]; then
            echo "  ✓ pcap file collected: ${cluster_name}-gateway-${GATEWAY_NODE}.pcap (${PCAP_SIZE} bytes)"

            # Generate text summary for offline analysis
            echo "  Generating text summary of captured traffic..."
            PCAP_FILE="${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap"
            SUMMARY_FILE="${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt"

            {
                echo "========================================="
                echo "TCPDUMP CAPTURE SUMMARY: ${cluster_name} Gateway"
                echo "Node: ${GATEWAY_NODE}"
                echo "Capture Filter: ${CAPTURE_FILTER}"
                echo "Capture Duration: ${capture_duration} seconds"
                echo "========================================="
                echo ""

                # Count total packets
                TOTAL_PACKETS=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | wc -l)
                echo "CAPTURE STATISTICS:"
                echo "  Total packets captured: ${TOTAL_PACKETS}"
                echo ""

                # Show first 50 packets with details
                echo "FIRST 50 PACKETS (detailed):"
                tcpdump -r "$PCAP_FILE" -nnv 2>/dev/null | head -50
                echo ""

                # Show unique source/destination pairs
                echo "UNIQUE SOURCE -> DESTINATION PAIRS:"
                if [ "$CAPTURE_FILTER" = "proto 50" ]; then
                    # ESP packets - show IP pairs
                    tcpdump -r "$PCAP_FILE" -nnq 2>/dev/null | awk '{print $3, "->", $5}' | sort | uniq -c | sort -rn
                else
                    # UDP packets - show IP:port pairs
                    tcpdump -r "$PCAP_FILE" -nnq 2>/dev/null | awk '{print $3, "->", $5}' | sort | uniq -c | sort -rn
                fi

            } > "$SUMMARY_FILE" 2>&1

            echo "  ✓ Text summary created: ${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt"
        else
            echo "  ✗ pcap file is empty or too small (${PCAP_SIZE} bytes) - no traffic captured"

            # Create summary file for no traffic case
            SUMMARY_FILE="${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt"
            {
                echo "========================================="
                echo "TCPDUMP CAPTURE SUMMARY: ${cluster_name} Gateway"
                echo "Node: ${GATEWAY_NODE}"
                echo "========================================="
                echo ""
                echo "CAPTURE STATISTICS:"
                echo "  Total packets captured: 0"
                echo ""
                echo "Capture filter: ${CAPTURE_FILTER}"
                echo "Capture duration: ${capture_duration} seconds"
                echo "File size: ${PCAP_SIZE} bytes (empty or too small)"
            } > "$SUMMARY_FILE"

            rm -f "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap"
        fi
    else
        echo "  ✗ Failed to extract pcap file from ${cluster_name}"
    fi

    # Cleanup
    echo "  Cleaning up tcpdump DaemonSet from ${cluster_name}..."
    kubectl delete daemonset submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" >/dev/null 2>&1
    echo "  ✓ Cleanup complete"
}

# Check if all 5 parameters are provided
if [ $# -ne 5 ]; then
    echo "ERROR: All 5 parameters are required"
    echo ""
    show_usage
fi

# Validate parameters before starting collection
echo "Validating parameters..."

# Validate kubeconfig1 exists
if [ ! -f "$KUBECONFIG1" ]; then
    echo "ERROR: Kubeconfig file not found: $KUBECONFIG1"
    return 1 2>/dev/null || exit 1
fi

# Validate kubeconfig2 exists
if [ ! -f "$KUBECONFIG2" ]; then
    echo "ERROR: Kubeconfig file not found: $KUBECONFIG2"
    return 1 2>/dev/null || exit 1
fi

# Validate cluster1 connectivity
echo "Checking connectivity to cluster1..."
if ! kubectl cluster-info --kubeconfig "$KUBECONFIG1" &>/dev/null; then
    echo "ERROR: Cannot connect to cluster using kubeconfig: $KUBECONFIG1"
    echo "Please verify:"
    echo "  - The kubeconfig file is valid"
    echo "  - The cluster is accessible from this machine"
    echo "  - Your credentials are valid"
    return 1 2>/dev/null || exit 1
fi

# Validate cluster2 connectivity
echo "Checking connectivity to cluster2..."
if ! kubectl cluster-info --kubeconfig "$KUBECONFIG2" &>/dev/null; then
    echo "ERROR: Cannot connect to cluster using kubeconfig: $KUBECONFIG2"
    echo "Please verify:"
    echo "  - The kubeconfig file is valid"
    echo "  - The cluster is accessible from this machine"
    echo "  - Your credentials are valid"
    return 1 2>/dev/null || exit 1
fi

# Validate context1 exists in kubeconfig1
if ! kubectl config get-contexts "$CLUSTER1_NAME" --kubeconfig "$KUBECONFIG1" &>/dev/null; then
    echo "ERROR: Context '$CLUSTER1_NAME' not found in kubeconfig: $KUBECONFIG1"
    echo "Available contexts:"
    kubectl config get-contexts --kubeconfig "$KUBECONFIG1" -o name
    return 1 2>/dev/null || exit 1
fi

# Validate context2 exists in kubeconfig2
if ! kubectl config get-contexts "$CLUSTER2_NAME" --kubeconfig "$KUBECONFIG2" &>/dev/null; then
    echo "ERROR: Context '$CLUSTER2_NAME' not found in kubeconfig: $KUBECONFIG2"
    echo "Available contexts:"
    kubectl config get-contexts --kubeconfig "$KUBECONFIG2" -o name
    return 1 2>/dev/null || exit 1
fi

# Validate contexts have different names
if [ "$CLUSTER1_NAME" = "$CLUSTER2_NAME" ]; then
    echo "ERROR: Context names must be different for cluster1 and cluster2"
    echo "  cluster1: $CLUSTER1_NAME"
    echo "  cluster2: $CLUSTER2_NAME"
    echo ""
    echo "Using the same context for both clusters will cause 'subctl verify' to fail."
    echo "Please provide unique context names for each cluster."
    return 1 2>/dev/null || exit 1
fi

# Check for required tools
echo "Checking for required tools..."
if ! command -v subctl &>/dev/null; then
    echo "ERROR: 'subctl' command not found"
    echo "Please install subctl from: https://github.com/submariner-io/subctl"
    return 1 2>/dev/null || exit 1
fi

if ! command -v kubectl &>/dev/null; then
    echo "ERROR: 'kubectl' command not found"
    echo "Please install kubectl"
    return 1 2>/dev/null || exit 1
fi

echo "✓ All validations passed"
echo ""

mkdir -p "${OUTPUT_DIR}"

COLLECTION_START_TIME=$(date +%s)
echo "========================================="
echo "Collecting Submariner diagnostics..."
echo "Start time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================="
echo ""
echo "Timestamp: ${TIMESTAMP}" > "${OUTPUT_DIR}/manifest.txt"
echo "Complaint: ${COMPLAINT}" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"

# Collect from Cluster 1
echo "Cluster 1:" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Name: ${CLUSTER1_NAME}" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Kubeconfig: ${KUBECONFIG1}" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"

collect_cluster_diagnostics "cluster1" "${KUBECONFIG1}" "${CLUSTER1_NAME}"

# Collect from Cluster 2
echo "Cluster 2:" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Name: ${CLUSTER2_NAME}" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Kubeconfig: ${KUBECONFIG2}" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"

collect_cluster_diagnostics "cluster2" "${KUBECONFIG2}" "${CLUSTER2_NAME}"

# Check tunnel status and collect tcpdump if tunnel is not connected
echo ""
echo "=== Checking tunnel status ==="
TUNNEL_STATUS_CLUSTER1=$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster1/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")
TUNNEL_STATUS_CLUSTER2=$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster2/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")

echo "Tunnel status:"
echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}"
echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}"

# Collect tcpdump only if tunnel is NOT connected on either cluster
if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] || [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo ""
    echo "=== Tunnel not fully connected - collecting tcpdump data ==="
    echo "This will help diagnose whether packets are reaching the gateway nodes."
    echo ""

    mkdir -p "${OUTPUT_DIR}/tcpdump"

    echo "tcpdump Data Collection:" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Reason: Tunnel not connected on one or both clusters" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Cluster1 status: ${TUNNEL_STATUS_CLUSTER1}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Cluster2 status: ${TUNNEL_STATUS_CLUSTER2}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"

    # Collect from both clusters in parallel (background processes)
    collect_tcpdump_from_cluster "cluster1" "${KUBECONFIG1}" "${OUTPUT_DIR}/tcpdump" 80 &
    PID1=$!

    collect_tcpdump_from_cluster "cluster2" "${KUBECONFIG2}" "${OUTPUT_DIR}/tcpdump" 80 &
    PID2=$!

    # Wait for both to complete
    echo "  Waiting for tcpdump collection to complete on both clusters..."
    wait $PID1
    wait $PID2

    echo ""
    echo "✓ tcpdump collection complete"

    # Check if any pcap files were collected
    PCAP_COUNT=$(find "${OUTPUT_DIR}/tcpdump" -name "*.pcap" 2>/dev/null | wc -l)
    if [ "$PCAP_COUNT" -eq 0 ]; then
        echo "  ⚠ No pcap files were collected (no traffic detected)"
        echo "  This may indicate that gateway pods are not sending ESP/UDP tunnel traffic."
        rmdir "${OUTPUT_DIR}/tcpdump" 2>/dev/null
    else
        echo "  ✓ Collected ${PCAP_COUNT} pcap file(s)"
        echo "  These files can be analyzed offline to determine where packets are being dropped."
    fi
else
    echo "  ✓ Tunnel connected on both clusters - skipping tcpdump collection"
    echo ""  >> "${OUTPUT_DIR}/manifest.txt"
    echo "tcpdump Collection: Skipped (tunnel connected on both clusters)" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Run connectivity verification
echo ""
echo "=== Checking connectivity verification eligibility ==="
mkdir -p "${OUTPUT_DIR}/verify"

# Use the tunnel status already determined
TUNNEL_STATUS_CLUSTER1=${TUNNEL_STATUS_CLUSTER1:-$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster1/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")}
TUNNEL_STATUS_CLUSTER2=${TUNNEL_STATUS_CLUSTER2:-$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster2/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")}

echo "Tunnel status:"
echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}"
echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}"

# Skip subctl verify entirely if tunnel is not connected on BOTH clusters
if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] || [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo ""
    echo "  ✗ Tunnel NOT connected on both clusters - skipping 'subctl verify'"
    echo "  → Reason: Need to fix tunnel connectivity first before running verify tests"
    echo "  → Alternative: tcpdump data provides packet-level diagnostics (see tcpdump/ directory)"
    echo ""

    # Create skip notes for all verify files
    echo "========================================" > "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "CONNECTIVITY VERIFICATION SKIPPED" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Connectivity verification was skipped because tunnel status is not 'connected' on both clusters." >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Tunnel status:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Why skipped:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  - Tunnel must be 'connected' on BOTH clusters to run verify tests" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  - Focus should be on fixing tunnel connectivity first" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  - tcpdump packet captures (if collected) provide better diagnostics for tunnel failures" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Recommended diagnostics for tunnel failures:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  1. Check tcpdump/ directory for packet-level analysis" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  2. Review cluster*/subctl-diagnose-all.txt for health check results" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  3. Review cluster*/gather/cluster*/ipsec-status.log for IPsec tunnel state" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "To run connectivity tests, fix the tunnel issue first, then re-collect diagnostics." >> "${OUTPUT_DIR}/verify/connectivity.txt"

    cp "${OUTPUT_DIR}/verify/connectivity.txt" "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
    cp "${OUTPUT_DIR}/verify/connectivity.txt" "${OUTPUT_DIR}/verify/service-discovery.txt"

    # Skip the entire verify section
    SKIP_VERIFY=true
else
    echo ""
    echo "  ✓ Tunnel status: connected on BOTH clusters"
    echo "  → Will run full connectivity verification tests (including MTU test)"

    SKIP_VERIFY=false
    VERIFY_CONNECTIVITY_FLAG="connectivity"
    RUN_MTU_TEST=true
fi

# Only run verify tests if tunnel is connected on at least one cluster
if [ "$SKIP_VERIFY" = "false" ]; then
    echo ""
    # Detect which image registry is accessible by actually trying to create pods on BOTH clusters
    echo "Detecting accessible image registry for nettest..."
    IMAGE_OVERRIDE=""
    RH_REGISTRY_OK=true

    # Test default Red Hat registry on cluster1
    echo "Testing registry.redhat.io/rhacm2/nettest:0.21.0 on cluster1..."
    kubectl run nettest-registry-check --image=registry.redhat.io/rhacm2/nettest:0.21.0 --restart=Never --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_NAME}" --command -- sleep 1 >/dev/null 2>&1
    sleep 3
    POD_STATUS=$(kubectl get pod nettest-registry-check --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_NAME}" -o jsonpath='{.status.containerStatuses[0].state}' 2>/dev/null)

    if echo "$POD_STATUS" | grep -qE "running|terminated|waiting.*PodInitializing|waiting.*ContainerCreating"; then
        echo "  ✓ Cluster1: registry.redhat.io is accessible"
    else
        echo "  ✗ Cluster1: registry.redhat.io not accessible (ImagePullBackOff)"
        RH_REGISTRY_OK=false
    fi
    kubectl delete pod nettest-registry-check --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_NAME}" --wait=false >/dev/null 2>&1

    # Test default Red Hat registry on cluster2
    echo "Testing registry.redhat.io/rhacm2/nettest:0.21.0 on cluster2..."
    kubectl run nettest-registry-check --image=registry.redhat.io/rhacm2/nettest:0.21.0 --restart=Never --kubeconfig="${KUBECONFIG2}" --context="${CLUSTER2_NAME}" --command -- sleep 1 >/dev/null 2>&1
    sleep 3
    POD_STATUS=$(kubectl get pod nettest-registry-check --kubeconfig="${KUBECONFIG2}" --context="${CLUSTER2_NAME}" -o jsonpath='{.status.containerStatuses[0].state}' 2>/dev/null)

    if echo "$POD_STATUS" | grep -qE "running|terminated|waiting.*PodInitializing|waiting.*ContainerCreating"; then
        echo "  ✓ Cluster2: registry.redhat.io is accessible"
    else
        echo "  ✗ Cluster2: registry.redhat.io not accessible (ImagePullBackOff)"
        RH_REGISTRY_OK=false
    fi
    kubectl delete pod nettest-registry-check --kubeconfig="${KUBECONFIG2}" --context="${CLUSTER2_NAME}" --wait=false >/dev/null 2>&1

    # If both clusters can access Red Hat registry, use default image
    if [ "$RH_REGISTRY_OK" = "true" ]; then
        echo "  ✓ Both clusters can access registry.redhat.io - using default image"
    else
        echo "  ✗ At least one cluster cannot access registry.redhat.io - using quay.io mirror"
        IMAGE_OVERRIDE="--image-override submariner-nettest=quay.io/submariner/nettest:devel"
    fi

    # Merge kubeconfigs temporarily for subctl verify
    MERGED_KUBECONFIG="${OUTPUT_DIR}/merged-kubeconfig"
    KUBECONFIG="${KUBECONFIG1}:${KUBECONFIG2}" kubectl config view --flatten > "${MERGED_KUBECONFIG}"

    echo ""
    echo "Running subctl verify for connectivity (using --only ${VERIFY_CONNECTIVITY_FLAG})..."
    echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
    VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_NAME} --tocontext ${CLUSTER2_NAME} --only ${VERIFY_CONNECTIVITY_FLAG} --verbose ${IMAGE_OVERRIDE}"
    echo "========================================" > "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Command executed:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify --context "${CLUSTER1_NAME}" --tocontext "${CLUSTER2_NAME}" --only "${VERIFY_CONNECTIVITY_FLAG}" --verbose ${IMAGE_OVERRIDE} >> "${OUTPUT_DIR}/verify/connectivity.txt" 2>&1 || echo "Connectivity verification failed or timed out" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"

    if [ "$RUN_MTU_TEST" = "true" ]; then
        echo ""
        echo "Running subctl verify for connectivity (small packet size for MTU testing)..."
        echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
        VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_NAME} --tocontext ${CLUSTER2_NAME} --only connectivity --verbose --packet-size 400 ${IMAGE_OVERRIDE}"
        echo "========================================" > "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "Command executed:" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify --context "${CLUSTER1_NAME}" --tocontext "${CLUSTER2_NAME}" --only connectivity --verbose --packet-size 400 ${IMAGE_OVERRIDE} >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>&1 || echo "Connectivity verification with small packets failed or timed out" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "Skipping MTU test (tunnel connected on only one cluster)"
        echo "========================================" > "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "MTU TEST SKIPPED" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "MTU test was skipped because tunnel is only connected on one cluster." >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "Tunnel status:" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "MTU testing requires tunnel connected on both clusters." >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
    fi

    # Check if service discovery is enabled before running the test
    echo ""
    echo "Checking if service discovery is enabled..."
    SD_ENABLED_CLUSTER1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig "${KUBECONFIG1}" -o jsonpath='{.spec.serviceDiscoveryEnabled}' 2>/dev/null)
    SD_ENABLED_CLUSTER2=$(kubectl get submariner submariner -n submariner-operator --kubeconfig "${KUBECONFIG2}" -o jsonpath='{.spec.serviceDiscoveryEnabled}' 2>/dev/null)

    if [ "$SD_ENABLED_CLUSTER1" = "true" ] || [ "$SD_ENABLED_CLUSTER2" = "true" ]; then
        echo "Running subctl verify for service-discovery..."
        echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
        VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_NAME} --tocontext ${CLUSTER2_NAME} --only service-discovery --verbose ${IMAGE_OVERRIDE}"
        echo "========================================" > "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Command executed:" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify --context "${CLUSTER1_NAME}" --tocontext "${CLUSTER2_NAME}" --only service-discovery --verbose ${IMAGE_OVERRIDE} >> "${OUTPUT_DIR}/verify/service-discovery.txt" 2>&1 || echo "Service discovery verification failed or timed out" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "Skipping service-discovery verification (not enabled on either cluster)"
        echo "========================================" > "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "SERVICE DISCOVERY VERIFICATION SKIPPED" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Service discovery is not enabled on either cluster." >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Cluster1 serviceDiscoveryEnabled: ${SD_ENABLED_CLUSTER1:-not set (defaults to false)}" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Cluster2 serviceDiscoveryEnabled: ${SD_ENABLED_CLUSTER2:-not set (defaults to false)}" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "To enable service discovery, see: https://submariner.io/getting-started/quickstart/openshift/service-discovery/" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
    fi

    # Cleanup merged kubeconfig
    rm -f "${MERGED_KUBECONFIG}"
fi

# Create tarball
echo ""
echo "Creating tarball..."
tar -czf "${OUTPUT_DIR}.tar.gz" "${OUTPUT_DIR}"

# Cleanup directory (keep only tarball)
rm -rf "${OUTPUT_DIR}"

COLLECTION_END_TIME=$(date +%s)
COLLECTION_DURATION=$((COLLECTION_END_TIME - COLLECTION_START_TIME))
COLLECTION_MINUTES=$((COLLECTION_DURATION / 60))
COLLECTION_SECONDS=$((COLLECTION_DURATION % 60))

echo ""
echo "=========================================="
echo "Diagnostic collection complete!"
echo "Output: ${OUTPUT_DIR}.tar.gz"
echo "End time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Total duration: ${COLLECTION_MINUTES}m ${COLLECTION_SECONDS}s"
echo "=========================================="
echo ""
echo "Contents:"
echo "  - Cluster 1 diagnostics (subctl gather, show, diagnose)"
echo "  - Cluster 2 diagnostics (subctl gather, show, diagnose)"

if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] || [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo "  - tcpdump packet captures from gateway nodes (tunnel not connected)"
fi

if [ "$SKIP_VERIFY" = "true" ]; then
    echo "  - Connectivity verification: SKIPPED (tunnel not connected on either cluster)"
    echo "    → tcpdump data provides packet-level diagnostics instead"
else
    echo "  - Connectivity verification results"
    echo "  - Service discovery verification results"
    if [ "$RUN_MTU_TEST" = "true" ]; then
        echo "  - MTU testing (small packet size)"
    else
        echo "  - MTU testing: SKIPPED (tunnel connected on only one cluster)"
    fi
fi
echo "  - RouteAgent status"
echo "  - ACM resources (if present)"
echo ""
echo "Next steps:"
echo "1. Share this tarball with your support team or Submariner expert"
echo "2. They can analyze it offline without needing cluster access"
echo "3. For AI-assisted analysis with Claude Code, run:"
echo "   /submariner:analyze-offline ${OUTPUT_DIR}.tar.gz"
echo ""
