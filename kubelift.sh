#!/usr/bin/env bash

set -euo pipefail

OPERATION=""
NONINTERACTIVE=false
SKIP_REQS=false
SSH_USER=""
KUBERNETES_VERSION=""
CONTROL_PLANE_IP=""
WORKER_IPS=""
ENABLE_CONTROL_PLANE_WORKLOADS=false

function print_usage() {
    cat << EOF
Usage: $0 [operation] [options...]
Operations:
    create                                  Create a new Kubernetes cluster
    upgrade                                 Upgrade an existing Kubernetes cluster
    cleanup                                 Remove Kubernetes cluster while preserving CNI

Options:
   -h, --help                              Display this help message
   --noninteractive <bool>                 Enable or disable noninteractive mode
   --ssh-user <username>                   Username to use for SSH connection
   --kubernetes-version <version>          Kubernetes version to install (create/upgrade only)
   --control-plane-ip <ip>                 Control plane node IP address
   --worker-ips <ip1,ip2,...>              Worker node IP addresses (create only)
   --enable-control-plane-workloads <bool> Enable control plane scheduling (create only)
   --skip-reqs <bool>                      Skip minimum requirements validation
EOF
    exit 0
}

function log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

function error() {
    log "ERROR: $1"
    exit 1
}

function parse_operation() {
    [[ $# -lt 1 ]] && print_usage

    OPERATION=$1; shift
    case $OPERATION in
        create|upgrade) ;;
        *) error "Invalid operation: $OPERATION" ;;
    esac
    return $#
}

function parse_args() {
    [[ $# -eq 0 || $1 == "-h" || $1 == "--help" ]] && print_usage

    OPERATION=$1; shift
    case $OPERATION in
        create|upgrade|cleanup) ;;
        *) error "Invalid operation: $OPERATION" ;;
    esac

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) print_usage ;;
            --noninteractive) NONINTERACTIVE="$2"; shift 2 ;;
            --ssh-user) SSH_USER="$2"; shift 2 ;;
            --kubernetes-version) KUBERNETES_VERSION="$2"; shift 2 ;;
            --control-plane-ip) CONTROL_PLANE_IP="$2"; shift 2 ;;
            --worker-ips)
                if [[ $OPERATION == "create" ]]; then
                    WORKER_IPS="$2"
                fi
                shift 2
                ;;
            --enable-control-plane-workloads) ENABLE_CONTROL_PLANE_WORKLOADS="$2"; shift 2 ;;
            --skip-reqs) SKIP_REQS="$2"; shift 2 ;;
            *) error "Unknown parameter $1" ;;
        esac
    done
}

function validate_input() {
    [[ $NONINTERACTIVE =~ ^(true|false)$ ]] || error "Invalid noninteractive value"
    [[ $SSH_USER =~ ^[a-zA-Z0-9_]+$ ]] || error "Invalid SSH user"
    [[ $CONTROL_PLANE_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || error "Invalid control plane IP"
    [[ $SKIP_REQS =~ ^(true|false)$ ]] || error "Invalid skip-reqs value"

    if [[ $OPERATION != "cleanup" ]]; then
        [[ $KUBERNETES_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || error "Invalid Kubernetes version"
    fi

    if [[ $OPERATION == "create" ]]; then
        [[ -z $WORKER_IPS || $WORKER_IPS =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,)*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || error "Invalid worker nodes IPs"
        [[ $ENABLE_CONTROL_PLANE_WORKLOADS =~ ^(true|false)$ ]] || error "Invalid control plane scheduling value"
    fi
}

function get_node_resources() {
    local node_ip=$1
    local resources

    resources=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
    {
        cpu_cores=$(nproc)
        mem_gb=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024))
        disk_gb=$(df -BG / | awk 'NR==2 {sub(/G/,"",$4); print $4}')

        echo "$cpu_cores $mem_gb $disk_gb"
    }
EOF
    )

    echo "$resources"
}

function validate_control_plane_resources() {
    local node_ip=$1
    local resources cpu_cores mem_gb disk_gb

    resources=$(get_node_resources "$node_ip")
    read -r cpu_cores mem_gb disk_gb <<< "$resources"

    local errors=()

    ((cpu_cores >= 2)) || errors+=("Insufficient CPU cores: $cpu_cores (minimum 2)")
    ((mem_gb >= 2)) || errors+=("Insufficient memory: ${mem_gb}GB (minimum 2GB)")
    ((disk_gb >= 50)) || errors+=("Insufficient disk space: ${disk_gb}GB (minimum 50GB)")

    if ((${#errors[@]} > 0)); then
        printf "Control plane node (%s) validation failed:\n" "$node_ip" >&2
        printf " - %s\n" "${errors[@]}" >&2
        return 1
    fi
}

function validate_worker_node_resources() {
    local node_ip=$1
    local resources cpu_cores mem_gb disk_gb

    resources=$(get_node_resources "$node_ip")
    read -r cpu_cores mem_gb disk_gb <<< "$resources"

    local errors=()

    ((cpu_cores >= 1)) || errors+=("Insufficient CPU cores: $cpu_cores (minimum 1)")
    ((mem_gb >= 1)) || errors+=("Insufficient memory: ${mem_gb}GB (minimum 1GB)")
    ((disk_gb >= 20)) || errors+=("Insufficient disk space: ${disk_gb}GB (minimum 20GB)")

    if ((${#errors[@]} > 0)); then
        printf "Worker node (%s) validation failed:\n" "$node_ip" >&2
        printf " - %s\n" "${errors[@]}" >&2
        return 1
    fi
}

function validate_cluster_resources() {
    $SKIP_REQS && return 0

    local validation_failed=false

    log "Validating control plane resources"
    validate_control_plane_resources "$CONTROL_PLANE_IP" || validation_failed=true

    if [[ -n $WORKER_IPS ]]; then
        log "Validating worker nodes resources"
        local pids=()

        for ip in ${WORKER_IPS//,/ }; do
            validate_worker_node_resources "$ip" &
            pids+=($!)
        done

        for pid in "${pids[@]}"; do
            wait "$pid" || validation_failed=true
        done
    fi

    $validation_failed && error "Resource validation failed"
}

function prompt_confirmation() {
    local message=${1:-"Continue with operation?"}
    $NONINTERACTIVE && return
    read -rp "$message [y/N] " response
    [[ $response =~ ^[Yy]$ ]] || exit 1
}

function get_cluster_nodes() {
    if [[ $OPERATION == "create" ]]; then
        echo "$CONTROL_PLANE_IP${WORKER_IPS:+,$WORKER_IPS}"
    else
        ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
            kubectl get nodes -o wide | awk '{print $6}' | grep -v 'INTERNAL-IP'
    fi
}

function verify_ssh_access() {
    local node_ip=$1
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 "$SSH_USER@$node_ip" exit || \
        error "Cannot SSH to $node_ip"
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 "$SSH_USER@$node_ip" sudo -n true || \
        error "Cannot sudo on $node_ip"
}

function verify_node_connectivity() {
    local source_ip=$1
    local target_ip=$2
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$source_ip" ping -c 3 -W 3 "$target_ip" > /dev/null || \
        error "Node $source_ip cannot ping $target_ip"
}

function verify_cluster_connectivity() {
    local all_nodes
    all_nodes=$(get_cluster_nodes)

    for ip in ${all_nodes//,/ }; do
        verify_ssh_access "$ip"
    done

    if [[ $OPERATION == "create" ]]; then
        validate_cluster_resources

        if [[ -n $WORKER_IPS ]]; then
            for ip in ${WORKER_IPS//,/ }; do
                verify_node_connectivity "$ip" "$CONTROL_PLANE_IP"
            done
        fi
    fi
}

function configure_system_prerequisites() {
    local node_ip=$1

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
set -euo pipefail

if grep -q "^/[^ ]* *none *swap" /proc/mounts; then
    swapoff -a
    cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d%H%M%S)
    sed -i '/\sswap\s/s/^/#/' /etc/fstab
fi

modprobe br_netfilter
echo "net.bridge.bridge-nf-call-iptables = 1" | tee -a /etc/sysctl.conf
sysctl -p
EOF
}

function setup_container_runtime() {
    local node_ip=$1

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
set -euo pipefail

apt-get update
apt-get install -y ca-certificates curl

if ! command -v docker &> /dev/null || ! docker info &> /dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /tmp/docker.gpg
    gpg --dearmor -o /etc/apt/keyrings/docker.asc /tmp/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.asc

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    systemctl enable --now docker
fi

cat > /etc/containerd/config.toml << EOC
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
EOC

systemctl restart containerd
EOF
}

function install_kubernetes_packages() {
    local node_ip=$1
    local version=$2

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << EOF
set -euo pipefail

KUBERNETES_VERSION="$version"
KUBERNETES_VERSION_REPOSITORY="v\${KUBERNETES_VERSION%.*}"

if ! grep -q "\$KUBERNETES_VERSION_REPOSITORY" /etc/apt/sources.list.d/kubernetes.list 2>/dev/null; then
    curl -fsSL "https://pkgs.k8s.io/core:/stable:/\$KUBERNETES_VERSION_REPOSITORY/deb/Release.key" -o /tmp/kubernetes.gpg
    gpg --dearmor -o "/etc/apt/keyrings/kubernetes-apt-keyring-\$KUBERNETES_VERSION_REPOSITORY.gpg" /tmp/kubernetes.gpg
    echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring-\$KUBERNETES_VERSION_REPOSITORY.gpg] https://pkgs.k8s.io/core:/stable:/\$KUBERNETES_VERSION_REPOSITORY/deb/ /" | \
        tee /etc/apt/sources.list.d/kubernetes.list
fi

apt-get update

# Remove any holds before installation
apt-mark unhold kubelet kubeadm kubectl || true

DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-change-held-packages \
    kubelet="\${KUBERNETES_VERSION}-*" \
    kubeadm="\${KUBERNETES_VERSION}-*" \
    kubectl="\${KUBERNETES_VERSION}-*"

# Re-apply holds after installation
apt-mark hold kubelet kubeadm kubectl

systemctl enable --now kubelet
EOF
}

function prepare_cluster_node() {
    local node_ip=$1

    configure_system_prerequisites "$node_ip"
    setup_container_runtime "$node_ip"
    install_kubernetes_packages "$node_ip" "$KUBERNETES_VERSION"
}

function bootstrap_control_plane() {
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
        kubeadm init --apiserver-advertise-address="$CONTROL_PLANE_IP" \
                     --pod-network-cidr=10.244.0.0/16 \
                     --kubernetes-version="$KUBERNETES_VERSION"

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" bash << 'EOF'
mkdir -p $HOME/.kube
cp /etc/kubernetes/admin.conf $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config
EOF
}

function install_cni() {
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" bash << 'EOF'
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

kubectl create ns kube-flannel
kubectl label --overwrite ns kube-flannel pod-security.kubernetes.io/enforce=privileged

helm repo add flannel https://flannel-io.github.io/flannel
helm repo update
helm install flannel --set podCidr=10.244.0.0/16 --namespace kube-flannel flannel/flannel
EOF
}

function join_worker_nodes() {
    local join_command
    join_command=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" kubeadm token create --print-join-command)

    for ip in ${WORKER_IPS//,/ }; do
        ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" "${join_command}"
    done
}

function verify_version_compatibility() {
    local nodes_versions
    nodes_versions=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
        kubectl get nodes -o=jsonpath='{range .items[*]}{.status.nodeInfo.kubeletVersion}{"\n"}{end}' | sort -u)

    local current_version
    current_version=$(echo "$nodes_versions" | head -1)

    [[ $current_version != "v$KUBERNETES_VERSION" ]] || error "Cluster already at version $KUBERNETES_VERSION"

    local current_major current_minor target_major target_minor
    current_major=$(echo "${current_version#v}" | cut -d. -f1)
    current_minor=$(echo "${current_version#v}" | cut -d. -f2)
    target_major=$(echo "$KUBERNETES_VERSION" | cut -d. -f1)
    target_minor=$(echo "$KUBERNETES_VERSION" | cut -d. -f2)

    [[ $target_major -ge $current_major ]] || error "Cannot downgrade major version"
    [[ $target_major -ne $current_major || $target_minor -ge $current_minor ]] || error "Cannot downgrade minor version"
    [[ $target_minor -le $((current_minor + 1)) ]] || error "Cannot skip minor versions"
}

function upgrade_node_components() {
    local node_ip=$1
    local is_control_plane=${2:-false}

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << EOF
set -euo pipefail

apt-mark unhold kubeadm && apt-get install -y kubeadm=$KUBERNETES_VERSION-* && apt-mark hold kubeadm

if $is_control_plane; then
    kubeadm upgrade plan "v$KUBERNETES_VERSION"
    kubeadm upgrade apply -y "v$KUBERNETES_VERSION"
else
    kubeadm upgrade node
fi

apt-mark unhold kubelet kubectl
apt-get install -y kubelet=$KUBERNETES_VERSION-* kubectl=$KUBERNETES_VERSION-*
apt-mark hold kubelet kubectl

systemctl daemon-reload
systemctl restart kubelet
EOF
}

function manage_node_workloads() {
    local action=$1
    local node_name=$2

    case $action in
        drain)
            ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
                kubectl drain "$node_name" --ignore-daemonsets --delete-emptydir-data
            ;;
        restore)
            ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
                kubectl uncordon "$node_name"
            ;;
    esac
}

function create_cluster() {
    log "Preparing cluster nodes"
    prepare_cluster_node "$CONTROL_PLANE_IP"
    for ip in ${WORKER_IPS//,/ }; do
        prepare_cluster_node "$ip"
    done

    log "Bootstrapping control plane"
    bootstrap_control_plane

    log "Installing CNI plugin"
    install_cni

    if [[ -n $WORKER_IPS ]]; then
        log "Joining worker nodes"
        join_worker_nodes
    fi

    if [[ $ENABLE_CONTROL_PLANE_WORKLOADS == "true" ]]; then
        log "Enabling workload scheduling on control plane"
        ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
            kubectl taint nodes --all node-role.kubernetes.io/control-plane-
    fi
}

function update_cluster_node() {
    local node_ip=$1
    local node_name=$2
    local is_control_plane=${3:-false}

    manage_node_workloads drain "$node_name"
    upgrade_node_components "$node_ip" "$is_control_plane"
    manage_node_workloads restore "$node_name"
}

function upgrade_cluster() {
    log "Verifying version compatibility"
    verify_version_compatibility

    log "Upgrading control plane node"
    local cp_node
    cp_node=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
        kubectl get nodes --selector=node-role.kubernetes.io/control-plane \
        -o jsonpath='{.items[0].metadata.name}')
    update_cluster_node "$CONTROL_PLANE_IP" "$cp_node" true

    if [[ -n $WORKER_IPS ]]; then
        log "Upgrading worker nodes"
        local worker_nodes
        worker_nodes=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
            kubectl get nodes --no-headers \
            -o custom-columns=NAME:.metadata.name,IP:.status.addresses[0].address | \
            grep -v "$CONTROL_PLANE_IP")

        while read -r node_name node_ip; do
            log "Upgrading worker node: $node_name"
            update_cluster_node "$node_ip" "$node_name" false
        done <<< "$worker_nodes"
    fi
}

function remove_worker_nodes() {
    local worker_nodes
    worker_nodes=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
        kubectl get nodes --no-headers \
        -o custom-columns=NAME:.metadata.name,IP:.status.addresses[0].address | \
        grep -v "$CONTROL_PLANE_IP") || true

    while read -r node_name node_ip; do
        [[ -z $node_name ]] && continue

        log "Draining worker node: $node_name"
        ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
            kubectl drain "$node_name" --ignore-daemonsets --delete-emptydir-data --force || true

        log "Removing node from cluster: $node_name"
        ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
            kubectl delete node "$node_name" || true

        log "Resetting kubeadm on worker: $node_ip"
        cleanup_node "$node_ip"
    done <<< "$worker_nodes"
}

function remove_control_plane() {
    log "Removing control plane node"
    cleanup_node "$CONTROL_PLANE_IP"
}

function cleanup_node() {
    local node_ip=$1
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
kubeadm reset -f
rm -rf $HOME/.kube
ip link delete cni0 || true
ip link delete flannel.1 || true
EOF
}

function cleanup_cluster() {
    if ! ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" kubectl get nodes &>/dev/null; then
        error "Cannot access the Kubernetes cluster"
    fi

    local worker_nodes
    worker_nodes=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
        kubectl get nodes -o custom-columns=IP:.status.addresses[0].address --no-headers | \
        grep -v "$CONTROL_PLANE_IP") || true

    for ip in $worker_nodes; do
        [[ -z $ip ]] && continue
        log "Cleaning up worker: $ip"
        cleanup_node "$ip"
    done

    log "Cleaning up control plane"
    cleanup_node "$CONTROL_PLANE_IP"

    if ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" kubectl get nodes &>/dev/null; then
        error "Cluster is still running after cleanup"
    fi
}

function main() {
    parse_args "$@"
    validate_input

    case $OPERATION in
        create)
            verify_cluster_connectivity
            prompt_confirmation "Ready to create new cluster"
            create_cluster
            ;;
        upgrade)
            verify_cluster_connectivity
            prompt_confirmation "Ready to upgrade cluster"
            upgrade_cluster
            ;;
        cleanup)
            prompt_confirmation "This will remove Kubernetes from all nodes. Continue?"
            cleanup_cluster
            ;;
    esac

    log "Operation completed successfully"
}

main "$@"
