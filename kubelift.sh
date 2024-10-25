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
NUKE=false

function print_usage() {
    cat << EOF
Usage: $0 [operation] [options...]
Operations:
    create                                  Create a new Kubernetes cluster
    upgrade                                 Upgrade an existing Kubernetes cluster
    cleanup                                 Remove Kubernetes cluster

Options:
   -h, --help                               Display this help message
   --noninteractive <bool>                  Enable or disable noninteractive mode
   --ssh-user <username>                    Username to use for SSH connection
   --kubernetes-version <version>           Kubernetes version to install (create/upgrade only)
   --control-plane-ip <ip>                  Control plane node IP address
   --worker-ips <ip1,ip2,...>               Worker node IP addresses (create only)
   --enable-control-plane-workloads <bool>  Enable control plane scheduling (create only)
   --skip-reqs <bool>                       Skip minimum requirements validation
   --nuke <bool>                            Perform deep cleanup (cleanup only)
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
                [[ $OPERATION == "create" ]] && WORKER_IPS="$2"
                shift 2
                ;;
            --enable-control-plane-workloads) ENABLE_CONTROL_PLANE_WORKLOADS="$2"; shift 2 ;;
            --skip-reqs) SKIP_REQS="$2"; shift 2 ;;
            --nuke) NUKE="$2"; shift 2 ;;
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

    if [[ $OPERATION == "cleanup" ]]; then
        [[ $NUKE =~ ^(true|false)$ ]] || error "Invalid nuke value"
    fi
}

function get_node_resources() {
    local node_ip=$1
    local cpu_cores mem_gb disk_gb

    if ! read -r cpu_cores mem_gb disk_gb < <(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$SSH_USER@$node_ip" bash << 'ENDSSH'
        cpu_cores=$(nproc)
        mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
        mem_gb=$((mem_kb / 1024 / 1024))
        disk_gb=$(df -B1G / | awk 'NR==2 {print $4}')
        echo "$cpu_cores $mem_gb $disk_gb"
ENDSSH
    ); then
        error "Failed to retrieve resources from node $node_ip"
    fi

    echo "$cpu_cores $mem_gb $disk_gb"
}

function validate_node_resources() {
    local node_ip=$1
    local min_cpu=$2
    local min_mem=$3
    local min_disk=$4
    local node_type=$5

            local resources cpu_cores mem_gb disk_gb
            resources=$(get_node_resources "$node_ip") || return 1
            read -r cpu_cores mem_gb disk_gb <<< "$resources"

            local errors=()
            ((cpu_cores >= min_cpu)) || errors+=("CPU cores: $cpu_cores (minimum $min_cpu)")
            ((mem_gb >= min_mem)) || errors+=("Memory: ${mem_gb}GB (minimum ${min_mem}GB)")
            ((disk_gb >= min_disk)) || errors+=("Disk: ${disk_gb}GB (minimum ${min_disk}GB)")

            if ((${#errors[@]} > 0)); then
                log "$node_type ($node_ip) validation failed:"
                printf " - %s\n" "${errors[@]}" >&2
                return 1
            fi

    return 0
}

function validate_cluster_resources() {
    $SKIP_REQS && return 0

    local failed=0
    log "Validating cluster node resources"

    if ! validate_node_resources "$CONTROL_PLANE_IP" 2 2 50 "Control plane"; then
        failed=1
    fi

    if [[ -n $WORKER_IPS ]]; then
        for ip in ${WORKER_IPS//,/ }; do
            if ! validate_node_resources "$ip" 1 1 20 "Worker node"; then
                failed=1
            fi
        done
    fi

    ((failed)) && error "Resource validation failed"
    return 0
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
    local all_nodes timeout=5
    all_nodes=$(get_cluster_nodes)
    log "Verifying cluster connectivity"

    for ip in ${all_nodes//,/ }; do
        if ! timeout "$timeout" bash -c "</dev/tcp/$ip/22" 2>/dev/null; then
            error "Node $ip is not reachable on port 22"
        fi

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

grep -q "^net.bridge.bridge-nf-call-iptables = 1" /etc/sysctl.conf || \
    echo "net.bridge.bridge-nf-call-iptables = 1" >> /etc/sysctl.conf

sysctl -p
EOF
}

function setup_container_runtime() {
    local node_ip=$1

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
set -euo pipefail

apt-get update
apt-get install -y ca-certificates curl gnupg

if ! command -v docker &> /dev/null || ! docker info &> /dev/null; then
    install -m 0755 -d /etc/apt/keyrings

    if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    fi

    if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    systemctl enable --now docker
fi

mkdir -p /etc/containerd
if [[ ! -f /etc/containerd/config.toml ]] || ! grep -q "SystemdCgroup = true" /etc/containerd/config.toml; then
    cat > /etc/containerd/config.toml << EOC
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
EOC
systemctl restart containerd
fi
EOF
}

function install_kubernetes_packages() {
    local node_ip=$1
    local version=$2

    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << EOF
set -euo pipefail

KUBERNETES_VERSION="$version"
KUBERNETES_VERSION_REPOSITORY="v\${KUBERNETES_VERSION%.*}"

install -m 0755 -d /etc/apt/keyrings
if [[ ! -f "/etc/apt/keyrings/kubernetes-apt-keyring-\$KUBERNETES_VERSION_REPOSITORY.gpg" ]]; then
    curl -fsSL "https://pkgs.k8s.io/core:/stable:/\$KUBERNETES_VERSION_REPOSITORY/deb/Release.key" | \
        gpg --dearmor --yes -o "/etc/apt/keyrings/kubernetes-apt-keyring-\$KUBERNETES_VERSION_REPOSITORY.gpg"
fi

if ! grep -q "\$KUBERNETES_VERSION_REPOSITORY" /etc/apt/sources.list.d/kubernetes.list 2>/dev/null; then
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
if ! command -v helm &> /dev/null; then
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

kubectl create ns kube-flannel
kubectl label --overwrite ns kube-flannel pod-security.kubernetes.io/enforce=privileged

if ! helm repo list | grep -q '^flannel\s'; then
    helm repo add flannel https://flannel-io.github.io/flannel
    helm repo update
fi

helm install flannel \
    --set podCidr=10.244.0.0/16 \
    --namespace kube-flannel \
    flannel/flannel
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
        "kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.kubeletVersion}'") || \
        error "Failed to get cluster version info"

    [[ -z "$nodes_versions" ]] && error "No nodes found in the cluster"

    local current_version
    current_version=$(echo "$nodes_versions" | tr ' ' '\n' | sort -u | head -1)

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

function deep_clean_node() {
    local node_ip=$1
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
set -euo pipefail

# Kill all kubernetes-related processes
for proc in kubelet kube-apiserver kube-controller-manager kube-scheduler kube-proxy containerd docker flannel coredns; do
    pkill -9 "$proc" || true
done

# Stop and disable services
systemctl stop kubelet containerd docker || true
systemctl disable kubelet containerd docker || true

# Force kubeadm reset
kubeadm reset -f || true

# Clean up mounts
for mount in $(mount | grep tmpfs | grep '/var/lib/kubelet' | awk '{ print $3 }'); do
    umount -f "$mount" || true
done

for mount in $(mount | grep kubernetes); do
    umount -f "$(echo "$mount" | awk '{print $3}')" || true
done

# Remove all kubernetes-related directories
rm -rf \
    /etc/kubernetes \
    /var/lib/kubelet \
    /var/lib/etcd \
    /var/lib/dockershim \
    /var/run/kubernetes \
    /var/lib/cni \
    /etc/cni \
    /opt/cni \
    /var/lib/containerd \
    /var/lib/docker \
    /etc/containerd \
    /etc/docker \
    $HOME/.kube \
    /root/.kube

# Clean up network namespaces that might be used by CoreDNS/pods
ip netns list | grep -E 'cni-|coredns' | xargs -r ip netns delete

# Clean up network interfaces
ip link set docker0 down 2>/dev/null || true
ip link delete docker0 2>/dev/null || true
ip link set cni0 down 2>/dev/null || true
ip link delete cni0 2>/dev/null || true
ip link set flannel.1 down 2>/dev/null || true
ip link delete flannel.1 2>/dev/null || true
ip link set weave down 2>/dev/null || true
ip link delete weave 2>/dev/null || true

# Clean up iptables
iptables-save | grep -v KUBE | grep -v CNI | grep -v FLANNEL | iptables-restore
ip6tables-save | grep -v KUBE | grep -v CNI | grep -v FLANNEL | ip6tables-restore

# Remove all container images
crictl rmi --all 2>/dev/null || true
docker system prune -af 2>/dev/null || true

# Remove all K8s and container packages
for pkg in kubectl kubeadm kubelet kubernetes-cni containerd.io containerd docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras coredns; do
    apt-mark unhold "$pkg" 2>/dev/null || true
done

# Force remove packages and their configurations
apt-get remove --purge -y \
    kubectl kubeadm kubelet \
    kubernetes-cni containerd.io containerd \
    docker-ce docker-ce-cli \
    docker-buildx-plugin docker-compose-plugin \
    docker-ce-rootless-extras || true

apt-get autoremove --purge -y || true
apt-get clean

# Clean up package repositories
rm -f /etc/apt/sources.list.d/kubernetes.list
rm -f /etc/apt/sources.list.d/docker.list
rm -f /etc/apt/keyrings/kubernetes*.gpg
rm -f /etc/apt/keyrings/docker*.gpg

# Remove binaries
rm -f /usr/bin/kubectl /usr/bin/kubeadm /usr/bin/kubelet

sed -i '/^net.bridge.bridge-nf-call-iptables = 1$/d' /etc/sysctl.conf
sysctl -p

# Restore original fstab if backup exists
if [[ -f /etc/fstab.bak.* ]]; then
    cp "$(ls -t /etc/fstab.bak.* | head -1)" /etc/fstab
fi

# Clean up systemd
rm -f /etc/systemd/system/kubelet.service
rm -f /etc/systemd/system/docker.service
rm -f /etc/systemd/system/containerd.service
rm -rf /etc/systemd/system/kubelet.service.d
rm -rf /etc/systemd/system/docker.service.d
rm -rf /etc/systemd/system/containerd.service.d

systemctl daemon-reload

# Remove any leftover process
for proc in kubelet kube-apiserver kube-controller-manager kube-scheduler kube-proxy containerd dockerd docker-containerd flannel flanneld; do
    killall -9 "$proc" || true
done

EOF
}

function verify_deep_clean() {
    local node_ip=$1
    local failed=false

    log "Verifying services and processes on $node_ip"
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF' || failed=true
set -euo pipefail

# Check for running services
services_running=false
for svc in kubelet containerd docker; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "Service still running: $svc"
        services_running=true
    fi
done
$services_running && exit 1

# Check for K8s processes
processes_running=false
for proc in kubelet kube-apiserver kube-controller-manager kube-scheduler kube-proxy containerd dockerd flanneld; do
    if pgrep -f "$proc" > /dev/null; then
        echo "Process still running: $proc"
        processes_running=true
    fi
done
$processes_running && exit 1

# Check for open ports
ports_in_use=false
for port in 6443 2379 2380 10250 10251 10252 10255 8472 51820 51821; do
    if netstat -tuln | grep -q ":$port "; then
        echo "Port still in use: $port"
        ports_in_use=true
    fi
done
$ports_in_use && exit 1

# Check for remaining files/directories
files_exist=false
for path in \
    /etc/kubernetes \
    /var/lib/kubelet \
    /var/lib/etcd \
    /var/run/kubernetes \
    /var/lib/dockershim \
    /etc/cni \
    /opt/cni \
    /var/lib/cni \
    /var/lib/containerd \
    /var/lib/docker \
    /etc/containerd \
    /etc/docker \
    $HOME/.kube \
    /root/.kube; do
    if [ -e "$path" ]; then
        echo "Path still exists: $path"
        files_exist=true
    fi
done
$files_exist && exit 1

# Check for network interfaces
interfaces_exist=false
for iface in docker0 cni0 flannel.1 weave; do
    if ip link show "$iface" &>/dev/null; then
        echo "Interface still exists: $iface"
        interfaces_exist=true
    fi
done
$interfaces_exist && exit 1

# Check for kubernetes iptables rules
if iptables-save | grep -qE 'KUBE|CNI|FLANNEL'; then
    echo "Kubernetes iptables rules still exist"
    exit 1
fi

# Check for installed packages
packages_exist=false
for pkg in kubectl kubeadm kubelet kubernetes-cni containerd.io docker-ce docker-ce-cli; do
    if dpkg -l | grep -q "^ii.*$pkg"; then
        echo "Package still installed: $pkg"
        packages_exist=true
    fi
done
$packages_exist && exit 1

# Remove helm and all repos
if command -v helm &> /dev/null; then
    helm repo list | tail -n +2 | awk '{print $1}' | xargs -r helm repo remove
    rm $(command -v helm)
fi

exit 0
EOF

    if $failed; then
        error "Deep clean verification failed on $node_ip - some components still present"
    else
        log "Verification passed for $node_ip"
    fi
}

function cleanup_node() {
    local node_ip=$1

    if [[ $NUKE == "true" ]]; then
        log "Starting deep clean on $node_ip"
        deep_clean_node "$node_ip"
        log "Deep clean completed, starting verification"
        verify_deep_clean "$node_ip"
    else
        log "Performing standard cleanup on $node_ip"
        ssh -o StrictHostKeyChecking=no "$SSH_USER@$node_ip" bash << 'EOF'
if [[ -f $HOME/.kube/config ]] && command -v helm &> /dev/null; then
    helm repo list | tail -n +2 | awk '{print $1}' | xargs -r helm repo remove
fi

kubeadm reset -f
rm -rf $HOME/.kube
ip link delete cni0 || true
ip link delete flannel.1 || true
EOF
    fi
}

function cleanup_cluster() {
    local worker_nodes=""
    if ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" kubectl get nodes &>/dev/null; then
        worker_nodes=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$CONTROL_PLANE_IP" \
            kubectl get nodes -o custom-columns=IP:.status.addresses[0].address --no-headers | \
            grep -v "$CONTROL_PLANE_IP") || true
    fi

    for ip in $worker_nodes; do
        [[ -z $ip ]] && continue
        log "Cleaning up worker: $ip"
        cleanup_node "$ip"
    done

    log "Cleaning up control plane"
    cleanup_node "$CONTROL_PLANE_IP"
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
