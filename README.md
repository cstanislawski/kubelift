# kubelift

Kubernetes cluster operations over SSH

## Goal

The goal of this project is to provide a simple tool to provision a Kubernetes cluster on VMs over SSH. By going with a script-based approach, you can easily customize the installation process to fit your needs, and fail fast if something goes wrong.

`kubelift` aims to be a bridge between the manual operations with `kubeadm` and the automated installation with `kubespray` requiring a lot of setup.

## Requirements

- A set of VM(s) with SSH access
- Sudo privileges without password prompt (NOPASSWD in sudoers) for the SSH user
- Internet connectivity on all nodes

## Features

- **Noninteractive mode** for automated operations
- **SSH-based Operations** for secure remote management
- **Seamless Upgrades** for managing cluster lifecycle
- **Input Validation** ensures all provided parameters are correct
- **Modular Design** for better maintainability

## Installation

### Quick Setup

```bash
curl -LO https://raw.githubusercontent.com/cstanislawski/kubelift/main/kubelift.sh
chmod +x kubelift.sh
```

### System-wide Installation

```bash
sudo curl -L https://raw.githubusercontent.com/cstanislawski/kubelift/main/kubelift.sh -o /usr/local/bin/kubelift
sudo chmod +x /usr/local/bin/kubelift
```

## Usage

```bash
kubelift --help
Usage: kubelift <operation> [options...]
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
```

### Cluster Creation

```bash
./kubelift.sh create \
    --noninteractive <true|false> \
    --ssh-user <username> \
    --kubernetes-version <version> \
    --control-plane-ip <ip> \
    --worker-ips <ip1,ip2,...> \
    --enable-control-plane-workloads <true|false>
```

The create operation will:

- Validate all input parameters
- Check SSH access to all specified nodes
- Prepare each node by:
  - Installing Docker and containerd
  - Installing kubeadm, kubectl, and kubelet
  - Configuring the cgroup driver
- Initialize the control plane node
- Join worker nodes to the cluster
- Install the CNI plugin (Flannel)
- Optionally enable scheduling on the control plane node

### Cluster Upgrade

```bash
./kubelift.sh upgrade \
    --noninteractive <true|false> \
    --ssh-user <username> \
    --kubernetes-version <version> \
    --control-plane-ip <ip>
```

The upgrade operation will:

- Validate all input parameters
- Check SSH access to all nodes
- Verify version differences between current and target
- Check availability of target Kubernetes components
- Upgrade the control plane node
- Upgrade worker nodes (if present)

### Cluster Cleanup

```bash
./kubelift.sh cleanup \
    --noninteractive <true|false> \
    --ssh-user <username> \
    --control-plane-ip <ip> \
    --nuke <true|false> # Optional
```

The cleanup operation will:

- Remove the Kubernetes cluster using kubeadm reset
- Clean up both control plane and worker nodes
- Preserve CNI configuration

## Configuration / Environment Variables

The scripts use the following environment variables:

### General variables

- `NONINTERACTIVE`: Enable or disable noninteractive mode (true/false)
- `SSH_USER`: SSH user for connecting to the nodes
- `KUBERNETES_VERSION`: Kubernetes version to install/upgrade to
- `CONTROL_PLANE_IP`: IP address of the control plane node

### Cluster creation variables

- `WORKER_IPS`: Comma-separated list of worker node IP addresses
- `ENABLE_CONTROL_PLANE_WORKLOADS`: Enable scheduling on control plane node (true/false)

## Limitations and Considerations

- Host OS: Scripts assume one of the latest Ubuntu LTS versions is used on all VMs
- Network: Scripts assume the VMs have internet connectivity
- Minimum Resources: Ensure VMs meet the minimum Kubernetes system requirements
- CNI Plugin: Scripts install Flannel as the default CNI plugin
- Version-specific Limitations: The upgrade script follows a general upgrade path. Specific versions may have additional requirements
- Downgrades: The upgrade script doesn't support downgrading the cluster

## Best Practices

- Always test the scripts in a non-production environment first
- Ensure you have recent backups before performing upgrades
- Review the scripts and understand their operation before running
- Monitor the cluster closely after any operations

## Alternatives

Some of the alternatives you could consider are:

- [kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/) - a tool built to provide best-practice "fast paths" for creating Kubernetes clusters, which `kubelift` is based on
- [kubespray](https://github.com/kubernetes-sigs/kubespray) - a set of Ansible playbooks to provision a Kubernetes cluster
- [kubean](https://github.com/kubean-io/kubean) - an operator for cluster lifecycle management based on kubespray
- [kops](https://github.com/kubernetes/kops) - CLI to create, destroy, upgrade and maintain production-grade Kubernetes clusters hosted on AWS/GCP with more providers in Beta/Alpha
- [k3sup](https://github.com/alexellis/k3sup) - k3s cluster installer over SSH

## TODO - unordered

## CI

- Add BATS - Bash Automated Testing System - for testing the scripts
- Consider checkbashisms instead of shellcheck
- Consider bash-language-server analysis
- CodeQL analysis for security scanning
- Add E2E tests with kind/k3d/Vagrant

## High Priority

- Allow custom CIDR ranges
- Add support for additional logging output to a file
- Add dry-run mode for operations

## Medium Priority

- Add support for more CNI plugins: Calico, Cilium
- Cluster configuration templating
- Add support for HA control plane
- Add downgrades support
- Assume presence of the flag equals true (e.g. --noninteractive) if the flag is present
- Add k3s support
- Add support for more Linux distributions

## Low Priority

- Air-gapped environments support
