# Proxmox Setup Guide for KlusterShield

This guide walks through preparing a Proxmox environment to run a KlusterShield
k3s cluster. Designed for a home lab or on-premises server with at least:

- **CPU:** 8+ cores (12+ recommended)
- **RAM:** 32GB+ (64GB recommended)
- **Storage:** 200GB+ SSD/NVMe
- **Network:** 1GbE minimum

---

## Step 1 — Create Ubuntu 22.04 Cloud-Init Template

```bash
# On your Proxmox host

# Download Ubuntu 22.04 cloud image
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

# Create a new VM for the template
qm create 9000 \
  --name ubuntu-22.04-template \
  --memory 4096 \
  --cores 2 \
  --net0 virtio,bridge=vmbr0 \
  --agent enabled=1

# Import the disk
qm importdisk 9000 jammy-server-cloudimg-amd64.img local-lvm

# Attach and configure the disk
qm set 9000 \
  --scsihw virtio-scsi-pci \
  --scsi0 local-lvm:vm-9000-disk-0 \
  --ide2 local-lvm:cloudinit \
  --boot c \
  --bootdisk scsi0 \
  --serial0 socket \
  --vga serial0

# Set Cloud-Init defaults
qm set 9000 \
  --ciuser ubuntu \
  --sshkeys ~/.ssh/authorized_keys \
  --ipconfig0 ip=dhcp

# Convert to template
qm template 9000

echo "Template 9000 created: ubuntu-22.04-template"
```

---

## Step 2 — Configure Proxmox API Access

KlusterShield uses the Proxmox API to create VMs programmatically.
Create a dedicated API token with minimal permissions:

```bash
# On Proxmox host — create API token
pveum user add klustershield@pam --comment "KlusterShield automation user"
pveum passwd klustershield@pam

pveum aclmod / -user klustershield@pam -role PVEVMAdmin
pveum aclmod /storage/local-lvm -user klustershield@pam -role PVEDatastoreUser

# Create API token (no expiry for lab use)
pveum user token add klustershield@pam klustershield-token
```

Store credentials in your environment:

```bash
# .env file (never commit this)
PROXMOX_HOST=192.168.1.10
PROXMOX_USER=klustershield@pam
PROXMOX_PASSWORD=your_password_here
PROXMOX_NODE=pve
```

---

## Step 3 — Network Configuration

For a lab cluster, a simple flat network works fine.
For production-like separation, create a dedicated VLAN:

```bash
# /etc/network/interfaces on Proxmox host
# Add a bridge for cluster traffic (adjust to your network)

auto vmbr1
iface vmbr1 inet static
    address 10.10.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up iptables -t nat -A POSTROUTING -s '10.10.10.0/24' -o vmbr0 -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.10.10.0/24' -o vmbr0 -j MASQUERADE
```

---

## Step 4 — Provision the Cluster

```bash
# Clone KlusterShield
git clone https://github.com/rudymartinezai/klustershield.git
cd KlusterShield

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your Proxmox credentials

# Provision 3-node cluster
python scripts/provision_cluster.py \
  --nodes 3 \
  --proxmox-host 192.168.1.10 \
  --vm-template ubuntu-22.04 \
  --ip-base 10.10.10.10 \
  --cluster-name klustershield \
  --kubeconfig-out ./kubeconfig.yaml
```

---

## Step 5 — Verify and Harden

```bash
# Set kubeconfig
export KUBECONFIG=./kubeconfig.yaml

# Verify all nodes are ready
kubectl get nodes

# Expected output:
# NAME                         STATUS   ROLES                  AGE
# klustershield-control-plane  Ready    control-plane,master   2m
# klustershield-worker-1       Ready    <none>                 1m
# klustershield-worker-2       Ready    <none>                 1m

# Run initial compliance scan (cluster-wide)
klustershield scan --output baseline-report.html
open baseline-report.html

# Provision your first hardened namespace
klustershield provision --namespace production --profile nist-800-218 --team platform

# Verify the namespace
kubectl get networkpolicies -n production
kubectl get roles -n production
kubectl get resourcequota -n production

# Run scoped scan
klustershield scan --namespace production --output production-report.html
```

---

## Recommended VM Sizing

| Role | vCPUs | RAM | Disk |
|---|---|---|---|
| Control Plane | 4 | 8GB | 32GB |
| Worker (standard) | 4 | 8GB | 32GB |
| Worker (heavy workloads) | 8 | 16GB | 64GB |

For a beefy single-server lab, 3 VMs total (1 control + 2 workers)
fits comfortably in 32GB RAM with room for workloads.
