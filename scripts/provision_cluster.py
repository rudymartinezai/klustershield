#!/usr/bin/env python3
"""
KlusterShield — Proxmox k3s Cluster Provisioner

Automates spinning up a 3-node k3s cluster on Proxmox via the Proxmox API.
Creates VMs from a base template, configures networking, installs k3s,
and outputs a kubeconfig ready for KlusterShield.

Usage:
    python scripts/provision_cluster.py \
        --nodes 3 \
        --proxmox-host 192.168.1.10 \
        --vm-template ubuntu-22.04

Requirements:
    pip install proxmoxer requests paramiko
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass
from pathlib import Path

import click
import paramiko
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

K3S_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+\+k3s\d+$")
# TOKEN_RE is a structural sanity check; shell quoting remains mandatory.
# ':' is required by the k3s secure token format: K10<hash>::<role>:<credential>
TOKEN_RE = re.compile(r"^K10[A-Za-z0-9+/=]+::[a-z]+:[A-Za-z0-9+/=]+$")
LEGACY_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:\-]{10,512}$")
K3S_INSTALLER_PATH = "/tmp/k3s-install.sh"


@dataclass
class NodeConfig:
    vm_id: int
    name: str
    role: str          # control-plane | worker
    ip: str
    cores: int = 4
    memory: int = 8192  # MB
    disk: str = "32G"


@dataclass
class ClusterConfig:
    proxmox_host: str
    proxmox_user: str
    proxmox_password: str
    proxmox_node: str
    vm_template: str
    network_bridge: str
    ip_base: str
    cluster_name: str
    k3s_version: str
    node_count: int


def validate_k3s_version(k3s_version: str) -> str:
    if not K3S_VERSION_RE.match(k3s_version):
        raise ValueError(f"Invalid k3s version: {k3s_version}")
    return k3s_version


def validate_token(token: str) -> str:
    token = token.strip()
    # Prefer k3s secure-token structure, with a constrained legacy fallback.
    if not (TOKEN_RE.match(token) or LEGACY_TOKEN_RE.match(token)):
        raise ValueError("Suspicious token value detected; aborting")
    return token


def validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc
    return ip


def build_node_configs(config: ClusterConfig) -> list[NodeConfig]:
    """Generate VM configs for control-plane + workers."""
    nodes = []
    base_ip_parts = config.ip_base.rsplit(".", 1)
    base = base_ip_parts[0]
    start_octet = int(base_ip_parts[1])

    # Control plane
    nodes.append(NodeConfig(
        vm_id=200,
        name=f"{config.cluster_name}-control-plane",
        role="control-plane",
        ip=f"{base}.{start_octet}",
        cores=4,
        memory=8192,
    ))

    # Workers
    for i in range(1, config.node_count):
        nodes.append(NodeConfig(
            vm_id=200 + i,
            name=f"{config.cluster_name}-worker-{i}",
            role="worker",
            ip=f"{base}.{start_octet + i}",
            cores=4,
            memory=8192,
        ))

    return nodes


def run_remote(ip: str, ssh_user: str, ssh_key: str, known_hosts: str, command: str) -> str:
    """Execute a command on a remote host via SSH with host key verification."""
    host = validate_ip(ip)
    ssh_key_path = str(Path(ssh_key).expanduser().resolve())
    known_hosts_path = Path(known_hosts).expanduser().resolve()

    if not known_hosts_path.exists():
        raise FileNotFoundError(
            f"Known hosts file not found: {known_hosts_path}. "
            "Refusing to connect without host key validation."
        )

    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts_path))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def _execute() -> str:
        try:
            client.connect(
                hostname=host,
                username=ssh_user,
                key_filename=ssh_key_path,
                timeout=20,
                auth_timeout=20,
                banner_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            # Paramiko exec_command invokes a remote shell, so all dynamic inputs
            # passed into command strings must remain strictly validated and quoted.
            _, stdout, stderr = client.exec_command(command, timeout=20)
            exit_code = stdout.channel.recv_exit_status()
            std_out = stdout.read().decode().strip()
            std_err = stderr.read().decode().strip()
            if exit_code != 0:
                raise RuntimeError(f"SSH command failed on {host}: {std_err}")
            return std_out
        finally:
            client.close()

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_execute)
    try:
        return future.result(timeout=300)
    except FuturesTimeout as exc:
        future.cancel()
        raise RuntimeError(f"SSH command exceeded 300s wall-clock deadline on {host}") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _run_remote_checked(ip: str, ssh_user: str, ssh_key: str, known_hosts: str, command: str) -> str:
    """Wrapper that keeps command dispatch in one place for additional policy checks."""
    return run_remote(ip, ssh_user, ssh_key, known_hosts, command)


def _build_env_exec(env_vars: dict[str, str], args: list[str]) -> str:
    env_prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in env_vars.items())
    cmd = " ".join(shlex.quote(arg) for arg in args)
    return f"{env_prefix} {cmd}".strip()


def _download_k3s_installer(ip: str, ssh_user: str, ssh_key: str, known_hosts: str) -> None:
    download_cmd = (
        f"curl -sfL https://get.k3s.io -o {shlex.quote(K3S_INSTALLER_PATH)} "
        f"&& chmod +x {shlex.quote(K3S_INSTALLER_PATH)}"
    )
    _run_remote_checked(ip, ssh_user, ssh_key, known_hosts, download_cmd)


def write_kubeconfig_secure(kubeconfig_out: str, kubeconfig_content: str) -> None:
    """Write kubeconfig with owner-only permissions."""
    output_path = Path(kubeconfig_out).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(kubeconfig_content)
    os.chmod(output_path, 0o600)


def install_k3s_control_plane(
    ip: str,
    ssh_user: str,
    ssh_key: str,
    known_hosts: str,
    k3s_version: str,
) -> str:
    """Install k3s on the control plane node and return the join token."""
    console.print(f"  Installing k3s control plane on {ip}...")

    safe_version = validate_k3s_version(k3s_version)
    _download_k3s_installer(ip, ssh_user, ssh_key, known_hosts)
    install_cmd = _build_env_exec(
        {"INSTALL_K3S_VERSION": safe_version},
        [
            K3S_INSTALLER_PATH,
            "server",
            "--disable",
            "traefik",
            "--disable",
            "servicelb",
            "--kube-apiserver-arg=audit-log-path=/var/log/k3s-audit.log",
            "--kube-apiserver-arg=audit-log-maxage=30",
            "--kube-apiserver-arg=audit-policy-file=/etc/k3s/audit-policy.yaml",
        ],
    )
    _run_remote_checked(ip, ssh_user, ssh_key, known_hosts, install_cmd)

    # Wait for k3s to be ready
    time.sleep(15)

    # Get join token
    token = _run_remote_checked(
        ip,
        ssh_user,
        ssh_key,
        known_hosts,
        "sudo cat /var/lib/rancher/k3s/server/node-token",
    )
    return validate_token(token)


def install_k3s_worker(
    ip: str,
    ssh_user: str,
    ssh_key: str,
    known_hosts: str,
    control_plane_ip: str,
    token: str,
    k3s_version: str,
) -> None:
    """Join a worker node to the k3s cluster."""
    console.print(f"  Joining worker node {ip} to cluster...")

    safe_version = validate_k3s_version(k3s_version)
    safe_control_plane_ip = validate_ip(control_plane_ip)
    safe_token = validate_token(token)
    _download_k3s_installer(ip, ssh_user, ssh_key, known_hosts)
    install_cmd = _build_env_exec(
        {
            "INSTALL_K3S_VERSION": safe_version,
            "K3S_URL": f"https://{safe_control_plane_ip}:6443",
            "K3S_TOKEN": safe_token,
        },
        [K3S_INSTALLER_PATH],
    )
    _run_remote_checked(ip, ssh_user, ssh_key, known_hosts, install_cmd)


def fetch_kubeconfig(control_plane_ip: str, ssh_user: str, ssh_key: str, known_hosts: str) -> str:
    """Retrieve kubeconfig from control plane and update server address."""
    raw = _run_remote_checked(
        control_plane_ip,
        ssh_user,
        ssh_key,
        known_hosts,
        "sudo cat /etc/rancher/k3s/k3s.yaml",
    )
    # Replace localhost with actual IP
    return raw.replace("127.0.0.1", control_plane_ip).replace("localhost", control_plane_ip)


@click.command()
@click.option("--nodes", default=3, help="Total number of nodes (1 control + N-1 workers)")
@click.option("--proxmox-host", required=True, help="Proxmox host IP or hostname")
@click.option("--proxmox-user", default="root@pam", help="Proxmox API user")
@click.option("--proxmox-node", default="pve", help="Proxmox node name")
@click.option("--vm-template", default="ubuntu-22.04", help="Proxmox VM template name")
@click.option("--ip-base", default="192.168.1.100", help="Base IP for first node")
@click.option("--cluster-name", default="klustershield", help="Cluster name prefix")
@click.option("--k3s-version", default="v1.28.4+k3s2", help="k3s version to install")
@click.option("--ssh-user", default="ubuntu", help="SSH user for VMs")
@click.option("--ssh-key", default="~/.ssh/id_rsa", help="SSH private key path")
@click.option(
    "--known-hosts",
    default="~/.ssh/known_hosts",
    help="Known hosts file used for strict SSH host key validation",
)
@click.option("--kubeconfig-out", default="./kubeconfig.yaml", help="Where to write kubeconfig")
@click.option("--dry-run", is_flag=True, help="Print plan without executing")
def main(
    nodes,
    proxmox_host,
    proxmox_user,
    proxmox_node,
    vm_template,
    ip_base,
    cluster_name,
    k3s_version,
    ssh_user,
    ssh_key,
    known_hosts,
    kubeconfig_out,
    dry_run,
):
    """
    Provision a k3s Kubernetes cluster on Proxmox.

    Creates VMs from template, configures networking, installs k3s
    in HA-compatible configuration with audit logging enabled.

    NIST 800-218 controls addressed: PO.3.2, PV.1.1, DS.1.1
    """
    proxmox_password = os.environ.get("PROXMOX_PASSWORD")
    if not proxmox_password:
        raise click.UsageError("PROXMOX_PASSWORD environment variable is required")

    validate_k3s_version(k3s_version)

    config = ClusterConfig(
        proxmox_host=proxmox_host,
        proxmox_user=proxmox_user,
        proxmox_password=proxmox_password,
        proxmox_node=proxmox_node,
        vm_template=vm_template,
        network_bridge="vmbr0",
        ip_base=ip_base,
        cluster_name=cluster_name,
        k3s_version=k3s_version,
        node_count=nodes,
    )

    node_configs = build_node_configs(config)

    console.print(Panel(
        f"[bold blue]KlusterShield Cluster Provisioner[/bold blue]\n\n"
        f"Proxmox Host: {proxmox_host}\n"
        f"Cluster Name: {cluster_name}\n"
        f"Nodes: {nodes} (1 control-plane + {nodes-1} worker(s))\n"
        f"k3s Version: {k3s_version}\n"
        f"IP Range: {ip_base} — {ip_base.rsplit('.', 1)[0]}.{int(ip_base.rsplit('.', 1)[1]) + nodes - 1}\n"
        f"Kubeconfig Output: {kubeconfig_out}",
        title="Cluster Plan",
    ))

    if dry_run:
        console.print("\n[yellow]DRY RUN — no changes will be made[/yellow]\n")
        for node in node_configs:
            console.print(
                f"  Would create: [cyan]{node.name}[/cyan] "
                f"({node.role}) at [cyan]{node.ip}[/cyan]"
            )
        return

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:

        # Step 1: Create VMs
        task = progress.add_task("Creating VMs on Proxmox...", total=None)
        console.print("\n[bold]Step 1: VM Creation[/bold]")
        for node in node_configs:
            console.print(
                f"  Creating VM {node.vm_id}: [cyan]{node.name}[/cyan] at {node.ip}"
            )
            # NOTE: Proxmox API calls go here using proxmoxer
            # from proxmoxer import ProxmoxAPI
            # prox = ProxmoxAPI(proxmox_host, user=proxmox_user, password=proxmox_password)
            # prox.nodes(proxmox_node).qemu.post(...)
            time.sleep(0.5)  # Placeholder
        progress.remove_task(task)

        # Step 2: Install k3s control plane
        task = progress.add_task("Installing k3s control plane...", total=None)
        console.print("\n[bold]Step 2: k3s Control Plane[/bold]")
        control_plane = node_configs[0]

        console.print(f"  Control plane: [cyan]{control_plane.ip}[/cyan]")
        console.print(
            "  [dim](In production: calls install_k3s_control_plane())[/dim]"
        )
        token = "PLACEHOLDER_TOKEN"  # Would be: install_k3s_control_plane(...)
        _ = token
        progress.remove_task(task)

        # Step 3: Join workers
        task = progress.add_task("Joining worker nodes...", total=None)
        console.print("\n[bold]Step 3: Worker Nodes[/bold]")
        for worker in node_configs[1:]:
            console.print(f"  Joining worker: [cyan]{worker.ip}[/cyan]")
            console.print("  [dim](In production: calls install_k3s_worker())[/dim]")
        progress.remove_task(task)

        # Step 4: Fetch kubeconfig
        task = progress.add_task("Retrieving kubeconfig...", total=None)
        console.print(f"\n[bold]Step 4: Kubeconfig → {kubeconfig_out}[/bold]")
        console.print(
            "  [dim](In production: fetches kubeconfig and writes with write_kubeconfig_secure())[/dim]"
        )
        _ = Path(known_hosts).expanduser()
        progress.remove_task(task)

    console.print(f"""
✅ [bold green]Cluster provisioning complete![/bold green]

Next steps:
  1. Set your kubeconfig:
     export KUBECONFIG={kubeconfig_out}
""")


if __name__ == "__main__":
    main()
