"""
KlusterShield CLI
Security-hardened Kubernetes compliance automation aligned to NIST SP 800-218
"""

from __future__ import annotations

import re

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")

BANNER = """
██╗  ██╗██╗     ██╗   ██╗███████╗████████╗███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
██║ ██╔╝██║     ██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
█████╔╝ ██║     ██║   ██║███████╗   ██║   █████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║
██╔═██╗ ██║     ██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║  ██╗███████╗╚██████╔╝███████║   ██║   ███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
"""


def _validate_dns_label(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    if value is None:
        return None
    if not DNS_LABEL_RE.match(value):
        raise click.BadParameter("Must be a valid DNS label: lowercase alphanumeric and hyphens, max 63 chars")
    return value


@click.group()
@click.version_option(version="0.1.0", prog_name="KlusterShield")
def main() -> None:
    """
    KlusterShield — Security-hardened Kubernetes compliance automation.

    Provisions, hardens, and audits Kubernetes clusters against NIST SP 800-218 (SSDF).
    """
    console.print(Text(BANNER, style="bold blue"))
    console.print(
        Panel(
            "NIST SP 800-218 (SSDF) Compliance Automation for Kubernetes",
            style="bold",
            border_style="blue",
        )
    )


@main.command()
@click.option("--namespace", "-n", required=True, callback=_validate_dns_label, help="Target namespace name")
@click.option(
    "--profile",
    "-p",
    default="nist-800-218",
    type=click.Choice(["nist-800-218", "nist-800-53", "cmmc-l2"]),
    help="Compliance profile to apply",
)
@click.option("--team", "-t", default="default", callback=_validate_dns_label, help="Owning team label")
@click.option("--dry-run", is_flag=True, help="Preview changes without applying")
def provision(namespace: str, profile: str, team: str, dry_run: bool) -> None:
    """
    Provision a hardened namespace with security controls pre-applied.

    Creates namespace with RBAC, NetworkPolicies, ResourceQuotas,
    and PodSecurityAdmission labels aligned to the selected compliance profile.
    """
    from klustershield.provisioner.namespace import NamespaceProvisioner

    provisioner = NamespaceProvisioner(profile=profile, dry_run=dry_run)
    provisioner.provision(namespace=namespace, team=team)


@main.command()
@click.option(
    "--namespace",
    "-n",
    default=None,
    callback=_validate_dns_label,
    help="Namespace to scan (omit for cluster-wide)",
)
@click.option(
    "--output",
    "-o",
    default="klustershield-report.html",
    help="Output file path (.html or .json)",
)
@click.option(
    "--profile",
    "-p",
    default="nist-800-218",
    type=click.Choice(["nist-800-218", "nist-800-53", "cmmc-l2"]),
    help="Compliance profile to scan against",
)
@click.option("--fail-below", default=80, help="Exit code 1 if compliance score below this %")
def scan(namespace: str | None, output: str, profile: str, fail_below: int) -> None:
    """
    Scan cluster or namespace against NIST 800-218 controls.

    Generates a scored compliance report with per-control PASS/FAIL/WARN status.
    Use --fail-below to integrate with CI/CD pipelines.
    """
    from klustershield.scanner.engine import ComplianceScanner

    scanner = ComplianceScanner(profile=profile)
    result = scanner.scan(namespace=namespace)

    try:
        scanner.report(result=result, output_path=output)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="output") from exc

    if result.score < fail_below:
        raise SystemExit(1)


@main.command()
@click.option("--install", is_flag=True, help="Install OPA Gatekeeper and apply constraint templates")
@click.option("--uninstall", is_flag=True, help="Remove Gatekeeper from cluster")
@click.option("--list", "list_policies", is_flag=True, help="List active constraint templates")
def enforce(install: bool, uninstall: bool, list_policies: bool) -> None:
    """
    Manage OPA Gatekeeper policy enforcement.

    Installs constraint templates that block non-compliant workloads
    at admission time — before they ever reach the cluster.
    """
    try:
        from klustershield.enforcer.gatekeeper import GatekeeperManager
    except ImportError as exc:
        raise click.ClickException(
            "The 'enforce' command is not available in this build yet. " "See project issues for implementation status."
        ) from exc

    manager = GatekeeperManager()

    if install:
        manager.install()
    elif uninstall:
        manager.uninstall()
    elif list_policies:
        manager.list_constraints()
    else:
        click.echo(enforce.get_help(click.Context(enforce)))


@main.command()
@click.option(
    "--namespace", "-n", default=None, callback=_validate_dns_label, help="Namespace to collect audit logs from"
)
@click.option(
    "--backend",
    "-b",
    default="file",
    type=click.Choice(["splunk", "loki", "file"]),
    help="Log shipping backend",
)
@click.option("--output", "-o", default="audit.json", help="Output file (for file backend)")
@click.option("--splunk-url", default=None, envvar="SPLUNK_HEC_URL", help="Splunk HEC endpoint")
@click.option("--splunk-token", default=None, envvar="SPLUNK_HEC_TOKEN", help="Splunk HEC token")
def audit(
    namespace: str | None,
    backend: str,
    output: str,
    splunk_url: str | None,
    splunk_token: str | None,
) -> None:
    """
    Collect and ship Kubernetes audit logs to a backend.

    Maps audit events to NIST 800-218 control references for traceability.
    Supports Splunk HEC, Loki, or local JSON file output.
    """
    try:
        from klustershield.auditor.shipper import AuditShipper
    except ImportError as exc:
        raise click.ClickException(
            "The 'audit' command is not available in this build yet. " "See project issues for implementation status."
        ) from exc

    shipper = AuditShipper(
        backend=backend,
        splunk_url=splunk_url,
        splunk_token=splunk_token,
    )
    shipper.collect_and_ship(namespace=namespace, output_path=output)


if __name__ == "__main__":
    main()
