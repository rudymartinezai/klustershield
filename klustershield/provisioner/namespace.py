"""
KlusterShield Namespace Provisioner

Creates hardened Kubernetes namespaces with security controls pre-applied:
- RBAC with least-privilege roles
- NetworkPolicy enforcing zero-trust pod communication
- ResourceQuota and LimitRange
- PodSecurityAdmission labels (restricted profile)
- Audit annotation labels for NIST traceability
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from rich.console import Console
from rich.table import Table

console = Console()

# NIST 800-218 control references applied by this provisioner
NIST_CONTROLS = ["PO.1.1", "PO.3.2", "DS.1.1", "DS.2.1", "PV.1.1"]
PSA_ENFORCE_VERSION = "v1.28"


@dataclass
class ProvisionResult:
    namespace: str
    profile: str
    team: str
    controls_applied: list[str] = field(default_factory=list)
    resources_created: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


class NamespaceProvisioner:
    """
    Provisions a security-hardened Kubernetes namespace.

    All resources are created idempotently — safe to run multiple times.
    Labels every resource with NIST control references for audit traceability.
    """

    def __init__(self, profile: str = "nist-800-218", dry_run: bool = False):
        self.profile = profile
        self.dry_run = dry_run
        self._load_kube_config()

        self.core_v1 = client.CoreV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()

    def _load_kube_config(self) -> None:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

    def provision(self, namespace: str, team: str = "default") -> ProvisionResult:
        result = ProvisionResult(
            namespace=namespace,
            profile=self.profile,
            team=team,
            dry_run=self.dry_run,
        )

        console.rule(f"[bold blue]Provisioning namespace: {namespace}[/bold blue]")

        steps = [
            ("Namespace", self._create_namespace),
            ("ResourceQuota", self._create_resource_quota),
            ("LimitRange", self._create_limit_range),
            ("NetworkPolicy (deny-all)", self._create_default_deny_policy),
            ("NetworkPolicy (allow-dns)", self._create_allow_dns_policy),
            ("RBAC: viewer Role", self._create_viewer_role),
            ("RBAC: editor Role", self._create_editor_role),
            ("RBAC: RoleBinding", self._create_role_binding),
        ]

        table = Table(title="Provisioning Steps", show_header=True)
        table.add_column("Resource", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("NIST Control")

        for name, step_fn in steps:
            if self.dry_run:
                table.add_row(name, "⏭  DRY RUN", ", ".join(NIST_CONTROLS))
                result.resources_created.append(f"[DRY RUN] {name}")
            else:
                try:
                    step_fn(namespace=namespace, team=team)
                    table.add_row(name, "✅ Created", ", ".join(NIST_CONTROLS))
                    result.resources_created.append(name)
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        table.add_row(name, "♻️  Exists", ", ".join(NIST_CONTROLS))
                        result.resources_created.append(f"[EXISTS] {name}")
                    else:
                        table.add_row(name, f"❌ Error: {e.reason}", "")
                        result.errors.append(f"{name}: {e.reason}")

        result.controls_applied = NIST_CONTROLS
        console.print(table)

        if result.success:
            console.print(
                f"\n✅ [bold green]Namespace '{namespace}' provisioned successfully[/bold green]"
            )
            console.print(f"   Profile: {self.profile}")
            console.print(f"   NIST controls applied: {', '.join(NIST_CONTROLS)}")
        else:
            console.print(f"\n❌ [bold red]Provisioning completed with errors[/bold red]")
            for error in result.errors:
                console.print(f"   • {error}")

        return result

    def _labels(self, team: str) -> dict[str, str]:
        """Standard labels applied to all KlusterShield-managed resources."""
        return {
            "app.kubernetes.io/managed-by": "klustershield",
            "klustershield/profile": self.profile,
            "klustershield/team": team,
            "klustershield/nist-controls": "PO.1.1-PO.3.2-DS.1.1-DS.2.1-PV.1.1",
            "klustershield/provisioned-at": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y%m%d"
            ),
        }

    def _create_namespace(self, namespace: str, team: str) -> None:
        ns = client.V1Namespace(
            metadata=client.V1ObjectMeta(
                name=namespace,
                labels={
                    **self._labels(team),
                    # PodSecurity admission — enforce restricted profile
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/enforce-version": PSA_ENFORCE_VERSION,
                    "pod-security.kubernetes.io/warn": "restricted",
                    "pod-security.kubernetes.io/audit": "restricted",
                },
                annotations={
                    "klustershield/compliance-profile": self.profile,
                    "klustershield/team": team,
                    "klustershield/doc": "https://github.com/rudy101/KlusterShield",
                },
            )
        )
        self.core_v1.create_namespace(ns)

    def _create_resource_quota(self, namespace: str, team: str) -> None:
        quota = client.V1ResourceQuota(
            metadata=client.V1ObjectMeta(
                name="klustershield-quota",
                namespace=namespace,
                labels=self._labels(team),
            ),
            spec=client.V1ResourceQuotaSpec(
                hard={
                    "requests.cpu": "4",
                    "requests.memory": "8Gi",
                    "limits.cpu": "8",
                    "limits.memory": "16Gi",
                    "pods": "50",
                    "services": "20",
                    "persistentvolumeclaims": "10",
                    "secrets": "50",
                    "configmaps": "50",
                }
            ),
        )
        self.core_v1.create_namespaced_resource_quota(namespace=namespace, body=quota)

    def _create_limit_range(self, namespace: str, team: str) -> None:
        limit_range = client.V1LimitRange(
            metadata=client.V1ObjectMeta(
                name="klustershield-limits",
                namespace=namespace,
                labels=self._labels(team),
            ),
            spec=client.V1LimitRangeSpec(
                limits=[
                    client.V1LimitRangeItem(
                        type="Container",
                        default={"cpu": "500m", "memory": "512Mi"},
                        default_request={"cpu": "100m", "memory": "128Mi"},
                        max={"cpu": "2", "memory": "4Gi"},
                        min={"cpu": "50m", "memory": "64Mi"},
                    )
                ]
            ),
        )
        self.core_v1.create_namespaced_limit_range(namespace=namespace, body=limit_range)

    def _create_default_deny_policy(self, namespace: str, team: str) -> None:
        """Zero-trust: deny all ingress and egress by default."""
        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(
                name="default-deny-all",
                namespace=namespace,
                labels=self._labels(team),
                annotations={"klustershield/nist": "DS.1.1 - Zero-trust network isolation"},
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(),  # selects all pods
                policy_types=["Ingress", "Egress"],
                # No ingress/egress rules = deny all
            ),
        )
        self.networking_v1.create_namespaced_network_policy(namespace=namespace, body=policy)

    def _create_allow_dns_policy(self, namespace: str, team: str) -> None:
        """Allow DNS egress so pods can resolve service names."""
        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(
                name="allow-dns-egress",
                namespace=namespace,
                labels=self._labels(team),
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(),
                policy_types=["Egress"],
                egress=[
                    client.V1NetworkPolicyEgressRule(
                        ports=[
                            client.V1NetworkPolicyPort(port=53, protocol="UDP"),
                            client.V1NetworkPolicyPort(port=53, protocol="TCP"),
                        ]
                    )
                ],
            ),
        )
        self.networking_v1.create_namespaced_network_policy(namespace=namespace, body=policy)

    def _create_viewer_role(self, namespace: str, team: str) -> None:
        role = client.V1Role(
            metadata=client.V1ObjectMeta(
                name="klustershield-viewer",
                namespace=namespace,
                labels=self._labels(team),
                annotations={"klustershield/nist": "DS.2.1 - Least-privilege access control"},
            ),
            rules=[
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["pods", "services", "configmaps", "events"],
                    verbs=["get", "list", "watch"],
                ),
            ],
        )
        self.rbac_v1.create_namespaced_role(namespace=namespace, body=role)

    def _create_editor_role(self, namespace: str, team: str) -> None:
        role = client.V1Role(
            metadata=client.V1ObjectMeta(
                name="klustershield-editor",
                namespace=namespace,
                labels=self._labels(team),
                annotations={"klustershield/nist": "DS.2.1 - Least-privilege access control"},
            ),
            rules=[
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["pods", "services", "configmaps"],
                    verbs=["get", "list", "watch", "create", "update", "patch"],
                ),
                client.V1PolicyRule(
                    api_groups=["apps"],
                    resources=["deployments", "replicasets"],
                    verbs=["get", "list", "watch", "create", "update", "patch"],
                ),
            ],
        )
        self.rbac_v1.create_namespaced_role(namespace=namespace, body=role)

    def _create_role_binding(self, namespace: str, team: str) -> None:
        binding = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(
                name="klustershield-team-binding",
                namespace=namespace,
                labels=self._labels(team),
            ),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="Role",
                name="klustershield-viewer",
            ),
            subjects=[
                client.RbacV1Subject(
                    kind="Group",
                    name=f"system:klustershield:{team}",
                    api_group="rbac.authorization.k8s.io",
                )
            ],
        )
        self.rbac_v1.create_namespaced_role_binding(namespace=namespace, body=binding)
