"""
Smoke tests for the KlusterShield scanner engine.
These tests mock the Kubernetes client — no live cluster needed.
"""
import os

import pytest
from unittest.mock import MagicMock, patch


def test_resolve_output_path_valid(tmp_path):
    """Output path within CWD should be accepted."""
    from klustershield.scanner.engine import ComplianceScanner

    with patch("klustershield.scanner.engine.config"):
        with patch("klustershield.scanner.engine.client"):
            scanner = ComplianceScanner.__new__(ComplianceScanner)
            scanner.namespace = None
            os.chdir(tmp_path)
            result = scanner._resolve_output_path("report.html")
            assert str(result).startswith(str(tmp_path))


def test_resolve_output_path_traversal_blocked(tmp_path):
    """Path traversal outside CWD should raise ValueError."""
    from klustershield.scanner.engine import ComplianceScanner

    with patch("klustershield.scanner.engine.config"):
        with patch("klustershield.scanner.engine.client"):
            scanner = ComplianceScanner.__new__(ComplianceScanner)
            scanner.namespace = None
            os.chdir(tmp_path)
            # Use a .html path outside CWD to hit the traversal guard
            with pytest.raises(ValueError):
                scanner._resolve_output_path("/tmp/evil.html")


def test_all_containers_extracts_containers():
    """_all_containers should return containers from pod spec."""
    from klustershield.scanner.engine import ComplianceScanner

    with patch("klustershield.scanner.engine.config"):
        with patch("klustershield.scanner.engine.client"):
            scanner = ComplianceScanner.__new__(ComplianceScanner)
            pod = MagicMock()
            container = MagicMock()
            pod.spec.containers = [container]
            pod.spec.init_containers = []
            pod.spec.ephemeral_containers = []
            result = scanner._all_containers(pod)
            assert container in result


def test_scan_result_score_calculation():
    """Compliance score should reflect weighted pass/fail ratio correctly."""
    from klustershield.scanner.engine import ScanResult, ControlCheck, Status

    result = ScanResult(namespace=None, profile="nist-800-218")
    result.checks = [
        ControlCheck(
            control_id="PO.1.1",
            control_family="PO",
            title="Security requirements",
            description="Security requirements defined",
            severity="critical",
            status=Status.PASS,
            finding="ok",
            remediation="",
        ),
        ControlCheck(
            control_id="PS.1.1",
            control_family="PS",
            title="Code review",
            description="Code review gates",
            severity="high",
            status=Status.PASS,
            finding="ok",
            remediation="",
        ),
        ControlCheck(
            control_id="PW.4.1",
            control_family="PW",
            title="Secure coding",
            description="Secure coding standards",
            severity="medium",
            status=Status.FAIL,
            finding="bad",
            remediation="fix it",
        ),
        ControlCheck(
            control_id="DS.1.1",
            control_family="DS",
            title="Data protection",
            description="Sensitive data protected",
            severity="high",
            status=Status.SKIP,
            finding="skipped",
            remediation="",
        ),
    ]
    # Weighted score: PASS critical(4) + PASS high(3) = 7 out of 9 scoreable (SKIP excluded)
    # FAIL medium(2) counted against. Score = 7/9 = 77.8%
    assert result.passed == 2
    assert result.failed == 1
    assert result.skipped == 1
    assert 77.0 < result.score < 78.0


def test_scan_result_score_zero_when_all_skip():
    """Score should be 0 when all checks are skipped."""
    from klustershield.scanner.engine import ScanResult, ControlCheck, Status

    result = ScanResult(namespace=None, profile="nist-800-218")
    result.checks = [
        ControlCheck(
            control_id="PO.1.1",
            control_family="PO",
            title="Test",
            description="Test check",
            severity="high",
            status=Status.SKIP,
            finding="skipped",
            remediation="",
        ),
    ]
    assert result.score == 0.0
    assert result.passed == 0
    assert result.skipped == 1


def test_status_enum_values():
    """Status enum should have the expected values."""
    from klustershield.scanner.engine import Status

    assert Status.PASS == "PASS"
    assert Status.FAIL == "FAIL"
    assert Status.WARN == "WARN"
    assert Status.SKIP == "SKIP"


def test_scan_result_warned_count():
    """ScanResult.warned should count WARN status checks."""
    from klustershield.scanner.engine import ScanResult, ControlCheck, Status

    result = ScanResult(namespace=None, profile="nist-800-218")
    result.checks = [
        ControlCheck(
            control_id="PS.2.1",
            control_family="PS",
            title="Root containers",
            description="No root containers",
            severity="high",
            status=Status.WARN,
            finding="some containers running as root",
            remediation="Set runAsNonRoot: true",
        ),
    ]
    assert result.warned == 1
    assert result.passed == 0
    assert result.failed == 0


def test_provision_result_success():
    """ProvisionResult.success should be True when no errors."""
    from klustershield.provisioner.namespace import ProvisionResult

    result = ProvisionResult(namespace="production", profile="nist-800-218", team="platform")
    assert result.success is True
    result.errors.append("something went wrong")
    assert result.success is False
