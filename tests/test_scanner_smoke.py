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
            with pytest.raises(ValueError, match="within current working directory"):
                scanner._resolve_output_path("/etc/passwd")


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
    """Compliance score should reflect pass/fail ratio correctly."""
    from klustershield.scanner.engine import ScanResult, CheckResult

    result = ScanResult(namespace=None, profile="nist-800-218")
    result.checks = [
        CheckResult(control_id="PO.1.1", status="PASS", severity="CRITICAL",
                    check_name="test", finding="ok", remediation=""),
        CheckResult(control_id="PS.1.1", status="PASS", severity="HIGH",
                    check_name="test", finding="ok", remediation=""),
        CheckResult(control_id="PW.4.1", status="FAIL", severity="MEDIUM",
                    check_name="test", finding="bad", remediation="fix it"),
        CheckResult(control_id="DS.1.1", status="SKIP", severity="HIGH",
                    check_name="test", finding="skipped", remediation=""),
    ]
    # 2 pass out of 3 scoreable (skip doesn't count) = 66.7%
    assert result.passed == 2
    assert result.failed == 1
    assert result.skipped == 1
    assert 66.0 < result.score < 67.0
