"""Comprehensive tests for StarVault Internal Neural Network Security Engine.

Tests:
1. Feature vector extraction across varied credential parameters.
2. Multilayer perceptron forward inference, activation functions, and class prediction.
3. Vault-wide neural security audits (safety index, grades, anomaly detection, risk ranking).
4. Individual entry evaluation and remediation recommendations.
5. VaultHealthAdvisor and AIAdvisor integration (hybrid/optional AI architecture).
6. MCP server neural tools (starvault_health_audit, starvault_neural_analyze_entry).
7. Chromium extension bridge endpoints (/api/neural_health, /api/neural_analyze_entry).
"""

import json
from datetime import datetime, timedelta, timezone
import urllib.request
import pytest

from starvault.ai_advisor import AIAdvisor, AI_PROVIDERS
from starvault.database import Database
from starvault.extension_bridge import ExtensionBridgeServer
from starvault.health import VaultHealthAdvisor
from starvault.mcp_server import StarVaultMCPServer
from starvault.models import VaultEntry
from starvault.neural_health import (
    VaultSecurityNeuralNet,
    audit_vault_neural,
    evaluate_entry_neural,
)


@pytest.fixture
def sample_entries():
    now = datetime.now(timezone.utc)
    ancient = (now - timedelta(days=400)).strftime("%Y-%m-%d")
    recent = (now - timedelta(days=10)).strftime("%Y-%m-%d")
    soon_exp = (now + timedelta(days=5)).strftime("%Y-%m-%d")

    # Entry 1: Strong server credential
    e1 = VaultEntry.create_server(
        title="Prod Bastion Server",
        hostname="bastion.internal.net",
        username="secops_admin",
        password="xK9#vP2$mL8@qW5!zR7*",
        category="Cloud & Infrastructure",
        tags=["prod", "critical", "bastion"],
    )
    e1.groups = ["Infrastructure", "Security"]
    e1.services = ["SSH Gateway"]
    e1.totp_secret = "JBSWY3DPEHPK3PXP"
    e1.created_at = recent
    e1.updated_at = recent

    # Entry 2: Weak, reused password
    e2 = VaultEntry.create_service(
        title="Legacy Dashboard",
        app_name="Legacy Dashboard",
        url="http://internal-dashboard.local",
        username="admin",
        password="password123",
        category="General",
        tags=[],
    )
    e2.created_at = ancient
    e2.updated_at = ancient

    # Entry 3: Duplicate of entry 2 password
    e3 = VaultEntry.create_service(
        title="Old Staging Portal",
        app_name="Staging",
        url="http://staging.local",
        username="testuser",
        password="password123",
        category="General",
    )

    # Entry 4: Expiring API key
    e4 = VaultEntry.create_api_key(
        title="Payment Gateway Key",
        provider="Stripe",
        api_token="sk_live_51M000000000000000000000000000000000000",
        category="Finance & Payments",
        tags=["payment", "stripe"],
    )
    e4.expires_at = soon_exp

    return [e1, e2, e3, e4]


def test_neural_feature_extraction(sample_entries):
    net = VaultSecurityNeuralNet()
    e1, e2, e3, e4 = sample_entries

    reuse_map = {"password123": 2}
    v1 = net.extract_features(e1, reuse_map=reuse_map)
    v2 = net.extract_features(e2, reuse_map=reuse_map)

    # Feature vector must be length 12
    assert len(v1) == 12
    assert len(v2) == 12

    # High entropy password vs weak password
    assert v1[0] > v2[0]  # length_norm
    assert v1[1] > v2[1]  # entropy_norm
    assert v1[2] > v2[2]  # char_variety
    assert v2[8] > 0.0    # reuse_count_norm (e2 is reused)
    assert v1[7] == 1.0   # mfa_protection (e1 has TOTP)
    assert v2[7] == 0.0   # e2 has no MFA


def test_neural_forward_inference(sample_entries):
    net = VaultSecurityNeuralNet()
    e1, e2, e3, e4 = sample_entries

    reuse_map = {"password123": 2}
    a1 = net.evaluate_entry(e1, reuse_map=reuse_map)
    a2 = net.evaluate_entry(e2, reuse_map=reuse_map)

    # Risk score bounds
    assert 0 <= a1.risk_score <= 100
    assert 0 <= a2.risk_score <= 100
    assert a1.safety_score == 100 - a1.risk_score

    # Anomaly score bounds
    assert 0 <= a1.anomaly_score <= 100
    assert 0 <= a2.anomaly_score <= 100

    # Strong credential must have lower risk than weak credential
    assert a1.risk_score < a2.risk_score
    assert a1.safety_score > a2.safety_score

    # Weak & reused credential predicted class
    assert a2.predicted_class in ("WEAK_ENTROPY", "REUSED_CREDENTIAL", "STALE_UNROTATED")

    # Softmax probabilities sum to ~ 1.0
    prob_sum = sum(a1.class_probabilities.values())
    assert abs(prob_sum - 1.0) < 0.01


def test_audit_vault_neural(sample_entries):
    audit = audit_vault_neural(sample_entries)

    assert audit.total_entries_evaluated == 4
    assert 0 <= audit.safety_index <= 100
    assert audit.letter_grade in ("A+", "A", "B", "C", "D", "F")
    assert audit.engine_name.startswith("StarVault Neural Engine")
    assert "100% Offline" in audit.engine_mode
    assert audit.execution_time_ms >= 0.05
    assert len(audit.entry_assessments) == 4
    assert len(audit.suggested_optimizations) > 0


def test_empty_vault_neural_audit():
    audit = audit_vault_neural([])
    assert audit.total_entries_evaluated == 0
    assert audit.safety_index == 100
    assert audit.letter_grade == "A+"
    assert audit.high_risk_entries_count == 0


def test_vault_health_advisor_neural_integration(sample_entries):
    advisor = VaultHealthAdvisor()
    report = advisor.analyze(sample_entries)

    assert report.neural_audit is not None
    assert report.neural_safety_index == report.neural_audit.safety_index
    assert report.neural_grade == report.neural_audit.letter_grade
    assert 0 <= report.overall_score <= 100


def test_ai_advisor_neural_provider_default(sample_entries):
    advisor = AIAdvisor()
    assert advisor.current_provider == "neural"
    assert "neural" in AI_PROVIDERS
    assert "Offline" in AI_PROVIDERS["neural"]["name"]

    # Analyze via local neural network (zero external network calls)
    report = advisor.analyze_neural(sample_entries)
    assert "Neural Network Audit" in report.summary
    assert any("Neural Safety Index" in f for f in report.findings)
    assert len(report.actions) > 0
    assert "StarVault Neural Engine" in report.raw_response

    # Test analyze_vault() triggers analyze_neural() when current_provider is neural
    generic_report = advisor.analyze_vault(sample_entries)
    assert "Neural Network Audit" in generic_report.summary


def test_mcp_server_neural_tools(tmp_path, sample_entries):
    db_path = tmp_path / "mcp_neural_test.db"
    db = Database(db_path)
    master_pass = "MCPSecurePass2026!"
    key = db.initialize_vault(master_pass)

    for e in sample_entries:
        db.save_entry(e, key)

    server = StarVaultMCPServer(db_path=db_path)
    server.session_key = key

    # 1. starvault_health_audit mode: neural
    neural_res = json.loads(server.execute_tool("starvault_health_audit", {"mode": "neural"}))
    assert "neural_safety_index" in neural_res
    assert "neural_grade" in neural_res
    assert neural_res["total_entries_evaluated"] == 4

    # 2. starvault_health_audit mode: full
    full_res = json.loads(server.execute_tool("starvault_health_audit", {"mode": "full"}))
    assert "neural_safety_index" in full_res
    assert "overall_score" in full_res
    assert "issues" in full_res

    # 3. starvault_neural_analyze_entry
    entry_eval = json.loads(server.execute_tool("starvault_neural_analyze_entry", {"identifier": "Prod Bastion Server"}))
    assert entry_eval["entry_title"] == "Prod Bastion Server"
    assert "risk_score" in entry_eval
    assert "safety_score" in entry_eval
    assert "predicted_class" in entry_eval
    assert "class_probabilities" in entry_eval


def test_extension_bridge_neural_endpoints(tmp_path, sample_entries):
    db_path = tmp_path / "bridge_neural_test.db"
    db = Database(db_path)
    master_pass = "BridgePass123!"
    key = db.initialize_vault(master_pass)

    for e in sample_entries:
        db.save_entry(e, key)

    port = 19088
    bridge = ExtensionBridgeServer(
        database=db,
        get_session_key=lambda: key,
        port=port,
    )
    bridge.start()

    try:
        # 1. POST /api/neural_health
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/neural_health",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert data["success"] is True
            assert "safety_index" in data
            assert "letter_grade" in data
            assert data["total_entries"] == 4

        # 2. GET /api/neural_health
        req_get = urllib.request.Request(f"http://127.0.0.1:{port}/api/neural_health")
        with urllib.request.urlopen(req_get) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert data["success"] is True
            assert data["total_entries"] == 4

        # 3. POST /api/neural_analyze_entry
        req_entry = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/neural_analyze_entry",
            data=json.dumps({"entry_id": sample_entries[0].id}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_entry) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert data["success"] is True
            assert data["entry_id"] == sample_entries[0].id
            assert "risk_score" in data
            assert "predicted_class" in data

    finally:
        bridge.stop()
