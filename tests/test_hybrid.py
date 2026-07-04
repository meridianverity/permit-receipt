from paygate_hybrid.hybrid_demo import run_hybrid_scenarios


def test_hybrid_scenarios():
    result = run_hybrid_scenarios()
    assert result["hybrid_ok"] is True
    lookup = {s["scenario"]: s for s in result["hybrid_scenarios"]}
    assert lookup["H01_ALLOW_joint_orprg_paygate_provider"]["final_outcome"] == "ALLOW"
    assert lookup["H01_ALLOW_joint_orprg_paygate_provider"]["tetpay_audit"]["status"] == "PASS"
    assert lookup["H02_DENY_orprg_scope_before_paygate"]["final_outcome"] == "DENY"
    assert lookup["H02_DENY_orprg_scope_before_paygate"]["orprg_result"]["denial_reason_code"] == "DRC-005_SCOPE_VIOLATION"
    assert lookup["H03_DENY_paygate_tsil_missing_after_orprg_allow"]["paygate_outcome"] == "DENY"
    assert "TSIL_SENSOR_RECEIPT_OBJECT_REQUIRED" in lookup["H03_DENY_paygate_tsil_missing_after_orprg_allow"]["paygate_reason_codes"]
    assert lookup["H04_DENY_direct_provider_bypass_without_gate_token"]["provider_result"]["provider_status"] == "DENIED"
    assert lookup["H05_DETECT_tetpay_evidence_tamper"]["tetpay_audit"]["status"] == "FAIL"
