from paygate_ref.reference import (
    scenario_in_scope_purchase,
    scenario_out_of_scope_or_stale_request,
    scenario_revoked_request,
    scenario_replay_attempt,
    scenario_dispute_packet,
)


def test_in_scope_purchase_allows_without_live_pan_or_settlement():
    s = scenario_in_scope_purchase()
    assert s["verification_result"]["decision"] == "ALLOW"
    assert s["adapter_result"]["status"] == "AUTHORIZED_SANDBOX"
    assert s["adapter_result"]["live_pan_used"] is False
    assert s["adapter_result"]["live_network_settlement"] is False


def test_out_of_scope_fails_closed():
    s = scenario_out_of_scope_or_stale_request()
    assert s["verification_result"]["decision"] == "DENY"
    assert s["verification_result"]["denial_reason_code"] == "DRC-005_SCOPE_VIOLATION"
    assert s["adapter_result"]["status"] == "BLOCKED_FAIL_CLOSED"


def test_revoked_receipt_fails_closed():
    s = scenario_revoked_request()
    assert s["verification_result"]["decision"] == "DENY"
    assert s["verification_result"]["denial_reason_code"] == "DRC-007_REVOKED_CONFIRMED"


def test_replay_attempt_fails_closed():
    s = scenario_replay_attempt()
    assert s["first_verification_result"]["decision"] == "ALLOW"
    assert s["second_verification_result"]["decision"] == "DENY"
    assert s["second_verification_result"]["denial_reason_code"] == "DRC-006_ANTI_REPLAY_FAILURE"


def test_dispute_packet_is_selective_and_has_no_raw_pan():
    s = scenario_dispute_packet()
    packet = s["dispute_packet"]
    assert packet["packet_type"] == "AgenticCommerceDisputeRecoursePacket"
    assert packet["raw_pan_or_sad_present"] is False
    assert "merchant_view" in packet["selective_disclosure_views"]
