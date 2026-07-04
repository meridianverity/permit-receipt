from __future__ import annotations

import unittest

from paygate_poc.scenario import run_scenarios


class PayGatePoCTest(unittest.TestCase):
    def test_scenarios(self):
        result = run_scenarios()
        by_name = {s["scenario"]: s for s in result["scenarios"]}
        self.assertTrue(result["ledger_verified"])
        self.assertEqual(by_name["01_ALLOW_exact_cart_card_provider"]["outcome"], "ALLOW")
        self.assertEqual(by_name["02_ALLOW_provider_neutral_wallet_provider"]["outcome"], "ALLOW")
        self.assertEqual(by_name["03_DENY_amount_tamper"]["outcome"], "DENY")
        self.assertIn("ACTION_DIGEST_MISMATCH", by_name["03_DENY_amount_tamper"]["reason_codes"])
        self.assertIn("AMOUNT_MISMATCH", by_name["03_DENY_amount_tamper"]["reason_codes"])
        self.assertEqual(by_name["04_DENY_cart_tamper_same_total"]["outcome"], "DENY")
        self.assertIn("CART_DIGEST_MISMATCH", by_name["04_DENY_cart_tamper_same_total"]["reason_codes"])
        self.assertEqual(by_name["05B_DENY_replay_second_use"]["outcome"], "DENY")
        self.assertIn("REPLAY_RECEIPT_ID_USED", by_name["05B_DENY_replay_second_use"]["reason_codes"])
        self.assertEqual(by_name["06_DENY_expired_receipt"]["outcome"], "DENY")
        self.assertIn("PERMIT_EXPIRED", by_name["06_DENY_expired_receipt"]["reason_codes"])
        self.assertEqual(by_name["07_DENY_epoch_mismatch"]["outcome"], "DENY")
        self.assertIn("EPOCH_MISMATCH", by_name["07_DENY_epoch_mismatch"]["reason_codes"])
        self.assertEqual(by_name["08_DENY_missing_tsil_sensor_receipt"]["outcome"], "DENY")
        self.assertIn("TSIL_SENSOR_RECEIPT_OBJECT_REQUIRED", by_name["08_DENY_missing_tsil_sensor_receipt"]["reason_codes"])
        self.assertEqual(by_name["09_DENY_untrusted_provider_class"]["outcome"], "DENY")
        self.assertIn("PROVIDER_CLASS_NOT_ALLOWED_BY_RECEIPT", by_name["09_DENY_untrusted_provider_class"]["reason_codes"])
        self.assertEqual(by_name["10_DENY_direct_provider_bypass_without_decision_token"]["outcome"], "DENY")
        self.assertIn("PROVIDER_DECISION_TOKEN_REQUIRED", by_name["10_DENY_direct_provider_bypass_without_decision_token"]["reason_codes"])


if __name__ == "__main__":
    unittest.main()
