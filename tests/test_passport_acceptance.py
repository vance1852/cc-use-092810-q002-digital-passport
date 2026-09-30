from __future__ import annotations

import unittest

from battery_passport.acceptance import run


class PassportAcceptanceTests(unittest.TestCase):
    def test_offline_acceptance(self) -> None:
        result = run(None)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["replayed_same_passport"])
        self.assertTrue(result["reuse_business_no_conflicted"])
        self.assertIn("evidence_missing", result["blocked_codes"])
        self.assertEqual(result["version_states"], [(1, "superseded"), (2, "revoked")])
        self.assertTrue(result["no_effective_after_revocation"])
        self.assertEqual(result["traced_sources"], 5)
        self.assertEqual(result["schema"]["missing_tables"], [])
        self.assertEqual(len(result["v1_content_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
