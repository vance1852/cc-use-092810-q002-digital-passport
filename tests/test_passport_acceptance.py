from __future__ import annotations

import unittest
from pathlib import Path

from product_passport.acceptance import run


ROOT = Path(__file__).resolve().parents[1]


class PassportAcceptanceTests(unittest.TestCase):
    def test_offline_acceptance(self) -> None:
        result = run(ROOT)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["issued_versions"], [2, 3, 4])
        self.assertEqual(result["historical_version"], 3)
        self.assertTrue(result["historical_digest_frozen"])
        self.assertEqual(
            result["provenance_evidence_kinds"], ["asset", "component", "quality", "transfer"]
        )
        self.assertEqual(result["invalidated_reference"], "invalidated")
        self.assertTrue(result["audit"]["valid"])
        self.assertEqual(result["schema"]["missing_tables"], [])
        self.assertEqual(result["schema"]["schema_version"], "1")
        # v1 候选被阻断后留痕为 abandoned；v2 被新版本取代但仍保持已签发历史；v3、v4 被吊销。
        self.assertEqual(
            result["version_states"],
            [(1, "abandoned"), (2, "issued"), (3, "revoked"), (4, "revoked")],
        )
        self.assertEqual(len(result["digest_clean"]), 64)


if __name__ == "__main__":
    unittest.main()
