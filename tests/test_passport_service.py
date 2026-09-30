from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from product_passport.clock import FrozenClock
from product_passport.errors import (
    Conflict,
    EvidenceGateBlocked,
    Forbidden,
    InvalidState,
    NotFound,
)
from product_passport.jsonio import digest_value
from product_passport.service import PassportService


ASSET = "bess-1"
PASSPORT = "DPP-1"


def ref(category: str, ref_name: str, version: str) -> dict:
    return {"category": category, "ref": ref_name, "version": version}


class PassportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc))
        self.service = PassportService(self.connection, self.clock)
        for user_id, role in (
            ("reg", "registrar"),
            ("op", "operator"),
            ("iss", "issuer"),
            ("aud", "auditor"),
            ("ins", "consumer"),
        ):
            self.service.create_user(user_id, user_id, role)
        self._seed_evidence()

    def tearDown(self) -> None:
        self.connection.close()

    def _seed_evidence(self) -> None:
        s = self.service
        s.register_evidence("reg", "asset", "asset-card", "1", ASSET, "资产档案", {"model": "LFP-20MWh"})
        s.register_evidence("reg", "component", "cell-lot", "1", ASSET, "电芯批次", {"cells": 1024})
        s.register_evidence("reg", "quality", "qa", "1", ASSET, "检测决定", {"result": "pass"}, state="approved")
        s.register_evidence("reg", "transfer", "ownership", "1", ASSET, "所有权", {"owner": "运营方"}, state="closed")

    def _good_refs(self) -> list[dict]:
        return [
            ref("asset", "asset-card", "1"),
            ref("component", "cell-lot", "1"),
            ref("quality", "qa", "1"),
            ref("transfer", "ownership", "1"),
        ]

    def _assemble_and_issue(self, key: str = "k1", refs: list[dict] | None = None) -> dict:
        candidate = self.service.assemble_candidate("op", PASSPORT, ASSET, refs or self._good_refs(), key)
        return self.service.issue("iss", PASSPORT, candidate["version_no"], key + "-issue")

    # ---------------------------------------------------------------- 权限

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.assemble_candidate("reg", PASSPORT, ASSET, self._good_refs(), "x")
        with self.assertRaises(Forbidden):
            self.service.issue("op", PASSPORT, 1, "x")
        with self.assertRaises(Forbidden):
            self.service.audit_chain("ins")

    # ---------------------------------------------------------------- 门禁

    def test_missing_evidence_blocks_issuance(self) -> None:
        incomplete = [item for item in self._good_refs() if item["category"] != "transfer"]
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, incomplete, "bad")
        codes = {(b["code"], b["category"]) for b in caught.exception.blockers}
        self.assertIn(("missing", "transfer"), codes)
        # 候选被持久化，但不能签发。
        version = self.service.get_version("aud", PASSPORT, 1)
        self.assertEqual(version["state"], "candidate")
        with self.assertRaises(InvalidState):
            self.service.issue("iss", PASSPORT, 1, "issue-bad")

    def test_revoked_evidence_blocks_assembly(self) -> None:
        self.service.revoke_evidence("reg", "component", "cell-lot", "1", "谱系登记有误")
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "bad")
        blocker = next(b for b in caught.exception.blockers if b["category"] == "component")
        self.assertEqual(blocker["code"], "revoked")
        self.assertIn("谱系登记有误", blocker["message"])

    def test_revoked_between_assembly_and_issue_blocks_issue(self) -> None:
        candidate = self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "c")
        self.service.revoke_evidence("reg", "quality", "qa", "1", "仪器校准过期")
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.issue("iss", PASSPORT, candidate["version_no"], "i")
        self.assertEqual(caught.exception.blockers[0]["code"], "revoked")

    def test_disputed_evidence_blocks(self) -> None:
        self.service.register_evidence(
            "reg", "transfer", "ownership-dispute", "1", ASSET, "争议所有权",
            {"owner": "?"}, state="disputed",
        )
        refs = [
            ref("asset", "asset-card", "1"),
            ref("component", "cell-lot", "1"),
            ref("quality", "qa", "1"),
            ref("transfer", "ownership-dispute", "1"),
        ]
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "d")
        self.assertTrue(any(b["code"] == "conflicted" for b in caught.exception.blockers))

    def test_pending_quality_decision_blocks(self) -> None:
        self.service.register_evidence(
            "reg", "quality", "qa-pending", "1", ASSET, "未定检测", {"result": "pending"}, state="pending"
        )
        refs = [
            ref("asset", "asset-card", "1"),
            ref("component", "cell-lot", "1"),
            ref("quality", "qa-pending", "1"),
            ref("transfer", "ownership", "1"),
        ]
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "p")
        self.assertTrue(any(b["code"] == "not_decided" for b in caught.exception.blockers))

    def test_asset_mismatch_blocks(self) -> None:
        self.service.register_evidence("reg", "component", "foreign-lot", "1", "bess-OTHER", "外来电芯", {})
        refs = [
            ref("asset", "asset-card", "1"),
            ref("component", "foreign-lot", "1"),
            ref("quality", "qa", "1"),
            ref("transfer", "ownership", "1"),
        ]
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "m")
        self.assertTrue(any(b["code"] == "asset_mismatch" for b in caught.exception.blockers))

    def test_declared_digest_mismatch_blocks(self) -> None:
        refs = [
            ref("asset", "asset-card", "1"),
            {"category": "component", "ref": "cell-lot", "version": "1", "content_sha256": "a" * 64},
            ref("quality", "qa", "1"),
            ref("transfer", "ownership", "1"),
        ]
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "h")
        self.assertTrue(any(b["code"] == "conflicted" for b in caught.exception.blockers))

    def test_duplicate_ref_in_one_candidate_blocks(self) -> None:
        refs = self._good_refs() + [ref("component", "cell-lot", "1")]
        with self.assertRaises(EvidenceGateBlocked) as caught:
            self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "dup")
        self.assertTrue(any(b["code"] == "duplicate_ref" for b in caught.exception.blockers))

    # ---------------------------------------------------------------- 幂等与冲突

    def test_same_material_retry_returns_same_version(self) -> None:
        first = self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "same")
        second = self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "same")
        self.assertEqual(first["version_no"], second["version_no"])
        self.assertEqual(first["content_sha256"], second["content_sha256"])
        issued = self.service.issue("iss", PASSPORT, 1, "issue-same")
        replayed_issue = self.service.issue("iss", PASSPORT, 1, "issue-same")
        self.assertEqual(issued["content_sha256"], replayed_issue["content_sha256"])

    def test_different_material_same_idempotency_key_conflicts(self) -> None:
        self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "shared")
        changed = [dict(item) for item in self._good_refs()]
        changed[1] = {**changed[1], "version": "9"}  # 不存在的版本 → 材料不同
        with self.assertRaises(Conflict):
            self.service.assemble_candidate("op", PASSPORT, ASSET, changed, "shared")

    def test_clean_open_candidate_blocks_new_assembly(self) -> None:
        self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "v1")
        # 登记维修新证据，组装不同材料且使用新幂等键：干净候选未处理 → 冲突。
        self.service.register_evidence(
            "reg", "transfer", "maint", "1", ASSET, "维修", {"wo": "1"}, state="closed"
        )
        refs2 = self._good_refs() + [ref("transfer", "maint", "1")]
        with self.assertRaises(Conflict):
            self.service.assemble_candidate("op", PASSPORT, ASSET, refs2, "v2")

    def test_blocked_candidate_is_abandoned_when_fixed_material_assembled(self) -> None:
        incomplete = [item for item in self._good_refs() if item["category"] != "transfer"]
        with self.assertRaises(EvidenceGateBlocked):
            self.service.assemble_candidate("op", PASSPORT, ASSET, incomplete, "bad")
        good = self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "good")
        self.assertEqual(good["version_no"], 2)
        self.assertEqual(good["previous_version"], 1)
        states = {v["version_no"]: v["state"] for v in
                  self.service.list_versions("aud", PASSPORT)["versions"]}
        self.assertEqual(states[1], "abandoned")

    # ---------------------------------------------------------------- 冻结与版本

    def test_history_frozen_after_issuance(self) -> None:
        first = self._assemble_and_issue("v1")
        self.assertEqual(first["state"], "issued")
        # 已签发版本不能再次签发。
        with self.assertRaises(InvalidState):
            self.service.issue("iss", PASSPORT, 1, "again")
        # 撤销来源证据不改变已签发版本的冻结内容。
        self.service.revoke_evidence("reg", "transfer", "ownership", "1", "事后撤销")
        stored = self.service.get_version("aud", PASSPORT, 1)
        self.assertEqual(stored["content_sha256"], first["content_sha256"])
        self.assertEqual(stored["state"], "issued")

    def test_new_maintenance_creates_new_version_chain(self) -> None:
        self._assemble_and_issue("v1")
        self.clock.advance(days=10)
        self.service.register_evidence(
            "reg", "transfer", "maint", "1", ASSET, "维修记录", {"wo": "9"}, state="closed"
        )
        refs = self._good_refs() + [ref("transfer", "maint", "1")]
        candidate = self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "v2")
        self.assertEqual(candidate["version_no"], 2)
        self.assertEqual(candidate["previous_version"], 1)
        self.assertEqual(candidate["replaces_version"], 1)
        issued = self.service.issue("iss", PASSPORT, 2, "issue-v2")
        versions = self.service.list_versions("aud", PASSPORT)["versions"]
        self.assertEqual([v["version_no"] for v in versions], [1, 2])
        self.assertEqual(versions[1]["state"], "issued")

    def test_passport_number_bound_to_single_asset(self) -> None:
        self._assemble_and_issue("v1")
        with self.assertRaises(Conflict):
            self.service.assemble_candidate("op", PASSPORT, "bess-OTHER", self._good_refs(), "x")

    # ---------------------------------------------------------------- 吊销与引用

    def test_revoke_keeps_reason_and_invalidates_pending_references(self) -> None:
        issued = self._assemble_and_issue("v1")
        pending = self.service.register_reference("ins", PASSPORT, 1, "保险", "underwrite-1")
        done = self.service.register_reference("ins", PASSPORT, 1, "理赔", "claim-1")
        self.service.complete_reference("ins", done["reference_id"])
        result = self.service.revoke("iss", PASSPORT, 1, "厂商召回")
        self.assertEqual(result["invalidated_references"], 1)
        version = self.service.get_version("aud", PASSPORT, 1)
        self.assertEqual(version["state"], "revoked")
        self.assertEqual(version["revoke_reason"], "厂商召回")
        refs = {r["reference_id"]: r["state"] for r in
                self.service.list_references("aud", PASSPORT)["references"]}
        self.assertEqual(refs[pending["reference_id"]], "invalidated")
        self.assertEqual(refs[done["reference_id"]], "completed")
        # 已吊销版本不能重复吊销。
        with self.assertRaises(InvalidState):
            self.service.revoke("iss", PASSPORT, 1, "再次吊销")

    def test_reference_requires_issued_version(self) -> None:
        candidate = self.service.assemble_candidate("op", PASSPORT, ASSET, self._good_refs(), "c")
        with self.assertRaises(InvalidState):
            self.service.register_reference("ins", PASSPORT, candidate["version_no"], "保险", "x")

    # ---------------------------------------------------------------- 时点与溯源

    def test_effective_at_point_in_time(self) -> None:
        issued1 = self._assemble_and_issue("v1")
        t1 = issued1["issued_at"]
        self.clock.advance(days=20)
        self.service.register_evidence(
            "reg", "transfer", "maint", "1", ASSET, "维修", {"wo": "1"}, state="closed"
        )
        refs = self._good_refs() + [ref("transfer", "maint", "1")]
        c2 = self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "v2")
        issued2 = self.service.issue("iss", PASSPORT, c2["version_no"], "issue-v2")
        # 历史时点取回 v1，当前取回 v2。
        self.assertEqual(self.service.effective_at("aud", PASSPORT, t1)["version_no"], 1)
        self.assertEqual(self.service.effective_at("aud", PASSPORT, issued2["issued_at"])["version_no"], 2)
        self.assertEqual(self.service.effective_at("aud", PASSPORT)["version_no"], 2)
        with self.assertRaises(NotFound):
            self.service.effective_at("aud", PASSPORT, "2020-01-01T00:00:00Z")
        # 吊销 v1 后，历史时点（吊销前）仍可复算；吊销之后则无 v1。
        self.clock.advance(days=2)
        self.service.revoke("iss", PASSPORT, 1, "历史版本召回")
        self.assertEqual(self.service.effective_at("aud", PASSPORT, t1)["version_no"], 1)

    def test_provenance_traces_claims_signatures_and_lineage(self) -> None:
        self._assemble_and_issue("v1")
        self.clock.advance(days=5)
        self.service.register_evidence(
            "reg", "transfer", "maint", "1", ASSET, "维修", {"wo": "7"}, state="closed"
        )
        refs = self._good_refs() + [ref("transfer", "maint", "1")]
        c2 = self.service.assemble_candidate("op", PASSPORT, ASSET, refs, "v2")
        self.service.issue("iss", PASSPORT, 2, "issue-v2")
        provenance = self.service.provenance("aud", PASSPORT, 2)
        self.assertEqual({e["category"] for e in provenance["evidence"]},
                         {"asset", "component", "quality", "transfer"})
        # 每份证据都带冻结内容与来源时间。
        for item in provenance["evidence"]:
            self.assertEqual(len(item["content_sha256"]), 64)
            self.assertTrue(item["payload"] is not None)
        signers = {(s["action"], s["signer_id"]) for s in provenance["signatures"]}
        self.assertIn(("assembled", "op"), signers)
        self.assertIn(("issued", "iss"), signers)
        self.assertEqual(provenance["lineage"][0]["version_no"], 1)
        self.assertEqual(provenance["successors"], [])
        # v1 的溯源里能看到后继版本 v2。
        lineage1 = self.service.provenance("aud", PASSPORT, 1)
        self.assertEqual(lineage1["successors"][0]["version_no"], 2)

    def test_audit_chain_is_valid(self) -> None:
        self._assemble_and_issue("v1")
        audit = self.service.audit_chain("aud")
        self.assertTrue(audit["valid"])
        self.assertGreater(audit["events"], 0)

    def test_content_digest_is_deterministic(self) -> None:
        a = {"z": 1, "a": [1, 2, {"k": "v"}]}
        b = {"a": [1, 2, {"k": "v"}], "z": 1}
        self.assertEqual(digest_value(a), digest_value(b))


if __name__ == "__main__":
    unittest.main()
