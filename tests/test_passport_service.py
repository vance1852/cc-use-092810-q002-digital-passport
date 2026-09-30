from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from battery_passport.clock import FrozenClock
from battery_passport.errors import (
    Conflict,
    Forbidden,
    InvalidState,
    IssuanceBlocked,
    NotFound,
    ValidationFailed,
)
from battery_passport.service import PassportService


def _ref(kind, record_id, digest, revision=1, role=None):
    item = {"kind": kind, "record_id": record_id, "revision": revision, "sha256": digest}
    if role is not None:
        item["role"] = role
    return item


class PassportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc))
        self.service = PassportService(self.connection, self.clock)
        for user_id, role in (
            ("op", "operator"),
            ("qa", "quality"),
            ("ap", "approver"),
            ("au", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.service.register_asset("op", "asset-1", "BESS", "厂商", "in_service", {"kwh": 2000})
        self.pack = self.service.record_evidence(
            "qa", "component", "pack-1", 1, "asset-1", {"part": "pack", "sn": "P1"}
        )
        self.insp = self.service.record_evidence(
            "qa", "inspection", "insp-1", 1, "asset-1", {"result": "pass"}
        )
        self.repair = self.service.record_evidence(
            "qa", "repair", "repair-1", 1, "asset-1", {"status": "closed"}
        )
        self.ownership = self.service.record_evidence(
            "op", "ownership", "own-1", 1, "asset-1",
            {"transfer_kind": "registration", "holder": "运营方"},
        )
        self.refs = [
            _ref("component", "pack-1", self.pack["content_sha256"], role="battery_pack"),
            _ref("inspection", "insp-1", self.insp["content_sha256"]),
            _ref("repair", "repair-1", self.repair["content_sha256"]),
            _ref("ownership", "own-1", self.ownership["content_sha256"]),
        ]

    def tearDown(self) -> None:
        self.connection.close()

    def _candidate(self, candidate_id="cand-1", refs=None, asset_revision=1, requirements=None):
        return self.service.create_candidate(
            "op", candidate_id, "asset-1", asset_revision, self.refs if refs is None else refs,
            requirements,
        )

    def _issue(self, candidate_id="cand-1", key="key-1", **kwargs):
        self._candidate(candidate_id)
        return self.service.issue_passport("ap", candidate_id, key, business_no="DPP-1", **kwargs)

    # ----- 签发与内容寻址 -----

    def test_issue_freezes_content(self) -> None:
        passport = self._issue()
        self.assertEqual(passport["version"], 1)
        self.assertEqual(passport["state"], "issued")
        self.assertEqual(len(passport["content_sha256"]), 64)
        self.assertEqual(len(passport["material_sha256"]), 64)
        kinds = {s["kind"] for s in passport["payload"]["statements"]}
        self.assertEqual(kinds, {"component", "inspection", "repair", "ownership"})

    def test_same_material_retry_returns_original(self) -> None:
        first = self._issue(key="key-1")
        second = self.service.issue_passport("ap", "cand-1", "key-1")
        third = self.service.issue_passport("ap", "cand-1", "different-key")
        self.assertTrue(second["replayed"] and third["replayed"])
        self.assertEqual({first["passport_id"], second["passport_id"], third["passport_id"]},
                         {first["passport_id"]})
        self.assertEqual(second["content_sha256"], first["content_sha256"])

    def test_different_content_same_business_number_conflicts(self) -> None:
        self._issue()
        self.service.record_evidence("qa", "repair", "repair-2", 1, "asset-1",
                                     {"status": "closed", "summary": "new"})
        digest = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE record_id='repair-2'"
        ).fetchone()[0]
        refs = self.refs + [_ref("repair", "repair-2", digest)]
        self._candidate("cand-2", refs)
        with self.assertRaises(Conflict):
            self.service.issue_passport("ap", "cand-2", "key-2", business_no="DPP-1")

    def test_new_version_supersedes_and_keeps_history(self) -> None:
        v1 = self._issue()
        # 新检测产生证据新版本。
        self.service.record_evidence("qa", "inspection", "insp-1", 2, "asset-1",
                                     {"result": "pass", "cycle": 410}, supersedes=1)
        digest2 = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE kind='inspection' "
            "AND record_id='insp-1' AND revision=2"
        ).fetchone()[0]
        refs = [dict(item) for item in self.refs]
        refs[1] = _ref("inspection", "insp-1", digest2, revision=2)
        self._candidate("cand-2", refs)
        v2 = self.service.issue_passport("ap", "cand-2", "key-2",
                                         replaces_passport_id=v1["passport_id"])
        self.assertEqual(v2["version"], 2)
        self.assertEqual(v2["business_no"], "DPP-1")
        self.assertEqual(v2["replaces_passport_id"], v1["passport_id"])
        self.assertNotEqual(v2["content_sha256"], v1["content_sha256"])
        # 历史版本冻结为 superseded，内容仍是旧检测。
        old = self.service.get_version("au", "DPP-1", 1)
        self.assertEqual(old["state"], "superseded")
        self.assertEqual(old["payload"]["statements"][1]["revision"], 1)

    def test_cannot_supersede_non_head_or_revoked(self) -> None:
        v1 = self._issue()
        self.service.revoke_passport("ap", v1["passport_id"], "撤销")
        # 需要不同材料，否则相同材料会直接回放已存在的护照而不是走取代分支。
        self.service.record_evidence("qa", "repair", "repair-2", 1, "asset-1",
                                     {"status": "closed", "summary": "新增维修"})
        digest = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE record_id='repair-2'"
        ).fetchone()[0]
        self._candidate("cand-2", self.refs + [_ref("repair", "repair-2", digest)])
        with self.assertRaises(InvalidState):
            self.service.issue_passport("ap", "cand-2", "key-2",
                                        replaces_passport_id=v1["passport_id"])

    # ----- 阻断门禁 -----

    def test_missing_evidence_blocks(self) -> None:
        refs = [
            _ref("component", "pack-1", self.pack["content_sha256"], role="battery_pack"),
            _ref("inspection", "ghost", "0" * 64),
            _ref("ownership", "own-1", self.ownership["content_sha256"]),
        ]
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        codes = {b["code"] for b in caught.exception.blockers}
        self.assertIn("evidence_missing", codes)

    def test_revoked_evidence_blocks(self) -> None:
        self.service.revoke_evidence("qa", "inspection", "insp-1", 1, "记录造假")
        self._candidate()
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-1", "key-1", business_no="DPP-1")
        codes = {b["code"] for b in caught.exception.blockers}
        self.assertIn("evidence_revoked", codes)

    def test_digest_mismatch_blocks_not_overwritten(self) -> None:
        refs = [dict(item) for item in self.refs]
        refs[1]["sha256"] = "f" * 64  # 与登记内容不一致
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        self.assertTrue(any(b["code"] == "evidence_digest_conflict" for b in caught.exception.blockers))

    def test_inspection_fail_blocks(self) -> None:
        self.service.record_evidence("qa", "inspection", "insp-fail", 1, "asset-1",
                                     {"result": "fail"})
        digest = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE record_id='insp-fail'"
        ).fetchone()[0]
        refs = [r for r in self.refs if r["kind"] != "inspection"]
        refs.append(_ref("inspection", "insp-fail", digest))
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        self.assertIn("inspection_failed", {b["code"] for b in caught.exception.blockers})

    def test_open_repair_blocks(self) -> None:
        self.service.record_evidence("qa", "repair", "repair-open", 1, "asset-1",
                                     {"status": "open"})
        digest = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE record_id='repair-open'"
        ).fetchone()[0]
        refs = self.refs + [_ref("repair", "repair-open", digest)]
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        self.assertIn("repair_open", {b["code"] for b in caught.exception.blockers})

    def test_component_role_conflict_blocks(self) -> None:
        other = self.service.record_evidence("qa", "component", "pack-2", 1, "asset-1",
                                             {"part": "pack", "sn": "P2"})
        refs = [
            _ref("component", "pack-1", self.pack["content_sha256"], role="battery_pack"),
            _ref("component", "pack-2", other["content_sha256"], role="battery_pack"),
            _ref("inspection", "insp-1", self.insp["content_sha256"]),
            _ref("ownership", "own-1", self.ownership["content_sha256"]),
        ]
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        self.assertIn("component_role_conflict",
                      {b["code"] for b in caught.exception.blockers})

    def test_competing_registrations_conflict(self) -> None:
        other = self.service.record_evidence("op", "ownership", "own-2", 1, "asset-1",
                                             {"transfer_kind": "registration", "holder": "运营方B"})
        refs = [
            _ref("component", "pack-1", self.pack["content_sha256"], role="battery_pack"),
            _ref("inspection", "insp-1", self.insp["content_sha256"]),
            _ref("ownership", "own-1", self.ownership["content_sha256"]),
            _ref("ownership", "own-2", other["content_sha256"]),
        ]
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        self.assertIn("ownership_registration_conflict",
                      {b["code"] for b in caught.exception.blockers})

    def test_blocked_issue_creates_no_passport(self) -> None:
        self.service.revoke_evidence("qa", "inspection", "insp-1", 1, "x")
        self._candidate()
        with self.assertRaises(IssuanceBlocked):
            self.service.issue_passport("ap", "cand-1", "key-1", business_no="DPP-1")
        count = self.connection.execute("SELECT count(*) FROM passports").fetchone()[0]
        self.assertEqual(count, 0)

    def test_same_record_two_revisions_conflict(self) -> None:
        self.service.record_evidence("qa", "inspection", "insp-1", 2, "asset-1",
                                     {"result": "pass", "cycle": 5}, supersedes=1)
        digest2 = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE kind='inspection' "
            "AND record_id='insp-1' AND revision=2"
        ).fetchone()[0]
        refs = self.refs + [_ref("inspection", "insp-1", digest2, revision=2)]
        self._candidate("cand-x", refs)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-x", "key-x", business_no="DPP-X")
        self.assertIn("inspection_revision_conflict",
                      {b["code"] for b in caught.exception.blockers})

    def test_idempotency_key_material_mismatch_conflicts(self) -> None:
        self._issue(key="shared-key")
        self.service.record_evidence("qa", "repair", "repair-2", 1, "asset-1",
                                     {"status": "closed", "summary": "不同维修内容"})
        digest = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE record_id='repair-2'"
        ).fetchone()[0]
        self._candidate("cand-2", self.refs + [_ref("repair", "repair-2", digest)])
        with self.assertRaises(Conflict):
            self.service.issue_passport("ap", "cand-2", "shared-key", business_no="DPP-2")

    def test_retired_asset_blocks(self) -> None:
        self.service.revise_asset("op", "asset-1", "BESS", "厂商", "retired", {"kwh": 2000})
        self._candidate(asset_revision=2)
        with self.assertRaises(IssuanceBlocked) as caught:
            self.service.issue_passport("ap", "cand-1", "key-1", business_no="DPP-1")
        self.assertIn("asset_retired", {b["code"] for b in caught.exception.blockers})

    # ----- 吊销与下游引用 -----

    def test_revoke_keeps_reason_and_invalidates_pending_refs(self) -> None:
        v1 = self._issue()
        self.service.create_reference("op", "ref-1", v1["passport_id"], "保险方", "续保")
        done = self.service.create_reference("op", "ref-2", v1["passport_id"], "保险方", "归档")
        self.service.complete_reference("op", "ref-2")
        result = self.service.revoke_passport("ap", v1["passport_id"], "依据撤销")
        self.assertEqual(result["invalidated_references"], ["ref-1"])
        revoked = self.service.get_passport("au", v1["passport_id"])
        self.assertEqual(revoked["state"], "revoked")
        self.assertEqual(revoked["revoke_reason"], "依据撤销")
        # 未完成引用失效且不可完成；已完成引用保留完成态。
        with self.assertRaises(InvalidState):
            self.service.complete_reference("op", "ref-1")
        completed = self.connection.execute(
            "SELECT state FROM passport_references WHERE reference_id='ref-2'"
        ).fetchone()[0]
        self.assertEqual(completed, "completed")

    def test_cannot_create_reference_on_non_issued(self) -> None:
        v1 = self._issue()
        self.service.revoke_passport("ap", v1["passport_id"], "x")
        with self.assertRaises(InvalidState):
            self.service.create_reference("op", "ref-1", v1["passport_id"], "保险方", "续保")

    # ----- 查询与追溯 -----

    def test_effective_passport_as_of(self) -> None:
        v1 = self._issue()
        at_v1 = v1["issued_at"]
        self.service.record_evidence("qa", "inspection", "insp-1", 2, "asset-1",
                                     {"result": "pass", "cycle": 9}, supersedes=1)
        digest2 = self.connection.execute(
            "SELECT content_sha256 FROM evidence_records WHERE kind='inspection' "
            "AND record_id='insp-1' AND revision=2"
        ).fetchone()[0]
        refs = [dict(item) for item in self.refs]
        refs[1] = _ref("inspection", "insp-1", digest2, revision=2)
        self.clock.advance(hours=1)
        self._candidate("cand-2", refs)
        v2 = self.service.issue_passport("ap", "cand-2", "key-2",
                                         replaces_passport_id=v1["passport_id"])
        self.assertEqual(
            self.service.effective_passport("au", "asset-1", at=at_v1)["passport_id"],
            v1["passport_id"],
        )
        self.assertEqual(
            self.service.effective_passport("au", "asset-1")["passport_id"],
            v2["passport_id"],
        )

    def test_trace_reports_sources_signers_and_lineage(self) -> None:
        v1 = self._issue()
        trace = self.service.trace("au", v1["passport_id"])
        self.assertEqual(len(trace["sources"]), 4)
        source = next(s for s in trace["sources"] if s["statement"]["kind"] == "inspection")
        self.assertEqual(source["signed_by"], "qa")
        self.assertEqual(source["source_digest"], self.insp["content_sha256"])
        self.assertEqual([v["version"] for v in trace["lineage"]], [1])

    def test_versions_listing(self) -> None:
        v1 = self._issue()
        listing = self.service.list_versions("au", "DPP-1")
        self.assertEqual([v["state"] for v in listing["versions"]], ["issued"])
        self.assertEqual(listing["versions"][0]["passport_id"], v1["passport_id"])

    # ----- 权限与契约 -----

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.issue_passport("op", "c", "k", business_no="B")
        with self.assertRaises(Forbidden):
            self.service.revoke_passport("qa", 1, "x")
        with self.assertRaises(Forbidden):
            self.service.revoke_evidence("op", "inspection", "insp-1", 1, "x")
        with self.assertRaises(Forbidden):
            self.service.audit_log("op")

    def test_invalid_evidence_payload_rejected(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.record_evidence("qa", "inspection", "bad", 1, "asset-1",
                                          {"result": "unknown"})
        with self.assertRaises(ValidationFailed):
            self.service.record_evidence("qa", "repair", "bad", 1, "asset-1",
                                          {"status": "maybe"})

    def test_component_requires_role(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.create_candidate(
                "op", "cand-bad", "asset-1", 1,
                [_ref("component", "pack-1", self.pack["content_sha256"])],
            )

    def test_evidence_no_gap_and_immutable(self) -> None:
        with self.assertRaises(InvalidState):
            self.service.record_evidence("qa", "inspection", "insp-9", 2, "asset-1",
                                         {"result": "pass"})
        # 已登记的同版本不能重复写入。
        with self.assertRaises(Conflict):
            self.service.record_evidence("qa", "inspection", "insp-1", 1, "asset-1",
                                         {"result": "pass"})

    def test_asset_revision_content_addressing(self) -> None:
        # 内容完全一致不允许登记新版本。
        with self.assertRaises(Conflict):
            self.service.revise_asset("op", "asset-1", "BESS", "厂商", "in_service", {"kwh": 2000})
        revised = self.service.revise_asset("op", "asset-1", "BESS", "厂商", "maintenance",
                                            {"kwh": 1990})
        self.assertEqual(revised["revision"], 2)
        self.assertNotEqual(revised["content_sha256"], self._asset1_digest())

    def _asset1_digest(self) -> str:
        return self.connection.execute(
            "SELECT content_sha256 FROM asset_revisions WHERE asset_id='asset-1' AND revision=1"
        ).fetchone()[0]


if __name__ == "__main__":
    unittest.main()
