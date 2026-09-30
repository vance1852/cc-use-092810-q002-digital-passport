from __future__ import annotations

import json
import sqlite3
import unittest

from battery_passport.api import JsonApplication
from battery_passport.service import PassportService


def _post(app, path, payload, actor=None):
    headers = {} if actor is None else {"X-Actor-Id": actor}
    return app.handle("POST", path, headers, json.dumps(payload).encode("utf-8"))


def _get(app, path, actor):
    return app.handle("GET", path, {"X-Actor-Id": actor}, b"")


class PassportApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(PassportService(self.connection))
        for uid, role in (("op", "operator"), ("qa", "quality"),
                          ("ap", "approver"), ("au", "auditor")):
            _post(self.app, "/users", {"user_id": uid, "display_name": uid, "role": role})
        _post(self.app, "/assets", {
            "asset_id": "asset-1", "model_name": "BESS", "vendor": "厂",
            "status": "in_service", "attributes": {"kwh": 2000},
        }, "op")
        self.pack = _post(self.app, "/evidence", {
            "kind": "component", "record_id": "pack-1", "revision": 1, "asset_id": "asset-1",
            "payload": {"sn": "P1"},
        }, "qa").body
        self.insp = _post(self.app, "/evidence", {
            "kind": "inspection", "record_id": "insp-1", "revision": 1, "asset_id": "asset-1",
            "payload": {"result": "pass"},
        }, "qa").body
        self.own = _post(self.app, "/evidence", {
            "kind": "ownership", "record_id": "own-1", "revision": 1, "asset_id": "asset-1",
            "payload": {"transfer_kind": "registration", "holder": "运营方"},
        }, "op").body
        refs = [
            {"kind": "component", "record_id": "pack-1", "revision": 1,
             "sha256": self.pack["content_sha256"], "role": "battery_pack"},
            {"kind": "inspection", "record_id": "insp-1", "revision": 1,
             "sha256": self.insp["content_sha256"]},
            {"kind": "ownership", "record_id": "own-1", "revision": 1,
             "sha256": self.own["content_sha256"]},
        ]
        _post(self.app, "/candidates", {
            "candidate_id": "cand-1", "asset_id": "asset-1", "asset_revision": 1,
            "refs": refs, "requirements": {"repairs_resolved": False},
        }, "op")
        self.issued = _post(self.app, "/passports/issue", {
            "candidate_id": "cand-1", "idempotency_key": "key-1", "business_no": "DPP-1",
        }, "ap").body

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = _get(self.app, "/health", "au")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["service"], "battery-passport")

    def test_issue_and_get(self) -> None:
        self.assertEqual(self.issued["version"], 1)
        response = _get(self.app, f"/passports/{self.issued['passport_id']}", "au")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["business_no"], "DPP-1")

    def test_replay_is_idempotent(self) -> None:
        again = _post(self.app, "/passports/issue",
                      {"candidate_id": "cand-1", "idempotency_key": "key-9"}, "ap")
        self.assertEqual(again.status, 201)
        self.assertEqual(again.body["passport_id"], self.issued["passport_id"])
        self.assertTrue(again.body["replayed"])

    def test_blocked_issue_returns_409_with_blockers(self) -> None:
        _post(self.app, "/candidates", {
            "candidate_id": "cand-bad", "asset_id": "asset-1", "asset_revision": 1,
            "refs": [{"kind": "inspection", "record_id": "ghost", "revision": 1,
                      "sha256": "0" * 64}],
            "requirements": {"components": False, "ownership": False, "inspection": True},
        }, "op")
        response = _post(self.app, "/passports/issue",
                         {"candidate_id": "cand-bad", "idempotency_key": "key-bad",
                          "business_no": "DPP-BAD"}, "ap")
        self.assertEqual(response.status, 409)
        self.assertEqual(response.body["error"]["code"], "issuance_blocked")
        codes = {b["code"] for b in response.body["error"]["details"]["blockers"]}
        self.assertIn("evidence_missing", codes)

    def test_revoke_and_trace(self) -> None:
        revoked = _post(self.app, f"/passports/{self.issued['passport_id']}/revoke",
                        {"reason": "依据撤销"}, "ap")
        self.assertEqual(revoked.status, 200)
        self.assertEqual(revoked.body["state"], "revoked")
        trace = _get(self.app, f"/passports/{self.issued['passport_id']}/trace", "au")
        self.assertEqual(trace.body["state"], "revoked")
        self.assertEqual(len(trace.body["sources"]), 3)

    def test_versions_and_effective(self) -> None:
        versions = _get(self.app, "/business/DPP-1/versions", "au")
        self.assertEqual(versions.status, 200)
        self.assertEqual(len(versions.body["versions"]), 1)
        specific = _get(self.app, "/business/DPP-1/versions/1", "au")
        self.assertEqual(specific.status, 200)
        effective = _get(self.app, "/assets/asset-1/effective", "au")
        self.assertEqual(effective.status, 200)
        self.assertEqual(effective.body["passport_id"], self.issued["passport_id"])

    def test_reference_lifecycle(self) -> None:
        created = _post(self.app, "/references", {
            "reference_id": "ref-1", "passport_id": self.issued["passport_id"],
            "consumer": "保险方", "purpose": "续保",
        }, "op")
        self.assertEqual(created.status, 201)
        completed = _post(self.app, "/references/ref-1/complete", {}, "op")
        self.assertEqual(completed.body["state"], "completed")

    def test_requires_actor(self) -> None:
        response = _post(self.app, "/evidence", {"kind": "inspection"})
        self.assertEqual(response.status, 422)

    def test_forbidden_for_role(self) -> None:
        response = _post(self.app, "/passports/issue",
                         {"candidate_id": "cand-1", "idempotency_key": "k",
                          "business_no": "X"}, "op")
        self.assertEqual(response.status, 403)

    def test_route_not_found(self) -> None:
        response = _get(self.app, "/nope", "au")
        self.assertEqual(response.status, 404)

    def test_audit_endpoint(self) -> None:
        response = _get(self.app, "/audit?entity_type=passport", "au")
        self.assertEqual(response.status, 200)
        self.assertTrue(any(e["event_type"] == "passport.issued" for e in response.body["events"]))


if __name__ == "__main__":
    unittest.main()
