from __future__ import annotations

import json
import sqlite3
import unittest

from product_passport.api import JsonApplication
from product_passport.service import PassportService


def _post(body: dict) -> bytes:
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


class PassportApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(PassportService(self.connection))
        for user_id, role in (
            ("reg", "registrar"), ("op", "operator"), ("iss", "issuer"),
            ("aud", "auditor"), ("ins", "consumer"),
        ):
            self.app.handle("POST", "/users", body=_post(
                {"user_id": user_id, "display_name": user_id, "role": role}))

    def tearDown(self) -> None:
        self.connection.close()

    def _headers(self, actor: str) -> dict:
        return {"X-Actor-Id": actor}

    def _register_evidence(self) -> None:
        base = {
            "asset_id": "bess-1",
        }
        items = [
            ("asset", "asset-card", "1", "资产档案", {"model": "LFP"}, "active"),
            ("component", "cell-lot", "1", "电芯批次", {"cells": 1024}, "active"),
            ("quality", "qa", "1", "检测决定", {"result": "pass"}, "approved"),
            ("transfer", "ownership", "1", "所有权", {"owner": "运营方"}, "closed"),
        ]
        for category, ref_id, version, title, payload, state in items:
            response = self.app.handle(
                "POST", "/evidence", headers=self._headers("reg"),
                body=_post({**base, "category": category, "ref": ref_id, "version": version,
                            "title": title, "payload": payload, "state": state}),
            )
            self.assertEqual(response.status, 201, response.body)

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)

    def test_full_http_flow_and_gate_error_shape(self) -> None:
        # 缺少 actor 头。
        response = self.app.handle(
            "POST", "/evidence", body=_post({"category": "asset", "ref": "x", "version": "1",
                                             "asset_id": "b", "title": "t", "payload": {}}))
        self.assertEqual(response.status, 422)

        self._register_evidence()

        good = [
            {"category": "asset", "ref": "asset-card", "version": "1"},
            {"category": "component", "ref": "cell-lot", "version": "1"},
            {"category": "quality", "ref": "qa", "version": "1"},
            {"category": "transfer", "ref": "ownership", "version": "1"},
        ]

        # 门禁阻断返回结构化 blockers。
        blocked = self.app.handle(
            "POST", "/passports/assemble", headers=self._headers("op"),
            body=_post({"passport_no": "DPP-1", "asset_id": "bess-1",
                        "evidence": good[:3], "idempotency_key": "bad"}),
        )
        self.assertEqual(blocked.status, 409)
        self.assertEqual(blocked.body["error"]["code"], "evidence_gate_blocked")
        self.assertTrue(any(b["code"] == "missing" for b in blocked.body["error"]["blockers"]))

        # 完整材料组装。
        assembled = self.app.handle(
            "POST", "/passports/assemble", headers=self._headers("op"),
            body=_post({"passport_no": "DPP-1", "asset_id": "bess-1",
                        "evidence": good, "idempotency_key": "ok"}),
        )
        self.assertEqual(assembled.status, 201)
        version_no = assembled.body["version_no"]

        # 非签发角色不能签发。
        forbidden = self.app.handle(
            "POST", f"/passports/DPP-1/versions/{version_no}/issue", headers=self._headers("op"),
            body=_post({"idempotency_key": "i"}),
        )
        self.assertEqual(forbidden.status, 403)

        issued = self.app.handle(
            "POST", f"/passports/DPP-1/versions/{version_no}/issue", headers=self._headers("iss"),
            body=_post({"idempotency_key": "i"}),
        )
        self.assertEqual(issued.status, 200)
        self.assertEqual(issued.body["state"], "issued")

        # 时点查询与版本列表。
        effective = self.app.handle(
            "GET", "/passports/DPP-1/effective", headers=self._headers("ins"))
        self.assertEqual(effective.status, 200)
        self.assertEqual(effective.body["version_no"], version_no)

        provenance = self.app.handle(
            "GET", f"/passports/DPP-1/versions/{version_no}/provenance",
            headers=self._headers("aud"),
        )
        self.assertEqual(provenance.status, 200)
        self.assertEqual(len(provenance.body["evidence"]), 4)

        # 下游引用与吊销。
        reference = self.app.handle(
            "POST", "/references", headers=self._headers("ins"),
            body=_post({"passport_no": "DPP-1", "version_no": version_no,
                        "consumer": "保险风控", "ref_key": "uw-1"}),
        )
        self.assertEqual(reference.status, 201)
        revoked = self.app.handle(
            "POST", "/passports/DPP-1/revoke", headers=self._headers("iss"),
            body=_post({"version_no": version_no, "reason": "厂商召回"}),
        )
        self.assertEqual(revoked.status, 200)
        self.assertEqual(revoked.body["invalidated_references"], 1)

        listing = self.app.handle(
            "GET", "/passports/DPP-1/references", headers=self._headers("aud"))
        self.assertEqual(listing.body["references"][0]["state"], "invalidated")

        not_found = self.app.handle("GET", "/passports/NOPE/versions", headers=self._headers("aud"))
        self.assertEqual(not_found.status, 404)
        unknown = self.app.handle("GET", "/nope")
        self.assertEqual(unknown.status, 404)


if __name__ == "__main__":
    unittest.main()
