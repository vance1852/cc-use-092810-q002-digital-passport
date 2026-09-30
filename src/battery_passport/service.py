"""数字产品护照的领域用例。

核心不变量：
1. 候选包只引用「确定版本 + 内容摘要」的资产与证据，签发前逐条核对，
   缺失 / 撤销 / 摘要不符 / 相互冲突一律阻断，绝不回退到最新值；
2. 护照内容寻址（material_sha256、content_sha256 全局唯一），相同材料的
   重试必然返回原护照；业务编号恒定，不同内容只能显式「取代」出新版本；
3. 签发即冻结：载荷以签发时刻的规范化 JSON 原样保存，后续维修 / 检测只能
   产生新版本，已交付历史不可改写；
4. 吊销保留原因，并使指向该版本的未完成下游引用立即失效。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping

from .clock import SystemClock, isoformat
from .contracts import (
    INSPECTION_RESULTS,
    OWNERSHIP_KINDS,
    TRANSFER_DIRECTIONS,
    EvidenceRef,
    identifier,
    parse_refs,
    parse_requirements,
    positive_integer,
    required_text,
)
from .errors import (
    Conflict,
    Forbidden,
    InvalidState,
    IssuanceBlocked,
    NotFound,
    ValidationFailed,
)
from .jsonio import canonical_json, digest_text
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "asset.write", "evidence.record", "candidate.assemble",
        "reference.write", "passport.read",
    },
    "quality": {"evidence.record", "evidence.revoke", "passport.read"},
    "approver": {"passport.issue", "passport.revoke", "passport.read"},
    "auditor": {"passport.read", "audit.read"},
}

#: 候选包未显式声明时采用的覆盖要求。
DEFAULT_REQUIREMENTS = {
    "components": True,
    "inspection": True,
    "ownership": True,
    "repairs_resolved": True,
}


class PassportService:
    """在单个 SQLite 连接上提供数字产品护照的全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ----- 基础辅助 -----

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    # ----- 确定版本的资产档案 -----

    def register_asset(
        self,
        actor_id: str,
        asset_id: str,
        model_name: str,
        vendor: str,
        status: str = "commissioned",
        attributes: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "asset.write")
        return self._write_asset(actor_id, asset_id, model_name, vendor, status, attributes, None)

    def revise_asset(
        self,
        actor_id: str,
        asset_id: str,
        model_name: str,
        vendor: str,
        status: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "asset.write")
        return self._write_asset(actor_id, asset_id, model_name, vendor, status, attributes, 1)

    def _write_asset(
        self, actor_id, asset_id, model_name, vendor, status, attributes, bump
    ) -> dict[str, Any]:
        asset_id = identifier(asset_id, "asset_id")
        model_name = required_text(model_name, "model_name")
        vendor = required_text(vendor, "vendor")
        if status not in {"commissioned", "in_service", "maintenance", "retired"}:
            raise ValidationFailed("status 不是受支持的资产状态")
        if attributes is not None and not isinstance(attributes, Mapping):
            raise ValidationFailed("attributes 必须是对象")
        body = {
            "asset_id": asset_id,
            "model_name": model_name,
            "vendor": vendor,
            "status": status,
            "attributes": {} if attributes is None else dict(attributes),
        }
        digest = digest_text(canonical_json(body))
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                if bump is None:
                    exists = self.connection.execute(
                        "SELECT 1 FROM assets WHERE asset_id=?", (asset_id,)
                    ).fetchone()
                    if exists is not None:
                        raise Conflict(f"资产已存在，请登记新版本: {asset_id}")
                    revision = 1
                    self.connection.execute(
                        "INSERT INTO assets(asset_id,latest_revision,registered_by,created_at) "
                        "VALUES(?,?,?,?)",
                        (asset_id, revision, actor_id, now),
                    )
                else:
                    latest = self.connection.execute(
                        "SELECT latest_revision FROM assets WHERE asset_id=?", (asset_id,)
                    ).fetchone()
                    if latest is None:
                        raise NotFound(f"资产不存在: {asset_id}")
                    current = self.connection.execute(
                        "SELECT content_sha256 FROM asset_revisions WHERE asset_id=? AND revision=?",
                        (asset_id, latest["latest_revision"]),
                    ).fetchone()
                    if current["content_sha256"] == digest:
                        raise Conflict("资产内容与当前版本完全一致，无需新增版本")
                    revision = latest["latest_revision"] + 1
                    self.connection.execute(
                        "UPDATE assets SET latest_revision=? WHERE asset_id=?", (revision, asset_id)
                    )
                self.connection.execute(
                    "INSERT INTO asset_revisions(asset_id,revision,model_name,vendor,status,"
                    "content_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                    (asset_id, revision, model_name, vendor, status, digest, now),
                )
                self._audit("asset", asset_id, "asset.registered" if bump is None else "asset.revised",
                            actor_id, {"revision": revision, "sha256": digest, "status": status})
        except sqlite3.IntegrityError as exc:
            raise Conflict("资产编号或内容摘要冲突") from exc
        return {"asset_id": asset_id, "revision": revision, "status": status, "content_sha256": digest}

    def _asset_revision(self, asset_id: str, revision: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM asset_revisions WHERE asset_id=? AND revision=?", (asset_id, revision)
        ).fetchone()
        if row is None:
            raise NotFound(f"资产版本不存在: {asset_id}@{revision}")
        return row

    # ----- 版本化的来源证据 -----

    def record_evidence(
        self,
        actor_id: str,
        kind: str,
        record_id: str,
        revision: int,
        asset_id: str,
        payload: Mapping[str, Any],
        supersedes: int | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "evidence.record")
        kind = required_text(kind, "kind", 32)
        if kind not in {"component", "inspection", "repair", "ownership"}:
            raise ValidationFailed("kind 必须是 component/inspection/repair/ownership")
        record_id = identifier(record_id, "record_id")
        revision = positive_integer(revision, "revision")
        asset_id = identifier(asset_id, "asset_id")
        if not isinstance(payload, Mapping):
            raise ValidationFailed("payload 必须是对象")
        normalized = self._validate_payload(kind, payload)
        digest = digest_text(canonical_json(normalized))
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                if self.connection.execute(
                    "SELECT 1 FROM assets WHERE asset_id=?", (asset_id,)
                ).fetchone() is None:
                    raise NotFound(f"资产不存在: {asset_id}")
                if revision > 1 and self.connection.execute(
                    "SELECT 1 FROM evidence_records WHERE kind=? AND record_id=? AND revision=?",
                    (kind, record_id, revision - 1),
                ).fetchone() is None:
                    raise InvalidState(f"证据前一版本 {revision - 1} 不存在，不能跳版登记")
                if supersedes is not None and self.connection.execute(
                    "SELECT 1 FROM evidence_records WHERE kind=? AND record_id=? AND revision=?",
                    (kind, record_id, supersedes),
                ).fetchone() is None:
                    raise NotFound(f"被取代的证据版本不存在: {record_id}@{supersedes}")
                self.connection.execute(
                    "INSERT INTO evidence_records(kind,record_id,revision,asset_id,content_sha256,"
                    "payload_json,status,recorded_by,recorded_at) VALUES(?,?,?,?,?,?,'active',?,?)",
                    (kind, record_id, revision, asset_id, digest, canonical_json(normalized), actor_id, now),
                )
                self.connection.execute(
                    "INSERT INTO evidence_revision_chains(kind,record_id,revision,supersedes_revision) "
                    "VALUES(?,?,?,?)",
                    (kind, record_id, revision, supersedes),
                )
                self._audit("evidence", f"{kind}/{record_id}@{revision}", "evidence.recorded", actor_id,
                            {"asset_id": asset_id, "sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("证据记录编号、版本或内容摘要冲突") from exc
        return {"kind": kind, "record_id": record_id, "revision": revision,
                "asset_id": asset_id, "content_sha256": digest, "status": "active"}

    @staticmethod
    def _validate_payload(kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if kind == "inspection":
            result = required_text(payload.get("result"), "payload.result", 16)
            if result not in INSPECTION_RESULTS:
                raise ValidationFailed("payload.result 必须是 pass/conditional/fail")
            return dict(payload)
        if kind == "repair":
            state = required_text(payload.get("status"), "payload.status", 16)
            if state not in {"open", "closed"}:
                raise ValidationFailed("payload.status 必须是 open/closed")
            return dict(payload)
        if kind == "ownership":
            transfer_kind = required_text(payload.get("transfer_kind"), "payload.transfer_kind", 16)
            if transfer_kind not in OWNERSHIP_KINDS:
                raise ValidationFailed("payload.transfer_kind 必须是 registration/transfer")
            required_text(payload.get("holder"), "payload.holder")
            if transfer_kind == "transfer":
                direction = required_text(payload.get("direction"), "payload.direction", 16)
                if direction not in TRANSFER_DIRECTIONS:
                    raise ValidationFailed("payload.direction 必须是 inbound/outbound/internal")
            return dict(payload)
        # component：出厂组件规格，自由结构但必须是对象。
        return dict(payload)

    def revoke_evidence(
        self, actor_id: str, kind: str, record_id: str, revision: int, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "evidence.revoke")
        reason = required_text(reason, "reason", 512)
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM evidence_records WHERE kind=? AND record_id=? AND revision=?",
                (kind, record_id, revision),
            ).fetchone()
            if row is None:
                raise NotFound("证据版本不存在")
            if row["status"] == "revoked":
                raise InvalidState("证据版本已经撤销")
            self.connection.execute(
                "UPDATE evidence_records SET status='revoked',revoke_reason=?,revoked_by=?,revoked_at=? "
                "WHERE evidence_id=?",
                (reason, actor_id, self._now(), row["evidence_id"]),
            )
            self._audit("evidence", f"{kind}/{record_id}@{revision}", "evidence.revoked", actor_id,
                        {"reason": reason})
        return {"kind": kind, "record_id": record_id, "revision": revision,
                "status": "revoked", "reason": reason}

    # ----- 候选包组装 -----

    def create_candidate(
        self,
        actor_id: str,
        candidate_id: str,
        asset_id: str,
        asset_revision: int,
        refs: Any,
        requirements: Any = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "candidate.assemble")
        candidate_id = identifier(candidate_id, "candidate_id")
        asset_id = identifier(asset_id, "asset_id")
        asset_revision = positive_integer(asset_revision, "asset_revision")
        parsed_refs = parse_refs(refs, "refs")
        required = {**DEFAULT_REQUIREMENTS, **parse_requirements(requirements)}
        with transaction(self.connection, immediate=True):
            asset = self._asset_revision(asset_id, asset_revision)
            self.connection.execute(
                "INSERT INTO candidate_packages(candidate_id,asset_id,asset_revision,asset_sha256,"
                "requirements_json,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (candidate_id, asset_id, asset_revision, asset["content_sha256"],
                 canonical_json(required), actor_id, self._now()),
            )
            for position, ref in enumerate(parsed_refs):
                self.connection.execute(
                    "INSERT INTO candidate_refs(candidate_id,position,kind,record_id,revision,sha256,role,note) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (candidate_id, position, ref.kind, ref.record_id, ref.revision,
                     ref.sha256, ref.role, ref.note),
                )
            self._audit("candidate", candidate_id, "candidate.assembled", actor_id,
                        {"asset_id": asset_id, "asset_revision": asset_revision, "refs": len(parsed_refs)})
        asset_identity = {"asset_id": asset_id, "revision": asset_revision,
                          "sha256": asset["content_sha256"]}
        material_sha256 = self._material_sha256(asset_identity, required, parsed_refs)
        return {"candidate_id": candidate_id, "asset_id": asset_id, "asset_revision": asset_revision,
                "requirements": required, "ref_count": len(parsed_refs), "material_sha256": material_sha256}

    def _load_candidate(self, candidate_id: str) -> tuple[sqlite3.Row, tuple[EvidenceRef, ...], dict[str, Any]]:
        package = self.connection.execute(
            "SELECT * FROM candidate_packages WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if package is None:
            raise NotFound(f"候选包不存在: {candidate_id}")
        rows = self.connection.execute(
            "SELECT * FROM candidate_refs WHERE candidate_id=? ORDER BY position", (candidate_id,)
        ).fetchall()
        refs = tuple(
            EvidenceRef(r["kind"], r["record_id"], r["revision"], r["sha256"], r["role"], r["note"])
            for r in rows
        )
        return package, refs, json.loads(package["requirements_json"])

    @staticmethod
    def _material_sha256(asset_identity: Mapping[str, Any], required: Mapping[str, bool],
                         refs: Any) -> str:
        material = {
            "asset": {
                "asset_id": asset_identity["asset_id"],
                "revision": asset_identity["revision"],
                "sha256": asset_identity["sha256"],
            },
            "requirements": {key: required[key] for key in sorted(required)},
            "refs": sorted(
                (
                    {
                        "kind": ref.kind,
                        "record_id": ref.record_id,
                        "revision": ref.revision,
                        "sha256": ref.sha256,
                        "role": ref.role,
                        "note": ref.note,
                    }
                    for ref in refs
                ),
                key=lambda item: (item["kind"], item["record_id"], item["revision"]),
            ),
        }
        return digest_text(canonical_json(material))

    # ----- 签发门禁 -----

    def _evidence_for_ref(self, ref: EvidenceRef, asset_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM evidence_records WHERE kind=? AND record_id=? AND revision=?",
            (ref.kind, ref.record_id, ref.revision),
        ).fetchone()

    def _evaluate_gate(
        self, package: sqlite3.Row, refs: tuple[EvidenceRef, ...], required: Mapping[str, bool]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """返回 (阻断项, 已解析声明)。阻断项非空时不得签发。"""
        blockers: list[dict[str, Any]] = []
        statements: list[dict[str, Any]] = []
        asset_id = package["asset_id"]

        asset = self._asset_revision(asset_id, package["asset_revision"])
        if asset["content_sha256"] != package["asset_sha256"]:
            blockers.append({"code": "asset_digest_conflict", "asset_id": asset_id,
                             "revision": package["asset_revision"]})
        if asset["status"] == "retired":
            blockers.append({"code": "asset_retired", "asset_id": asset_id})

        active_by_kind: dict[str, list[sqlite3.Row]] = {
            "component": [], "inspection": [], "repair": [], "ownership": []
        }
        for ref in refs:
            row = self._evidence_for_ref(ref, asset_id)
            if row is None:
                blockers.append({"code": "evidence_missing", "kind": ref.kind,
                                 "record_id": ref.record_id, "revision": ref.revision})
                continue
            if row["content_sha256"] != ref.sha256:
                blockers.append({"code": "evidence_digest_conflict", "kind": ref.kind,
                                 "record_id": ref.record_id, "revision": ref.revision,
                                 "expected": ref.sha256, "actual": row["content_sha256"]})
                continue
            if row["asset_id"] != asset_id:
                blockers.append({"code": "evidence_asset_mismatch", "kind": ref.kind,
                                 "record_id": ref.record_id, "revision": ref.revision,
                                 "evidence_asset_id": row["asset_id"]})
                continue
            if row["status"] == "revoked":
                blockers.append({"code": "evidence_revoked", "kind": ref.kind,
                                 "record_id": ref.record_id, "revision": ref.revision,
                                 "reason": row["revoke_reason"]})
                continue
            active_by_kind[row["kind"]].append(row)
            statements.append(self._statement(ref, row))

        components = active_by_kind["component"]
        if required.get("components"):
            if not components:
                blockers.append({"code": "components_required"})
            else:
                # 同一出厂组件角色由两条不同记录声明 → 冲突。
                seen_role: dict[str, str] = {}
                comp_refs = [r for r in refs if r.kind == "component"]
                for ref in comp_refs:
                    row = next((c for c in components if c["record_id"] == ref.record_id
                                and c["revision"] == ref.revision), None)
                    if row is None:
                        continue
                    if ref.role in seen_role and seen_role[ref.role] != ref.record_id:
                        blockers.append({"code": "component_role_conflict", "role": ref.role,
                                         "records": [seen_role[ref.role], ref.record_id]})
                    seen_role.setdefault(ref.role, ref.record_id)
                # 同一组件记录的两个不同版本被同时引用 → 版本冲突。
                records: dict[str, set[int]] = {}
                for ref in comp_refs:
                    records.setdefault(ref.record_id, set()).add(ref.revision)
                for record_id, revisions in records.items():
                    if len(revisions) > 1:
                        blockers.append({"code": "component_revision_conflict",
                                         "record_id": record_id, "revisions": sorted(revisions)})

        inspections = active_by_kind["inspection"]
        if required.get("inspection"):
            if not inspections:
                blockers.append({"code": "inspection_required"})
            else:
                payloads = [json.loads(r["payload_json"]) for r in inspections]
                if any(item.get("result") == "fail" for item in payloads):
                    failed = [r["record_id"] for r, item in zip(inspections, payloads)
                              if item.get("result") == "fail"]
                    blockers.append({"code": "inspection_failed", "records": failed})
                elif not any(item.get("result") == "pass" for item in payloads):
                    blockers.append({"code": "inspection_not_passing",
                                     "records": [r["record_id"] for r in inspections]})
                in_records: dict[str, set[int]] = {}
                for r in inspections:
                    in_records.setdefault(r["record_id"], set()).add(r["revision"])
                for record_id, revs in in_records.items():
                    if len(revs) > 1:
                        blockers.append({"code": "inspection_revision_conflict",
                                         "record_id": record_id, "revisions": sorted(revs)})

        repairs = active_by_kind["repair"]
        if required.get("repairs_resolved"):
            open_repairs = []
            for row in repairs:
                if json.loads(row["payload_json"]).get("status") == "open":
                    open_repairs.append(f"{row['record_id']}@{row['revision']}")
            if open_repairs:
                blockers.append({"code": "repair_open", "records": open_repairs})

        ownership = active_by_kind["ownership"]
        if required.get("ownership"):
            if not ownership:
                blockers.append({"code": "ownership_required"})
            else:
                ownership_payloads = [json.loads(r["payload_json"]) for r in ownership]
                transfer_kinds = {item.get("transfer_kind") for item in ownership_payloads}
                if "registration" not in transfer_kinds:
                    blockers.append({"code": "ownership_without_registration"})
                # 两条相互独立的初始登记指向不同持有方 → 所有权冲突；
                # 正常的登记→流转（持有方随时间变化）不算冲突。
                registrations = [
                    (r["record_id"], item.get("holder"))
                    for r, item in zip(ownership, ownership_payloads)
                    if item.get("transfer_kind") == "registration"
                ]
                registered_holders = {holder for _, holder in registrations}
                if len(registered_holders) > 1:
                    blockers.append({"code": "ownership_registration_conflict",
                                     "holders": sorted(registered_holders),
                                     "records": [record_id for record_id, _ in registrations]})
                latest = max(ownership, key=lambda r: (r["record_id"], r["revision"]))
                latest_payload = json.loads(latest["payload_json"])
                if latest_payload.get("transfer_kind") == "transfer" \
                        and latest_payload.get("direction") == "outbound":
                    blockers.append({"code": "ownership_outbound", "record_id": latest["record_id"]})

        return blockers, statements

    @staticmethod
    def _statement(ref: EvidenceRef, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "kind": ref.kind,
            "record_id": ref.record_id,
            "revision": ref.revision,
            "sha256": ref.sha256,
            "role": ref.role,
            "note": ref.note,
            "status": row["status"],
            "payload": json.loads(row["payload_json"]),
            "recorded_by": row["recorded_by"],
            "recorded_at": row["recorded_at"],
        }

    # ----- 签发 -----

    def issue_passport(
        self,
        actor_id: str,
        candidate_id: str,
        idempotency_key: str,
        business_no: str | None = None,
        replaces_passport_id: int | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "passport.issue")
        idempotency_key = identifier(idempotency_key, "idempotency_key")
        package, refs, required = self._load_candidate(candidate_id)
        asset_identity = {"asset_id": package["asset_id"], "revision": package["asset_revision"],
                          "sha256": package["asset_sha256"]}
        material_sha256 = self._material_sha256(asset_identity, required, refs)

        with transaction(self.connection, immediate=True):
            # 1) 相同材料的重试：无论是否带业务编号/幂等键，都返回原护照。
            identical = self.connection.execute(
                "SELECT * FROM passports WHERE material_sha256=?", (material_sha256,)
            ).fetchone()
            if identical is not None:
                return self._passport_view(identical, replayed=True)

            if (business_no is None) == (replaces_passport_id is None):
                raise ValidationFailed(
                    "签发必须且只能提供 business_no（首次）或 replaces_passport_id（新版本）之一"
                )

            # 2) 幂等键必须与材料一致。
            stored = self.connection.execute(
                "SELECT material_sha256, passport_id FROM issuance_requests WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if stored is not None and stored["material_sha256"] != material_sha256:
                raise Conflict("同一签发请求编号对应了不同的候选材料")

            # 3) 确定业务编号与版本。
            replaces_row = None
            if replaces_passport_id is not None:
                replaces_row = self.connection.execute(
                    "SELECT * FROM passports WHERE passport_id=?", (replaces_passport_id,)
                ).fetchone()
                if replaces_row is None:
                    raise NotFound("被取代的护照版本不存在")
                head = self.connection.execute(
                    "SELECT * FROM passports WHERE business_no=? ORDER BY version DESC LIMIT 1",
                    (replaces_row["business_no"],),
                ).fetchone()
                if head["passport_id"] != replaces_passport_id:
                    raise InvalidState("只能取代业务编号下的最新版本")
                if replaces_row["state"] == "revoked":
                    raise InvalidState("被取代的护照版本已吊销，不能在其上续接新版本")
                if replaces_row["state"] != "issued":
                    raise InvalidState("被取代的护照版本不是当前有效版本")
                target_business_no = replaces_row["business_no"]
                version = replaces_row["version"] + 1
            else:
                business_no = identifier(business_no, "business_no")
                existing = self.connection.execute(
                    "SELECT 1 FROM passports WHERE business_no=?", (business_no,)
                ).fetchone()
                if existing is not None:
                    raise Conflict("业务编号已被占用；不同内容必须显式取代当前版本以产生新版本")
                target_business_no = business_no
                version = 1

            # 4) 证据门禁：缺失 / 撤销 / 冲突明确阻断，不被最新值覆盖。
            blockers, statements = self._evaluate_gate(package, refs, required)
            if blockers:
                raise IssuanceBlocked(blockers)

            # 5) 冻结内容并签发。
            now = self._now()
            asset = self._asset_revision(package["asset_id"], package["asset_revision"])
            frozen = {
                "business_no": target_business_no,
                "version": version,
                "asset": {
                    "asset_id": asset["asset_id"],
                    "revision": asset["revision"],
                    "sha256": asset["content_sha256"],
                    "model_name": asset["model_name"],
                    "vendor": asset["vendor"],
                    "status": asset["status"],
                },
                "requirements": {key: required[key] for key in sorted(required)},
                "statements": sorted(statements, key=lambda s: (s["kind"], s["record_id"], s["revision"])),
                "issued_by": actor_id,
                "issued_at": now,
                "replaces_passport_id": None if replaces_row is None else replaces_row["passport_id"],
            }
            content_sha256 = digest_text(canonical_json(frozen))
            try:
                cursor = self.connection.execute(
                    "INSERT INTO passports(business_no,version,asset_id,candidate_id,material_sha256,"
                    "content_sha256,payload_json,state,issued_by,issued_at,replaces_passport_id) "
                    "VALUES(?,?,?,?,?,?,?,'issued',?,?,?)",
                    (target_business_no, version, package["asset_id"], candidate_id, material_sha256,
                     content_sha256, canonical_json(frozen), actor_id, now,
                     None if replaces_row is None else replaces_row["passport_id"]),
                )
                passport_id = int(cursor.lastrowid)
                if replaces_row is not None:
                    self.connection.execute(
                        "UPDATE passports SET state='superseded' WHERE passport_id=?",
                        (replaces_row["passport_id"],),
                    )
                self.connection.execute(
                    "INSERT INTO issuance_requests(idempotency_key,candidate_id,material_sha256,"
                    "passport_id,created_by,created_at) VALUES(?,?,?,?,?,?)",
                    (idempotency_key, candidate_id, material_sha256, passport_id, actor_id, now),
                )
                self._audit("passport", target_business_no, "passport.issued", actor_id,
                            {"passport_id": passport_id, "version": version,
                             "material_sha256": material_sha256, "content_sha256": content_sha256,
                             "replaces_passport_id": frozen["replaces_passport_id"]})
                if replaces_row is not None:
                    self._audit("passport", target_business_no, "passport.superseded", actor_id,
                                {"passport_id": replaces_row["passport_id"],
                                 "successor_passport_id": passport_id})
                row = self.connection.execute(
                    "SELECT * FROM passports WHERE passport_id=?", (passport_id,)
                ).fetchone()
            except sqlite3.IntegrityError as exc:
                raise Conflict("护照内容或签发请求冲突") from exc
        return self._passport_view(row, replayed=False)

    def _passport_view(self, row: sqlite3.Row, *, replayed: bool) -> dict[str, Any]:
        payload = json.loads(row["payload_json"])
        return {
            "passport_id": row["passport_id"],
            "business_no": row["business_no"],
            "version": row["version"],
            "state": row["state"],
            "material_sha256": row["material_sha256"],
            "content_sha256": row["content_sha256"],
            "issued_by": row["issued_by"],
            "issued_at": row["issued_at"],
            "replaces_passport_id": row["replaces_passport_id"],
            "revoked_by": row["revoked_by"],
            "revoked_at": row["revoked_at"],
            "revoke_reason": row["revoke_reason"],
            "payload": payload,
            "replayed": replayed,
        }

    # ----- 吊销 -----

    def revoke_passport(self, actor_id: str, passport_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "passport.revoke")
        reason = required_text(reason, "reason", 512)
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM passports WHERE passport_id=?", (passport_id,)
            ).fetchone()
            if row is None:
                raise NotFound("护照不存在")
            if row["state"] == "revoked":
                raise InvalidState("护照已经吊销")
            if row["state"] == "superseded":
                raise InvalidState("只能吊销当前有效版本；请吊销业务编号的最新版本")
            now = self._now()
            self.connection.execute(
                "UPDATE passports SET state='revoked',revoke_reason=?,revoked_by=?,revoked_at=? "
                "WHERE passport_id=?",
                (reason, actor_id, now, passport_id),
            )
            pending = self.connection.execute(
                "SELECT reference_id FROM passport_references WHERE passport_id=? AND state='pending'",
                (passport_id,),
            ).fetchall()
            self.connection.execute(
                "UPDATE passport_references SET state='invalidated',invalidated_at=?,"
                "invalidate_reason=? WHERE passport_id=? AND state='pending'",
                (now, f"护照已吊销: {reason}", passport_id),
            )
            self._audit("passport", row["business_no"], "passport.revoked", actor_id,
                        {"passport_id": passport_id, "version": row["version"], "reason": reason,
                         "invalidated_references": [item["reference_id"] for item in pending]})
        return {"passport_id": passport_id, "state": "revoked", "reason": reason,
                "invalidated_references": [item["reference_id"] for item in pending]}

    # ----- 下游引用 -----

    def create_reference(
        self, actor_id: str, reference_id: str, passport_id: int, consumer: str, purpose: str
    ) -> dict[str, Any]:
        self._require(actor_id, "reference.write")
        reference_id = identifier(reference_id, "reference_id")
        consumer = required_text(consumer, "consumer")
        purpose = required_text(purpose, "purpose")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                row = self.connection.execute(
                    "SELECT state FROM passports WHERE passport_id=?", (passport_id,)
                ).fetchone()
                if row is None:
                    raise NotFound("护照不存在")
                if row["state"] != "issued":
                    raise InvalidState("只能对当前有效护照建立未完成引用")
                self.connection.execute(
                    "INSERT INTO passport_references(reference_id,passport_id,consumer,purpose,state,"
                    "created_by,created_at) VALUES(?,?,?,?,'pending',?,?)",
                    (reference_id, passport_id, consumer, purpose, actor_id, now),
                )
                self._audit("reference", reference_id, "reference.created", actor_id,
                            {"passport_id": passport_id, "consumer": consumer})
        except sqlite3.IntegrityError as exc:
            raise Conflict("下游引用编号冲突") from exc
        return {"reference_id": reference_id, "passport_id": passport_id, "state": "pending"}

    def complete_reference(self, actor_id: str, reference_id: str) -> dict[str, Any]:
        self._require(actor_id, "reference.write")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT r.*, p.state AS passport_state FROM passport_references r "
                "JOIN passports p ON p.passport_id=r.passport_id WHERE r.reference_id=?",
                (reference_id,),
            ).fetchone()
            if row is None:
                raise NotFound("下游引用不存在")
            if row["state"] == "invalidated":
                raise InvalidState("引用已因护照吊销而失效")
            if row["state"] == "completed":
                raise InvalidState("引用已经完成")
            if row["passport_state"] != "issued":
                raise InvalidState("护照已不再有效，不能完成该引用")
            now = self._now()
            self.connection.execute(
                "UPDATE passport_references SET state='completed',completed_at=? WHERE reference_id=?",
                (now, reference_id),
            )
            self._audit("reference", reference_id, "reference.completed", actor_id, {})
        return {"reference_id": reference_id, "state": "completed"}

    # ----- 查询：时点有效、逐项追溯、版本关系 -----

    def get_passport(self, actor_id: str, passport_id: int) -> dict[str, Any]:
        self._require(actor_id, "passport.read")
        row = self.connection.execute(
            "SELECT * FROM passports WHERE passport_id=?", (passport_id,)
        ).fetchone()
        if row is None:
            raise NotFound("护照不存在")
        return self._passport_view(row, replayed=False)

    def get_version(self, actor_id: str, business_no: str, version: int) -> dict[str, Any]:
        self._require(actor_id, "passport.read")
        row = self.connection.execute(
            "SELECT * FROM passports WHERE business_no=? AND version=?", (business_no, version)
        ).fetchone()
        if row is None:
            raise NotFound("护照版本不存在")
        return self._passport_view(row, replayed=False)

    def effective_passport(self, actor_id: str, asset_id: str, at: str | None = None) -> dict[str, Any]:
        """返回某一时点（默认当前）对资产有效的护照。

        取该时点之前签发的最高版本：它若在该时点之前已吊销，则该时点不存在
        有效护照；已被取代的旧版本不会重新生效。
        """
        self._require(actor_id, "passport.read")
        point = self._now() if at is None else required_text(at, "at", 40)
        row = self.connection.execute(
            "SELECT * FROM passports WHERE asset_id=? AND issued_at<=? "
            "ORDER BY issued_at DESC, passport_id DESC LIMIT 1",
            (asset_id, point),
        ).fetchone()
        if row is None:
            raise NotFound("该时点没有有效的护照")
        if row["revoked_at"] is not None and row["revoked_at"] <= point:
            raise NotFound("该时点最新护照已吊销，且不存在更新版本")
        return self._passport_view(row, replayed=False)

    def list_versions(self, actor_id: str, business_no: str) -> dict[str, Any]:
        self._require(actor_id, "passport.read")
        rows = self.connection.execute(
            "SELECT passport_id,version,state,material_sha256,content_sha256,issued_by,issued_at,"
            "replaces_passport_id,revoked_by,revoked_at,revoke_reason "
            "FROM passports WHERE business_no=? ORDER BY version",
            (business_no,),
        ).fetchall()
        if not rows:
            raise NotFound("业务编号不存在")
        return {"business_no": business_no, "versions": [dict(row) for row in rows]}

    def trace(self, actor_id: str, passport_id: int) -> dict[str, Any]:
        """逐项追溯声明来源、签署责任与新旧版本关系。"""
        self._require(actor_id, "passport.read")
        row = self.connection.execute(
            "SELECT * FROM passports WHERE passport_id=?", (passport_id,)
        ).fetchone()
        if row is None:
            raise NotFound("护照不存在")
        frozen = json.loads(row["payload_json"])

        sources = []
        for statement in frozen["statements"]:
            current = self.connection.execute(
                "SELECT status,revoke_reason,revoked_by,revoked_at FROM evidence_records "
                "WHERE kind=? AND record_id=? AND revision=?",
                (statement["kind"], statement["record_id"], statement["revision"]),
            ).fetchone()
            sources.append({
                "statement": statement,
                "frozen_status": statement["status"],
                "current_status": None if current is None else current["status"],
                "current_revoke_reason": None if current is None else current["revoke_reason"],
                "signed_by": statement["recorded_by"],
                "signed_at": statement["recorded_at"],
                "source_digest": statement["sha256"],
            })

        lineage_rows = self.connection.execute(
            "SELECT passport_id,version,state,content_sha256,issued_by,issued_at,replaces_passport_id,"
            "revoked_by,revoked_at,revoke_reason FROM passports WHERE business_no=? ORDER BY version",
            (row["business_no"],),
        ).fetchall()
        references = self.connection.execute(
            "SELECT reference_id,consumer,purpose,state,created_at,completed_at,invalidated_at,"
            "invalidate_reason FROM passport_references WHERE passport_id=? ORDER BY reference_id",
            (passport_id,),
        ).fetchall()
        return {
            "passport_id": row["passport_id"],
            "business_no": row["business_no"],
            "version": row["version"],
            "state": row["state"],
            "content_sha256": row["content_sha256"],
            "material_sha256": row["material_sha256"],
            "issued_by": row["issued_by"],
            "issued_at": row["issued_at"],
            "asset": frozen["asset"],
            "requirements": frozen["requirements"],
            "sources": sources,
            "lineage": [dict(item) for item in lineage_rows],
            "references": [dict(item) for item in references],
        }

    def audit_log(self, actor_id: str, entity_type: str | None = None,
                  entity_id: str | None = None) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        query = "SELECT * FROM audit_events"
        params: list[Any] = []
        clauses = []
        if entity_type is not None:
            clauses.append("entity_type=?")
            params.append(entity_type)
        if entity_id is not None:
            clauses.append("entity_id=?")
            params.append(entity_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY event_id"
        rows = self.connection.execute(query, params).fetchall()
        return {"events": [
            {"event_id": r["event_id"], "entity_type": r["entity_type"], "entity_id": r["entity_id"],
             "event_type": r["event_type"], "actor_id": r["actor_id"],
             "payload": json.loads(r["payload_json"]), "created_at": r["created_at"]}
            for r in rows
        ]}
