"""数字产品护照领域用例。

职责边界：

- 护照本身不产生资产、组件、检测或流转事实，只把各来源系统 *确定版本* 的证据
  登记并冻结进候选版本；
- 证据缺失、撤销或相互冲突时，``assemble_candidate`` 会持久化候选但抛出
  :class:`EvidenceGateBlocked`，签发因此被明确阻止，绝不会被“最新值”静默覆盖；
- 签发后内容摘要与依据冻结；维修/检测等新事实只能组装新版本；
- 相同材料（含相同幂等键）的重试返回原版本；同一业务编号复用幂等键但内容不同则冲突；
- 吊销保留原因，并把未完成的下游引用置为失效；
- 可按时间点取得有效护照，并逐项追溯声明来源、签署责任与版本关系。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Mapping

from .clock import SystemClock, isoformat, parse_utc_text
from .contracts import (
    CATEGORY_ALIASES,
    BlockerCode,
    CONFLICTED_STATES,
    EvidenceRef,
    GateResult,
    PENDING_STATES,
    REVOKED_STATES,
    VALID_STATES,
    _identifier,
    _required_text,
    normalize_state,
)
from .errors import (
    Conflict,
    EvidenceGateBlocked,
    Forbidden,
    InvalidState,
    NotFound,
    ValidationFailed,
)
from .jsonio import canonical_json, digest_value
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "registrar": {"evidence.write", "evidence.revoke", "passport.read"},
    "operator": {"passport.assemble", "passport.read"},
    "issuer": {"passport.issue", "passport.revoke", "passport.read"},
    "auditor": {"passport.read", "audit.read"},
    "consumer": {"passport.read", "reference.write"},
}

CATEGORIES = ("asset", "component", "quality", "transfer")
# 各证据类别在签发门禁处认可的有效状态（终态、可作为声明依据）。
CATEGORY_ACCEPTED_STATES = {
    "asset": VALID_STATES,
    "component": VALID_STATES,
    "quality": frozenset({"approved", "passed", "released", "active", "effective"}),
    "transfer": frozenset({"active", "effective", "closed", "settled", "completed", "released"}),
}


class PassportService:
    """在单个 SQLite 连接上提供护照全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    # ------------------------------------------------------------------ 用户/权限

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM passport_users WHERE user_id=?",
            (user_id,),
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

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO passport_users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM passport_audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO passport_audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                entity_type,
                entity_id,
                event_type,
                actor_id,
                canonical_json(payload),
                previous_hash,
                event_hash,
                body["created_at"],
            ),
        )

    # --------------------------------------------------------------- 证据登记/撤销

    def register_evidence(
        self,
        actor_id: str,
        category: str,
        ref: str,
        version: str,
        asset_id: str,
        title: str,
        payload: Mapping[str, Any],
        state: str = "active",
    ) -> dict[str, Any]:
        self._require(actor_id, "evidence.write")
        normalized_category = CATEGORY_ALIASES.get(category.strip() if isinstance(category, str) else None)
        if normalized_category is None:
            raise ValidationFailed("证据类别必须是 asset、component、quality 或 transfer")
        ref = _identifier(ref, "证据编号")
        version = _required_text(version, "证据版本", 64)
        asset_id = _identifier(asset_id, "asset_id")
        title = _required_text(title, "证据标题")
        if not isinstance(payload, Mapping):
            raise ValidationFailed("证据内容必须是对象")
        normalized_state = normalize_state(state)
        content_sha = digest_value(payload)
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_records(category,ref,version,asset_id,title,payload_json,"
                    "content_sha256,state,registered_by,registered_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        normalized_category,
                        ref,
                        version,
                        asset_id,
                        title,
                        canonical_json(payload),
                        content_sha,
                        normalized_state,
                        actor_id,
                        now,
                        now,
                    ),
                )
                self._audit(
                    "evidence",
                    f"{normalized_category}/{ref}@{version}",
                    "evidence.registered",
                    actor_id,
                    {"asset_id": asset_id, "state": normalized_state, "sha256": content_sha},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("证据编号+版本冲突，或内容摘要已存在") from exc
        return {
            "category": normalized_category,
            "ref": ref,
            "version": version,
            "asset_id": asset_id,
            "state": normalized_state,
            "content_sha256": content_sha,
        }

    def revoke_evidence(self, actor_id: str, category: str, ref: str, version: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "evidence.revoke")
        normalized_category = CATEGORY_ALIASES.get(category.strip() if isinstance(category, str) else None)
        if normalized_category is None:
            raise ValidationFailed("证据类别必须是 asset、component、quality 或 transfer")
        if not reason.strip():
            raise ValidationFailed("撤销原因不能为空")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT state FROM evidence_records WHERE category=? AND ref=? AND version=?",
                (normalized_category, ref, version),
            ).fetchone()
            if row is None:
                raise NotFound("证据版本不存在")
            if row["state"] in REVOKED_STATES:
                raise InvalidState("证据已经被撤销")
            cursor = self.connection.execute(
                "UPDATE evidence_records SET state='revoked',revoke_reason=?,updated_at=? "
                "WHERE category=? AND ref=? AND version=?",
                (reason.strip(), self._now(), normalized_category, ref, version),
            )
            if cursor.rowcount != 1:
                raise InvalidState("证据状态已变化")
            self._audit(
                "evidence",
                f"{normalized_category}/{ref}@{version}",
                "evidence.revoked",
                actor_id,
                {"reason": reason.strip()},
            )
        # 不回写已签发版本：历史冻结，仅影响后续组装/签发。
        return {"category": normalized_category, "ref": ref, "version": version, "state": "revoked"}

    def get_evidence(self, category: str, ref: str, version: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM evidence_records WHERE category=? AND ref=? AND version=?",
            (category, ref, version),
        ).fetchone()
        if row is None:
            raise NotFound(f"证据不存在: {category}/{ref}@{version}")
        return row

    # --------------------------------------------------------------- 候选版本组装

    @staticmethod
    def _build_claims(asset_id: str, snapshots: list[sqlite3.Row]) -> list[dict[str, Any]]:
        """从冻结证据逐项生成声明，声明身份即来源定位，可逐项追溯。"""

        claims: list[dict[str, Any]] = [
            {
                "claim_id": "asset.identity",
                "category": "asset",
                "label": "资产身份",
                "value": asset_id,
            }
        ]
        for index, row in enumerate(snapshots):
            claims.append(
                {
                    "claim_id": f"{row['category']}.{index + 1}",
                    "category": row["category"],
                    "ref": row["ref"],
                    "version": row["version"],
                    "label": row["title"],
                    "evidence_sha256": row["content_sha256"],
                }
            )
        return claims

    @staticmethod
    def _build_manifest(snapshots: list[sqlite3.Row]) -> list[dict[str, str]]:
        return [
            {
                "category": row["category"],
                "ref": row["ref"],
                "version": row["version"],
                "content_sha256": row["content_sha256"],
            }
            for row in snapshots
        ]

    def _evaluate_gate(
        self, asset_id: str, refs: tuple[EvidenceRef, ...]
    ) -> tuple[GateResult, list[sqlite3.Row]]:
        gate = GateResult()
        seen: set[tuple[str, str]] = set()
        covered: set[str] = set()
        snapshots: list[sqlite3.Row] = []
        for item in refs:
            if item.key() in seen:
                gate.block(
                    BlockerCode.DUPLICATE_REF,
                    item.category,
                    item.ref,
                    "同一证据在候选中被重复引用",
                )
                continue
            seen.add(item.key())
            covered.add(item.category)
            row = self.connection.execute(
                "SELECT * FROM evidence_records WHERE category=? AND ref=? AND version=?",
                (item.category, item.ref, item.version),
            ).fetchone()
            if row is None:
                gate.block(
                    BlockerCode.MISSING,
                    item.category,
                    item.ref,
                    f"缺少确定版本证据 {item.ref}@{item.version}",
                )
                continue
            if item.declared_sha256 is not None and item.declared_sha256 != row["content_sha256"]:
                gate.block(
                    BlockerCode.CONFLICTED,
                    item.category,
                    item.ref,
                    "声明摘要与登记证据摘要不一致，证据可能已被替换",
                )
            if row["asset_id"] != asset_id:
                gate.block(
                    BlockerCode.ASSET_MISMATCH,
                    item.category,
                    item.ref,
                    f"证据归属资产 {row['asset_id']} 与护照资产 {asset_id} 不一致",
                )
            state = row["state"]
            if state in REVOKED_STATES:
                reason = row["revoke_reason"] or "证据已撤销"
                gate.block(BlockerCode.REVOKED, item.category, item.ref, f"证据已撤销: {reason}")
            elif state in CONFLICTED_STATES:
                gate.block(BlockerCode.CONFLICTED, item.category, item.ref, "证据处于争议/冲突状态")
            elif state in CATEGORY_ACCEPTED_STATES[item.category]:
                snapshots.append(row)
            elif state in PENDING_STATES:
                gate.block(
                    BlockerCode.NOT_DECIDED,
                    item.category,
                    item.ref,
                    f"证据尚未形成终态决定（{state}）",
                )
            else:
                gate.block(
                    BlockerCode.NOT_DECIDED,
                    item.category,
                    item.ref,
                    f"证据状态 {state} 不能作为签发依据",
                )
        for category in CATEGORIES:
            if category not in covered:
                gate.block(
                    BlockerCode.MISSING,
                    category,
                    f"{category}#required",
                    f"护照必须包含至少一份 {category} 类证据",
                )
        return gate, snapshots

    def _idempotent(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM passport_idempotency WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一业务编号/幂等键对应了不同的护照材料")
        return json.loads(row["response_json"])

    def assemble_candidate(
        self,
        actor_id: str,
        passport_no: str,
        asset_id: str,
        evidence: list[Mapping[str, Any]] | tuple[EvidenceRef, ...],
        idempotency_key: str,
        note: str = "",
    ) -> dict[str, Any]:
        self._require(actor_id, "passport.assemble")
        if isinstance(evidence, (list, tuple)) and evidence and isinstance(evidence[0], EvidenceRef):
            refs = tuple(evidence)  # type: ignore[arg-type]
        else:
            refs = tuple(EvidenceRef.from_dict(item) for item in evidence)  # type: ignore[union-attr]
        if not refs:
            raise ValidationFailed("证据列表不能为空")
        request_digest = digest_value(
            {
                "passport_no": passport_no,
                "asset_id": asset_id,
                "evidence": [
                    {
                        "category": item.category,
                        "ref": item.ref,
                        "version": item.version,
                        "content_sha256": item.declared_sha256,
                    }
                    for item in refs
                ],
            }
        )
        scope = f"assemble:{passport_no}"
        existing = self._idempotent(scope, idempotency_key, request_digest)
        if existing is not None:
            # 材料相同：返回原版本的当前状态（可能已由候选变为已签发/已吊销）。
            fresh = self.connection.execute(
                "SELECT * FROM passport_versions WHERE passport_no=? AND content_sha256=?",
                (passport_no, request_digest),
            ).fetchone()
            if fresh is not None:
                existing = self._version_summary(fresh)
            self._raise_if_blocked(existing)
            return existing

        with transaction(self.connection, immediate=True):
            passport_row = self.connection.execute(
                "SELECT * FROM passports WHERE passport_no=?", (passport_no,)
            ).fetchone()
            if passport_row is None:
                self.connection.execute(
                    "INSERT INTO passports(passport_no,asset_id,current_version,created_by,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (passport_no, asset_id, None, actor_id, self._now()),
                )
                previous_version = None
                replaces_version = None
                version_no = 1
            else:
                if passport_row["asset_id"] != asset_id:
                    raise Conflict("业务编号已绑定其他资产，不能跨资产复用")
                replaces_version = passport_row["current_version"]
                open_candidate = self.connection.execute(
                    "SELECT version_no,content_sha256,gate_blockers_json FROM passport_versions "
                    "WHERE passport_no=? AND state='candidate' ORDER BY version_no DESC LIMIT 1",
                    (passport_no,),
                ).fetchone()
                max_row = self.connection.execute(
                    "SELECT coalesce(max(version_no),0) AS m FROM passport_versions WHERE passport_no=?",
                    (passport_no,),
                ).fetchone()
                version_no = int(max_row["m"]) + 1
                previous_version = None if version_no == 1 else version_no - 1
                if open_candidate is not None:
                    if open_candidate["content_sha256"] == request_digest:
                        # 相同材料重试：返回原候选（仍可能带阻断）。
                        response = self._version_summary(
                            self.connection.execute(
                                "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
                                (passport_no, open_candidate["version_no"]),
                            ).fetchone()
                        )
                        self._store_idempotency(scope, idempotency_key, request_digest, response)
                        self._raise_if_blocked(response)
                        return response
                    stale = bool(json.loads(open_candidate["gate_blockers_json"]))
                    if not stale:
                        # 候选出生时门禁通过，但其依据证据可能在组装后被撤销/删除/替换。
                        try:
                            self._revalidate_frozen_evidence(passport_no, open_candidate["version_no"])
                        except EvidenceGateBlocked:
                            stale = True
                    if stale:
                        # 原候选已不可签发：留痕放弃后允许用修正后的材料开新版本。
                        self.connection.execute(
                            "UPDATE passport_versions SET state='abandoned' WHERE passport_no=? AND version_no=?",
                            (passport_no, open_candidate["version_no"]),
                        )
                        self._audit(
                            "passport", passport_no, "candidate.abandoned", actor_id,
                            {"version_no": open_candidate["version_no"],
                             "reason": "证据门禁未通过或依据证据失效，使用修正材料重新组装"},
                        )
                    else:
                        raise Conflict("存在未签发的候选版本，请先签发或放弃后再组装新材料")

            gate, snapshots = self._evaluate_gate(asset_id, refs)
            claims = self._build_claims(asset_id, snapshots)
            manifest = self._build_manifest(snapshots)
            # 内容摘要覆盖全部请求材料（含被阻断项），由规范化输入确定性重算，
            # 与请求摘要一致，从而“相同材料”必然命中同一版本。
            content_sha = request_digest
            # 内容寻址：任一版本已冻结过完全相同的材料，则返回原版本。
            same = self.connection.execute(
                "SELECT * FROM passport_versions WHERE passport_no=? AND content_sha256=?",
                (passport_no, content_sha),
            ).fetchone()
            if same is not None:
                response = self._version_summary(same)
                self._store_idempotency(scope, idempotency_key, request_digest, response)
                self._audit(
                    "passport",
                    passport_no,
                    "candidate.replayed",
                    actor_id,
                    {"version_no": response["version_no"], "content_sha256": content_sha},
                )
                self._raise_if_blocked(response)
                return response

            now = self._now()
            self.connection.execute(
                "INSERT INTO passport_versions(passport_no,version_no,state,claims_json,manifest_json,"
                "content_sha256,gate_blockers_json,assembled_by,assembled_at,previous_version,replaces_version) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    passport_no,
                    version_no,
                    "candidate",
                    canonical_json(claims),
                    canonical_json(manifest),
                    content_sha,
                    canonical_json(gate.as_dicts()),
                    actor_id,
                    now,
                    previous_version,
                    replaces_version,
                ),
            )
            for row in snapshots:
                self.connection.execute(
                    "INSERT INTO passport_version_evidence(passport_no,version_no,category,ref,version,"
                    "asset_id,content_sha256,state_at_assembly,payload_json,registered_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        passport_no,
                        version_no,
                        row["category"],
                        row["ref"],
                        row["version"],
                        row["asset_id"],
                        row["content_sha256"],
                        row["state"],
                        row["payload_json"],
                        row["registered_at"],
                    ),
                )
            self._sign(passport_no, version_no, "assembled", actor_id, content_sha, note or None)
            self._audit(
                "passport",
                passport_no,
                "candidate.assembled",
                actor_id,
                {
                    "version_no": version_no,
                    "content_sha256": content_sha,
                    "gate_passed": gate.passed,
                    "blockers": gate.as_dicts(),
                    "replaces_version": replaces_version,
                },
            )
            response = self._version_summary(
                self.connection.execute(
                    "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
                    (passport_no, version_no),
                ).fetchone()
            )
            self._store_idempotency(scope, idempotency_key, request_digest, response)

        if not gate.passed:
            raise EvidenceGateBlocked(gate.as_dicts())
        return response

    def _store_idempotency(
        self, scope: str, key: str, request_digest: str, response: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO passport_idempotency(scope,key,request_sha256,response_json,created_at) "
            "VALUES(?,?,?,?,?)",
            (scope, key, request_digest, canonical_json(response), self._now()),
        )

    @staticmethod
    def _raise_if_blocked(response: Mapping[str, Any]) -> None:
        blockers = response.get("gate_blockers") or []
        if blockers:
            raise EvidenceGateBlocked(blockers)

    def _revalidate_frozen_evidence(self, passport_no: str, version_no: int) -> None:
        """签发前复查：组装后被撤销、删除或内容被替换的证据必须再次阻断签发。"""

        blockers: list[dict[str, str]] = []
        frozen_rows = self.connection.execute(
            "SELECT category,ref,version,content_sha256,state_at_assembly "
            "FROM passport_version_evidence WHERE passport_no=? AND version_no=?",
            (passport_no, version_no),
        ).fetchall()
        for frozen in frozen_rows:
            current = self.connection.execute(
                "SELECT content_sha256,state,revoke_reason FROM evidence_records "
                "WHERE category=? AND ref=? AND version=?",
                (frozen["category"], frozen["ref"], frozen["version"]),
            ).fetchone()
            if current is None:
                blockers.append(
                    {"code": "missing", "category": frozen["category"], "ref": frozen["ref"],
                     "message": "证据在组装后被删除"}
                )
            elif current["content_sha256"] != frozen["content_sha256"]:
                blockers.append(
                    {"code": "conflicted", "category": frozen["category"], "ref": frozen["ref"],
                     "message": "证据内容在组装后被替换"}
                )
            elif current["state"] in REVOKED_STATES:
                blockers.append(
                    {"code": "revoked", "category": frozen["category"], "ref": frozen["ref"],
                     "message": f"证据在组装后被撤销: {current['revoke_reason'] or '证据已撤销'}"}
                )
            elif current["state"] in CONFLICTED_STATES:
                blockers.append(
                    {"code": "conflicted", "category": frozen["category"], "ref": frozen["ref"],
                     "message": "证据在组装后进入争议状态"}
                )
        if blockers:
            raise EvidenceGateBlocked(blockers)

    def _sign(
        self,
        passport_no: str,
        version_no: int,
        action: str,
        signer_id: str,
        content_sha: str,
        reason: str | None,
    ) -> None:
        role = self.connection.execute(
            "SELECT role FROM passport_users WHERE user_id=?", (signer_id,)
        ).fetchone()["role"]
        self.connection.execute(
            "INSERT INTO passport_signatures(passport_no,version_no,action,signer_id,signer_role,"
            "content_sha256,reason,signed_at) VALUES(?,?,?,?,?,?,?,?)",
            (passport_no, version_no, action, signer_id, role, content_sha, reason, self._now()),
        )

    # --------------------------------------------------------------------- 签发

    def issue(
        self,
        actor_id: str,
        passport_no: str,
        version_no: int,
        idempotency_key: str,
        expected_content_sha256: str | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "passport.issue")
        request_digest = digest_value(
            {"passport_no": passport_no, "version_no": version_no, "expected": expected_content_sha256}
        )
        scope = f"issue:{passport_no}:{version_no}"
        existing = self._idempotent(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
                (passport_no, version_no),
            ).fetchone()
            if row is None:
                raise NotFound("护照版本不存在")
            if row["state"] == "issued":
                # 同键重试已在上面的幂等检查中返回原结果；用新键重复签发属于非法状态变更。
                raise InvalidState("版本已经签发，不能重复签发")
            if row["state"] != "candidate":
                raise InvalidState(f"版本处于 {row['state']} 状态，不能签发")
            blockers = json.loads(row["gate_blockers_json"])
            if blockers:
                # 绝不放行：阻断证据必须先通过重新组装形成新版本解决。
                raise InvalidState("证据门禁存在阻断，不能签发")
            # 组装之后证据若被撤销/删除/替换，于签发瞬间再次阻断。
            self._revalidate_frozen_evidence(passport_no, version_no)
            if expected_content_sha256 is not None and expected_content_sha256 != row["content_sha256"]:
                raise Conflict("期望摘要与候选版本不一致")
            now = self._now()
            self.connection.execute(
                "UPDATE passport_versions SET state='issued',issued_by=?,issued_at=? "
                "WHERE passport_no=? AND version_no=? AND state='candidate'",
                (actor_id, now, passport_no, version_no),
            )
            self.connection.execute(
                "UPDATE passports SET current_version=? WHERE passport_no=?",
                (version_no, passport_no),
            )
            self._sign(passport_no, version_no, "issued", actor_id, row["content_sha256"], None)
            self._audit(
                "passport",
                passport_no,
                "passport.issued",
                actor_id,
                {"version_no": version_no, "content_sha256": row["content_sha256"], "issued_at": now},
            )
            response = self._version_summary(
                self.connection.execute(
                    "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
                    (passport_no, version_no),
                ).fetchone()
            )
            self._store_idempotency(scope, idempotency_key, request_digest, response)
        return response

    def abandon_candidate(self, actor_id: str, passport_no: str, version_no: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "passport.assemble")
        if not reason.strip():
            raise ValidationFailed("放弃原因不能为空")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT state FROM passport_versions WHERE passport_no=? AND version_no=?",
                (passport_no, version_no),
            ).fetchone()
            if row is None:
                raise NotFound("护照版本不存在")
            if row["state"] != "candidate":
                raise InvalidState("只有候选版本可以放弃")
            self.connection.execute(
                "UPDATE passport_versions SET state='abandoned' WHERE passport_no=? AND version_no=?",
                (passport_no, version_no),
            )
            self._audit(
                "passport", passport_no, "candidate.abandoned", actor_id,
                {"version_no": version_no, "reason": reason.strip()},
            )
        return {"passport_no": passport_no, "version_no": version_no, "state": "abandoned"}

    # --------------------------------------------------------------------- 吊销

    def revoke(self, actor_id: str, passport_no: str, version_no: int | None, reason: str) -> dict[str, Any]:
        self._require(actor_id, "passport.revoke")
        if not reason.strip():
            raise ValidationFailed("吊销原因不能为空")
        with transaction(self.connection, immediate=True):
            if version_no is None:
                row = self.connection.execute(
                    "SELECT version_no FROM passport_versions WHERE passport_no=? AND state='issued' "
                    "ORDER BY version_no DESC LIMIT 1",
                    (passport_no,),
                ).fetchone()
                if row is None:
                    raise InvalidState("没有已签发版本可吊销")
                version_no = int(row["version_no"])
            row = self.connection.execute(
                "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
                (passport_no, version_no),
            ).fetchone()
            if row is None:
                raise NotFound("护照版本不存在")
            if row["state"] != "issued":
                raise InvalidState(f"版本处于 {row['state']} 状态，不能吊销")
            now = self._now()
            self.connection.execute(
                "UPDATE passport_versions SET state='revoked',revoke_reason=?,revoked_by=?,revoked_at=? "
                "WHERE passport_no=? AND version_no=? AND state='issued'",
                (reason.strip(), actor_id, now, passport_no, version_no),
            )
            cursor = self.connection.execute(
                "UPDATE passport_references SET state='invalidated',invalidated_at=?,invalidate_reason=? "
                "WHERE passport_no=? AND version_no=? AND state='pending'",
                (now, f"护照版本已吊销: {reason.strip()}", passport_no, version_no),
            )
            invalidated = cursor.rowcount
            self._sign(passport_no, version_no, "revoked", actor_id, row["content_sha256"], reason.strip())
            self._audit(
                "passport",
                passport_no,
                "passport.revoked",
                actor_id,
                {"version_no": version_no, "reason": reason.strip(), "invalidated_references": invalidated},
            )
        return {
            "passport_no": passport_no,
            "version_no": version_no,
            "state": "revoked",
            "reason": reason.strip(),
            "invalidated_references": invalidated,
        }

    # ----------------------------------------------------------------- 下游引用

    def register_reference(
        self, actor_id: str, passport_no: str, version_no: int, consumer: str, ref_key: str
    ) -> dict[str, Any]:
        self._require(actor_id, "reference.write")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT state FROM passport_versions WHERE passport_no=? AND version_no=?",
                (passport_no, version_no),
            ).fetchone()
            if row is None:
                raise NotFound("护照版本不存在")
            if row["state"] != "issued":
                raise InvalidState("只能引用已签发版本")
            now = self._now()
            try:
                cursor = self.connection.execute(
                    "INSERT INTO passport_references(passport_no,version_no,consumer,ref_key,state,"
                    "created_by,created_at) VALUES(?,?,?,?, 'pending',?,?)",
                    (passport_no, version_no, consumer.strip(), ref_key.strip(), actor_id, now),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("该消费方引用键已存在") from exc
            reference_id = int(cursor.lastrowid)
            self._audit(
                "reference",
                str(reference_id),
                "reference.registered",
                actor_id,
                {"passport_no": passport_no, "version_no": version_no, "consumer": consumer.strip()},
            )
        return {
            "reference_id": reference_id,
            "passport_no": passport_no,
            "version_no": version_no,
            "state": "pending",
        }

    def complete_reference(self, actor_id: str, reference_id: int) -> dict[str, Any]:
        self._require(actor_id, "reference.write")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM passport_references WHERE reference_id=?", (reference_id,)
            ).fetchone()
            if row is None:
                raise NotFound("下游引用不存在")
            if row["state"] == "completed":
                return dict(row)
            if row["state"] != "pending":
                raise InvalidState(f"引用已{row['state']}，不能完成")
            self.connection.execute(
                "UPDATE passport_references SET state='completed',completed_at=? WHERE reference_id=? AND state='pending'",
                (self._now(), reference_id),
            )
        return {
            "reference_id": reference_id,
            "passport_no": row["passport_no"],
            "version_no": row["version_no"],
            "state": "completed",
        }

    def list_references(self, actor_id: str, passport_no: str) -> dict[str, Any]:
        self._require(actor_id, "passport.read")
        rows = self.connection.execute(
            "SELECT reference_id,version_no,consumer,ref_key,state,created_at,completed_at,"
            "invalidated_at,invalidate_reason FROM passport_references WHERE passport_no=? "
            "ORDER BY reference_id",
            (passport_no,),
        ).fetchall()
        return {"passport_no": passport_no, "references": [dict(row) for row in rows]}

    # --------------------------------------------------------------------- 查询

    @staticmethod
    def _version_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "passport_no": row["passport_no"],
            "version_no": row["version_no"],
            "state": row["state"],
            "content_sha256": row["content_sha256"],
            "claims": json.loads(row["claims_json"]),
            "manifest": json.loads(row["manifest_json"]),
            "gate_blockers": json.loads(row["gate_blockers_json"]),
            "assembled_by": row["assembled_by"],
            "assembled_at": row["assembled_at"],
            "issued_by": row["issued_by"],
            "issued_at": row["issued_at"],
            "previous_version": row["previous_version"],
            "replaces_version": row["replaces_version"],
            "revoke_reason": row["revoke_reason"],
        }

    def get_version(self, actor_id: str, passport_no: str, version_no: int) -> dict[str, Any]:
        self._require(actor_id, "passport.read")
        row = self.connection.execute(
            "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
            (passport_no, version_no),
        ).fetchone()
        if row is None:
            raise NotFound("护照版本不存在")
        return self._version_summary(row)

    def list_versions(self, actor_id: str, passport_no: str) -> dict[str, Any]:
        self._require(actor_id, "passport.read")
        rows = self.connection.execute(
            "SELECT passport_no,version_no,state,content_sha256,assembled_at,issued_at,"
            "previous_version,replaces_version,revoke_reason,issued_by,revoked_by "
            "FROM passport_versions WHERE passport_no=? ORDER BY version_no",
            (passport_no,),
        ).fetchall()
        if not rows:
            raise NotFound("护照不存在")
        return {"passport_no": passport_no, "versions": [dict(row) for row in rows]}

    def effective_at(self, actor_id: str, passport_no: str, at: str | None = None) -> dict[str, Any]:
        """返回某一时点（含）有效（已签发且当时未吊销）的护照版本。"""

        self._require(actor_id, "passport.read")
        point = self._now() if at is None else parse_utc_text(at)
        # 取该时点（含）之前最新签发的版本，不论其当前是否已被后续吊销——
        # 这样在“签发后、吊销前”的历史时点仍可复算当时有效的护照。
        row = self.connection.execute(
            "SELECT * FROM passport_versions WHERE passport_no=? AND issued_at IS NOT NULL "
            "AND issued_at<=? ORDER BY issued_at DESC, version_no DESC LIMIT 1",
            (passport_no, point),
        ).fetchone()
        if row is None:
            raise NotFound("该时点没有有效护照")
        result = self._version_summary(row)
        result["as_of"] = point
        if row["state"] == "revoked" and row["revoked_at"] is not None and row["revoked_at"] <= point:
            raise NotFound("该时点护照已被吊销")
        result["currently_revoked"] = row["state"] == "revoked"
        if result["currently_revoked"]:
            result["revoked_at"] = row["revoked_at"]
        return result

    def provenance(self, actor_id: str, passport_no: str, version_no: int) -> dict[str, Any]:
        """逐项追溯声明来源、签署责任与新旧版本关系。"""

        self._require(actor_id, "passport.read")
        version = self.connection.execute(
            "SELECT * FROM passport_versions WHERE passport_no=? AND version_no=?",
            (passport_no, version_no),
        ).fetchone()
        if version is None:
            raise NotFound("护照版本不存在")
        evidence_rows = self.connection.execute(
            "SELECT category,ref,version,asset_id,content_sha256,state_at_assembly,payload_json,registered_at "
            "FROM passport_version_evidence WHERE passport_no=? AND version_no=? "
            "ORDER BY category,ref",
            (passport_no, version_no),
        ).fetchall()
        signatures = self.connection.execute(
            "SELECT action,signer_id,signer_role,content_sha256,reason,signed_at "
            "FROM passport_signatures WHERE passport_no=? AND version_no=? ORDER BY signature_id",
            (passport_no, version_no),
        ).fetchall()
        lineage: list[dict[str, Any]] = []
        cursor_no = version["previous_version"]
        while cursor_no is not None:
            link = self.connection.execute(
                "SELECT version_no,state,content_sha256,previous_version,replaces_version "
                "FROM passport_versions WHERE passport_no=? AND version_no=?",
                (passport_no, cursor_no),
            ).fetchone()
            if link is None:
                break
            lineage.append(dict(link))
            cursor_no = link["previous_version"]
        successors = self.connection.execute(
            "SELECT version_no,state,content_sha256,previous_version,replaces_version "
            "FROM passport_versions WHERE passport_no=? AND previous_version=? ORDER BY version_no",
            (passport_no, version_no),
        ).fetchall()
        return {
            "passport_no": passport_no,
            "version_no": version_no,
            "state": version["state"],
            "content_sha256": version["content_sha256"],
            "claims": json.loads(version["claims_json"]),
            "gate_blockers": json.loads(version["gate_blockers_json"]),
            "evidence": [
                {
                    "category": item["category"],
                    "ref": item["ref"],
                    "version": item["version"],
                    "asset_id": item["asset_id"],
                    "content_sha256": item["content_sha256"],
                    "state_at_assembly": item["state_at_assembly"],
                    "registered_at": item["registered_at"],
                    "payload": json.loads(item["payload_json"]),
                }
                for item in evidence_rows
            ],
            "signatures": [dict(item) for item in signatures],
            "lineage": lineage,
            "successors": [dict(item) for item in successors],
        }

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute(
            "SELECT * FROM passport_audit_events ORDER BY event_id"
        ).fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
