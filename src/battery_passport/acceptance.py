"""数字产品护照的离线验收入口。

在临时 SQLite 数据库里走完一套大型储能电池续保前的护照生命周期：
确定版本资产与四类证据 -> 组装候选 -> 签发冻结 -> 同材料重试 / 异材冲突 /
新版本取代 -> 吊销保留原因并使未完成下游引用失效 -> 时点有效查询与逐项追溯，
并演示缺失 / 撤销证据如何明确阻止签发。不访问外部网络。
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .errors import IssuanceBlocked
from .service import PassportService
from .storage import connect, inspect_schema


def _refs(*items: dict) -> list[dict]:
    return list(items)


def run(workspace: Path | None = None) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="battery-passport-") as temporary:
        database = Path(temporary) / "passport.sqlite3"
        connection = connect(database)
        try:
            service = PassportService(connection)
            service.create_user("operator-1", "运营责任方", "operator")
            service.create_user("quality-1", "质量责任方", "quality")
            service.create_user("approver-1", "签发审批人", "approver")
            service.create_user("auditor-1", "保险审计人", "auditor")

            # 确定版本的资产。
            asset = service.register_asset(
                "operator-1", "bess-2mwh-01", "2MWh 液冷储能系统", "示例电芯厂",
                "in_service", {"energy_kwh": 2000, "chemistry": "LFP"},
            )

            # 四类来源证据：出厂组件、检测结论、维修记录、所有权登记。
            pack = service.record_evidence(
                "quality-1", "component", "pack-A01", 1, "bess-2mwh-01",
                {"component": "battery_pack", "serial": "PACK-A01", "capacity_kwh": 280},
            )
            bms = service.record_evidence(
                "quality-1", "component", "bms-07", 1, "bess-2mwh-01",
                {"component": "bms", "serial": "BMS-07", "firmware": "3.2.1"},
            )
            inspection = service.record_evidence(
                "quality-1", "inspection", "insp-2026-09", 1, "bess-2mwh-01",
                {"result": "pass", "standard": "GB/T 36276", "inspector": "质量-1"},
            )
            repair = service.record_evidence(
                "quality-1", "repair", "repair-0518", 1, "bess-2mwh-01",
                {"status": "closed", "summary": "更换 2 个温度传感器", "closed_at": "2026-06-02"},
            )
            ownership = service.record_evidence(
                "operator-1", "ownership", "title-0001", 1, "bess-2mwh-01",
                {"transfer_kind": "registration", "holder": "示例新能源运营有限公司",
                 "registered_at": "2025-03-10"},
            )

            refs = _refs(
                {"kind": "component", "record_id": "pack-A01", "revision": 1,
                 "sha256": pack["content_sha256"], "role": "battery_pack"},
                {"kind": "component", "record_id": "bms-07", "revision": 1,
                 "sha256": bms["content_sha256"], "role": "bms"},
                {"kind": "inspection", "record_id": "insp-2026-09", "revision": 1,
                 "sha256": inspection["content_sha256"]},
                {"kind": "repair", "record_id": "repair-0518", "revision": 1,
                 "sha256": repair["content_sha256"]},
                {"kind": "ownership", "record_id": "title-0001", "revision": 1,
                 "sha256": ownership["content_sha256"]},
            )

            # 缺失证据必须阻止签发：候选引用一条尚不存在的检测结论。
            service.create_candidate(
                "operator-1", "cand-blocked", "bess-2mwh-01", asset["revision"],
                [dict(refs[0]), {"kind": "inspection", "record_id": "insp-missing",
                                 "revision": 1, "sha256": "0" * 64}, dict(refs[4])],
            )
            blocked_codes: set[str] = set()
            try:
                service.issue_passport(
                    "approver-1", "cand-blocked", "issue-blocked", business_no="DPP-BLOCKED"
                )
            except IssuanceBlocked as exc:
                blocked_codes = {item["code"] for item in exc.blockers}
            if "evidence_missing" not in blocked_codes:
                raise RuntimeError("缺失证据未阻止签发")

            # 组装正式候选并签发第一版。
            service.create_candidate(
                "operator-1", "cand-v1", "bess-2mwh-01", asset["revision"], refs
            )
            passport_v1 = service.issue_passport(
                "approver-1", "cand-v1", "issue-v1", business_no="DPP-2026-0001"
            )
            if passport_v1["version"] != 1:
                raise RuntimeError("首版护照版本号应为 1")

            # 相同材料的重试（即使换了签发请求编号）返回同一本护照。
            replayed = service.issue_passport("approver-1", "cand-v1", "issue-v1-retry")
            if replayed["passport_id"] != passport_v1["passport_id"] or not replayed["replayed"]:
                raise RuntimeError("相同材料重试未返回原护照")

            # 保险方建立一个未完成的下游引用。
            service.create_reference(
                "operator-1", "ref-insurance-v1", passport_v1["passport_id"],
                "保险风控团队", "2026 年度续保尽调",
            )

            # 后续新检测：登记检测结论新版本（旧版本保留、不可改写）。
            service.record_evidence(
                "quality-1", "inspection", "insp-2026-09", 2, "bess-2mwh-01",
                {"result": "pass", "standard": "GB/T 36276", "inspector": "质量-1",
                 "cycle_count": 410}, supersedes=1,
            )
            inspection_v2 = connection.execute(
                "SELECT content_sha256 FROM evidence_records "
                "WHERE kind='inspection' AND record_id='insp-2026-09' AND revision=2"
            ).fetchone()["content_sha256"]

            # 不同内容复用同一业务编号必须冲突。
            refs_conflict = [dict(item) for item in refs]
            refs_conflict[2] = {"kind": "inspection", "record_id": "insp-2026-09",
                                "revision": 2, "sha256": inspection_v2}
            service.create_candidate(
                "operator-1", "cand-v2-conflict", "bess-2mwh-01", asset["revision"], refs_conflict
            )
            reuse_conflicted = False
            try:
                service.issue_passport(
                    "approver-1", "cand-v2-conflict", "issue-conflict",
                    business_no="DPP-2026-0001",
                )
            except Exception:
                reuse_conflicted = True
            if not reuse_conflicted:
                raise RuntimeError("不同内容复用业务编号未报冲突")

            # 显式取代当前版本，产生第二版；第一版冻结为 superseded。
            passport_v2 = service.issue_passport(
                "approver-1", "cand-v2-conflict", "issue-v2",
                replaces_passport_id=passport_v1["passport_id"],
            )
            if passport_v2["version"] != 2 or passport_v2["business_no"] != "DPP-2026-0001":
                raise RuntimeError("新版本未正确续接业务编号")

            service.create_reference(
                "operator-1", "ref-insurance-v2", passport_v2["passport_id"],
                "保险风控团队", "2027 年度续保尽调",
            )

            # 事后发现第二版所依据的检测结论新版本被撤销 -> 吊销护照并保留原因，
            # 未完成的下游引用随之失效；已完成历史不受影响。
            service.revoke_evidence(
                "quality-1", "inspection", "insp-2026-09", 2, "复测发现循环计数记录错误"
            )
            revoked = service.revoke_passport(
                "approver-1", passport_v2["passport_id"], "依据的检测结论已撤销"
            )
            if "ref-insurance-v2" not in revoked["invalidated_references"]:
                raise RuntimeError("吊销未使未完成下游引用失效")

            # 第一版的内容仍然冻结可读，没有被新检测改写。
            frozen_v1 = service.get_version("auditor-1", "DPP-2026-0001", 1)
            frozen_inspection = next(
                s for s in frozen_v1["payload"]["statements"]
                if s["kind"] == "inspection"
            )
            if frozen_inspection["revision"] != 1 or frozen_inspection["sha256"] != inspection["content_sha256"]:
                raise RuntimeError("已交付护照的历史被改写")

            # 时点有效性：在第二版签发之前（第一版签发当时）有效的是 v1。
            effective_before = service.effective_passport(
                "auditor-1", "bess-2mwh-01", at=passport_v1["issued_at"]
            )
            # 当前最新版本已吊销 -> 不存在有效护照（旧版不会复活）。
            no_effective_now = False
            try:
                service.effective_passport("auditor-1", "bess-2mwh-01")
            except Exception:
                no_effective_now = True

            versions = service.list_versions("auditor-1", "DPP-2026-0001")
            trace_v1 = service.trace("auditor-1", passport_v1["passport_id"])
            audit = service.audit_log("auditor-1")
            schema = inspect_schema(connection)
        finally:
            connection.close()

    if effective_before["passport_id"] != passport_v1["passport_id"]:
        raise RuntimeError("时点有效护照查询不正确")
    if not no_effective_now:
        raise RuntimeError("最新版本吊销后不应返回任何有效护照")
    if len(trace_v1["sources"]) != len(refs):
        raise RuntimeError("逐项追溯的声明数量不正确")
    if schema["missing_tables"] or schema["schema_version"] != "1":
        raise RuntimeError("SQLite 结构检查失败")

    return {
        "status": "ok",
        "business_no": "DPP-2026-0001",
        "v1_passport_id": passport_v1["passport_id"],
        "v2_passport_id": passport_v2["passport_id"],
        "v1_content_sha256": passport_v1["content_sha256"],
        "replayed_same_passport": replayed["passport_id"] == passport_v1["passport_id"],
        "reuse_business_no_conflicted": reuse_conflicted,
        "blocked_codes": sorted(blocked_codes),
        "revoked_invalidated_references": revoked["invalidated_references"],
        "version_states": [(v["version"], v["state"]) for v in versions["versions"]],
        "effective_before_revocation": effective_before["passport_id"],
        "no_effective_after_revocation": no_effective_now,
        "traced_sources": len(trace_v1["sources"]),
        "audit_events": len(audit["events"]),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行数字产品护照能力的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
