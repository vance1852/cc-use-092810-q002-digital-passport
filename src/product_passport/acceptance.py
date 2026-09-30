"""数字产品护照完整业务故事的离线验收入口。

场景：一批大型储能电池即将续保，运营方需向保险风控证明每套电池当前声明依据了
哪些出厂组件、检测结论、维修记录和所有权事实。脚本在临时 SQLite 中演示：

1. 登记确定版本的四类证据（资产/组件/质量/流转）；
2. 证据缺失或被撤销时门禁明确阻止签发；
3. 签发后摘要与依据冻结，后续维修只能产生新版本；
4. 相同材料重试返回原护照，不同材料复用幂等键冲突；
5. 吊销保留原因并使未完成下游引用失效；
6. 按时点取回有效护照，并逐项追溯声明来源、签署责任与版本关系。
"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .errors import Conflict, EvidenceGateBlocked
from .service import PassportService
from .storage import connect, inspect_schema


def _evidence(category: str, ref: str, version: str, title: str, payload: dict, *, state: str = "active") -> dict:
    return {
        "category": category, "ref": ref, "version": version, "title": title,
        "payload": payload, "state": state,
    }


def run(workspace: Path) -> dict[str, object]:
    base_time = datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)
    with tempfile.TemporaryDirectory(prefix="product-passport-") as temporary:
        database = Path(temporary) / "passport.sqlite3"
        connection = connect(database)
        try:
            clock = FrozenClock(base_time)
            service = PassportService(connection, clock)
            for user_id, role in (
                ("registrar-1", "registrar"),
                ("operator-1", "operator"),
                ("issuer-1", "issuer"),
                ("auditor-1", "auditor"),
                ("insurer-1", "consumer"),
            ):
                service.create_user(user_id, user_id, role)

            asset_id = "bess-pack-0001"
            passport_no = "DPP-BESS-0001"

            def register(item: dict) -> dict:
                return service.register_evidence(
                    "registrar-1", item["category"], item["ref"], item["version"], asset_id,
                    item["title"], item["payload"], item["state"],
                )

            register(_evidence("asset", "asset-card", "1.0", "储能电池资产档案",
                               {"model": "BESS-20MWh-LFP", "vendor": "宁德示例", "rated_kwh": 20000}))
            register(_evidence("component", "cell-lot-A", "3", "出厂电芯批次谱系",
                               {"chemistry": "LFP", "cell_count": 12288, "line": "L7"}))
            register(_evidence("component", "bms-unit-7", "2", "BMS 控制单元",
                               {"firmware": "4.2.1", "manufactured": "2024-03-11"}))
            register(_evidence("quality", "qa-report-2024", "1", "出厂检测与质量决定",
                               {"conclusion": "passed", "capacity_retention": "1.000", "soh": "1.000"},
                               state="approved"))
            register(_evidence("transfer", "ownership-2024", "1", "所有权登记与场站流转",
                               {"owner": "示例储能运营有限公司", "site": "北部储能站", "bill_of_sale": "BoS-77"},
                               state="closed"))

            good_refs = [
                {"category": "asset", "ref": "asset-card", "version": "1.0"},
                {"category": "component", "ref": "cell-lot-A", "version": "3"},
                {"category": "component", "ref": "bms-unit-7", "version": "2"},
                {"category": "quality", "ref": "qa-report-2024", "version": "1"},
                {"category": "transfer", "ref": "ownership-2024", "version": "1"},
            ]

            # --- 门禁：缺少 transfer 证据时不能签发（形成 v1 失败候选） ---
            incomplete = [item for item in good_refs if item["category"] != "transfer"]
            try:
                service.assemble_candidate("operator-1", passport_no, asset_id, incomplete, "try-incomplete")
                raise RuntimeError("缺少流转证据时本应阻断")
            except EvidenceGateBlocked as exc:
                missing_codes = {b["code"] for b in exc.blockers}
                assert "missing" in missing_codes

            # --- 完整材料组装 v2（v1 失败候选自动留痕放弃）并签发 ---
            candidate = service.assemble_candidate(
                "operator-1", passport_no, asset_id, good_refs, "assemble-v1", "续保前首版"
            )
            assert candidate["version_no"] == 2 and candidate["state"] == "candidate"
            digest_clean = candidate["content_sha256"]
            issued_clean = service.issue("issuer-1", passport_no, 2, "issue-v1")
            assert issued_clean["state"] == "issued"

            # --- 证据在签发后被撤销：不影响已交付历史，但会阻断后续新版本 ---
            service.revoke_evidence(
                "registrar-1", "quality", "qa-report-2024", "1", "原始检测仪器校准过期"
            )
            frozen = service.get_version("auditor-1", passport_no, 2)
            assert frozen["state"] == "issued"

            # 重新登记有效的检测决定（新版本证据），再组装新版本。
            clock.advance(days=1)
            register(_evidence("quality", "qa-report-2024", "2", "复检质量决定",
                               {"conclusion": "passed", "capacity_retention": "0.986", "soh": "0.986",
                                "recheck_reason": "仪器校准后复检"},
                               state="approved"))
            refs_v3 = [
                item if item["ref"] != "qa-report-2024"
                else {"category": "quality", "ref": "qa-report-2024", "version": "2"}
                for item in good_refs
            ]
            candidate_v3 = service.assemble_candidate(
                "operator-1", passport_no, asset_id, refs_v3, "assemble-v2", "复检后组装"
            )
            assert candidate_v3["version_no"] == 3
            issued_v3 = service.issue("issuer-1", passport_no, 3, "issue-v2")
            assert issued_v3["state"] == "issued"

            # --- 相同材料重试：返回原护照 ---
            replay = service.assemble_candidate(
                "operator-1", passport_no, asset_id, refs_v3, "assemble-v2", "复检后组装"
            )
            assert replay["version_no"] == 3
            assert replay["content_sha256"] == candidate_v3["content_sha256"]
            replay_issue = service.issue("issuer-1", passport_no, 3, "issue-v2")
            assert replay_issue["state"] == "issued"

            # --- 不同材料复用同一业务幂等键：冲突 ---
            try:
                service.assemble_candidate(
                    "operator-1", passport_no, asset_id, good_refs, "assemble-v2"
                )
                raise RuntimeError("不同材料复用幂等键本应冲突")
            except Conflict:
                pass

            # --- 保险方在 v3 有效期间建立下游引用 ---
            clock.advance(days=2)
            reference = service.register_reference(
                "insurer-1", passport_no, 3, "保险风控", "renewal-2026-underwriting"
            )
            reference_id = reference["reference_id"]

            # v3 签发时点的有效护照可复算。
            at_issue = issued_v3["issued_at"]
            effective_v3 = service.effective_at("insurer-1", passport_no, at_issue)
            assert effective_v3["version_no"] == 3

            # --- 后续维修只能产生新版本，不能改写已交付历史 ---
            clock.advance(days=30)
            register(_evidence("transfer", "maintenance-2026", "1", "簇控制器维修记录",
                               {"action": "replaced-cluster-controller", "work_order": "WO-5512"},
                               state="closed"))
            refs_v4 = refs_v3 + [
                {"category": "transfer", "ref": "maintenance-2026", "version": "1"}
            ]
            candidate_v4 = service.assemble_candidate(
                "operator-1", passport_no, asset_id, refs_v4, "assemble-v3", "维修后更新"
            )
            assert candidate_v4["version_no"] == 4
            assert candidate_v4["replaces_version"] == 3
            issued_v4 = service.issue("issuer-1", passport_no, 4, "issue-v3")
            assert issued_v4["state"] == "issued"

            # 历史时点仍取回 v3，内容摘要保持冻结。
            historical = service.effective_at("auditor-1", passport_no, at_issue)
            assert historical["version_no"] == 3
            assert historical["content_sha256"] == candidate_v3["content_sha256"]

            # --- 逐项追溯声明来源、签署责任与版本关系 ---
            provenance = service.provenance("auditor-1", passport_no, 4)
            categories = {item["category"] for item in provenance["evidence"]}
            assert categories == {"asset", "component", "quality", "transfer"}
            actions = [item["action"] for item in provenance["signatures"]]
            assert actions == ["assembled", "issued"]
            assert provenance["lineage"][0]["version_no"] == 3

            # --- 吊销 v3：保留原因，未完成的下游引用失效 ---
            clock.advance(hours=6)
            revoked = service.revoke(
                "issuer-1", passport_no, 3, "复检批次被厂商召回，历史版本对保险方标记失效"
            )
            assert revoked["invalidated_references"] == 1
            refs_after = service.list_references("auditor-1", passport_no)["references"]
            pending_ref = next(item for item in refs_after if item["reference_id"] == reference_id)
            assert pending_ref["state"] == "invalidated"
            assert "召回" in pending_ref["invalidate_reason"]

            # 已完成的引用不受吊销影响（补一条已完成引用验证）。
            done_ref = service.register_reference(
                "insurer-1", passport_no, 4, "理赔系统", "claim-archived-1"
            )
            service.complete_reference("insurer-1", done_ref["reference_id"])
            service.revoke("issuer-1", passport_no, 4, "演示吊销最新版本")
            done = next(
                item for item in service.list_references("auditor-1", passport_no)["references"]
                if item["reference_id"] == done_ref["reference_id"]
            )
            assert done["state"] == "completed"

            schema = inspect_schema(connection)
            audit = service.audit_chain("auditor-1")
            versions = service.list_versions("auditor-1", passport_no)["versions"]
        finally:
            connection.close()

    if schema["missing_tables"] or schema["schema_version"] != "1":
        raise RuntimeError("数字产品护照 SQLite 结构检查失败")
    if not audit["valid"]:
        raise RuntimeError("护照审计哈希链校验失败")
    return {
        "status": "ok",
        "passport_no": passport_no,
        "asset_id": asset_id,
        "digest_clean": digest_clean,
        "issued_versions": [2, 3, 4],
        "version_states": [(item["version_no"], item["state"]) for item in versions],
        "historical_version": historical["version_no"],
        "historical_digest_frozen": historical["content_sha256"] == candidate_v3["content_sha256"],
        "provenance_evidence_kinds": sorted(categories),
        "invalidated_reference": pending_ref["state"],
        "audit": audit,
        "schema": schema,
        "workspace": workspace.name,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行数字产品护照离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace.resolve()), ensure_ascii=False, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
