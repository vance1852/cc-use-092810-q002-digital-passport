"""数字产品护照的输入契约与证据判定。

护照把四类事实材料收敛为统一的 *证据引用*：

- ``asset``：确定版本的资产档案；
- ``component``：出厂组件谱系条目（电芯批次、模组、BMS 等）；
- ``quality``：检测/质量决定（含复核结论）；
- ``transfer``：所有权与流转/维修记录。

每份证据都有独立的状态机。护照候选版本只引用 *确定版本* 的证据，并在签发门禁处
显式检查缺失、撤销（revoked/void/retracted/superseded）与相互冲突。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

# 证据类别 → 允许出现的类别取值（兼容中文/英文别名字面量）。
CATEGORY_ALIASES = {
    "asset": "asset", "资产": "asset",
    "component": "component", "组件": "component", "组件谱系": "component",
    "quality": "quality", "检测": "quality", "质量": "quality", "质量决定": "quality",
    "transfer": "transfer", "流转": "transfer", "所有权": "transfer", "维修": "transfer",
}

# 被视为“撤销/失效”的证据状态；签发时一律阻断。
REVOKED_STATES = frozenset({"revoked", "void", "voided", "retracted", "recalled", "superseded"})
# 终态但有效；其余状态按具体类别判断是否可作为签发依据。
VALID_STATES = frozenset({"active", "effective", "released", "approved", "passed", "closed", "settled", "completed"})
PENDING_STATES = frozenset({"draft", "pending", "in_review", "provisional"})
CONFLICTED_STATES = frozenset({"disputed", "conflicted", "conflict"})


def _identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValidationFailed(f"{field_name} 必须是 1-64 位字母数字 _.:- 标识")
    return value.strip()


def _required_text(value: object, field_name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field_name} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field_name} 不能超过 {maximum} 个字符")
    return result


def normalize_category(value: object) -> str:
    if not isinstance(value, str) or value.strip() not in CATEGORY_ALIASES:
        raise ValidationFailed("证据类别必须是 asset、component、quality 或 transfer")
    return CATEGORY_ALIASES[value.strip()]


def normalize_state(value: object) -> str:
    state = _required_text(value, "证据状态", 32).lower().replace("-", "_").replace(" ", "_")
    return state


class BlockerCode(str, Enum):
    MISSING = "missing"
    REVOKED = "revoked"
    CONFLICTED = "conflicted"
    NOT_DECIDED = "not_decided"
    ASSET_MISMATCH = "asset_mismatch"
    DUPLICATE_REF = "duplicate_ref"
    REUSED_KEY = "reused_key"


@dataclass(frozen=True, slots=True)
class Blocker:
    code: str
    category: str
    ref: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "category": self.category, "ref": self.ref, "message": self.message}


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """候选版本对一份确定版本证据的引用。"""

    category: str
    ref: str
    version: str
    declared_sha256: str | None = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "EvidenceRef":
        if not isinstance(raw, Mapping):
            raise ValidationFailed("证据引用必须是对象")
        return cls(
            category=normalize_category(raw.get("category")),
            ref=_identifier(raw.get("ref") or raw.get("evidence_ref") or raw.get("id"), "证据编号"),
            version=_required_text(raw.get("version"), "证据版本", 64),
            declared_sha256=(
                None
                if raw.get("content_sha256") in (None, "")
                else _sha256(raw.get("content_sha256"), "证据声明摘要")
            ),
        )

    def key(self) -> tuple[str, str]:
        return self.category, self.ref


def _sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()):
        raise ValidationFailed(f"{field_name} 必须是 64 位十六进制 SHA-256")
    return value.strip().lower()


@dataclass(frozen=True, slots=True)
class PassportRequest:
    """组装候选护照版本的请求。"""

    passport_no: str
    asset_id: str
    evidence: tuple[EvidenceRef, ...]
    idempotency_key: str
    note: str = ""

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PassportRequest":
        if not isinstance(raw, Mapping):
            raise ValidationFailed("请求体必须是对象")
        entries = raw.get("evidence")
        if not isinstance(entries, list) or not entries:
            raise ValidationFailed("evidence 必须是非空数组")
        refs = tuple(EvidenceRef.from_dict(item) for item in entries)
        return cls(
            passport_no=_identifier(raw.get("passport_no"), "passport_no"),
            asset_id=_identifier(raw.get("asset_id"), "asset_id"),
            evidence=refs,
            idempotency_key=_identifier(raw.get("idempotency_key"), "idempotency_key"),
            note=str(raw.get("note") or "").strip()[:1000],
        )


@dataclass(slots=True)
class GateResult:
    """证据门禁判定结果。"""

    blockers: list[Blocker] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.blockers

    def block(self, code: BlockerCode, category: str, ref: str, message: str) -> None:
        self.blockers.append(Blocker(code.value, category, ref, message))

    def as_dicts(self) -> list[dict[str, str]]:
        return [item.as_dict() for item in self.blockers]
