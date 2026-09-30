"""数字产品护照组装输入的严格数据契约。

护照候选包不直接内联来源数据，而是引用「确定版本」的来源记录：每条引用都
必须同时给出记录编号、正整数版本与 64 位内容摘要。服务在签发前逐条核对
引用的真实状态与摘要，杜绝「最新值覆盖」。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

#: 出厂组件谱系
KIND_COMPONENT = "component"
#: 检测结论
KIND_INSPECTION = "inspection"
#: 维修记录
KIND_REPAIR = "repair"
#: 所有权流转事实
KIND_OWNERSHIP = "ownership"
EVIDENCE_KINDS = frozenset(
    {KIND_COMPONENT, KIND_INSPECTION, KIND_REPAIR, KIND_OWNERSHIP}
)

#: 检测结论；只有 pass 能支撑签发，conditional/fail 属于相互冲突的证据。
INSPECTION_RESULTS = frozenset({"pass", "conditional", "fail"})

#: 资产声明的生命周期状态。
ASSET_STATUSES = frozenset({"commissioned", "in_service", "maintenance", "retired"})

#: 所有权流转类型与方向。
OWNERSHIP_KINDS = frozenset({"registration", "transfer"})
TRANSFER_DIRECTIONS = frozenset({"inbound", "outbound", "internal"})

#: 候选包可以声明的证据覆盖要求。
REQUIREMENT_KEYS = frozenset(
    {"components", "inspection", "ownership", "repairs_resolved"}
)


def required_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 必须是非空字符串")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


def identifier(value: object, field: str) -> str:
    result = required_text(value, field, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{field} 格式不正确")
    return result


def digest_value(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} 必须是 64 位 SHA-256")
    result = value.strip().lower()
    if not SHA256.fullmatch(result):
        raise ValidationFailed(f"{field} 必须是 64 位十六进制 SHA-256")
    return result


def positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationFailed(f"{field} 必须是正整数")
    return value


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """对一条确定版本来源记录的引用。"""

    kind: str
    record_id: str
    revision: int
    sha256: str
    role: str | None = None
    note: str | None = None

    @classmethod
    def from_dict(cls, raw: object, path: str) -> "EvidenceRef":
        if not isinstance(raw, Mapping):
            raise ValidationFailed(f"{path} 必须是对象")
        kind = required_text(raw.get("kind"), f"{path}.kind", 32)
        if kind not in EVIDENCE_KINDS:
            raise ValidationFailed(
                f"{path}.kind 必须是 {sorted(EVIDENCE_KINDS)} 之一"
            )
        role_raw = raw.get("role")
        role = None if role_raw is None else required_text(role_raw, f"{path}.role", 64)
        if kind == KIND_COMPONENT and role is None:
            raise ValidationFailed(f"{path}.role 对组件证据必填")
        if kind != KIND_COMPONENT and role is not None:
            raise ValidationFailed(f"{path}.role 仅组件证据可填")
        note_raw = raw.get("note")
        note = None if note_raw is None else required_text(note_raw, f"{path}.note", 512)
        return cls(
            kind=kind,
            record_id=identifier(raw.get("record_id"), f"{path}.record_id"),
            revision=positive_integer(raw.get("revision"), f"{path}.revision"),
            sha256=digest_value(raw.get("sha256"), f"{path}.sha256"),
            role=role,
            note=note,
        )

    def key(self) -> tuple[str, str, int]:
        return (self.kind, self.record_id, self.revision)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "record_id": self.record_id,
            "revision": self.revision,
            "sha256": self.sha256,
            "role": self.role,
            "note": self.note,
        }


def parse_refs(raw: object, field: str) -> tuple[EvidenceRef, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValidationFailed(f"{field} 必须是数组")
    refs = tuple(EvidenceRef.from_dict(item, f"{field}[{index}]") for index, item in enumerate(raw))
    if not refs:
        raise ValidationFailed(f"{field} 不能为空")
    seen: set[tuple[str, str, int]] = set()
    for ref in refs:
        if ref.key() in seen:
            raise ValidationFailed(
                f"{field} 中证据引用重复: {ref.kind}/{ref.record_id}@{ref.revision}"
            )
        seen.add(ref.key())
    return refs


def parse_requirements(raw: object) -> dict[str, bool]:
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ValidationFailed("requirements 必须是对象")
    result: dict[str, bool] = {}
    for key, value in raw.items():
        if key not in REQUIREMENT_KEYS:
            raise ValidationFailed(f"requirements.{key} 不是受支持的要求项")
        if not isinstance(value, bool):
            raise ValidationFailed(f"requirements.{key} 必须是布尔值")
        result[key] = value
    return result
