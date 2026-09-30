"""确定性的 JSON 规范化与内容摘要。"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Iterable


def _json_default(value: object) -> object:
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError(f"不能序列化 {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """生成跨平台一致的紧凑 JSON 文本。"""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def digest_value(value: Any) -> str:
    """单个值的规范化 SHA-256 摘要。"""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def content_digest(values: Iterable[Any]) -> str:
    """按输入顺序计算规范化内容摘要（逐项追加换行，与既有模块保持一致）。"""

    digest = hashlib.sha256()
    for value in values:
        digest.update(canonical_bytes(value))
        digest.update(b"\n")
    return digest.hexdigest()
