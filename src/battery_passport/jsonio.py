"""确定性的规范化 JSON 与内容摘要。

护照的复算性建立在「同样的材料必然得到同样的摘要」之上：候选包只引用
确定版本（带摘要）的来源记录，组装与签发全程使用这里的规范化序列化。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


def _json_default(value: object) -> object:
    raise TypeError(f"不能规范化序列化 {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """生成跨平台一致、按键排序的紧凑 JSON 文本。"""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def content_digest(values: Iterable[Any]) -> str:
    """按输入顺序计算规范化内容摘要。"""

    digest = hashlib.sha256()
    for value in values:
        digest.update(canonical_json(value).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
