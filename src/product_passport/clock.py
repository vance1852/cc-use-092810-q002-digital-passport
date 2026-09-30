"""可注入时间源。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass
class FrozenClock:
    current: datetime

    def now(self) -> datetime:
        if self.current.tzinfo is None:
            raise ValueError("冻结时钟必须带时区")
        return self.current

    def advance(self, **kwargs: float) -> None:
        self.current += timedelta(**kwargs)


def isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("时间必须带时区")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc_text(value: object) -> str:
    """解析带时区的时间文本并归一化为 UTC 的 Z 形式，便于字典序比较。"""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("时间文本不能为空")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("时间必须是 ISO 8601 文本") from exc
    if parsed.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return isoformat(parsed)
