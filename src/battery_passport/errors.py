"""数字产品护照服务向接口层暴露的稳定错误。"""

from __future__ import annotations

from typing import Any, Sequence


class PassportError(RuntimeError):
    code = "passport_error"
    status = 400

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.details = details


class NotFound(PassportError):
    code = "not_found"
    status = 404


class Conflict(PassportError):
    code = "conflict"
    status = 409


class Forbidden(PassportError):
    code = "forbidden"
    status = 403


class InvalidState(PassportError):
    code = "invalid_state"
    status = 409


class ValidationFailed(PassportError):
    code = "validation_failed"
    status = 422


class IssuanceBlocked(PassportError):
    """缺失、撤销或相互冲突的证据明确阻止签发。"""

    code = "issuance_blocked"
    status = 409

    def __init__(self, blockers: Sequence[dict[str, Any]]) -> None:
        super().__init__("证据不满足签发条件", {"blockers": list(blockers)})
        self.blockers = list(blockers)
