"""护照服务可观察错误。"""


class PassportError(RuntimeError):
    code = "passport_error"
    status = 400


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


class EvidenceGateBlocked(PassportError):
    """证据门禁未通过：缺失、撤销或相互冲突，必须明确阻止签发。"""

    code = "evidence_gate_blocked"
    status = 409

    def __init__(self, blockers: list[dict]) -> None:
        super().__init__("证据门禁未通过，护照不能签发")
        self.blockers = blockers
