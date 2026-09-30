"""数字产品护照的无第三方依赖 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import IssuanceBlocked, PassportError, ValidationFailed
from .service import PassportService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    """把 HTTP 路由映射到护照领域服务，便于无网络单元测试。"""

    def __init__(self, service: PassportService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok", "service": "battery-passport"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}

            if method == "POST" and path == "/users":
                result = self.service.create_user(
                    payload["user_id"], payload["display_name"], payload["role"]
                )
                return Response(201, result)

            if method == "POST" and path == "/assets":
                result = self.service.register_asset(
                    self._actor(normalized), payload["asset_id"], payload["model_name"],
                    payload["vendor"], payload.get("status", "commissioned"),
                    payload.get("attributes"),
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "assets" and parts[2] == "revisions":
                result = self.service.revise_asset(
                    self._actor(normalized), parts[1], payload["model_name"], payload["vendor"],
                    payload["status"], payload.get("attributes"),
                )
                return Response(201, result)

            if method == "POST" and path == "/evidence":
                result = self.service.record_evidence(
                    self._actor(normalized), payload["kind"], payload["record_id"],
                    int(payload["revision"]), payload["asset_id"], payload["payload"],
                    None if payload.get("supersedes") is None else int(payload["supersedes"]),
                )
                return Response(201, result)
            if method == "POST" and path == "/evidence/revoke":
                result = self.service.revoke_evidence(
                    self._actor(normalized), payload["kind"], payload["record_id"],
                    int(payload["revision"]), payload["reason"],
                )
                return Response(200, result)

            if method == "POST" and path == "/candidates":
                result = self.service.create_candidate(
                    self._actor(normalized), payload["candidate_id"], payload["asset_id"],
                    int(payload["asset_revision"]), payload["refs"], payload.get("requirements"),
                )
                return Response(201, result)

            if method == "POST" and path == "/passports/issue":
                result = self.service.issue_passport(
                    self._actor(normalized), payload["candidate_id"], payload["idempotency_key"],
                    payload.get("business_no"),
                    None if payload.get("replaces_passport_id") is None
                    else int(payload["replaces_passport_id"]),
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 2 and parts[0] == "passports":
                return Response(200, self.service.get_passport(self._actor(normalized), int(parts[1])))
            if method == "GET" and len(parts) == 3 and parts[0] == "passports" and parts[2] == "trace":
                return Response(200, self.service.trace(self._actor(normalized), int(parts[1])))
            if method == "POST" and len(parts) == 3 and parts[0] == "passports" and parts[2] == "revoke":
                result = self.service.revoke_passport(
                    self._actor(normalized), int(parts[1]), payload["reason"]
                )
                return Response(200, result)

            if method == "GET" and len(parts) == 3 and parts[0] == "business" and parts[2] == "versions":
                return Response(200, self.service.list_versions(self._actor(normalized), parts[1]))
            if method == "GET" and len(parts) == 4 and parts[0] == "business" and parts[2] == "versions":
                return Response(
                    200,
                    self.service.get_version(self._actor(normalized), parts[1], int(parts[3])),
                )
            if method == "GET" and len(parts) == 3 and parts[0] == "assets" and parts[2] == "effective":
                at = query.get("at", [None])[0]
                return Response(
                    200, self.service.effective_passport(self._actor(normalized), parts[1], at)
                )

            if method == "POST" and path == "/references":
                result = self.service.create_reference(
                    self._actor(normalized), payload["reference_id"], int(payload["passport_id"]),
                    payload["consumer"], payload["purpose"],
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "references" and parts[2] == "complete":
                result = self.service.complete_reference(self._actor(normalized), parts[1])
                return Response(200, result)

            if method == "GET" and path == "/audit":
                result = self.service.audit_log(
                    self._actor(normalized),
                    query.get("entity_type", [None])[0],
                    query.get("entity_id", [None])[0],
                )
                return Response(200, result)

            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except IssuanceBlocked as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc),
                                                   "details": exc.details}})
        except PassportError as exc:
            body = {"error": {"code": exc.code, "message": str(exc)}}
            if exc.details is not None:
                body["error"]["details"] = exc.details
            return Response(exc.status, body)
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "BatteryPassport/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动储能电池数字产品护照 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("battery_passport.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    application = JsonApplication(PassportService(connection))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
