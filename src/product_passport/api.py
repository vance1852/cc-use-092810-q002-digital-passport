"""数字产品护照的无第三方依赖 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import EvidenceGateBlocked, PassportError, ValidationFailed
from .service import PassportService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    """将 HTTP 路由映射到护照领域服务，便于无网络单元测试。"""

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
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}

            if method == "POST" and path == "/users":
                result = self.service.create_user(
                    payload["user_id"], payload["display_name"], payload["role"]
                )
                return Response(201, result)

            if method == "POST" and path == "/evidence":
                result = self.service.register_evidence(
                    self._actor(normalized_headers),
                    payload["category"], payload["ref"], payload["version"], payload["asset_id"],
                    payload["title"], payload["payload"], payload.get("state", "active"),
                )
                return Response(201, result)
            if method == "POST" and path == "/evidence/revoke":
                result = self.service.revoke_evidence(
                    self._actor(normalized_headers),
                    payload["category"], payload["ref"], payload["version"], payload["reason"],
                )
                return Response(200, result)

            if method == "POST" and path == "/passports/assemble":
                result = self.service.assemble_candidate(
                    self._actor(normalized_headers),
                    payload["passport_no"], payload["asset_id"], payload["evidence"],
                    payload["idempotency_key"], payload.get("note", ""),
                )
                return Response(201, result)

            if (
                method == "POST" and len(parts) == 5
                and parts[0] == "passports" and parts[2] == "versions" and parts[4] == "issue"
            ):
                result = self.service.issue(
                    self._actor(normalized_headers), parts[1], int(parts[3]),
                    payload["idempotency_key"], payload.get("expected_content_sha256"),
                )
                return Response(200, result)
            if (
                method == "POST" and len(parts) == 5
                and parts[0] == "passports" and parts[2] == "versions" and parts[4] == "abandon"
            ):
                result = self.service.abandon_candidate(
                    self._actor(normalized_headers), parts[1], int(parts[3]), payload["reason"]
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "passports" and parts[2] == "revoke":
                result = self.service.revoke(
                    self._actor(normalized_headers),
                    parts[1],
                    None if payload.get("version_no") is None else int(payload["version_no"]),
                    payload["reason"],
                )
                return Response(200, result)

            if method == "GET" and len(parts) == 3 and parts[0] == "passports" and parts[2] == "versions":
                return Response(200, self.service.list_versions(self._actor(normalized_headers), parts[1]))
            if (
                method == "GET" and len(parts) == 4
                and parts[0] == "passports" and parts[2] == "versions"
            ):
                return Response(
                    200, self.service.get_version(self._actor(normalized_headers), parts[1], int(parts[3]))
                )
            if (
                method == "GET" and len(parts) == 5
                and parts[0] == "passports" and parts[2] == "versions" and parts[4] == "provenance"
            ):
                return Response(
                    200,
                    self.service.provenance(self._actor(normalized_headers), parts[1], int(parts[3])),
                )
            if method == "GET" and len(parts) == 3 and parts[0] == "passports" and parts[2] == "effective":
                at = query.get("at", [None])[0]
                return Response(
                    200, self.service.effective_at(self._actor(normalized_headers), parts[1], at)
                )
            if method == "GET" and len(parts) == 3 and parts[0] == "passports" and parts[2] == "references":
                return Response(
                    200, self.service.list_references(self._actor(normalized_headers), parts[1])
                )

            if method == "POST" and path == "/references":
                result = self.service.register_reference(
                    self._actor(normalized_headers),
                    payload["passport_no"], int(payload["version_no"]),
                    payload["consumer"], payload["ref_key"],
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "references" and parts[2] == "complete":
                result = self.service.complete_reference(
                    self._actor(normalized_headers), int(parts[1])
                )
                return Response(200, result)

            if method == "GET" and path == "/audit/chain":
                return Response(200, self.service.audit_chain(self._actor(normalized_headers)))

            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except EvidenceGateBlocked as exc:
            return Response(
                exc.status,
                {"error": {"code": exc.code, "message": str(exc), "blockers": exc.blockers}},
            )
        except PassportError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except sqlite3.IntegrityError as exc:
            return Response(409, {"error": {"code": "conflict", "message": f"并发写入冲突: {exc}"}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ProductPassport/1"
        # 共享单个 SQLite 连接：串行化请求分发，避免跨线程并发使用连接。
        _connection_lock = threading.Lock()

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            with self._connection_lock:
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
    parser.add_argument("--database", type=Path, default=Path("product-passport.sqlite3"))
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
