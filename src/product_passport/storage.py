"""数字产品护照的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS passport_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passport_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('registrar','operator','issuer','auditor','consumer')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

-- 四类来源系统冻结下来的确定版本证据：资产 / 组件谱系 / 质量决定 / 流转记录。
CREATE TABLE IF NOT EXISTS evidence_records (
    category TEXT NOT NULL CHECK (category IN ('asset','component','quality','transfer')),
    ref TEXT NOT NULL,
    version TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    title TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    state TEXT NOT NULL,
    revoke_reason TEXT,
    registered_by TEXT NOT NULL REFERENCES passport_users(user_id),
    registered_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (category, ref, version)
);

CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence_records(asset_id, category);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_sha ON evidence_records(content_sha256);

-- 护照业务编号；一个编号对应一条不可改写的版本链。
CREATE TABLE IF NOT EXISTS passports (
    passport_no TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    current_version INTEGER,
    created_by TEXT NOT NULL REFERENCES passport_users(user_id),
    created_at TEXT NOT NULL
);

-- 候选版本与签发版本共用一张表；签发后摘要与依据冻结，只能再开新版本。
CREATE TABLE IF NOT EXISTS passport_versions (
    passport_no TEXT NOT NULL REFERENCES passports(passport_no),
    version_no INTEGER NOT NULL CHECK (version_no > 0),
    state TEXT NOT NULL CHECK (state IN ('candidate','abandoned','issued','revoked')),
    claims_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    gate_blockers_json TEXT NOT NULL DEFAULT '[]',
    assembled_by TEXT NOT NULL REFERENCES passport_users(user_id),
    assembled_at TEXT NOT NULL,
    issued_by TEXT REFERENCES passport_users(user_id),
    issued_at TEXT,
    revoke_reason TEXT,
    revoked_by TEXT REFERENCES passport_users(user_id),
    revoked_at TEXT,
    previous_version INTEGER,
    replaces_version INTEGER,
    PRIMARY KEY (passport_no, version_no)
);

CREATE INDEX IF NOT EXISTS idx_passport_versions_digest
ON passport_versions(passport_no, content_sha256);

-- 每个版本逐份冻结的证据依据（快照，不随后续证据状态变化而改写）。
CREATE TABLE IF NOT EXISTS passport_version_evidence (
    passport_no TEXT NOT NULL,
    version_no INTEGER NOT NULL,
    category TEXT NOT NULL,
    ref TEXT NOT NULL,
    version TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    state_at_assembly TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    PRIMARY KEY (passport_no, version_no, category, ref),
    FOREIGN KEY (passport_no, version_no) REFERENCES passport_versions(passport_no, version_no)
);

CREATE TABLE IF NOT EXISTS passport_signatures (
    signature_id INTEGER PRIMARY KEY AUTOINCREMENT,
    passport_no TEXT NOT NULL,
    version_no INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('assembled','issued','revoked')),
    signer_id TEXT NOT NULL REFERENCES passport_users(user_id),
    signer_role TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    reason TEXT,
    signed_at TEXT NOT NULL,
    FOREIGN KEY (passport_no, version_no) REFERENCES passport_versions(passport_no, version_no)
);

-- 保险方等下游对某一护照版本的未完成引用；吊销时级联失效。
CREATE TABLE IF NOT EXISTS passport_references (
    reference_id INTEGER PRIMARY KEY AUTOINCREMENT,
    passport_no TEXT NOT NULL,
    version_no INTEGER NOT NULL,
    consumer TEXT NOT NULL,
    ref_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','completed','invalidated')),
    created_by TEXT NOT NULL REFERENCES passport_users(user_id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    invalidated_at TEXT,
    invalidate_reason TEXT,
    UNIQUE (passport_no, consumer, ref_key),
    FOREIGN KEY (passport_no, version_no) REFERENCES passport_versions(passport_no, version_no)
);

CREATE TABLE IF NOT EXISTS passport_idempotency (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS passport_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passport_audit_entity
ON passport_audit_events(entity_type, entity_id, event_id);
"""

REQUIRED_TABLES = frozenset({
    "passport_schema_meta", "passport_users", "evidence_records", "passports",
    "passport_versions", "passport_version_evidence", "passport_signatures",
    "passport_references", "passport_idempotency", "passport_audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用外键与显式事务。"""

    connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    initialize(connection)
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化护照表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO passport_schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM passport_schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
