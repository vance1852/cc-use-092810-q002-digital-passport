"""数字产品护照服务的 SQLite 模式与事务辅助。

设计要点：
- 来源证据（组件 / 检测 / 维修 / 所有权）与护照分离，证据一旦登记即不可改写，
  新版本另起一行，撤销通过显式状态位表达而非删除；
- 护照是内容寻址的：business_no 恒定标识一份业务档案，version 单调递增，
  content_sha256 对 (business_no, version) 唯一，构成「同材料→同护照」的基础；
- 已签发护照的载荷以签发时刻的 canonical JSON 原样冻结，永不更新；
- 下游引用单独建表，吊销护照时未完成引用被一次性置为失效。
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator','quality','approver','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

-- 资产逻辑身份（编号恒定），其它表以 asset_id 此外键引用。
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    latest_revision INTEGER NOT NULL DEFAULT 1 CHECK (latest_revision > 0),
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

-- 确定版本的资产档案：每次内容变化新增一行，永不更新。
CREATE TABLE IF NOT EXISTS asset_revisions (
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    model_name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('commissioned','in_service','maintenance','retired')),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (asset_id, revision),
    UNIQUE (content_sha256)
);

-- 来源证据登记表。每条证据自身版本化；记录编号内的新版本另起一行。
CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('component','inspection','repair','ownership')),
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    -- 来源系统（出厂/检测/维修/登记机构）中的不可变载荷摘要与正文。
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    payload_json TEXT NOT NULL,
    -- active：当前仍可被确定版本引用（新旧版本并存，不互相覆盖）；
    -- revoked：该具体版本被撤销（保留撤销原因）。
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    revoke_reason TEXT,
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    recorded_by TEXT NOT NULL REFERENCES users(user_id),
    recorded_at TEXT NOT NULL,
    UNIQUE (kind, record_id, revision),
    UNIQUE (content_sha256)
);

CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence_records(asset_id, kind);

-- 同一记录不同版本的取代链（仅用于谱系展示，不参与「最新值覆盖」语义）。
CREATE TABLE IF NOT EXISTS evidence_revision_chains (
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    supersedes_revision INTEGER,
    PRIMARY KEY (kind, record_id, revision),
    FOREIGN KEY (kind, record_id, revision)
        REFERENCES evidence_records(kind, record_id, revision)
);

-- 待组装的候选包：只持有确定版本的资产与证据引用及覆盖要求。
-- 引用不加外键：来源记录可能在组装后、签发前缺失或被撤销，这必须在签发时
-- 作为明确的阻断项暴露，而不是在候选阶段被最新值静默替换。
CREATE TABLE IF NOT EXISTS candidate_packages (
    candidate_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    asset_revision INTEGER NOT NULL CHECK (asset_revision > 0),
    asset_sha256 TEXT NOT NULL CHECK (length(asset_sha256) = 64),
    requirements_json TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidate_refs (
    candidate_id TEXT NOT NULL REFERENCES candidate_packages(candidate_id),
    position INTEGER NOT NULL CHECK (position >= 0),
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    role TEXT,
    note TEXT,
    PRIMARY KEY (candidate_id, position),
    UNIQUE (candidate_id, kind, record_id, revision)
);

-- 签发幂等：相同候选材料的重试返回原护照。
CREATE TABLE IF NOT EXISTS issuance_requests (
    idempotency_key TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidate_packages(candidate_id),
    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
    passport_id INTEGER REFERENCES passports(passport_id),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (candidate_id, material_sha256)
);

-- 数字产品护照：内容寻址、版本化、签发即冻结。
CREATE TABLE IF NOT EXISTS passports (
    passport_id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_no TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    candidate_id TEXT NOT NULL REFERENCES candidate_packages(candidate_id),
    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued','revoked','superseded')),
    issued_by TEXT NOT NULL REFERENCES users(user_id),
    issued_at TEXT NOT NULL,
    replaces_passport_id INTEGER REFERENCES passports(passport_id),
    revoke_reason TEXT,
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    UNIQUE (business_no, version),
    UNIQUE (content_sha256),
    UNIQUE (material_sha256)
);

CREATE INDEX IF NOT EXISTS idx_passports_asset ON passports(asset_id, version);

-- 下游对某版护照的引用（保险方、再处置等）。
CREATE TABLE IF NOT EXISTS passport_references (
    reference_id TEXT PRIMARY KEY,
    passport_id INTEGER NOT NULL REFERENCES passports(passport_id),
    consumer TEXT NOT NULL,
    purpose TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','completed','invalidated')),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    invalidated_at TEXT,
    invalidate_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_references_passport ON passport_references(passport_id, state);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_events(entity_type, entity_id, event_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "users", "assets", "asset_revisions", "evidence_records",
    "evidence_revision_chains", "candidate_packages", "candidate_refs", "issuance_requests",
    "passports", "passport_references", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
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
    """初始化表结构，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
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
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
