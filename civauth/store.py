from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    hash TEXT PRIMARY KEY,
    uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    csrf TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    binding_hash TEXT NOT NULL,
    params TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS join_codes (
    hash TEXT PRIMARY KEY,
    uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS join_failures (
    address TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS codes (
    hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    code_challenge TEXT,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
    hash TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS apps (
    client_id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    owner_uuid TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS apps_owner ON apps (owner_uuid);
CREATE INDEX IF NOT EXISTS requests_binding ON requests (binding_hash);
CREATE TABLE IF NOT EXISTS accounts (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT,
    name_checked_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
    credential_id TEXT PRIMARY KEY,
    uuid TEXT NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS passkeys_uuid ON passkeys (uuid);
CREATE TABLE IF NOT EXISTS login_failures (
    uuid TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_time ON login_failures (created_at);
CREATE TABLE IF NOT EXISTS grants (
    uuid TEXT NOT NULL,
    client_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER NOT NULL,
    PRIMARY KEY (uuid, client_id)
);
CREATE TABLE IF NOT EXISTS avatars (
    uuid TEXT PRIMARY KEY,
    png BLOB NOT NULL,
    fetched_at INTEGER NOT NULL
);
"""

class Store:
    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)

    @staticmethod
    def hash(secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()

    def session(self, hash: str) -> dict | None:
        return self._one("SELECT * FROM sessions WHERE hash = ?", (hash,))

    def create_session(
        self,
        hash: str,
        uuid: str,
        name: str,
        expires_at: int,
        csrf: str,
    ) -> None:
        self._write(
            "INSERT INTO sessions (hash, uuid, name, expires_at, csrf) VALUES (?, ?, ?, ?, ?)",
            (hash, uuid, name, expires_at, csrf),
        )

    def delete_session(self, hash: str) -> None:
        self._write("DELETE FROM sessions WHERE hash = ?", (hash,))

    def create_request(self, id: str, binding_hash: str, params: dict, created_at: int) -> None:
        self._write(
            "INSERT INTO requests (id, binding_hash, params, created_at) VALUES (?, ?, ?, ?)",
            (id, binding_hash, json.dumps(params), created_at),
        )

    def request(self, id: str) -> dict | None:
        return self._request_row("SELECT * FROM requests WHERE id = ?", (id,))

    def request_by_binding(self, binding_hash: str) -> dict | None:
        return self._request_row(
            "SELECT * FROM requests WHERE binding_hash = ? ORDER BY created_at DESC LIMIT 1",
            (binding_hash,),
        )

    def _request_row(self, sql: str, args: tuple) -> dict | None:
        row = self._one(sql, args)
        if row is not None:
            row["params"] = json.loads(row["params"])
        return row

    def touch_request(self, id: str, now: int) -> None:
        self._write("UPDATE requests SET created_at = ? WHERE id = ?", (now, id))

    def delete_request(self, id: str) -> None:
        self._write("DELETE FROM requests WHERE id = ?", (id,))

    def count_attempt(self, id: str) -> int:
        with self._lock:
            self._db.execute("UPDATE requests SET attempts = attempts + 1 WHERE id = ?", (id,))
            row = self._db.execute("SELECT attempts FROM requests WHERE id = ?", (id,)).fetchone()
        return 0 if row is None else int(row["attempts"])

    def create_join_code(self, hash: str, uuid: str, name: str, now: int) -> bool:
        return (
            self._write(
                "INSERT OR IGNORE INTO join_codes (hash, uuid, name, created_at) VALUES (?, ?, ?, ?)",
                (hash, uuid, name, now),
            )
            == 1
        )

    def consume_join_code(self, hash: str, not_before: int) -> dict | None:
        with self._lock:
            cursor = self._db.execute(
                "UPDATE join_codes SET used = 1 WHERE hash = ? AND used = 0 AND created_at >= ?",
                (hash, not_before),
            )
            if cursor.rowcount != 1:
                return None
            row = self._db.execute(
                "SELECT uuid, name FROM join_codes WHERE hash = ?", (hash,)
            ).fetchone()
        return None if row is None else dict(row)

    def record_join_failure(self, address: str, now: int) -> None:
        self._write("INSERT INTO join_failures (address, created_at) VALUES (?, ?)", (address, now))

    def join_failures_since(self, address: str, since: int) -> int:
        row = self._one(
            "SELECT COUNT(*) AS n FROM join_failures WHERE created_at >= ? AND address = ?",
            (since, address),
        )
        return 0 if row is None else int(row["n"])

    def create_code(
        self,
        hash: str,
        client_id: str,
        redirect_uri: str,
        uuid: str,
        name: str,
        code_challenge: str | None,
        expires_at: int,
    ) -> None:
        self._write(
            "INSERT INTO codes (hash, client_id, redirect_uri, uuid, name, code_challenge, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (hash, client_id, redirect_uri, uuid, name, code_challenge, expires_at),
        )

    def code(self, hash: str) -> dict | None:
        return self._one("SELECT * FROM codes WHERE hash = ?", (hash,))

    def consume_code(self, hash: str) -> bool:
        return self._write("UPDATE codes SET used = 1 WHERE hash = ? AND used = 0", (hash,)) == 1

    def create_token(
        self,
        hash: str,
        code_hash: str,
        client_id: str,
        uuid: str,
        name: str,
        expires_at: int,
    ) -> None:
        self._write(
            "INSERT INTO tokens (hash, code_hash, client_id, uuid, name, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (hash, code_hash, client_id, uuid, name, expires_at),
        )

    def revoke_tokens_for_code(self, code_hash: str) -> None:
        self._write("DELETE FROM tokens WHERE code_hash = ?", (code_hash,))

    def token(self, hash: str) -> dict | None:
        return self._one("SELECT * FROM tokens WHERE hash = ?", (hash,))

    def app(self, client_id: str) -> dict | None:
        return self._one("SELECT * FROM apps WHERE client_id = ?", (client_id,))

    def apps_owned_by(self, uuid: str) -> list[dict]:
        rows = self._db.execute(
            "SELECT * FROM apps WHERE owner_uuid = ? ORDER BY created_at, client_id", (uuid,)
        ).fetchall()
        return [dict(row) for row in rows]

    def create_app(
        self,
        client_id: str,
        secret_hash: str,
        name: str,
        redirect_uris: list[str],
        owner_uuid: str,
        now: int,
    ) -> bool:
        return (
            self._write(
                "INSERT OR IGNORE INTO apps (client_id, secret_hash, name, redirect_uris, owner_uuid, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    client_id,
                    secret_hash,
                    name,
                    json.dumps(list(redirect_uris)),
                    owner_uuid,
                    now,
                    now,
                ),
            )
            == 1
        )

    def update_app(self, client_id: str, name: str, redirect_uris: list[str], now: int) -> None:
        self._write(
            "UPDATE apps SET name = ?, redirect_uris = ?, updated_at = ? WHERE client_id = ?",
            (name, json.dumps(list(redirect_uris)), now, client_id),
        )

    def set_app_secret(self, client_id: str, secret_hash: str, now: int) -> None:
        self._write(
            "UPDATE apps SET secret_hash = ?, updated_at = ? WHERE client_id = ?",
            (secret_hash, now, client_id),
        )

    def grant(self, uuid: str, client_id: str) -> dict | None:
        return self._one("SELECT * FROM grants WHERE uuid = ? AND client_id = ?", (uuid, client_id))

    def record_grant(self, uuid: str, client_id: str, now: int) -> None:
        self._write(
            "INSERT INTO grants (uuid, client_id, created_at, used_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (uuid, client_id) DO UPDATE SET used_at = excluded.used_at",
            (uuid, client_id, now, now),
        )

    def grants_for(self, uuid: str) -> list[dict]:
        rows = self._db.execute(
            "SELECT grants.client_id, grants.created_at, grants.used_at, apps.name, apps.owner_uuid,"
            " accounts.name AS owner_name"
            " FROM grants"
            " JOIN apps ON apps.client_id = grants.client_id"
            " LEFT JOIN accounts ON accounts.uuid = apps.owner_uuid"
            " WHERE grants.uuid = ? ORDER BY grants.used_at DESC",
            (uuid,),
        ).fetchall()
        return [dict(row) for row in rows]

    def delete_grant(self, uuid: str, client_id: str) -> bool:
        with self._lock:
            removed = self._db.execute(
                "DELETE FROM grants WHERE uuid = ? AND client_id = ?", (uuid, client_id)
            ).rowcount
            for table in ("tokens", "codes"):
                self._db.execute(
                    f"DELETE FROM {table} WHERE uuid = ? AND client_id = ?", (uuid, client_id)
                )
        return removed == 1

    def delete_app(self, client_id: str) -> None:
        with self._lock:
            for table in ("tokens", "codes", "grants", "apps"):
                self._db.execute(f"DELETE FROM {table} WHERE client_id = ?", (client_id,))

    def account(self, uuid: str) -> dict | None:
        return self._one("SELECT * FROM accounts WHERE uuid = ?", (uuid,))

    def touch_account(self, uuid: str, name: str, now: int) -> dict:
        self._write(
            "INSERT INTO accounts (uuid, name, created_at, updated_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(uuid) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
            (uuid, name, now, now),
        )
        return self.account(uuid)

    def set_password(self, uuid: str, password_hash: str | None, now: int) -> None:
        self._write(
            "UPDATE accounts SET password_hash = ?, updated_at = ? WHERE uuid = ?", (password_hash, now, uuid)
        )

    def account_by_name(self, name: str) -> dict | None:
        return self._one("SELECT * FROM accounts WHERE name = ? COLLATE NOCASE", (name,))

    def accounts_to_check(self, before: int, limit: int) -> list[dict]:
        cursor = self._db.execute(
            "SELECT uuid, name FROM accounts WHERE name_checked_at < ? ORDER BY name_checked_at LIMIT ?",
            (before, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def checked_name(self, uuid: str, name: str, now: int) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE accounts SET name = ?, name_checked_at = ?, updated_at = ? WHERE uuid = ?",
                (name, now, now, uuid),
            )
            self._db.execute("UPDATE sessions SET name = ? WHERE uuid = ?", (name, uuid))

    def add_passkey(
        self, credential_id: str, uuid: str, public_key: str, sign_count: int, now: int
    ) -> None:
        self._write(
            "INSERT OR REPLACE INTO passkeys (credential_id, uuid, public_key, sign_count, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (credential_id, uuid, public_key, sign_count, now),
        )

    def passkey(self, credential_id: str) -> dict | None:
        return self._one("SELECT * FROM passkeys WHERE credential_id = ?", (credential_id,))

    def passkeys_for(self, uuid: str) -> list[dict]:
        cursor = self._db.execute("SELECT * FROM passkeys WHERE uuid = ? ORDER BY created_at", (uuid,))
        return [dict(row) for row in cursor.fetchall()]

    def used_passkey(self, credential_id: str, sign_count: int, now: int) -> None:
        self._write(
            "UPDATE passkeys SET sign_count = ?, used_at = ? WHERE credential_id = ?",
            (sign_count, now, credential_id),
        )

    def delete_passkey(self, credential_id: str, uuid: str) -> bool:
        return self._write("DELETE FROM passkeys WHERE credential_id = ? AND uuid = ?", (credential_id, uuid)) == 1

    def record_login_failure(self, uuid: str, address: str, now: int) -> None:
        self._write("INSERT INTO login_failures (uuid, address, created_at) VALUES (?, ?, ?)", (uuid, address, now))

    def login_failures_by_address(self, address: str, since: int) -> int:
        row = self._one(
            "SELECT COUNT(*) AS n FROM login_failures WHERE created_at >= ? AND address = ?",
            (since, address),
        )
        return int(row["n"])

    def login_failures_by_uuid(self, uuid: str, since: int) -> int:
        row = self._one(
            "SELECT COUNT(*) AS n FROM login_failures WHERE created_at >= ? AND uuid = ?",
            (since, uuid),
        )
        return int(row["n"])

    def avatar(self, uuid: str) -> dict | None:
        return self._one("SELECT * FROM avatars WHERE uuid = ?", (uuid,))

    def put_avatar(self, uuid: str, png: bytes, now: int) -> None:
        self._write(
            "INSERT OR REPLACE INTO avatars (uuid, png, fetched_at) VALUES (?, ?, ?)",
            (uuid, png, now),
        )

    def extend_session(self, hash: str, expires_at: int) -> None:
        self._write("UPDATE sessions SET expires_at = ? WHERE hash = ?", (expires_at, hash))

    def purge(self, now: int, request_ttl: int, join_code_ttl: int, failure_window: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            self._db.execute("DELETE FROM requests WHERE created_at < ?", (now - request_ttl,))
            self._db.execute("DELETE FROM codes WHERE expires_at < ?", (now,))
            self._db.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
            self._db.execute("DELETE FROM join_codes WHERE created_at < ?", (now - join_code_ttl,))
            self._db.execute("DELETE FROM join_failures WHERE created_at < ?", (now - failure_window,))
            self._db.execute("DELETE FROM login_failures WHERE created_at < ?", (now - failure_window,))

    def _one(self, sql: str, args: tuple) -> dict | None:
        row = self._db.execute(sql, args).fetchone()
        return None if row is None else dict(row)

    def _write(self, sql: str, args: tuple) -> int:
        with self._lock:
            return self._db.execute(sql, args).rowcount
