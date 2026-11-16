import { DatabaseSync, type SQLInputValue, type StatementSync } from "node:sqlite";

const SCHEMA = `
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
CREATE TABLE IF NOT EXISTS refresh_tokens (
    hash TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS refresh_tokens_code ON refresh_tokens (code_hash);
CREATE INDEX IF NOT EXISTS tokens_code ON tokens (code_hash);
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
`;

export interface SessionRow {
  hash: string;
  uuid: string;
  name: string;
  expires_at: number;
  csrf: string;
}

export interface FlowParams {
  client_id?: string;
  redirect_uri?: string;
  state?: string | null;
  code_challenge?: string | null;
  return_to?: string;
}

export interface RequestRow {
  id: string;
  binding_hash: string;
  params: FlowParams;
  created_at: number;
  attempts: number;
}

export interface CodeRow {
  hash: string;
  client_id: string;
  redirect_uri: string;
  uuid: string;
  name: string;
  code_challenge: string | null;
  expires_at: number;
  used: number;
}

export interface TokenRow {
  hash: string;
  code_hash: string;
  client_id: string;
  uuid: string;
  name: string;
  expires_at: number;
}

export interface RefreshTokenRow extends TokenRow {
  used: number;
  used_at: number | null;
}

export interface AppRow {
  client_id: string;
  secret_hash: string;
  name: string;
  redirect_uris: string;
  owner_uuid: string;
  created_at: number;
  updated_at: number;
}

export interface GrantRow {
  uuid: string;
  client_id: string;
  created_at: number;
  used_at: number;
}

export interface GrantListing {
  client_id: string;
  created_at: number;
  used_at: number;
  name: string;
  owner_uuid: string;
  owner_name: string | null;
}

export interface AccountRow {
  uuid: string;
  name: string;
  password_hash: string | null;
  name_checked_at: number;
  created_at: number;
  updated_at: number;
}

export interface PasskeyRow {
  credential_id: string;
  uuid: string;
  public_key: string;
  sign_count: number;
  created_at: number;
  used_at: number | null;
}

export interface AvatarRow {
  uuid: string;
  png: Uint8Array;
  fetched_at: number;
}

export interface TokenPair {
  access_hash: string;
  refresh_hash: string;
  code_hash: string;
  client_id: string;
  uuid: string;
  name: string;
  access_expires_at: number;
  refresh_expires_at: number;
}

type Args = SQLInputValue[];

export class Store {
  private readonly db: DatabaseSync;
  private readonly statements = new Map<string, StatementSync>();

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA busy_timeout = 5000");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec(SCHEMA);
  }

  session(hash: string): SessionRow | null {
    return this.one("SELECT * FROM sessions WHERE hash = ?", [hash]);
  }

  createSession(hash: string, uuid: string, name: string, expiresAt: number, csrf: string): void {
    this.write("INSERT INTO sessions (hash, uuid, name, expires_at, csrf) VALUES (?, ?, ?, ?, ?)", [
      hash,
      uuid,
      name,
      expiresAt,
      csrf,
    ]);
  }

  deleteSession(hash: string): void {
    this.write("DELETE FROM sessions WHERE hash = ?", [hash]);
  }

  createRequest(id: string, bindingHash: string, params: FlowParams, createdAt: number): void {
    this.write("INSERT INTO requests (id, binding_hash, params, created_at) VALUES (?, ?, ?, ?)", [
      id,
      bindingHash,
      JSON.stringify(params),
      createdAt,
    ]);
  }

  request(id: string): RequestRow | null {
    return this.requestRow("SELECT * FROM requests WHERE id = ?", [id]);
  }

  requestByBinding(bindingHash: string): RequestRow | null {
    return this.requestRow("SELECT * FROM requests WHERE binding_hash = ? ORDER BY created_at DESC LIMIT 1", [
      bindingHash,
    ]);
  }

  private requestRow(sql: string, args: Args): RequestRow | null {
    const row = this.one<Omit<RequestRow, "params"> & { params: string }>(sql, args);
    if (row === null) return null;
    return { ...row, params: JSON.parse(row.params) as FlowParams };
  }

  touchRequest(id: string, now: number): void {
    this.write("UPDATE requests SET created_at = ? WHERE id = ?", [now, id]);
  }

  deleteRequest(id: string): void {
    this.write("DELETE FROM requests WHERE id = ?", [id]);
  }

  countAttempt(id: string): number {
    this.run("UPDATE requests SET attempts = attempts + 1 WHERE id = ?", [id]);
    const row = this.one<{ attempts: number }>("SELECT attempts FROM requests WHERE id = ?", [id]);
    return row === null ? 0 : Number(row.attempts);
  }

  createJoinCode(hash: string, uuid: string, name: string, now: number): boolean {
    return (
      this.write("INSERT OR IGNORE INTO join_codes (hash, uuid, name, created_at) VALUES (?, ?, ?, ?)", [
        hash,
        uuid,
        name,
        now,
      ]) === 1
    );
  }

  consumeJoinCode(hash: string, notBefore: number): { uuid: string; name: string } | null {
    const changed = this.write("UPDATE join_codes SET used = 1 WHERE hash = ? AND used = 0 AND created_at >= ?", [
      hash,
      notBefore,
    ]);
    if (changed !== 1) return null;
    return this.one("SELECT uuid, name FROM join_codes WHERE hash = ?", [hash]);
  }

  recordJoinFailure(address: string, now: number): void {
    this.write("INSERT INTO join_failures (address, created_at) VALUES (?, ?)", [address, now]);
  }

  joinFailuresSince(address: string, since: number): number {
    const row = this.one<{ n: number }>(
      "SELECT COUNT(*) AS n FROM join_failures WHERE created_at >= ? AND address = ?",
      [since, address],
    );
    return row === null ? 0 : Number(row.n);
  }

  createCode(
    hash: string,
    clientId: string,
    redirectUri: string,
    uuid: string,
    name: string,
    codeChallenge: string | null,
    expiresAt: number,
  ): void {
    this.write(
      "INSERT INTO codes (hash, client_id, redirect_uri, uuid, name, code_challenge, expires_at)" +
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
      [hash, clientId, redirectUri, uuid, name, codeChallenge, expiresAt],
    );
  }

  code(hash: string): CodeRow | null {
    return this.one("SELECT * FROM codes WHERE hash = ?", [hash]);
  }

  exchangeCode(codeHash: string, pair: TokenPair | null): boolean {
    return this.transaction(() => {
      const used = this.run("UPDATE codes SET used = 1 WHERE hash = ? AND used = 0", [codeHash]);
      if (used !== 1) return false;
      if (pair !== null) this.mint(pair);
      return true;
    });
  }

  rotateRefreshToken(hash: string, now: number, pair: TokenPair): boolean {
    return this.transaction(() => {
      const used = this.run("UPDATE refresh_tokens SET used = 1, used_at = ? WHERE hash = ? AND used = 0", [now, hash]);
      if (used !== 1) return false;
      this.mint(pair);
      return true;
    });
  }

  private mint(pair: TokenPair): void {
    this.run("INSERT INTO tokens (hash, code_hash, client_id, uuid, name, expires_at)" + " VALUES (?, ?, ?, ?, ?, ?)", [
      pair.access_hash,
      pair.code_hash,
      pair.client_id,
      pair.uuid,
      pair.name,
      pair.access_expires_at,
    ]);
    this.run(
      "INSERT INTO refresh_tokens (hash, code_hash, client_id, uuid, name, expires_at)" + " VALUES (?, ?, ?, ?, ?, ?)",
      [pair.refresh_hash, pair.code_hash, pair.client_id, pair.uuid, pair.name, pair.refresh_expires_at],
    );
  }

  revokeTokensForCode(codeHash: string): void {
    this.transaction(() => {
      for (const table of ["tokens", "refresh_tokens"]) {
        this.run(`DELETE FROM ${table} WHERE code_hash = ?`, [codeHash]);
      }
    });
  }

  token(hash: string): TokenRow | null {
    return this.one("SELECT * FROM tokens WHERE hash = ?", [hash]);
  }

  refreshToken(hash: string): RefreshTokenRow | null {
    return this.one("SELECT * FROM refresh_tokens WHERE hash = ?", [hash]);
  }

  app(clientId: string): AppRow | null {
    return this.one("SELECT * FROM apps WHERE client_id = ?", [clientId]);
  }

  appsOwnedBy(uuid: string): AppRow[] {
    return this.all("SELECT * FROM apps WHERE owner_uuid = ? ORDER BY created_at, client_id", [uuid]);
  }

  createApp(
    clientId: string,
    secretHash: string,
    name: string,
    redirectUris: readonly string[],
    ownerUuid: string,
    now: number,
  ): boolean {
    return (
      this.write(
        "INSERT OR IGNORE INTO apps (client_id, secret_hash, name, redirect_uris, owner_uuid, created_at, updated_at)" +
          " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [clientId, secretHash, name, JSON.stringify([...redirectUris]), ownerUuid, now, now],
      ) === 1
    );
  }

  updateApp(clientId: string, name: string, redirectUris: readonly string[], now: number): void {
    this.write("UPDATE apps SET name = ?, redirect_uris = ?, updated_at = ? WHERE client_id = ?", [
      name,
      JSON.stringify([...redirectUris]),
      now,
      clientId,
    ]);
  }

  setAppSecret(clientId: string, secretHash: string, now: number): void {
    this.write("UPDATE apps SET secret_hash = ?, updated_at = ? WHERE client_id = ?", [secretHash, now, clientId]);
  }

  grant(uuid: string, clientId: string): GrantRow | null {
    return this.one("SELECT * FROM grants WHERE uuid = ? AND client_id = ?", [uuid, clientId]);
  }

  recordGrant(uuid: string, clientId: string, now: number): void {
    this.write(
      "INSERT INTO grants (uuid, client_id, created_at, used_at) VALUES (?, ?, ?, ?)" +
        " ON CONFLICT (uuid, client_id) DO UPDATE SET used_at = excluded.used_at",
      [uuid, clientId, now, now],
    );
  }

  grantsFor(uuid: string): GrantListing[] {
    return this.all(
      "SELECT grants.client_id, grants.created_at, grants.used_at, apps.name, apps.owner_uuid," +
        " accounts.name AS owner_name" +
        " FROM grants" +
        " JOIN apps ON apps.client_id = grants.client_id" +
        " LEFT JOIN accounts ON accounts.uuid = apps.owner_uuid" +
        " WHERE grants.uuid = ? ORDER BY grants.used_at DESC",
      [uuid],
    );
  }

  deleteGrant(uuid: string, clientId: string): boolean {
    const removed = this.run("DELETE FROM grants WHERE uuid = ? AND client_id = ?", [uuid, clientId]);
    for (const table of ["tokens", "refresh_tokens", "codes"]) {
      this.run(`DELETE FROM ${table} WHERE uuid = ? AND client_id = ?`, [uuid, clientId]);
    }
    return removed === 1;
  }

  deleteApp(clientId: string): void {
    for (const table of ["tokens", "refresh_tokens", "codes", "grants", "apps"]) {
      this.run(`DELETE FROM ${table} WHERE client_id = ?`, [clientId]);
    }
  }

  account(uuid: string): AccountRow | null {
    return this.one("SELECT * FROM accounts WHERE uuid = ?", [uuid]);
  }

  touchAccount(uuid: string, name: string, now: number): AccountRow {
    this.write(
      "INSERT INTO accounts (uuid, name, created_at, updated_at) VALUES (?, ?, ?, ?)" +
        " ON CONFLICT(uuid) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
      [uuid, name, now, now],
    );
    return this.account(uuid)!;
  }

  setPassword(uuid: string, passwordHash: string | null, now: number): void {
    this.write("UPDATE accounts SET password_hash = ?, updated_at = ? WHERE uuid = ?", [passwordHash, now, uuid]);
  }

  accountByName(name: string): AccountRow | null {
    return this.one("SELECT * FROM accounts WHERE name = ? COLLATE NOCASE", [name]);
  }

  accountsToCheck(before: number, limit: number): { uuid: string; name: string }[] {
    return this.all("SELECT uuid, name FROM accounts WHERE name_checked_at < ? ORDER BY name_checked_at LIMIT ?", [
      before,
      limit,
    ]);
  }

  checkedName(uuid: string, name: string, now: number): void {
    this.run("UPDATE accounts SET name = ?, name_checked_at = ?, updated_at = ? WHERE uuid = ?", [
      name,
      now,
      now,
      uuid,
    ]);
    this.run("UPDATE sessions SET name = ? WHERE uuid = ?", [name, uuid]);
  }

  addPasskey(credentialId: string, uuid: string, publicKey: string, signCount: number, now: number): void {
    this.write(
      "INSERT OR REPLACE INTO passkeys (credential_id, uuid, public_key, sign_count, created_at)" +
        " VALUES (?, ?, ?, ?, ?)",
      [credentialId, uuid, publicKey, signCount, now],
    );
  }

  passkey(credentialId: string): PasskeyRow | null {
    return this.one("SELECT * FROM passkeys WHERE credential_id = ?", [credentialId]);
  }

  passkeysFor(uuid: string): PasskeyRow[] {
    return this.all("SELECT * FROM passkeys WHERE uuid = ? ORDER BY created_at", [uuid]);
  }

  usedPasskey(credentialId: string, signCount: number, now: number): void {
    this.write("UPDATE passkeys SET sign_count = ?, used_at = ? WHERE credential_id = ?", [
      signCount,
      now,
      credentialId,
    ]);
  }

  deletePasskey(credentialId: string, uuid: string): boolean {
    return this.write("DELETE FROM passkeys WHERE credential_id = ? AND uuid = ?", [credentialId, uuid]) === 1;
  }

  recordLoginFailure(uuid: string, address: string, now: number): void {
    this.write("INSERT INTO login_failures (uuid, address, created_at) VALUES (?, ?, ?)", [uuid, address, now]);
  }

  loginFailuresByAddress(address: string, since: number): number {
    const row = this.one<{ n: number }>(
      "SELECT COUNT(*) AS n FROM login_failures WHERE created_at >= ? AND address = ?",
      [since, address],
    );
    return Number(row!.n);
  }

  loginFailuresByUuid(uuid: string, since: number): number {
    const row = this.one<{ n: number }>("SELECT COUNT(*) AS n FROM login_failures WHERE created_at >= ? AND uuid = ?", [
      since,
      uuid,
    ]);
    return Number(row!.n);
  }

  avatar(uuid: string): AvatarRow | null {
    return this.one("SELECT * FROM avatars WHERE uuid = ?", [uuid]);
  }

  putAvatar(uuid: string, png: Uint8Array, now: number): void {
    this.write("INSERT OR REPLACE INTO avatars (uuid, png, fetched_at) VALUES (?, ?, ?)", [uuid, png, now]);
  }

  extendSession(hash: string, expiresAt: number): void {
    this.write("UPDATE sessions SET expires_at = ? WHERE hash = ?", [expiresAt, hash]);
  }

  purge(now: number, requestTtl: number, joinCodeTtl: number, failureWindow: number, replayWindow: number): void {
    this.run("DELETE FROM sessions WHERE expires_at < ?", [now]);
    this.run("DELETE FROM requests WHERE created_at < ?", [now - requestTtl]);
    this.run("DELETE FROM codes WHERE expires_at < ? AND (used = 0 OR expires_at < ?)", [now, now - replayWindow]);
    this.run("DELETE FROM tokens WHERE expires_at < ?", [now]);
    this.run("DELETE FROM refresh_tokens WHERE expires_at < ? OR (used = 1 AND used_at < ?)", [
      now,
      now - replayWindow,
    ]);
    this.run("DELETE FROM join_codes WHERE created_at < ?", [now - joinCodeTtl]);
    this.run("DELETE FROM join_failures WHERE created_at < ?", [now - failureWindow]);
    this.run("DELETE FROM login_failures WHERE created_at < ?", [now - failureWindow]);
  }

  private statement(sql: string): StatementSync {
    let statement = this.statements.get(sql);
    if (statement === undefined) {
      statement = this.db.prepare(sql);
      this.statements.set(sql, statement);
    }
    return statement;
  }

  private one<T>(sql: string, args: Args): T | null {
    const row = this.statement(sql).get(...args);
    return row === undefined ? null : ({ ...row } as T);
  }

  private all<T>(sql: string, args: Args): T[] {
    return this.statement(sql)
      .all(...args)
      .map((row) => ({ ...row }) as T);
  }

  private run(sql: string, args: Args): number {
    return Number(this.statement(sql).run(...args).changes);
  }

  private write(sql: string, args: Args): number {
    return this.run(sql, args);
  }

  private transaction<T>(body: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    let result: T;
    try {
      result = body();
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    this.db.exec("COMMIT");
    return result;
  }
}
