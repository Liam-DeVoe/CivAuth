import { readFileSync } from "node:fs";

const KEYS = new Set([
  "issuer",
  "microsoftClientId",
  "microsoftClientSecret",
  "joinSecret",
  "joinAddress",
  "database",
  "ownerNames",
  "trustProxy",
]);

export class Config {
  readonly issuer: string;
  readonly issuerPath: string;
  readonly microsoftClientId: string;
  readonly microsoftClientSecret: string;
  readonly joinSecret: string;
  readonly joinAddress: string;
  readonly database: string;
  readonly ownerNames: Readonly<Record<string, string>>;
  readonly trustProxy: number;

  constructor(data: Record<string, unknown>) {
    const unknown = Object.keys(data).filter((key) => !KEYS.has(key));
    if (unknown.length > 0) {
      throw new Error("unknown config keys: " + unknown.sort().join(", "));
    }

    const issuer = parseIssuer(string(data, "issuer"));
    this.issuer = issuer.origin + issuer.path;
    this.issuerPath = issuer.path;

    this.microsoftClientId = string(data, "microsoftClientId");
    this.microsoftClientSecret = string(data, "microsoftClientSecret");

    this.joinSecret = string(data, "joinSecret");
    this.joinAddress = string(data, "joinAddress");
    if (this.joinSecret.length < 32) {
      throw new Error("joinSecret must be at least 32 characters");
    }

    this.database = string(data, "database");

    const owners = data.ownerNames ?? {};
    if (
      typeof owners !== "object" ||
      owners === null ||
      Array.isArray(owners) ||
      !Object.values(owners).every((value) => typeof value === "string" && value !== "")
    ) {
      throw new Error("ownerNames must map client ids to non-empty strings");
    }
    this.ownerNames = { ...(owners as Record<string, string>) };

    const trustProxy = data.trustProxy ?? 0;
    if (typeof trustProxy !== "number" || !Number.isInteger(trustProxy) || trustProxy < 0) {
      throw new Error("trustProxy must be the number of proxies in front of the server");
    }
    this.trustProxy = trustProxy;
  }

  static fromFile(path: string): Config {
    const data: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new Error("config must be a JSON object");
    }
    return new Config(data as Record<string, unknown>);
  }

  path(route: string): string {
    return this.issuerPath + route;
  }

  url(route: string): string {
    return this.issuer + route;
  }

  cookiePath(): string {
    return this.issuerPath || "/";
  }
}

export function configPath(): string {
  return process.env.CIVAUTH_CONFIG || "config.json";
}

export function issuerPathOf(path: string): string {
  let issuer: unknown;
  try {
    issuer = (JSON.parse(readFileSync(path, "utf8")) as { issuer?: unknown }).issuer;
  } catch {
    return "";
  }
  return typeof issuer === "string" ? parseIssuer(issuer).path : "";
}

function parseIssuer(value: string): { origin: string; path: string } {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("issuer must be an https URL");
  }
  if (url.protocol !== "https:" || url.search || url.hash || url.username || url.password) {
    throw new Error("issuer must be an https URL with no query, fragment or credentials");
  }
  return { origin: url.origin, path: url.pathname.replace(/\/+$/, "") };
}

function string(data: Record<string, unknown>, key: string): string {
  const value = data[key];
  if (typeof value !== "string" || value === "") {
    throw new Error(`${key} must be a non-empty string`);
  }
  return value;
}
