import { data } from "react-router";

import { MAX_NAME, MAX_URIS } from "../constants";
import { MAX_PER_OWNER } from "./constants";
import { formString } from "./http";
import { store } from "./services";
import { hash, newClientId, now, randomToken, requireSession } from "./session";
import type { AppRow, SessionRow } from "./store";

const FORBIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

export interface Fields {
  name: string;
  redirectUris: string[];
}

export interface AppSecret {
  clientId: string;
  name: string;
  secret: string;
}

export interface AppActionData {
  errors?: string[];
  fields?: Fields;
  message?: string;
  secret?: AppSecret;
}

export function requireAppsSession(request: Request): SessionRow {
  return requireSession(request, "/apps");
}

export function redirectUris(row: AppRow): string[] {
  return JSON.parse(row.redirect_uris) as string[];
}

function isRegistrableUri(uri: string): boolean {
  if (!/^https?:\/\/[^\s#]+$/.test(uri)) return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

function submitted(form: FormData): Fields {
  const uris = form.getAll("redirect_uris[]").filter((value) => typeof value === "string");
  return { name: formString(form, "name") ?? "", redirectUris: uris.length > 0 ? uris : [""] };
}

function invalid(errors: string[], fields: Fields) {
  return data<AppActionData>({ errors, fields }, { status: 400 });
}

function validate(fields: Fields): { errors: string[]; parsed: Fields } {
  const errors: string[] = [];
  const name = fields.name.trim();
  const length = [...name].length;
  if (!(length >= 1 && length <= MAX_NAME) || FORBIDDEN.test(name)) {
    errors.push("Invalid name.");
  }
  const uris = [...new Set(fields.redirectUris.map((uri) => uri.trim()).filter((uri) => uri !== ""))];
  if (uris.length === 0) {
    errors.push("A redirect URI is required.");
  } else if (uris.length > MAX_URIS) {
    errors.push("Too many redirect URIs.");
  }
  for (const uri of uris) {
    if (!isRegistrableUri(uri)) errors.push(`Invalid address: ${uri}`);
  }
  return { errors, parsed: { name, redirectUris: uris } };
}

export function createApp(session: SessionRow, form: FormData) {
  const fields = submitted(form);
  const { errors, parsed } = validate(fields);
  if (store.appsOwnedBy(session.uuid).length >= MAX_PER_OWNER) errors.push("Too many apps.");
  if (errors.length > 0) return invalid(errors, fields);
  const secret = randomToken();
  for (let attempt = 0; attempt < 5; attempt++) {
    const clientId = newClientId();
    if (store.createApp(clientId, hash(secret), parsed.name, parsed.redirectUris, session.uuid, now())) {
      return data<AppActionData>({ secret: { clientId, name: parsed.name, secret } });
    }
  }
  return invalid(["Try again."], fields);
}

export function updateApp(row: AppRow, form: FormData) {
  const fields = submitted(form);
  const { errors, parsed } = validate(fields);
  if (errors.length > 0) return invalid(errors, fields);
  store.updateApp(row.client_id, parsed.name, parsed.redirectUris, now());
  return data<AppActionData>({ message: "Saved." });
}

export function regenerateSecret(row: AppRow) {
  const secret = randomToken();
  store.setAppSecret(row.client_id, hash(secret), now());
  return data<AppActionData>({ secret: { clientId: row.client_id, name: row.name, secret } });
}
