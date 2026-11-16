import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { redirect } from "react-router";

import {
  CLIENT_ID_ALPHABET,
  CLIENT_ID_LENGTH,
  FLOW_COOKIE,
  REQUEST_TTL,
  SESSION_COOKIE,
  SESSION_SLIDE_AFTER,
  SESSION_TTL,
} from "./constants";
import { errorPage, expireCookie, getCookie, setCookie, unverifiedForm } from "./http";
import { store } from "./services";
import type { FlowParams, RequestRow, SessionRow } from "./store";

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export function newClientId(): string {
  let id = "";
  for (let i = 0; i < CLIENT_ID_LENGTH; i++) {
    id += CLIENT_ID_ALPHABET[randomInt(CLIENT_ID_ALPHABET.length)];
  }
  return id;
}

export function hash(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

export function compareDigest(known: string, given: string): boolean {
  const a = Buffer.from(known, "utf8");
  const b = Buffer.from(given, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function getSession(request: Request): SessionRow | null {
  const cookie = getCookie(request, SESSION_COOKIE);
  if (!cookie) return null;
  const row = store.session(hash(cookie));
  const time = now();
  if (row === null || row.expires_at <= time) return null;
  if (row.expires_at - time < SESSION_TTL - SESSION_SLIDE_AFTER) {
    store.extendSession(row.hash, time + SESSION_TTL);
    row.expires_at = time + SESSION_TTL;
  }
  return row;
}

export function requireSession(request: Request, returnTo: string): SessionRow {
  const session = getSession(request);
  if (session !== null) return session;
  if (request.method !== "GET") throw errorPage("Not signed in", 400);
  throw startLogin(returnTo);
}

export function csrfMatches(session: SessionRow, form: FormData): boolean {
  const csrf = form.get("csrf");
  return typeof csrf === "string" && compareDigest(session.csrf, csrf);
}

export function checkCsrf(session: SessionRow, form: FormData): void {
  if (!csrfMatches(session, form)) throw unverifiedForm();
}

export function sessionCookie(token: string): string {
  return setCookie(SESSION_COOKIE, token, SESSION_TTL);
}

export function expireSessionCookie(): string {
  return expireCookie(SESSION_COOKIE);
}

export const RETURN_TO: readonly string[] = ["/account", "/apps"];

export function pendingRequest(request: Request): RequestRow | null {
  const flow = getCookie(request, FLOW_COOKIE);
  return fresh(flow === undefined ? null : store.requestByBinding(hash(flow)));
}

export function fresh(req: RequestRow | null): RequestRow | null {
  if (req === null || req.created_at + REQUEST_TTL <= now()) return null;
  return req;
}

export function startFlow(params: FlowParams): string {
  const flow = randomToken();
  store.createRequest(randomToken(), hash(flow), params, now());
  return setCookie(FLOW_COOKIE, flow, REQUEST_TTL);
}

export function finishFlow(): string {
  return expireCookie(FLOW_COOKIE);
}

export function startLogin(returnTo: string): Response {
  if (!RETURN_TO.includes(returnTo)) {
    throw new Error(`not a page a login may return to: ${returnTo}`);
  }
  return redirect("/", { headers: { "Set-Cookie": startFlow({ return_to: returnTo }) } });
}
