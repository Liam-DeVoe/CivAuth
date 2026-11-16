import { data, redirect, redirectDocument } from "react-router";

import * as constants from "./constants";
import {
  appendQuery,
  errorPage,
  expired,
  formString,
  getCookie,
  isObject,
  parseJson,
  readForm,
  unverifiedForm,
  type ErrorAction,
} from "./http";
import { verifyPasskey } from "./passkey";
import { checkPasswordHash, generatePasswordHash } from "./password";
import { config, store } from "./services";
import {
  RETURN_TO,
  csrfMatches,
  expireSessionCookie,
  finishFlow,
  getSession,
  hash,
  now,
  pendingRequest,
  randomToken,
  sessionCookie,
  startFlow,
} from "./session";
import type { AppRow, FlowParams, SessionRow } from "./store";

export interface LoginErrors {
  username?: string;
  error?: string;
  joinError?: string;
  passkeyError?: string;
}

export interface AppSummary {
  name: string;
  owner: string;
}

export interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string | null;
}

interface Flow {
  request: Request;
  form: FormData;
  remoteAddress: string;
}

export function appSummary(app: AppRow): AppSummary {
  return {
    name: app.name,
    owner: config.ownerNames[app.client_id] || (store.account(app.owner_uuid)?.name ?? ""),
  };
}

export function continueFlow(request: Request, params: AuthorizeParams): HeadersInit {
  const req = pendingRequest(request);
  const same =
    req !== null &&
    (["client_id", "redirect_uri", "state", "code_challenge"] as const).every(
      (key) => (req.params[key] ?? null) === params[key],
    );
  if (!same) return { "Set-Cookie": startFlow(params) };
  store.touchRequest(req.id, now());
  return {};
}

function failed(errors: LoginErrors) {
  return data(errors);
}

export function signedIn(request: Request, params: FlowParams, uuid: string, name: string): Response {
  const headers = new Headers();
  const old = getCookie(request, constants.SESSION_COOKIE);
  if (old !== undefined) store.deleteSession(hash(old));
  const token = randomToken();
  const tokenHash = hash(token);
  store.createSession(tokenHash, uuid, name, now() + constants.SESSION_TTL, randomToken());
  store.touchAccount(uuid, name, now());
  headers.append("Set-Cookie", sessionCookie(token));

  if (params.return_to !== undefined && params.return_to !== null) {
    headers.append("Set-Cookie", finishFlow());
    return redirect(RETURN_TO.includes(params.return_to) ? params.return_to : "/", { headers });
  }
  if (params.client_id === undefined || params.client_id === null) {
    headers.append("Set-Cookie", finishFlow());
    return redirect("/account", { headers });
  }
  requireApp(params.client_id, headers);
  return issue(params as AuthorizeParams, store.session(tokenHash)!, headers);
}

function requireApp(clientId: string, headers = new Headers()): AppRow {
  const app = store.app(clientId);
  if (app !== null) return app;
  headers.append("Set-Cookie", finishFlow());
  throw errorPage("Unknown site", 400, { headers });
}

export function proceed(request: Request, params: AuthorizeParams, session: SessionRow) {
  const app = requireApp(params.client_id);
  if (store.grant(session.uuid, app.client_id) !== null) return issue(params, session);
  return data(
    {
      app: appSummary(app),
      address: config.joinAddress,
      consent: { account: { uuid: session.uuid, name: session.name }, csrf: session.csrf },
    },
    { headers: continueFlow(request, params) },
  );
}

function issue(params: AuthorizeParams, session: SessionRow, headers = new Headers()): Response {
  const code = randomToken();
  store.createCode(
    hash(code),
    params.client_id,
    params.redirect_uri,
    session.uuid,
    session.name,
    params.code_challenge,
    now() + constants.CODE_TTL,
  );
  store.recordGrant(session.uuid, params.client_id, now());
  headers.append("Set-Cookie", finishFlow());
  return redirectDocument(appendQuery(params.redirect_uri, { code, state: params.state }), { headers });
}

export function redirectError(
  redirectUri: string,
  error: string,
  description: string,
  state: string | null | undefined,
  headers?: HeadersInit,
): Response {
  return redirectDocument(appendQuery(redirectUri, { error, error_description: description, state }), { headers });
}

function pendingAuthorization(request: Request) {
  const req = pendingRequest(request);
  if (req === null || req.params.client_id === undefined || req.params.client_id === null) throw expired();
  return { id: req.id, params: req.params as AuthorizeParams };
}

function decide(f: Flow) {
  const req = pendingAuthorization(f.request);
  const session = getSession(f.request);
  if (session === null) return data(null);
  if (!csrfMatches(session, f.form)) throw unverifiedForm();
  const decision = formString(f.form, "decision");
  if (decision === "switch") {
    store.deleteSession(session.hash);
    return data(null, { headers: { "Set-Cookie": expireSessionCookie() } });
  }
  store.deleteRequest(req.id);
  if (decision === "allow") return issue(req.params, session);
  return declined(req.params);
}

function cancel(f: Flow): Response {
  const req = pendingAuthorization(f.request);
  store.deleteRequest(req.id);
  return declined(req.params);
}

function declined(params: AuthorizeParams): Response {
  const headers = { "Set-Cookie": finishFlow() };
  return redirectError(params.redirect_uri, "access_denied", "The user declined.", params.state, headers);
}

export function loginFailed(params: FlowParams, message: string) {
  if (params.return_to !== undefined && params.return_to !== null) {
    const returnTo = RETURN_TO.includes(params.return_to) ? params.return_to : "/";
    return errorPage("Login failed", 400, { message, actions: retryActions(returnTo, "/account") });
  }
  const oauth = params as AuthorizeParams;
  const retry = appendQuery("/oauth/authorize", {
    client_id: oauth.client_id,
    redirect_uri: oauth.redirect_uri,
    state: oauth.state,
    code_challenge: oauth.code_challenge,
    response_type: "code",
    code_challenge_method: oauth.code_challenge ? "S256" : null,
  });
  const cancelUri = appendQuery(oauth.redirect_uri, {
    error: "access_denied",
    error_description: "The login did not complete.",
    state: oauth.state,
  });
  return errorPage("Login failed", 400, { message, actions: retryActions(retry, cancelUri) });
}

function retryActions(retry: string, cancel: string): ErrorAction[] {
  return [
    { href: retry, label: "Try again" },
    { href: cancel, label: "Cancel", plain: true },
  ];
}

function verifyCode(f: Flow) {
  const req = pendingRequest(f.request);
  if (req === null) throw expired();

  const time = now();
  if (store.joinFailuresSince(f.remoteAddress, time - constants.JOIN_FAILURE_WINDOW) >= constants.JOIN_FAILURES) {
    return failed({ joinError: "Too many wrong codes. Wait a few minutes and try again." });
  }
  const code = (formString(f.form, "code") ?? "").replace(/\D/g, "");
  const owner = code.length === 6 ? store.consumeJoinCode(hash(code), time - constants.JOIN_CODE_TTL) : null;
  if (owner === null) {
    store.recordJoinFailure(f.remoteAddress, time);
    if (store.countAttempt(req.id) >= constants.JOIN_ATTEMPTS) {
      store.deleteRequest(req.id);
      throw expired();
    }
    return failed({ joinError: "Incorrect verification code." });
  }
  store.deleteRequest(req.id);
  return signedIn(f.request, req.params, owner.uuid, owner.name);
}

const PROFILE = "https://api.mojang.com/users/profiles/minecraft/";
const PROFILE_TIMEOUT = 5_000;
const NAME = /^[A-Za-z0-9_]{1,16}$/;
const UUID = /^[0-9a-fA-F]{32}$/;
const WRONG = "Incorrect username or password.";
const TOO_MANY = "Too many failed attempts. Wait a few minutes and try again.";

let dummyHash: Promise<string> | null = null;
function getDummyHash(): Promise<string> {
  return (dummyHash ??= generatePasswordHash(randomToken()));
}

const pendingChecks = { address: new Map<string, number>(), uuid: new Map<string, number>() };

function hold(counts: Map<string, number>, key: string): () => void {
  counts.set(key, (counts.get(key) ?? 0) + 1);
  let held = true;
  return () => {
    if (!held) return;
    held = false;
    const left = counts.get(key)! - 1;
    if (left > 0) counts.set(key, left);
    else counts.delete(key);
  };
}

async function verifyPassword(f: Flow) {
  const req = pendingRequest(f.request);
  if (req === null) throw expired();

  const time = now();
  const username = (formString(f.form, "username") ?? "").trim();
  const password = formString(f.form, "password") ?? "";
  const remoteAddress = f.remoteAddress;

  const since = time - constants.PASSWORD_ATTEMPT_WINDOW;
  const byAddress =
    (pendingChecks.address.get(remoteAddress) ?? 0) + store.loginFailuresByAddress(remoteAddress, since);
  if (byAddress >= constants.PASSWORD_ATTEMPTS) {
    return failed({ username, error: TOO_MANY });
  }
  const releaseAddress = hold(pendingChecks.address, remoteAddress);
  let releaseUuid = () => {};
  try {
    const account = await resolve(username);
    if (account !== null) {
      const byUuid = (pendingChecks.uuid.get(account.uuid) ?? 0) + store.loginFailuresByUuid(account.uuid, since);
      if (byUuid >= constants.PASSWORD_ATTEMPTS) {
        return failed({ username, error: TOO_MANY });
      }
      releaseUuid = hold(pendingChecks.uuid, account.uuid);
    }

    const stored = account === null ? null : account.password_hash;
    const verified = await checkPasswordHash(stored || (await getDummyHash()), password);
    if (stored === null || !verified) {
      store.recordLoginFailure(account === null ? "" : account.uuid, remoteAddress, time);
      return failed({ username, error: WRONG });
    }

    store.deleteRequest(req.id);
    return signedIn(f.request, req.params, account!.uuid, account!.name);
  } finally {
    releaseUuid();
    releaseAddress();
  }
}

async function resolve(username: string) {
  if (!NAME.test(username)) return null;
  let status: number;
  let body: Uint8Array;
  try {
    const response = await fetch(PROFILE + encodeURIComponent(username), {
      redirect: "manual",
      signal: AbortSignal.timeout(PROFILE_TIMEOUT),
    });
    status = response.status;
    body = new Uint8Array(await response.arrayBuffer());
  } catch {
    return store.accountByName(username);
  }
  if (status === 404 || body.length === 0) return null;
  if (status !== 200) return store.accountByName(username);
  const parsed = parseJson(new TextDecoder().decode(body));
  if (parsed === undefined) return store.accountByName(username);
  const uuid = isObject(parsed) ? parsed.id : undefined;
  if (typeof uuid !== "string" || !UUID.test(uuid)) return null;
  return store.account(uuid.toLowerCase());
}

async function passkey(f: Flow) {
  const req = pendingRequest(f.request);
  if (req === null) return failed({ passkeyError: "This login has expired. Start again." });
  const account = await verifyPasskey(req, formString(f.form, "credential") ?? "");
  if (typeof account === "string") return failed({ passkeyError: account });
  store.deleteRequest(req.id);
  return signedIn(f.request, req.params, account.uuid, account.name);
}

export async function submit(request: Request, remoteAddress: string) {
  const f: Flow = { request, form: await readForm(request), remoteAddress };
  switch (formString(f.form, "intent")) {
    case "code":
      return verifyCode(f);
    case "password":
      return verifyPassword(f);
    case "passkey":
      return passkey(f);
    case "consent":
      return decide(f);
    case "cancel":
      return cancel(f);
    default:
      throw unverifiedForm();
  }
}
