import { createHash } from "node:crypto";

import * as constants from "../../.server/constants";
import { formString, noStoreJson, readForm } from "../../.server/http";
import { store } from "../../.server/services";
import { compareDigest, hash, now, randomToken } from "../../.server/session";
import type { AppRow, TokenPair } from "../../.server/store";
import type { Route } from "./+types/token";

const BASIC = /^Basic\s+((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/i;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

export async function action({ request }: Route.ActionArgs) {
  const form = await readForm(request);
  const [clientId, secret, conflict] = clientCredentials(request, form);
  if (conflict) return error("invalid_request", "Conflicting client credentials.");
  const client = clientId === null ? null : store.app(clientId);
  if (client === null || secret === null || !compareDigest(client.secret_hash, hash(secret))) {
    return noStoreJson({ error: "invalid_client", error_description: "Client authentication failed." }, 401, {
      "WWW-Authenticate": 'Basic realm="civauth"',
    });
  }
  const time = now();
  store.purge(
    time,
    constants.REQUEST_TTL,
    constants.JOIN_CODE_TTL,
    constants.JOIN_FAILURE_WINDOW,
    constants.REPLAY_WINDOW,
  );

  const grantType = formString(form, "grant_type");
  if (grantType === "authorization_code") return exchangeCode(form, client, time);
  if (grantType === "refresh_token") return refresh(form, client, time);
  return error("unsupported_grant_type", "Only authorization_code and refresh_token are supported.");
}

function exchangeCode(form: FormData, client: AppRow, time: number): Response {
  const code = formString(form, "code");
  if (code === null) return error("invalid_request", "Missing code.");
  const row = store.code(hash(code));
  if (row === null || row.expires_at <= time) {
    return error("invalid_grant", "The code is unknown or has expired.");
  }

  let problem: string | null = null;
  if (row.client_id !== client.client_id) {
    problem = "The code was issued to a different client.";
  } else if (formString(form, "redirect_uri") !== row.redirect_uri) {
    problem = "redirect_uri does not match the authorization request.";
  } else if (row.code_challenge !== null) {
    const verifier = formString(form, "code_verifier");
    if (verifier === null || !VERIFIER.test(verifier) || !compareDigest(row.code_challenge, challenge(verifier))) {
      problem = "code_verifier does not match code_challenge.";
    }
  }

  const [pair, response] = tokenPair(row.hash, client.client_id, row.uuid, row.name, time);
  if (!store.exchangeCode(row.hash, problem ? null : pair)) {
    store.revokeTokensForCode(row.hash);
    return error("invalid_grant", "The code has already been used.");
  }
  if (problem) return error("invalid_grant", problem);
  return response;
}

function refresh(form: FormData, client: AppRow, time: number): Response {
  const presented = formString(form, "refresh_token");
  if (presented === null) return error("invalid_request", "Missing refresh_token.");
  const row = store.refreshToken(hash(presented));
  if (row === null || row.client_id !== client.client_id) {
    return error("invalid_grant", "The refresh token is unknown.");
  }
  if (row.expires_at <= time) return error("invalid_grant", "The refresh token has expired.");
  const account = store.account(row.uuid);
  const name = account === null ? row.name : account.name;
  const [pair, response] = tokenPair(row.code_hash, client.client_id, row.uuid, name, time);
  if (!store.rotateRefreshToken(row.hash, time, pair)) {
    store.revokeTokensForCode(row.code_hash);
    return error("invalid_grant", "The refresh token was already used. All tokens from this login are revoked.");
  }
  store.recordGrant(row.uuid, client.client_id, time);
  return response;
}

function tokenPair(
  codeHash: string,
  clientId: string,
  uuid: string,
  name: string,
  time: number,
): [TokenPair, Response] {
  const access = randomToken();
  const refreshToken = randomToken();
  const pair: TokenPair = {
    access_hash: hash(access),
    refresh_hash: hash(refreshToken),
    code_hash: codeHash,
    client_id: clientId,
    uuid,
    name,
    access_expires_at: time + constants.TOKEN_TTL,
    refresh_expires_at: time + constants.REFRESH_TTL,
  };
  const response = noStoreJson({
    access_token: access,
    token_type: "Bearer",
    expires_in: constants.TOKEN_TTL,
    refresh_token: refreshToken,
  });
  return [pair, response];
}

function challenge(verifier: string): string {
  return createHash("sha256").update(verifier, "utf8").digest("base64url");
}

function clientCredentials(request: Request, form: FormData): [string | null, string | null, boolean] {
  const auth = request.headers.get("Authorization");
  if (auth === null) return [formString(form, "client_id"), formString(form, "client_secret"), false];
  const match = BASIC.exec(auth);
  if (match === null) return [null, null, false];
  const decoded = Buffer.from(match[1]!, "base64").toString("utf8");
  const colon = decoded.indexOf(":");
  if (colon === -1) return [null, null, false];
  const clientId = formDecode(decoded.slice(0, colon));
  const secret = formDecode(decoded.slice(colon + 1));
  if (clientId === null || secret === null) return [null, null, false];
  const bodyId = formString(form, "client_id");
  const bodySecret = formString(form, "client_secret");
  const conflict =
    (bodyId !== null && bodyId !== clientId) || (bodySecret !== null && !compareDigest(secret, bodySecret));
  return [clientId, secret, conflict];
}

function formDecode(value: string): string | null {
  try {
    return decodeURIComponent(value.replaceAll("+", " "));
  } catch {
    return null;
  }
}

function error(code: string, description: string): Response {
  return noStoreJson({ error: code, error_description: description }, 400);
}
