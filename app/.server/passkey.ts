import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";

import { FLOW_COOKIE, REQUEST_TTL } from "./constants";
import { getCookie, isObject, noStoreJson, parseJson, readJsonObject, setCookie } from "./http";
import { config, store } from "./services";
import { compareDigest, getSession, hash, now, pendingRequest, randomToken } from "./session";
import type { AccountRow, FlowParams, RequestRow, SessionRow } from "./store";

const CHALLENGE = "passkey_challenge";
const ALGORITHMS = [-8, -7, -257];
const ORIGIN = new URL(config.issuer).origin;
const RP_ID = new URL(config.issuer).hostname;

type ChallengeParams = FlowParams & { [CHALLENGE]?: string };

export async function addOptions(request: Request): Promise<Response> {
  const session = getSession(request);
  if (session === null) return fail("You are not signed in.");
  if (!allowed(session, await readJsonObject(request)))
    return fail("This page could not be verified. Reload it and try again.");
  const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: "CivAuth",
    userID: new TextEncoder().encode(session.uuid),
    userName: session.name,
    userDisplayName: session.name,
    excludeCredentials: store.passkeysFor(session.uuid).map((row) => ({ id: row.credential_id })),
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    supportedAlgorithmIDs: ALGORITHMS,
  });
  return noStoreJson(options, 200, { "Set-Cookie": keepChallenge(request, options.challenge) });
}

export async function addPasskey(
  request: Request,
  session: SessionRow,
  credentialJson: string,
): Promise<string | null> {
  const req = pendingRequest(request);
  const challenge = req === null ? undefined : (req.params as ChallengeParams)[CHALLENGE];
  if (typeof challenge !== "string") return "This request has expired. Start again.";
  const credential = parseJson(credentialJson);
  if (!isObject(credential)) return "That passkey could not be read.";
  let info;
  try {
    const result = await verifyRegistrationResponse({
      response: credential as unknown as RegistrationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
      supportedAlgorithmIDs: ALGORITHMS,
    });
    if (!result.verified) return "That passkey could not be verified.";
    info = result.registrationInfo.credential;
  } catch {
    return "That passkey could not be verified.";
  }
  const existing = store.passkey(info.id);
  if (existing !== null && existing.uuid !== session.uuid) return "That passkey could not be verified.";
  store.addPasskey(info.id, session.uuid, Buffer.from(info.publicKey).toString("base64url"), info.counter, now());
  release(req!);
  return null;
}

export async function loginOptions(request: Request): Promise<Response> {
  if (pendingRequest(request) === null) return fail("This login has expired. Start again.");
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [],
    userVerification: "preferred",
  });
  return noStoreJson(options, 200, { "Set-Cookie": keepChallenge(request, options.challenge) });
}

export async function verifyPasskey(req: RequestRow, credentialJson: string): Promise<AccountRow | string> {
  const challenge = (req.params as ChallengeParams)[CHALLENGE];
  if (typeof challenge !== "string") return "This login has expired. Start again.";
  const credential = parseJson(credentialJson);
  if (!isObject(credential) || typeof credential.id !== "string") return "That passkey could not be read.";
  const row = store.passkey(credential.id);
  if (row === null) return "That passkey is not registered here.";
  let counter: number;
  try {
    const result = await verifyAuthenticationResponse({
      response: credential as unknown as AuthenticationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: row.credential_id,
        publicKey: Buffer.from(row.public_key, "base64url"),
        counter: Number(row.sign_count),
      },
      requireUserVerification: false,
    });
    if (!result.verified) return "That passkey could not be verified.";
    counter = result.authenticationInfo.newCounter;
  } catch {
    return "That passkey could not be verified.";
  }
  store.usedPasskey(row.credential_id, counter, now());
  return store.account(row.uuid) ?? "That account no longer exists.";
}

function keepChallenge(request: Request, challenge: string): string {
  const req = pendingRequest(request);
  const params: ChallengeParams = { ...req?.params, [CHALLENGE]: challenge };
  const flow = getCookie(request, FLOW_COOKIE) || randomToken();
  store.createRequest(randomToken(), hash(flow), params, now());
  if (req !== null) store.deleteRequest(req.id);
  return setCookie(FLOW_COOKIE, flow, REQUEST_TTL);
}

function release(req: RequestRow): void {
  store.deleteRequest(req.id);
  const carried = withoutChallenge(req.params);
  if (Object.keys(carried).length > 0) {
    store.createRequest(randomToken(), req.binding_hash, carried, now());
  }
}

function withoutChallenge(params: FlowParams): FlowParams {
  const { [CHALLENGE]: _challenge, ...rest } = params as ChallengeParams;
  return rest;
}

function allowed(session: SessionRow, body: Record<string, unknown>): boolean {
  return typeof body.csrf === "string" && compareDigest(session.csrf, body.csrf);
}

function fail(message: string): Response {
  return noStoreJson({ ok: false, error: message }, 400);
}
