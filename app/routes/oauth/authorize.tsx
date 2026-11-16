import { data } from "react-router";

import { Footer } from "../../components/layout";
import { AlternativeLogin, Consent, LoginCard } from "../../components/login";
import { requestContext } from "../../context";
import { redirectUris } from "../../.server/apps";
import * as constants from "../../.server/constants";
import { errorPage } from "../../.server/http";
import { appSummary, continueFlow, proceed, redirectError, submit, type AuthorizeParams } from "../../.server/login";
import { config, store } from "../../.server/services";
import { getSession, now } from "../../.server/session";
import type { Route } from "./+types/authorize";

export { ErrorBoundary } from "../../components/error-page";

const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

export function loader({ request }: Route.LoaderArgs) {
  store.purge(
    now(),
    constants.REQUEST_TTL,
    constants.JOIN_CODE_TTL,
    constants.JOIN_FAILURE_WINDOW,
    constants.REPLAY_WINDOW,
  );
  const args = new URL(request.url).searchParams;
  const clientId = args.get("client_id") ?? "";
  const app = store.app(clientId);
  if (app === null) throw errorPage("Unknown site", 400);
  const redirect = args.get("redirect_uri") ?? "";
  if (!redirectUris(app).includes(redirect)) throw errorPage("Unknown return address", 400);

  const state = args.get("state");
  const fail = (error: string, description: string) => redirectError(redirect, error, description, state);

  if (args.get("response_type") !== "code") {
    return fail("unsupported_response_type", "Only response_type=code is supported.");
  }
  const challenge = args.get("code_challenge");
  const method = args.get("code_challenge_method");
  if (challenge !== null || method !== null) {
    if (method !== "S256") {
      return fail("invalid_request", "Only code_challenge_method=S256 is supported.");
    }
    if (challenge === null || !CODE_CHALLENGE.test(challenge)) {
      return fail("invalid_request", "code_challenge must be the base64url SHA-256 of the verifier.");
    }
  }

  const params: AuthorizeParams = { client_id: clientId, redirect_uri: redirect, state, code_challenge: challenge };
  const session = getSession(request);
  if (session !== null) return proceed(request, params, session);
  return data(
    { app: appSummary(app), address: config.joinAddress, consent: null },
    { headers: continueFlow(request, params) },
  );
}

export async function action({ request, context }: Route.ActionArgs) {
  return submit(request, context.get(requestContext).remoteAddress);
}

export default function Authorize({ loaderData, actionData }: Route.ComponentProps) {
  const { app, address, consent } = loaderData;
  return (
    <div className="page-consent">
      <div className="consent">
        {consent ? (
          <Consent app={app} {...consent} />
        ) : (
          <LoginCard app={app} address={address} errors={actionData ?? null} />
        )}
      </div>
      <Footer>{consent ? null : <AlternativeLogin newTab />}</Footer>
    </div>
  );
}
