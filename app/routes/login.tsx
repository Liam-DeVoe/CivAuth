import { data, redirect } from "react-router";

import { AlternativeLogin, LoginPage } from "../components/login";
import { requestContext } from "../context";
import { submit } from "../.server/login";
import { config, store } from "../.server/services";
import { getSession, now, pendingRequest, startLogin } from "../.server/session";
import type { Route } from "./+types/login";
import type { PageHandle } from "./layout";

export const handle: PageHandle = { footer: <AlternativeLogin /> };

export function loader({ request }: Route.LoaderArgs) {
  const req = pendingRequest(request);
  if (req === null || req.params.return_to === undefined || req.params.return_to === null) {
    if (req !== null) store.deleteRequest(req.id);
    if (getSession(request) !== null) return redirect("/account");
    return startLogin("/account");
  }
  store.touchRequest(req.id, now());
  return data({ address: config.joinAddress });
}

export async function action({ request, context }: Route.ActionArgs) {
  return submit(request, context.get(requestContext).remoteAddress);
}

export default function Login({ loaderData, actionData }: Route.ComponentProps) {
  return <LoginPage address={loaderData.address} errors={actionData ?? null} />;
}
