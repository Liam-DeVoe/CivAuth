import { redirect } from "react-router";

import { readForm } from "../.server/http";
import { store } from "../.server/services";
import { csrfMatches, expireSessionCookie, getSession } from "../.server/session";
import type { Route } from "./+types/signout";

export async function action({ request }: Route.ActionArgs) {
  const session = getSession(request);
  if (session !== null && csrfMatches(session, await readForm(request))) store.deleteSession(session.hash);
  return redirect("/", { headers: { "Set-Cookie": expireSessionCookie() } });
}
