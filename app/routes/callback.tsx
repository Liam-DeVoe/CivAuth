import { FLOW_COOKIE } from "../.server/constants";
import { expired, getCookie } from "../.server/http";
import { loginFailed, signedIn } from "../.server/login";
import { LoginFailed } from "../.server/minecraft";
import { minecraft, store } from "../.server/services";
import { compareDigest, fresh, hash } from "../.server/session";
import type { Route } from "./+types/callback";

export async function loader({ request }: Route.LoaderArgs) {
  const args = new URL(request.url).searchParams;
  const state = args.get("state");
  const req = fresh(state === null ? null : store.request(state));
  const flowCookie = getCookie(request, FLOW_COOKIE);
  if (req === null || flowCookie === undefined || !compareDigest(req.binding_hash, hash(flowCookie))) {
    throw expired();
  }
  store.deleteRequest(req.id);

  if (args.get("error") !== null) throw loginFailed(req.params, "Microsoft sign-in cancelled.");
  const code = args.get("code");
  if (code === null) throw loginFailed(req.params, "Microsoft sent nothing back.");
  let profile;
  try {
    profile = await minecraft.authenticate(code);
  } catch (error) {
    if (!(error instanceof LoginFailed)) throw error;
    console.error(`login failed: ${error.message}`);
    throw loginFailed(req.params, error.message);
  }
  return signedIn(request, req.params, profile.uuid, profile.name);
}

export default function Callback() {
  return null;
}
