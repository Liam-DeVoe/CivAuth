import { hyphenated } from "../../.server/account";
import { noStoreJson } from "../../.server/http";
import { store } from "../../.server/services";
import { hash, now } from "../../.server/session";
import type { Route } from "./+types/user";

const BEARER = /^Bearer\s+(\S+)$/i;

export function loader({ request }: Route.LoaderArgs) {
  const auth = request.headers.get("Authorization");
  const match = auth === null ? null : BEARER.exec(auth);
  const row = match === null ? null : store.token(hash(match[1]!));
  if (row === null || row.expires_at <= now()) {
    return noStoreJson({ error: "invalid_token" }, 401, { "WWW-Authenticate": 'Bearer error="invalid_token"' });
  }
  return noStoreJson({ uuid: hyphenated(row.uuid), name: row.name });
}
