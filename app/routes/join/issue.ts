import { randomInt } from "node:crypto";

import * as constants from "../../.server/constants";
import { noStoreJson, readJsonObject, stringField } from "../../.server/http";
import { config, store } from "../../.server/services";
import { compareDigest, hash, now } from "../../.server/session";
import type { Route } from "./+types/issue";

export async function action({ request }: Route.ActionArgs) {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ") || !compareDigest(config.joinSecret, auth.slice(7))) {
    return noStoreJson({ error: "unauthorized" }, 401);
  }
  const body = await readJsonObject(request);
  const uuid = (stringField(body, "uuid") ?? "").replaceAll("-", "").toLowerCase();
  const name = stringField(body, "name") ?? "";
  if (!/^[0-9a-f]{32}$/.test(uuid) || !/^[A-Za-z0-9_]{1,16}$/.test(name)) {
    return noStoreJson({ error: "invalid_profile" }, 400);
  }
  const time = now();
  store.purge(
    time,
    constants.REQUEST_TTL,
    constants.JOIN_CODE_TTL,
    constants.JOIN_FAILURE_WINDOW,
    constants.REPLAY_WINDOW,
  );
  for (let i = 0; i < 5; i++) {
    const code = String(randomInt(1_000_000)).padStart(6, "0");
    if (store.createJoinCode(hash(code), uuid, name, time)) {
      return noStoreJson({ code, expires_in: constants.JOIN_CODE_TTL });
    }
  }
  return noStoreJson({ error: "try_again" }, 503);
}
