import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";

import { NAME_CHECK_INTERVAL } from "../app/.server/constants";
import { isObject, parseJson } from "../app/.server/http";
import { store } from "../app/.server/services";
import { now } from "../app/.server/session";

const PROFILE_URL = "https://sessionserver.mojang.com/session/minecraft/profile/";
const USER_AGENT = "civauth-refresh-names/1.0";
const TIMEOUT = 5_000;

class RateLimited extends Error {}

async function lookup(uuid: string): Promise<string | null> {
  let response: Response;
  try {
    response = await fetch(PROFILE_URL + uuid.replaceAll("-", ""), {
      redirect: "manual",
      headers: { "User-Agent": USER_AGENT },
      signal: AbortSignal.timeout(TIMEOUT),
    });
  } catch {
    return null;
  }
  if (response.status === 429) {
    await response.body?.cancel();
    throw new RateLimited();
  }
  const body = parseJson(await response.text().catch(() => ""));
  if (response.status !== 200 || !isObject(body)) return null;
  return typeof body.name === "string" && body.name !== "" ? body.name : null;
}

const { values } = parseArgs({
  options: {
    limit: { type: "string", default: "200" },
    pause: { type: "string", default: "1" },
  },
});
const limit = Number(values.limit);
const pause = Number(values.pause);
if (!Number.isInteger(limit) || limit < 0 || !Number.isFinite(pause) || pause < 0) {
  console.error("usage: refresh-names [--limit N] [--pause SECONDS]");
  process.exit(2);
}

const accounts = store.accountsToCheck(now() - NAME_CHECK_INTERVAL, limit);

let checked = 0;
let renamed = 0;
let failed = 0;
let limited = false;
for (const [index, account] of accounts.entries()) {
  if (index > 0) await sleep(pause * 1000);
  let name: string | null;
  try {
    name = await lookup(account.uuid);
  } catch (error) {
    if (!(error instanceof RateLimited)) throw error;
    limited = true;
    break;
  }
  if (name === null) {
    failed += 1;
    continue;
  }
  store.checkedName(account.uuid, name, now());
  checked += 1;
  if (name !== account.name) renamed += 1;
}

const tail = limited ? ", stopped on rate limit" : "";
console.log(`refresh-names: ${accounts.length} due, ${checked} checked, ${renamed} renamed, ${failed} failed${tail}`);
