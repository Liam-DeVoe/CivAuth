import sys
import time
from argparse import ArgumentParser

import httpx

import secret
from civauth import constants
from civauth.config import Config
from civauth.store import Store

PROFILE_URL = "https://sessionserver.mojang.com/session/minecraft/profile/"
USER_AGENT = "civauth-refresh-names/1.0"
TIMEOUT = 5
DEFAULT_LIMIT = 200
DEFAULT_PAUSE = 1.0


class RateLimited(Exception):
    pass


def lookup(client: httpx.Client, uuid: str) -> str | None:
    response = client.get(PROFILE_URL + uuid.replace("-", ""))
    if response.status_code == 429:
        raise RateLimited
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    name = body.get("name")
    return name if isinstance(name, str) and name else None


def main(argv: list[str]) -> int:
    parser = ArgumentParser()
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--pause", type=float, default=DEFAULT_PAUSE)
    args = parser.parse_args(argv)

    store = Store(Config.from_module(secret).database)
    accounts = store.accounts_to_check(
        int(time.time()) - constants.NAME_CHECK_INTERVAL, max(args.limit, 0)
    )

    checked = 0
    renamed = 0
    failed = 0
    limited = False
    with httpx.Client(
        timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": USER_AGENT}
    ) as client:
        for index, account in enumerate(accounts):
            if index:
                time.sleep(max(args.pause, 0.0))
            try:
                name = lookup(client, account["uuid"])
            except RateLimited:
                limited = True
                break
            except httpx.HTTPError:
                name = None
            if name is None:
                failed += 1
                continue
            store.checked_name(account["uuid"], name, int(time.time()))
            checked += 1
            if name != account["name"]:
                renamed += 1

    tail = ", stopped on rate limit" if limited else ""
    print(
        f"refresh-names: {len(accounts)} due, {checked} checked, "
        f"{renamed} renamed, {failed} failed{tail}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
