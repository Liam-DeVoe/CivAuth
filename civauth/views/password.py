import re
from urllib.parse import quote

import httpx
from flask import Response, request
from werkzeug.security import check_password_hash, generate_password_hash

from civauth import CivAuth, civ, constants
from civauth.views.authorize import expired, login_page, pending, signed_in

PROFILE = "https://api.mojang.com/users/profiles/minecraft/"
TIMEOUT = 5

NAME = re.compile(r"\w{1,16}", re.ASCII)
UUID = re.compile(r"[0-9a-fA-F]{32}")

DUMMY_HASH = generate_password_hash(CivAuth.random_token())

WRONG = "Incorrect username or password."
TOO_MANY = "Too many failed attempts. Wait a few minutes and try again."


def verify_password() -> Response:
    app = civ()
    req = pending()
    if req is None:
        return expired()

    now = app.now()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    address = (
        (request.headers.get("X-Forwarded-For", request.remote_addr) or "")
        .split(",")[0]
        .strip()
    )

    since = now - constants.PASSWORD_ATTEMPT_WINDOW
    if (
        app.store.login_failures_by_address(address, since)
        >= constants.PASSWORD_ATTEMPTS
    ):
        return form(username, TOO_MANY)
    account = resolve(username)
    if (
        account is not None
        and app.store.login_failures_by_uuid(account["uuid"], since)
        >= constants.PASSWORD_ATTEMPTS
    ):
        return form(username, TOO_MANY)

    stored = None if account is None else account["password_hash"]
    verified = check_password_hash(stored or DUMMY_HASH, password)
    if stored is None or not verified:
        app.store.record_login_failure(
            "" if account is None else account["uuid"], address, now
        )
        return form(username, WRONG)

    app.store.delete_request(req["id"])
    return signed_in(req["params"], account["uuid"], account["name"])


def resolve(username: str) -> dict | None:
    store = civ().store
    if not NAME.fullmatch(username):
        return None
    try:
        response = httpx.get(
            PROFILE + quote(username, safe=""), timeout=TIMEOUT, follow_redirects=False
        )
    except httpx.HTTPError:
        return store.account_by_name(username)
    if response.status_code == 404 or not response.content:
        return None
    if response.status_code != 200:
        return store.account_by_name(username)
    try:
        data = response.json()
    except ValueError:
        return store.account_by_name(username)
    uuid = data.get("id") if isinstance(data, dict) else None
    if not isinstance(uuid, str) or not UUID.fullmatch(uuid):
        return None
    return store.account(uuid.lower())


def form(username: str, error: str | None) -> Response:
    return login_page(username=username, error=error)
