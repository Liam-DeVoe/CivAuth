import re
import secrets

from flask import Blueprint, Response, request

from civauth import civ, constants, json_response
from civauth.store import Store
from civauth.views.authorize import expired, login_page, pending, signed_in

bp = Blueprint("join", __name__)


def verify_code() -> Response:
    app = civ()
    req = pending()
    if req is None:
        return expired()

    now = app.now()
    address = (
        (request.headers.get("X-Forwarded-For", request.remote_addr) or "")
        .split(",")[0]
        .strip()
    )
    if (
        app.store.join_failures_since(address, now - constants.JOIN_FAILURE_WINDOW)
        >= constants.JOIN_FAILURES
    ):
        return form("Too many wrong codes. Wait a few minutes and try again.")
    code = re.sub(r"\D+", "", request.form.get("code", ""))
    owner = (
        app.store.consume_join_code(Store.hash(code), now - constants.JOIN_CODE_TTL)
        if len(code) == 6
        else None
    )
    if owner is None:
        app.store.record_join_failure(address, now)
        if app.store.count_attempt(req["id"]) >= constants.JOIN_ATTEMPTS:
            app.store.delete_request(req["id"])
            return expired()
        return form("Incorrect verification code.")
    app.store.delete_request(req["id"])
    return signed_in(req["params"], owner["uuid"], owner["name"])


def form(error: str | None) -> Response:
    return login_page(join_error=error)


@bp.post("/join/issue")
def issue() -> Response:
    app = civ()
    secret = app.config.join_secret
    auth = request.headers.get("Authorization", "")
    if (
        secret is None
        or not auth.startswith("Bearer ")
        or not secrets.compare_digest(secret, auth[7:])
    ):
        return json_response({"error": "unauthorized"}, 401)
    body = request.get_json(silent=True, force=True)
    if not isinstance(body, dict):
        body = {}
    uuid = str(body.get("uuid") or "").replace("-", "").lower()
    name = str(body.get("name") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", uuid) or not re.fullmatch(
        r"\w{1,16}", name, re.ASCII
    ):
        return json_response({"error": "invalid_profile"}, 400)
    now = app.now()
    app.store.purge(
        now,
        constants.REQUEST_TTL,
        constants.JOIN_CODE_TTL,
        constants.JOIN_FAILURE_WINDOW,
    )
    for _ in range(5):
        code = f"{secrets.randbelow(1000000):06d}"
        if app.store.create_join_code(Store.hash(code), uuid, name, now):
            return json_response({"code": code, "expires_in": constants.JOIN_CODE_TTL})
    return json_response({"error": "try_again"}, 503)
