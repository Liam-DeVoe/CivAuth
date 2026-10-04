import datetime
import secrets

from flask import Blueprint, Response, abort, render_template, request
from markupsafe import Markup
from werkzeug.security import generate_password_hash

from civauth import civ, html_response, hyphenated, redirect_response
from civauth.constants import NOTICE_COOKIE

bp = Blueprint("account", __name__)

MESSAGES = {
    "password-set": "Password set.",
    "password-changed": "Password changed.",
    "passkey-added": "Passkey added.",
    "passkey-removed": "That passkey has been removed.",
}
ERRORS = {
    "empty-password": "Enter a password.",
    "app-gone": "That app has already been removed.",
    "passkey-gone": "That passkey has already been removed.",
}


@bp.get("/account")
def index() -> Response:
    session = require_session()
    notice = request.cookies.get(NOTICE_COOKIE, "")
    message = MESSAGES.get(notice)
    if notice.startswith("app-removed:"):
        app = civ().store.app(notice.removeprefix("app-removed:"))
        name = "That app" if app is None else app["name"]
        message = Markup("Removed {} from authorized apps.").format(name)
    response = page(session, message, ERRORS.get(notice))
    if notice:
        civ().clear_cookie(response, NOTICE_COOKIE)
    return response


@bp.post("/account/password")
def password() -> Response:
    auth = civ()
    session = require_session()
    check_csrf(session)
    account = auth.store.account(session["uuid"])
    stored = None if account is None else account["password_hash"]
    new = request.form.get("new", "")
    if not new:
        return back("empty-password")
    auth.store.set_password(session["uuid"], generate_password_hash(new), auth.now())
    return back("password-set" if stored is None else "password-changed")


@bp.post("/account/apps/remove")
def remove_app() -> Response:
    auth = civ()
    session = require_session()
    check_csrf(session)
    client_id = request.form.get("client_id", "")
    if not auth.store.delete_grant(session["uuid"], client_id):
        return back("app-gone")
    return back(f"app-removed:{client_id}")


@bp.post("/account/passkeys/delete")
def remove_passkey() -> Response:
    auth = civ()
    session = require_session()
    check_csrf(session)
    credential_id = request.form.get("credential_id", "")
    if not auth.store.delete_passkey(credential_id, session["uuid"]):
        return back("passkey-gone")
    return back("passkey-removed")


def back(notice: str) -> Response:
    response = redirect_response(civ().config.path("/account"))
    return civ().set_cookie(response, NOTICE_COOKIE, notice, 60)


def require_session() -> dict:
    session = civ().session()
    if session is not None:
        return session
    if request.method != "GET":
        abort(civ().error_page("Not signed in", "", 400))
    from civauth.views.authorize import start_login

    abort(start_login("/account"))


def check_csrf(session: dict) -> None:
    csrf = request.form.get("csrf")
    if csrf is None or not equals(session["csrf"], csrf):
        abort(civ().error_page("This form could not be verified", "", 400))


def equals(known: str, given: str) -> bool:
    return secrets.compare_digest(known.encode(), given.encode())


def page(session: dict, message: str | None, error: str | None) -> Response:
    auth = civ()
    account = auth.store.account(session["uuid"])
    grants = auth.store.grants_for(session["uuid"])
    html = render_template(
        "account.html",
        title="Your account",
        name=session["name"],
        uuid=hyphenated(session["uuid"]),
        has_password=account is not None and account["password_hash"] is not None,
        passkeys=[
            {"credential_id": row["credential_id"], "added": added(row["created_at"])}
            for row in auth.store.passkeys_for(session["uuid"])
        ],
        password_url=auth.config.path("/account/password"),
        remove_url=auth.config.path("/account/passkeys/delete"),
        grants=[
            {
                "name": row["name"],
                "client_id": row["client_id"],
                "owner": row["owner_name"],
                "used": added(row["used_at"]),
            }
            for row in grants
        ],
        revoke_url=auth.config.path("/account/apps/remove"),
        passkey_options_url=auth.config.path("/account/passkey/options"),
        passkey_verify_url=auth.config.path("/account/passkey/verify"),
        passkey_done_url=auth.config.path("/account"),
        csrf=session["csrf"],
        message=message,
        error=error,
    )
    return html_response(html, 200)


def added(created_at: int) -> str:
    moment = datetime.datetime.fromtimestamp(int(created_at), datetime.timezone.utc)
    return f"{moment.day} {moment:%B %Y}"
