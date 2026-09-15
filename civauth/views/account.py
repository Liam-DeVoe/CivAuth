import datetime
import secrets

from flask import Blueprint, Response, abort, render_template, request
from markupsafe import Markup
from werkzeug.security import generate_password_hash

from civauth import civ, html_response

bp = Blueprint("account", __name__)


@bp.get("/account")
def index() -> Response:
    message = "Passkey added." if request.args.get("added") else None
    return page(require_session(), message, None)


@bp.post("/account/password")
def password() -> Response:
    auth = civ()
    session = require_session()
    check_csrf(session)
    account = auth.store.account(session["uuid"])
    stored = None if account is None else account["password_hash"]
    new = request.form.get("new", "")
    if not new:
        return page(session, None, "Enter a password.")
    auth.store.set_password(session["uuid"], generate_password_hash(new), auth.now())
    if stored is None:
        return page(session, "Password set.", None)
    return page(session, "Password changed.", None)


@bp.post("/account/apps/remove")
def remove_app() -> Response:
    auth = civ()
    session = require_session()
    check_csrf(session)
    client_id = request.form.get("client_id", "")
    app = auth.store.app(client_id)
    if not auth.store.delete_grant(session["uuid"], client_id):
        return page(session, None, "That app has already been removed.")
    name = "That app" if app is None else app["name"]
    return page(session, Markup("Removed {} from authorized apps.").format(name), None)


@bp.post("/account/passkeys/delete")
def remove_passkey() -> Response:
    auth = civ()
    session = require_session()
    check_csrf(session)
    credential_id = request.form.get("credential_id", "")
    if not auth.store.delete_passkey(credential_id, session["uuid"]):
        return page(session, None, "That passkey is already gone.")
    return page(session, "That passkey has been removed.", None)


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
        uuid=session["uuid"],
        has_password=account is not None and account["password_hash"] is not None,
        passkeys=[
            {"credential_id": row["credential_id"], "added": added(row["created_at"])}
            for row in auth.store.passkeys_for(session["uuid"])
        ],
        password_url=auth.config.url("/account/password"),
        remove_url=auth.config.url("/account/passkeys/delete"),
        grants=[
            {
                "name": row["name"],
                "client_id": row["client_id"],
                "owner": owner(row),
                "used": added(row["used_at"]),
            }
            for row in grants
        ],
        revoke_url=auth.config.url("/account/apps/remove"),
        passkey_options_url=auth.config.url("/account/passkey/options"),
        passkey_verify_url=auth.config.url("/account/passkey/verify"),
        passkey_done_url=auth.config.url("/account?added=passkey"),
        csrf=session["csrf"],
        message=message,
        error=error,
    )
    return html_response(html, 200 if error is None else 400)


def owner(row: dict) -> str:
    if not row["owner_uuid"]:
        return "CivAuth"
    return row["owner_name"] or row["owner_uuid"]


def added(created_at: int) -> str:
    moment = datetime.datetime.fromtimestamp(int(created_at), datetime.timezone.utc)
    return f"{moment.day} {moment:%B %Y}"
