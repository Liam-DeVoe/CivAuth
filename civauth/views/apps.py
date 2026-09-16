import json
import secrets
import unicodedata
from typing import Any
from urllib.parse import quote

from flask import Blueprint, Response, abort, render_template, request

from civauth import CivAuth, Client, civ, html_response, redirect_response
from civauth.constants import MAX_NAME, MAX_PER_OWNER, MAX_URIS

bp = Blueprint("apps", __name__)

TRIM = " \t\n\r\0\x0b"

FORBIDDEN = frozenset({"Cc", "Cf", "Zl", "Zp"})


@bp.route("/apps", methods=["GET", "POST"])
def handle() -> Response:
    session = require_session()
    if request.method == "GET":
        return index(session)
    check_csrf(session)
    return create(session)


@bp.get("/apps/new")
def new() -> Response:
    return form(require_session(), None, [], blank())


@bp.route("/apps/<client_id>", methods=["GET", "POST"])
def app_page(client_id: str) -> Response:
    session = require_session()
    if client_id == "new":
        return civ().method_not_allowed(["GET"])
    row = owned(client_id, session)
    if request.method == "GET":
        return form(session, row, [], values(row))
    check_csrf(session)
    return update(session, row)


@bp.post("/apps/<client_id>/regenerate")
def regenerate(client_id: str) -> Response:
    session = require_session()
    row = owned(client_id, session)
    check_csrf(session)
    secret = CivAuth.random_token()
    civ().store.set_app_secret(row["client_id"], civ().store.hash(secret), civ().now())
    return secret_page(row["client_id"], row["name"], secret)


@bp.post("/apps/<client_id>/delete")
def delete(client_id: str) -> Response:
    session = require_session()
    row = owned(client_id, session)
    check_csrf(session)
    civ().store.delete_app(row["client_id"])
    return redirect_response(civ().config.path("/apps"))


@bp.post("/signout")
def signout() -> Response:
    session = civ().session()
    csrf = request.form.get("csrf")
    if session is not None and csrf is not None and equals(session["csrf"], csrf):
        civ().store.delete_session(session["hash"])
    return civ().clear_session_cookie(redirect_response(civ().config.path("/")))


def require_session() -> dict:
    session = civ().session()
    if session is not None:
        return session
    if request.method != "GET":
        abort(civ().error_page("Not signed in", "", 400))
    from civauth.views.authorize import start_login

    abort(start_login("/apps"))


def check_csrf(session: dict) -> None:
    csrf = request.form.get("csrf")
    if csrf is None or not equals(session["csrf"], csrf):
        abort(civ().error_page("This form could not be verified", "", 400))


def owned(client_id: str, session: dict) -> dict:
    row = civ().store.app(client_id)
    if row is None or row["owner_uuid"] != session["uuid"]:
        abort(civ().not_found())
    return row


def index(session: dict) -> Response:
    rows = civ().store.apps_owned_by(session["uuid"])
    html = render_template(
        "apps_index.html",
        title="OAuth apps",
        apps=[{"name": row["name"], "url": url(row["client_id"])} for row in rows],
        can_create=len(rows) < MAX_PER_OWNER,
        new_url=url("new"),
        docs_url=civ().config.path("/docs"),
    )
    return html_response(html)


def form(
    session: dict, row: dict | None, errors: list[str], fields: dict[str, Any]
) -> Response:
    editing = row is not None
    title = f"Edit {row['name']}" if editing else "Create an app"
    html = render_template(
        "apps_form.html",
        title=title,
        editing=editing,
        errors=errors,
        csrf=session["csrf"],
        action=url(row["client_id"]) if editing else civ().config.path("/apps"),
        client_id=row["client_id"] if editing else None,
        name=fields["name"],
        redirect_uris=fields["redirect_uris"],
        max_name=MAX_NAME,
        max_uris=MAX_URIS,
        apps_url=civ().config.path("/apps"),
        regenerate_url=url(row["client_id"], "regenerate") if editing else None,
        delete_url=url(row["client_id"], "delete") if editing else None,
    )
    return html_response(html, 200 if not errors else 400)


def secret_page(client_id: str, name: str, secret: str) -> Response:
    html = render_template(
        "apps_secret.html",
        title=name,
        name=name,
        client_id=client_id,
        secret=secret,
        apps_url=civ().config.path("/apps"),
        docs_url=civ().config.path("/docs"),
    )
    return html_response(html)


def create(session: dict) -> Response:
    fields = submitted()
    edited = row_action(fields)
    if edited is not None:
        return form(session, None, [], edited)
    errors, parsed = validate(fields)
    if len(civ().store.apps_owned_by(session["uuid"])) >= MAX_PER_OWNER:
        errors.append("Too many apps.")
    if errors:
        return form(session, None, errors, fields)
    secret = CivAuth.random_token()
    for _attempt in range(5):
        client_id = CivAuth.client_id()
        created = civ().store.create_app(
            client_id,
            civ().store.hash(secret),
            parsed["name"],
            parsed["redirect_uris"],
            session["uuid"],
            civ().now(),
        )
        if created:
            return secret_page(client_id, parsed["name"], secret)
    return form(session, None, ["Try again."], fields)


def update(session: dict, row: dict) -> Response:
    fields = submitted()
    edited = row_action(fields)
    if edited is not None:
        return form(session, row, [], edited)
    errors, parsed = validate(fields)
    if errors:
        return form(session, row, errors, fields)
    civ().store.update_app(
        row["client_id"], parsed["name"], parsed["redirect_uris"], civ().now()
    )
    return redirect_response(url(row["client_id"]))


def blank() -> dict[str, Any]:
    return {"name": "", "redirect_uris": [""]}


def row_action(fields: dict[str, Any]) -> dict[str, Any] | None:
    action = request.form.get("action", "")
    uris = list(fields["redirect_uris"])
    if action == "add":
        if len(uris) < MAX_URIS:
            uris.append("")
        return {**fields, "redirect_uris": uris}
    if action.startswith("remove:") and action[len("remove:") :].isdigit():
        index_ = int(action[len("remove:") :])
        if index_ < len(uris):
            del uris[index_]
        return {**fields, "redirect_uris": uris or [""]}
    return None


def values(row: dict) -> dict[str, Any]:
    return {"name": row["name"], "redirect_uris": json.loads(row["redirect_uris"])}


def submitted() -> dict[str, Any]:
    return {
        "name": request.form.get("name", ""),
        "redirect_uris": request.form.getlist("redirect_uris[]") or [""],
    }


def validate(fields: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    name = fields["name"].strip(TRIM)
    if not 1 <= len(name) <= MAX_NAME or any(
        unicodedata.category(c) in FORBIDDEN for c in name
    ):
        errors.append("Invalid name.")
    trimmed = (uri.strip(TRIM) for uri in fields["redirect_uris"])
    redirects = list(dict.fromkeys(uri for uri in trimmed if uri))
    if not redirects:
        errors.append("A redirect URI is required.")
    elif len(redirects) > MAX_URIS:
        errors.append("Too many redirect URIs.")
    for uri in redirects:
        if not Client.is_registrable_uri(uri):
            errors.append(f"Invalid address: {uri}")
    return errors, {"name": name, "redirect_uris": redirects}


def equals(known: str, given: str) -> bool:
    return secrets.compare_digest(known.encode(), given.encode())


def url(client_id: str, action: str | None = None) -> str:
    path = "/apps/" + quote(client_id, safe="")
    return civ().config.path(path if action is None else f"{path}/{action}")
