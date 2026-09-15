from __future__ import annotations

import logging
import re
import secrets

from flask import Blueprint, Response, render_template, request
from markupsafe import Markup, escape

from civauth import CivAuth, Client, civ, constants, html_response, redirect_response
from civauth.minecraft import LoginFailed
from civauth.store import Store

bp = Blueprint("authorize", __name__)

logger = logging.getLogger(__name__)

RETURN_TO: list[str] = ["/account", "/apps"]

CODE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")

@bp.get("/oauth/authorize")
def authorize() -> Response:
    auth = civ()
    auth.store.purge(
        auth.now(), constants.REQUEST_TTL, constants.JOIN_CODE_TTL, constants.JOIN_FAILURE_WINDOW
    )
    client_id = request.args.get("client_id", "")
    client = auth.client(client_id)
    if client is None:
        return auth.error_page("Unknown site", "", 400)
    redirect = request.args.get("redirect_uri", "")
    if redirect not in client.redirect_uris:
        return auth.error_page("Unknown return address", "", 400)

    state = request.args.get("state")

    def fail(error: str, description: str) -> Response:
        return auth.redirect_error(redirect, error, description, state)

    if request.args.get("response_type") != "code":
        return fail("unsupported_response_type", "Only response_type=code is supported.")
    challenge = request.args.get("code_challenge")
    method = request.args.get("code_challenge_method")
    if challenge is not None or method is not None:
        if method != "S256":
            return fail("invalid_request", "Only code_challenge_method=S256 is supported.")
        if challenge is None or not CODE_CHALLENGE.fullmatch(challenge):
            return fail("invalid_request", "code_challenge must be the base64url SHA-256 of the verifier.")

    params: dict = {
        "client_id": client_id,
        "redirect_uri": redirect,
        "state": state,
        "code_challenge": challenge,
    }

    session = auth.session()
    if session is None:
        return start(login_page(), params)
    return proceed(params, session)

def start_login(return_to: str) -> Response:
    if return_to not in RETURN_TO:
        raise ValueError(f"not a page a login may return to: {return_to}")
    return start(redirect_response(civ().config.url("/")), {"return_to": return_to})

def start(response: Response, params: dict) -> Response:
    """Store a pending login and bind it to this browser with the flow cookie."""
    auth = civ()
    flow = CivAuth.random_token()
    auth.store.create_request(CivAuth.random_token(), Store.hash(flow), params, auth.now())
    return auth.set_cookie(response, constants.FLOW_COOKIE, flow, constants.REQUEST_TTL)

def pending() -> dict | None:
    flow = request.cookies.get(constants.FLOW_COOKIE)
    req = None if flow is None else civ().store.request_by_binding(Store.hash(flow))
    return fresh(req)

def login_flow(req: dict) -> bool:
    params = req["params"]
    return params.get("client_id") is not None or params.get("return_to") is not None

def fresh(req: dict | None) -> dict | None:
    if req is None or req["created_at"] + constants.REQUEST_TTL <= civ().now():
        return None
    return req

def expired() -> Response:
    return civ().error_page("This login has expired", "", 400)

def login_page(**fields: object) -> Response:
    fields.setdefault("username", request.form.get("username", ""))
    return html_response(
        render_template("login.html", address=civ().config.join_address, **fields)
    )

@bp.get("/login/minecraft")
def minecraft() -> Response:
    req = pending()
    if req is None:
        return expired()
    return redirect_response(civ().authenticator.login_url(req["id"]))

@bp.get("/callback")
def callback() -> Response:
    auth = civ()
    state = request.args.get("state")
    req = fresh(None if state is None else auth.store.request(state))
    flow = request.cookies.get(constants.FLOW_COOKIE)
    if req is None or flow is None or not secrets.compare_digest(req["binding_hash"], Store.hash(flow)):
        return expired()
    params = req["params"]
    auth.store.delete_request(req["id"])

    if request.args.get("error") is not None:
        return login_failed(params, "Microsoft sign-in cancelled.")
    code = request.args.get("code")
    if code is None:
        return login_failed(params, "Microsoft sent nothing back.")
    try:
        profile = auth.authenticator.authenticate(code)
    except LoginFailed as error:
        logger.error("login failed: %s", error)
        return login_failed(params, str(error))
    return signed_in(params, profile.uuid, profile.name)

def signed_in(params: dict, uuid: str, name: str) -> Response:
    auth = civ()
    old = request.cookies.get(constants.SESSION_COOKIE)
    if old is not None:
        auth.store.delete_session(Store.hash(old))
    now = auth.now()
    token = CivAuth.random_token()
    token_hash = Store.hash(token)
    auth.store.create_session(
        token_hash, uuid, name, now + constants.SESSION_TTL, CivAuth.random_token()
    )
    session = auth.store.session(token_hash)
    auth.store.touch_account(uuid, name, now)

    if params.get("return_to") is not None:
        return_to = params["return_to"] if params["return_to"] in RETURN_TO else "/"
        response = finish(redirect_response(auth.config.url(return_to)))
    elif params.get("client_id") is None:
        response = finish(redirect_response(auth.config.url("/account")))
    else:
        response = proceed(params, session)
    return auth.set_session_cookie(response, token)

def finish(response: Response) -> Response:
    return civ().clear_cookie(response, constants.FLOW_COOKIE)

def proceed(params: dict, session: dict) -> Response:
    auth = civ()
    client = auth.client(params["client_id"])
    if client is None:
        return finish(auth.error_page("Unknown site", "", 400))
    if auth.store.grant(session["uuid"], client.client_id) is None:
        return start(consent_page(client, session, params), params)
    return finish(issue(params, session))

def consent_page(client: Client, session: dict, params: dict) -> Response:
    owner = civ().store.account(client.owner_uuid) if client.owner_uuid else None
    html = render_template(
        "consent.html",
        app_name=client.name,
        owner_name=None if owner is None else owner["name"],
        account=session,
        csrf=session["csrf"],
    )
    return html_response(html)

def decide() -> Response:
    auth = civ()
    req = pending()
    if req is None or req["params"].get("client_id") is None:
        return expired()
    params = req["params"]
    session = auth.session()
    if session is None:
        auth.store.delete_request(req["id"])
        return start(login_page(), params)
    csrf = request.form.get("csrf")
    if csrf is None or not secrets.compare_digest(session["csrf"], csrf):
        return auth.error_page("This form could not be verified", "", 400)
    auth.store.delete_request(req["id"])
    decision = request.form.get("decision")
    if decision == "allow":
        return finish(issue(params, session))
    if decision == "switch":
        auth.store.delete_session(session["hash"])
        return auth.clear_session_cookie(start(login_page(account=None), params))
    return finish(
        auth.redirect_error(params["redirect_uri"], "access_denied", "The user declined.", params["state"])
    )

def issue(params: dict, session: dict) -> Response:
    auth = civ()
    code = CivAuth.random_token()
    auth.store.create_code(
        Store.hash(code),
        params["client_id"],
        params["redirect_uri"],
        session["uuid"],
        session["name"],
        params["code_challenge"],
        auth.now() + constants.CODE_TTL,
    )
    auth.store.record_grant(session["uuid"], params["client_id"], auth.now())
    query: dict = {"code": code}
    if params["state"] is not None:
        query["state"] = params["state"]
    return redirect_response(CivAuth.append_query(params["redirect_uri"], query))

def login_failed(params: dict, message: str) -> Response:
    auth = civ()
    if params.get("return_to") is not None:
        return_to = params["return_to"] if params["return_to"] in RETURN_TO else "/"
        return auth.error_page(
            "Login failed",
            message,
            200,
            actions(auth.config.url(return_to), auth.config.url("/account")),
        )

    retry: dict = {
        name: params[name]
        for name in ("client_id", "redirect_uri", "state", "code_challenge")
        if params[name] is not None
    }
    retry["response_type"] = "code"
    if params["code_challenge"] is not None:
        retry["code_challenge_method"] = "S256"
    cancel: dict = {"error": "access_denied", "error_description": "The login did not complete."}
    if params["state"] is not None:
        cancel["state"] = params["state"]
    return auth.error_page(
        "Login failed",
        message,
        200,
        actions(
            CivAuth.append_query(auth.config.url("/oauth/authorize"), retry),
            CivAuth.append_query(params["redirect_uri"], cancel),
        ),
    )

def actions(retry: str, cancel: str) -> Markup:
    return Markup(
        '<div class="actions">'
        '<a class="button" href="{}">Try again</a>'
        '<a class="button button--plain" href="{}">Cancel</a>'
        "</div>"
    ).format(escape(retry), escape(cancel))
