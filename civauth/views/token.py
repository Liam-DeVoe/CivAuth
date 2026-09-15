import base64
import binascii
import hashlib
import re
import secrets
from urllib.parse import unquote

from flask import Blueprint, Response, request

from civauth import CivAuth, civ, constants, json_response
from civauth.store import Store

bp = Blueprint("token", __name__)

_BASIC = re.compile(r"Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
_BEARER = re.compile(r"Bearer\s+(\S+)", re.IGNORECASE)
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")


@bp.route("/oauth/token", methods=["POST"])
def token() -> Response:
    client_id, secret, conflict = _client_credentials()
    if conflict:
        return _error("invalid_request", "Conflicting client credentials.")
    client = None if client_id is None else civ().client(client_id)
    if client is None or secret is None or not client.verify_secret(secret):
        response = json_response(
            {
                "error": "invalid_client",
                "error_description": "Client authentication failed.",
            },
            401,
        )
        response.headers["WWW-Authenticate"] = 'Basic realm="civauth"'
        return response
    now = civ().now()
    civ().store.purge(
        now,
        constants.REQUEST_TTL,
        constants.JOIN_CODE_TTL,
        constants.JOIN_FAILURE_WINDOW,
    )

    if request.form.get("grant_type") != "authorization_code":
        return _error("unsupported_grant_type", "Only authorization_code is supported.")
    code = request.form.get("code")
    row = None if code is None else civ().store.code(Store.hash(code))
    if row is None or row["expires_at"] <= now:
        return _error("invalid_grant", "The code is unknown or has expired.")
    if not civ().store.consume_code(row["hash"]):
        civ().store.revoke_tokens_for_code(row["hash"])
        return _error("invalid_grant", "The code has already been used.")
    if row["client_id"] != client.client_id:
        return _error("invalid_grant", "The code was issued to a different client.")
    if request.form.get("redirect_uri") != row["redirect_uri"]:
        return _error(
            "invalid_grant", "redirect_uri does not match the authorization request."
        )
    if row["code_challenge"] is not None:
        verifier = request.form.get("code_verifier")
        if (
            verifier is None
            or not _VERIFIER.fullmatch(verifier)
            or not secrets.compare_digest(row["code_challenge"], _challenge(verifier))
        ):
            return _error(
                "invalid_grant", "code_verifier does not match code_challenge."
            )

    access = CivAuth.random_token()
    civ().store.create_token(
        Store.hash(access),
        row["hash"],
        client.client_id,
        row["uuid"],
        row["name"],
        now + constants.TOKEN_TTL,
    )
    return json_response(
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": constants.TOKEN_TTL,
        }
    )


@bp.route("/oauth/user", methods=["GET"])
def user() -> Response:
    auth = request.headers.get("Authorization")
    match = None if auth is None else _BEARER.fullmatch(auth)
    row = None if match is None else civ().store.token(Store.hash(match.group(1)))
    if row is None or row["expires_at"] <= civ().now():
        response = json_response({"error": "invalid_token"}, 401)
        response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
        return response
    return json_response({"uuid": row["uuid"], "name": row["name"]})


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _client_credentials() -> tuple[str | None, str | None, bool]:
    auth = request.headers.get("Authorization")
    if auth is None:
        return request.form.get("client_id"), request.form.get("client_secret"), False
    match = _BASIC.fullmatch(auth)
    if match is None:
        return None, None, False
    try:
        decoded = base64.b64decode(match.group(1), validate=True).decode(
            "utf-8", "surrogateescape"
        )
    except (binascii.Error, ValueError):
        return None, None, False
    if ":" not in decoded:
        return None, None, False
    client_id, secret = decoded.split(":", 1)
    client_id = unquote(client_id)
    secret = unquote(secret)
    body_id = request.form.get("client_id")
    body_secret = request.form.get("client_secret")
    conflict = (body_id is not None and body_id != client_id) or (
        body_secret is not None and not secrets.compare_digest(secret, body_secret)
    )
    return client_id, secret, conflict


def _error(error: str, description: str) -> Response:
    return json_response({"error": error, "error_description": description}, 400)
