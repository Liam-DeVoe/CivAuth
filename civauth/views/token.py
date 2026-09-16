import base64
import binascii
import hashlib
import re
import secrets
from urllib.parse import unquote

from flask import Blueprint, Response, request

from civauth import CivAuth, Client, civ, constants, hyphenated, json_response
from civauth.store import Store, TokenPair

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
        constants.REPLAY_WINDOW,
    )

    grant_type = request.form.get("grant_type")
    if grant_type == "authorization_code":
        return _exchange_code(client, now)
    if grant_type == "refresh_token":
        return _refresh(client, now)
    return _error(
        "unsupported_grant_type",
        "Only authorization_code and refresh_token are supported.",
    )


def _exchange_code(client: Client, now: int) -> Response:
    code = request.form.get("code")
    if code is None:
        return _error("invalid_request", "Missing code.")
    row = civ().store.code(Store.hash(code))
    if row is None or row["expires_at"] <= now:
        return _error("invalid_grant", "The code is unknown or has expired.")

    problem = None
    if row["client_id"] != client.client_id:
        problem = "The code was issued to a different client."
    elif request.form.get("redirect_uri") != row["redirect_uri"]:
        problem = "redirect_uri does not match the authorization request."
    elif row["code_challenge"] is not None:
        verifier = request.form.get("code_verifier")
        if (
            verifier is None
            or not _VERIFIER.fullmatch(verifier)
            or not secrets.compare_digest(row["code_challenge"], _challenge(verifier))
        ):
            problem = "code_verifier does not match code_challenge."

    pair, response = _pair(row["hash"], client.client_id, row["uuid"], row["name"], now)
    if not civ().store.exchange_code(row["hash"], None if problem else pair):
        civ().store.revoke_tokens_for_code(row["hash"])
        return _error("invalid_grant", "The code has already been used.")
    if problem:
        return _error("invalid_grant", problem)
    return response


def _refresh(client: Client, now: int) -> Response:
    presented = request.form.get("refresh_token")
    if presented is None:
        return _error("invalid_request", "Missing refresh_token.")
    row = civ().store.refresh_token(Store.hash(presented))
    if row is None or row["client_id"] != client.client_id:
        return _error("invalid_grant", "The refresh token is unknown.")
    if row["expires_at"] <= now:
        return _error("invalid_grant", "The refresh token has expired.")
    account = civ().store.account(row["uuid"])
    name = row["name"] if account is None else account["name"]
    pair, response = _pair(row["code_hash"], client.client_id, row["uuid"], name, now)
    if not civ().store.rotate_refresh_token(row["hash"], now, pair):
        civ().store.revoke_tokens_for_code(row["code_hash"])
        return _error(
            "invalid_grant",
            "The refresh token was already used. All tokens from this login are revoked.",
        )
    civ().store.record_grant(row["uuid"], client.client_id, now)
    return response


def _pair(
    code_hash: str, client_id: str, uuid: str, name: str, now: int
) -> tuple[TokenPair, Response]:
    access = CivAuth.random_token()
    refresh = CivAuth.random_token()
    pair = TokenPair(
        access_hash=Store.hash(access),
        refresh_hash=Store.hash(refresh),
        code_hash=code_hash,
        client_id=client_id,
        uuid=uuid,
        name=name,
        access_expires_at=now + constants.TOKEN_TTL,
        refresh_expires_at=now + constants.REFRESH_TTL,
    )
    response = json_response(
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": constants.TOKEN_TTL,
            "refresh_token": refresh,
        }
    )
    return pair, response


@bp.route("/oauth/user", methods=["GET"])
def user() -> Response:
    auth = request.headers.get("Authorization")
    match = None if auth is None else _BEARER.fullmatch(auth)
    row = None if match is None else civ().store.token(Store.hash(match.group(1)))
    if row is None or row["expires_at"] <= civ().now():
        response = json_response({"error": "invalid_token"}, 401)
        response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
        return response
    return json_response({"uuid": hyphenated(row["uuid"]), "name": row["name"]})


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
