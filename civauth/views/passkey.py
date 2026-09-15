import json
import os
import secrets
from urllib.parse import urlparse

from flask import Blueprint, Response, request
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from civauth import CivAuth, civ, constants, json_response
from civauth.store import Store
from civauth.views.authorize import pending, signed_in

bp = Blueprint("passkey", __name__)

RP_NAME = "CivAuth"

CHALLENGE = "passkey_challenge"


@bp.post("/account/passkey/options")
def add_options() -> Response:
    auth = civ()
    session = auth.session()
    if session is None:
        return fail("You are not signed in.")
    body = payload()
    if not allowed(session, body):
        return fail("This page could not be verified. Reload it and try again.")
    challenge = os.urandom(32)
    options = generate_registration_options(
        rp_id=rp_id(),
        rp_name=RP_NAME,
        user_id=session["uuid"].encode(),
        user_name=session["name"],
        user_display_name=session["name"],
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
            for row in auth.store.passkeys_for(session["uuid"])
        ],
    )
    return keep(challenge, json_response(json.loads(options_to_json(options))))


@bp.post("/account/passkey/verify")
def add_verify() -> Response:
    auth = civ()
    session = auth.session()
    if session is None:
        return fail("You are not signed in.")
    body = payload()
    if not allowed(session, body):
        return fail("This page could not be verified. Reload it and try again.")
    req = pending()
    challenge = None if req is None else req["params"].get(CHALLENGE)
    if challenge is None:
        return fail("This request has expired. Start again.")
    credential = body.get("credential")
    if not isinstance(credential, dict):
        return fail("That passkey could not be read.")
    try:
        result = verify_registration_response(
            credential=json.dumps(credential),
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=rp_id(),
            expected_origin=origin(),
        )
    except Exception:
        return fail("That passkey could not be verified.")
    now = auth.now()
    auth.store.add_passkey(
        bytes_to_base64url(result.credential_id),
        session["uuid"],
        bytes_to_base64url(result.credential_public_key),
        int(result.sign_count),
        now,
    )
    release(req)
    return json_response({"ok": True})


@bp.post("/login/passkey/options")
def login_options() -> Response:
    if pending() is None:
        return fail("This login has expired. Start again.")
    challenge = os.urandom(32)
    options = generate_authentication_options(
        rp_id=rp_id(),
        challenge=challenge,
        allow_credentials=[],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return keep(challenge, json_response(json.loads(options_to_json(options))))


@bp.post("/login/passkey/verify")
def login_verify() -> Response:
    auth = civ()
    req = pending()
    challenge = None if req is None else req["params"].get(CHALLENGE)
    if challenge is None:
        return fail("This login has expired. Start again.")
    credential = payload().get("credential")
    if not isinstance(credential, dict):
        return fail("That passkey could not be read.")
    try:
        credential_id = bytes_to_base64url(
            base64url_to_bytes(
                str(credential.get("rawId") or credential.get("id") or "")
            )
        )
    except Exception:
        return fail("That passkey could not be read.")
    row = auth.store.passkey(credential_id)
    if row is None:
        return fail("That passkey is not registered here.")
    try:
        result = verify_authentication_response(
            credential=json.dumps(credential),
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=rp_id(),
            expected_origin=origin(),
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
        )
    except Exception:
        return fail("That passkey could not be verified.")
    count = int(result.new_sign_count)
    stored = int(row["sign_count"])
    if (count or stored) and count <= stored:
        return fail("That passkey could not be verified.")
    now = auth.now()
    auth.store.used_passkey(credential_id, count, now)
    account = auth.store.account(row["uuid"])
    if account is None:
        return fail("That account no longer exists.")
    params = {name: value for name, value in req["params"].items() if name != CHALLENGE}
    auth.store.delete_request(req["id"])
    return handoff(signed_in(params, account["uuid"], account["name"]))


def handoff(response: Response) -> Response:
    location = response.headers.get("Location")
    if location is None:
        return fail("This login could not be completed.")
    out = json_response({"ok": True, "url": location})
    for cookie in response.headers.getlist("Set-Cookie"):
        out.headers.add("Set-Cookie", cookie)
    return out


def keep(challenge: bytes, response: Response) -> Response:
    auth = civ()
    req = pending()
    params = dict(req["params"]) if req is not None else {}
    params[CHALLENGE] = bytes_to_base64url(challenge)
    flow = request.cookies.get(constants.FLOW_COOKIE) or CivAuth.random_token()
    auth.store.create_request(
        CivAuth.random_token(), Store.hash(flow), params, auth.now()
    )
    if req is not None:
        auth.store.delete_request(req["id"])
    return auth.set_cookie(response, constants.FLOW_COOKIE, flow, constants.REQUEST_TTL)


def release(req: dict) -> None:
    auth = civ()
    auth.store.delete_request(req["id"])
    carried = {
        name: value for name, value in req["params"].items() if name != CHALLENGE
    }
    if carried:
        auth.store.create_request(
            CivAuth.random_token(), req["binding_hash"], carried, auth.now()
        )


def payload() -> dict:
    body = request.get_json(silent=True, force=True)
    return body if isinstance(body, dict) else {}


def allowed(session: dict, body: dict) -> bool:
    csrf = body.get("csrf")
    return isinstance(csrf, str) and secrets.compare_digest(session["csrf"], csrf)


def fail(message: str) -> Response:
    return json_response({"ok": False, "error": message}, 400)


def issuer() -> tuple[str, str]:
    parts = urlparse(civ().config.issuer)
    return parts.hostname or "", f"{parts.scheme}://{parts.netloc}"


def rp_id() -> str:
    return issuer()[0]


def origin() -> str:
    return issuer()[1]
