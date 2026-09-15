from __future__ import annotations

import base64
import os
import secrets
import time
from typing import Any, Callable
from urllib.parse import urlencode

from flask import Flask, Response, current_app, g, make_response, render_template, request

from civauth import constants
from civauth.config import Config
from civauth.store import Store

class Client:

    def __init__(self, row: dict) -> None:
        import json

        self.client_id: str = row["client_id"]
        self.name: str = row["name"]
        self.owner_uuid: str = row["owner_uuid"]
        self.redirect_uris: list[str] = json.loads(row["redirect_uris"])
        self._secret_hash: str = row["secret_hash"]

    def verify_secret(self, secret: str) -> bool:
        return secrets.compare_digest(self._secret_hash, Store.hash(secret))

    @staticmethod
    def is_registrable_uri(uri: str) -> bool:
        import re
        from urllib.parse import urlparse

        if not re.fullmatch(r"https?://[^\s#]+", uri):
            return False
        parts = urlparse(uri)
        if not parts.hostname:
            return False
        if parts.scheme == "https":
            return True
        return parts.hostname.lower() in ("localhost", "127.0.0.1", "::1")

class CivAuth:

    def __init__(
        self,
        config: Config,
        store: Store,
        authenticator: Any,
        clock: Callable[[], int],
    ) -> None:
        self.config = config
        self.store = store
        self.authenticator = authenticator
        self._clock = clock

    def now(self) -> int:
        return self._clock()

    def session(self) -> dict | None:
        cookie = request.cookies.get(constants.SESSION_COOKIE)
        if not cookie:
            return None
        row = self.store.session(Store.hash(cookie))
        now = self.now()
        if row is None or row["expires_at"] <= now:
            return None
        if row["expires_at"] - now < constants.SESSION_TTL - constants.SESSION_SLIDE_AFTER:
            self.store.extend_session(row["hash"], now + constants.SESSION_TTL)
            row["expires_at"] = now + constants.SESSION_TTL
        return row

    def client(self, client_id: str) -> Client | None:
        row = self.store.app(client_id)
        return None if row is None else Client(row)

    def error_page(self, title: str, message: str, status: int, extra: str = "") -> Response:
        html = render_template("error.html", title=title, message=message, extra=extra)
        return html_response(html, status)

    def not_found(self) -> Response:
        return self.error_page("Not found", "", 404)

    def method_not_allowed(self, methods: list[str]) -> Response:
        response = self.error_page("Method not allowed", "", 405)
        response.headers["Allow"] = ", ".join(methods)
        return response

    def redirect_error(self, redirect_uri: str, error: str, description: str, state: str | None) -> Response:
        params: dict[str, str] = {"error": error, "error_description": description}
        if state is not None:
            params["state"] = state
        return redirect_response(self.append_query(redirect_uri, params))

    def set_session_cookie(self, response: Response, token: str) -> Response:
        return self.set_cookie(response, constants.SESSION_COOKIE, token, constants.SESSION_TTL)

    def clear_session_cookie(self, response: Response) -> Response:
        return self.set_cookie(response, constants.SESSION_COOKIE, "", 0, expire_now=True)

    def set_cookie(
        self, response: Response, name: str, value: str, max_age: int, expire_now: bool = False
    ) -> Response:
        response.set_cookie(
            name,
            value,
            max_age=0 if expire_now else max_age,
            expires=1 if expire_now else None,
            path=self.config.cookie_path(),
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        return response

    def clear_cookie(self, response: Response, name: str) -> Response:
        return self.set_cookie(response, name, "", 0, expire_now=True)

    @staticmethod
    def random_token() -> str:
        return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

    @staticmethod
    def client_id() -> str:
        return "".join(
            secrets.choice(constants.CLIENT_ID_ALPHABET)
            for _ in range(constants.CLIENT_ID_LENGTH)
        )

    @staticmethod
    def append_query(uri: str, params: dict) -> str:
        clean = {k: v for k, v in params.items() if v is not None}
        return uri + ("&" if "?" in uri else "?") + urlencode(clean, quote_via=_quote)

def _quote(string: str, safe: str, encoding: str | None = None, errors: str | None = None) -> str:
    from urllib.parse import quote

    return quote(str(string), safe="~-._")

def html_response(html: str, status: int = 200) -> Response:
    response = make_response(html, status)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    return response

def json_response(data: dict, status: int = 200, cacheable: bool = False) -> Response:
    import json

    body = json.dumps(data)
    response = make_response(body, status)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    if cacheable:
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response

def redirect_response(url: str) -> Response:
    response = make_response("", 302)
    response.headers["Location"] = url
    response.headers["Cache-Control"] = "no-store"
    return response

def civ() -> CivAuth:
    return current_app.extensions["civauth"]

def script_nonce() -> str:
    if "script_nonce" not in g:
        g.script_nonce = CivAuth.random_token()
    return g.script_nonce

def content_security_policy(nonce: str) -> str:
    return "; ".join(
        (
            "default-src 'none'",
            f"script-src 'nonce-{nonce}'",
            "style-src 'self'",
            "img-src 'self'",
            "connect-src 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        )
    )

def create_app(config: Config | None = None) -> Flask:
    from civauth.minecraft import MojangChain
    from civauth.views import (
        account,
        apps,
        authorize,
        avatar,
        join,
        login,
        passkey,
        permissions,
        style,
        token,
    )

    import secret

    config = config or Config.from_module(secret)
    store = Store(config.database)

    app = Flask(__name__, static_folder=None)
    app.url_map.strict_slashes = False
    app.extensions["civauth"] = CivAuth(
        config,
        store,
        MojangChain(
            config.microsoft_client_id,
            config.microsoft_client_secret,
            config.url("/callback"),
        ),
        lambda: int(time.time()),
    )

    prefix = config.issuer_path
    for blueprint in (
        authorize.bp,
        login.bp,
        avatar.bp,
        join.bp,
        passkey.bp,
        account.bp,
        token.bp,
        permissions.bp,
        style.bp,
        apps.bp,
    ):
        app.register_blueprint(blueprint, url_prefix=prefix or None)

    @app.errorhandler(404)
    def missing(_error):
        return civ().not_found()

    @app.errorhandler(405)
    def wrong_method(error):
        methods = sorted(error.valid_methods or [])
        return civ().method_not_allowed(methods)

    @app.context_processor
    def signed_in_person() -> dict:
        auth = civ()
        session = auth.session()
        return {
            "account": session,
            "url": auth.config.url,
            "stylesheet": auth.config.url(f"/style.css?v={style.VERSION}"),
            "nonce": script_nonce(),
        }

    @app.after_request
    def secure_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if response.mimetype == "text/html":
            response.headers.setdefault(
                "Content-Security-Policy", content_security_policy(script_nonce())
            )
        return response

    return app
