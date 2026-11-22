from __future__ import annotations

import base64
import hashlib
import os
import secrets
from urllib.parse import quote, urlencode, urlparse

import httpx
from flask import Flask, Response, make_response, render_template, request, session
from jinja2 import DictLoader

ISSUER = "https://civauth.exe.xyz"
BACKCHANNEL = "http://127.0.0.1"
CLIENT_ID = "cd20b6"
CLIENT_SECRET = "@CLIENT_SECRET@"
BASE = "https://civauth.exe.xyz/example"

PREFIX = urlparse(BASE).path.rstrip("/")

LABELS = {"uuid": "Minecraft UUID", "name": "Minecraft name"}

STYLE = (
    "body{margin:0;padding:2rem 1rem;background:#f4f4f2;color:#202122;font:16px/1.5 system-ui,sans-serif}"
    "main{max-width:32rem;margin:0 auto;padding:1.5rem 2rem;background:#fff;border:1px solid #c8ccd1;border-radius:4px}"
    "h1{margin:0 0 1rem;font-size:1.4rem}table{border-collapse:collapse;width:100%;margin-bottom:1rem}"
    "th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #eaecf0;word-break:break-all}"
    "button,a.button{display:inline-block;padding:.4rem 1rem;border:1px solid #36c;border-radius:2px;"
    "background:#36c;color:#fff;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}"
)

TEMPLATES = {
    "page.html": (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>{{ title }}</title><style>" + STYLE + "</style></head><body><main>"
        "<h1>{{ title }}</h1>{% block body %}{% endblock %}</main></body></html>"
    ),
    "message.html": '{% extends "page.html" %}{% block body %}{{ message }}{% endblock %}',
    "home.html": (
        '{% extends "page.html" %}{% block body %}'
        '{% if rows is none %}<p><a class="button" href="{{ login_url }}">Log in with CivAuth</a></p>'
        "{% else %}<table>{% for label, value in rows %}"
        "<tr><th>{{ label }}</th><td>{{ value }}</td></tr>{% endfor %}</table>"
        '<form method="post" action="{{ logout_url }}">'
        '<input type="hidden" name="csrf" value="{{ csrf }}">'
        '<button type="submit">Log out</button></form>{% endif %}{% endblock %}'
    ),
}

app = Flask(__name__, static_folder=None)
app.url_map.strict_slashes = False
app.jinja_loader = DictLoader(TEMPLATES)
app.secret_key = hashlib.sha256(("civauth-example\0" + CLIENT_SECRET).encode()).digest()
app.config.update(
    SESSION_COOKIE_NAME="civauth_example",
    SESSION_COOKIE_PATH=PREFIX or "/",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


@app.get(PREFIX + "/")
def home() -> Response:
    user = session.get("user")
    if user is None:
        return page("home.html", "Example site", rows=None, login_url=BASE + "/login")
    rows = [(LABELS.get(key, key), value) for key, value in user.items()]
    return page(
        "home.html",
        "Example site",
        rows=rows,
        logout_url=BASE + "/logout",
        csrf=session.get("csrf", ""),
    )


@app.get(PREFIX + "/login")
def login() -> Response:
    verifier = b64url(os.urandom(32))
    session["login"] = {"state": b64url(os.urandom(16)), "verifier": verifier}
    query = urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": BASE + "/callback",
            "state": session["login"]["state"],
            "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
    )
    return redirect(ISSUER + "/oauth/authorize?" + query)


@app.get(PREFIX + "/callback")
def callback() -> Response:
    login_state = session.pop("login", None)
    state = request.args.get("state")
    if login_state is None or state is None or not equals(login_state["state"], state):
        return page("message.html", "Login failed", message="The login could not be verified.", status=400)
    error = request.args.get("error")
    if error is not None:
        return page("message.html", "Login failed", message=error, status=400)
    token = exchange(request.args.get("code", ""), login_state["verifier"])
    user = whoami(token.get("access_token"))
    if user is None:
        return page("message.html", "Login failed", message="CivAuth did not say who you are.", status=400)
    session.clear()
    session["user"] = user
    session["csrf"] = b64url(os.urandom(16))
    return redirect(BASE + "/")


@app.post(PREFIX + "/logout")
def logout() -> Response:
    csrf = session.get("csrf")
    given = request.form.get("csrf")
    if csrf is None or given is None or not equals(csrf, given):
        return page("message.html", "This form could not be verified", message="", status=400)
    session.clear()
    return redirect(BASE + "/")


@app.errorhandler(404)
@app.errorhandler(405)
def missing(_error) -> Response:
    return page("message.html", "Not found", message="", status=404)


def exchange(code: str, verifier: str) -> dict:
    try:
        response = httpx.post(
            BACKCHANNEL + "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": BASE + "/callback",
                "code_verifier": verifier,
            },
            auth=(quote(CLIENT_ID, safe="-_.~"), quote(CLIENT_SECRET, safe="-_.~")),
            timeout=15,
        )
        body = response.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def whoami(access_token) -> dict | None:
    if not isinstance(access_token, str) or not access_token:
        return None
    try:
        response = httpx.get(
            BACKCHANNEL + "/oauth/user",
            headers={"Authorization": "Bearer " + access_token},
            timeout=15,
        )
        body = response.json()
    except Exception:
        return None
    if response.status_code != 200 or not isinstance(body, dict):
        return None
    uuid, name = body.get("uuid"), body.get("name")
    if not isinstance(uuid, str) or not isinstance(name, str):
        return None
    return {"uuid": uuid, "name": name}


def page(template: str, title: str, status: int = 200, **context) -> Response:
    response = make_response(render_template(template, title=title, **context), status)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Cache-Control"] = "no-store"
    return response


def redirect(url: str) -> Response:
    response = make_response("", 302)
    response.headers["Location"] = url
    response.headers["Cache-Control"] = "no-store"
    return response


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def equals(known: str, given: str) -> bool:
    return secrets.compare_digest(known.encode(), given.encode())
