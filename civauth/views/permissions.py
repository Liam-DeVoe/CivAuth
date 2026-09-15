from __future__ import annotations

from flask import Blueprint, Response, render_template

from civauth import civ, html_response

bp = Blueprint("permissions", __name__)

XSTS = (
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/services/fundamentals"
    "/s2s-auth-calls/service-authentication/security-tokens/live-security-tokens"
)

@bp.get("/permissions")
def page() -> Response:
    address = civ().config.join_address
    return html_response(render_template("permissions.html", address=address, xsts=XSTS))
