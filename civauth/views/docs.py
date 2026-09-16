from flask import Blueprint, Response, render_template

from civauth import civ, constants, html_response

bp = Blueprint("docs", __name__)


@bp.get("/docs")
def page() -> Response:
    config = civ().config
    return html_response(
        render_template(
            "docs.html",
            issuer=config.issuer,
            code_ttl=constants.CODE_TTL,
            token_ttl=constants.TOKEN_TTL // 86400,
            refresh_ttl=constants.REFRESH_TTL // 86400,
        )
    )
