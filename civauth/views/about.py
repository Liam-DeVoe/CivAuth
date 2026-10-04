from flask import Blueprint, Response, render_template

from civauth import html_response

bp = Blueprint("about", __name__)


@bp.get("/about")
def page() -> Response:
    return html_response(render_template("about.html"))
