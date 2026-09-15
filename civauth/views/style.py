import hashlib
from pathlib import Path

import sass
from flask import Blueprint, Response, request

bp = Blueprint("style", __name__)

STYLES = Path(__file__).resolve().parent.parent / "styles"

CSS = sass.compile(
    filename=str(STYLES / "style.scss"),
    include_paths=[str(STYLES)],
    output_style="compressed",
)
VERSION = hashlib.sha256(CSS.encode()).hexdigest()[:12]
ETAG = f'"{VERSION}"'


@bp.get("/style.css")
def stylesheet() -> Response:
    if request.headers.get("If-None-Match") == ETAG:
        return Response(status=304, headers={"ETag": ETAG})
    response = Response(CSS, mimetype="text/css")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    response.headers["ETag"] = ETAG
    return response
