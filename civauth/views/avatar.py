import base64
import hashlib
import io
import json
import logging
import re
from urllib.parse import urlsplit, urlunsplit

import httpx
from flask import Blueprint, Response, make_response, request
from PIL import Image

from civauth import civ

logger = logging.getLogger(__name__)

bp = Blueprint("avatar", __name__)

UUID = re.compile(r"[0-9a-f]{32}|[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
PROFILE_URL = "https://sessionserver.mojang.com/session/minecraft/profile/"
TEXTURES_HOST = "textures.minecraft.net"
USER_AGENT = "civauth-avatar/1.0"
TIMEOUT = 5
MAX_AGE = 7 * 86400
SIZE = 64
HEAD_BOX = (8, 8, 16, 16)
HAT_BOX = (40, 8, 48, 16)

PLACEHOLDER_SKIN = (0xB5, 0x8B, 0x69, 0xFF)
PLACEHOLDER_MARK = (0x3F, 0x2C, 0x1E, 0xFF)
PLACEHOLDER_ROWS = (
    "........",
    "..####..",
    ".##..##.",
    ".....##.",
    "....##..",
    "...##...",
    "........",
    "...##...",
)


class Unavailable(Exception):
    pass


@bp.route("/avatar/<uuid>.png", methods=["GET"])
def head(uuid: str) -> Response:
    app = civ()
    if not UUID.fullmatch(uuid):
        return app.not_found()
    uuid = uuid.replace("-", "")
    now = app.now()
    cached = app.store.avatar(uuid)
    if cached is not None and now - int(cached["fetched_at"]) < MAX_AGE:
        return png_response(bytes(cached["png"]))
    try:
        png = build(uuid)
    except Exception:
        logger.warning("avatar for %s could not be built", uuid, exc_info=True)
        return png_response(PLACEHOLDER if cached is None else bytes(cached["png"]))
    app.store.put_avatar(uuid, png, now)
    return png_response(png)


def build(uuid: str) -> bytes:
    with httpx.Client(
        timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": USER_AGENT}
    ) as client:
        response = client.get(PROFILE_URL + uuid)
        if response.status_code != 200:
            raise Unavailable(f"profile lookup returned {response.status_code}")
        url = skin_url(response.json())
        if url is None:
            return PLACEHOLDER
        skin = client.get(url)
        if skin.status_code != 200:
            raise Unavailable(f"skin download returned {skin.status_code}")
    return render(skin.content)


def skin_url(body: object) -> str | None:
    if not isinstance(body, dict):
        return None
    properties = body.get("properties")
    if not isinstance(properties, list):
        return None
    for entry in properties:
        if not isinstance(entry, dict) or entry.get("name") != "textures":
            continue
        value = entry.get("value")
        if not isinstance(value, str):
            continue
        textures = json.loads(base64.b64decode(value, validate=True))
        skin = (textures.get("textures") or {}).get("SKIN") or {}
        url = texture_url(skin.get("url"))
        if url is not None:
            return url
    return None


def texture_url(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.hostname != TEXTURES_HOST:
        return None
    return urlunsplit(("https", TEXTURES_HOST, parts.path, parts.query, ""))


def render(skin_png: bytes) -> bytes:
    with Image.open(io.BytesIO(skin_png)) as opened:
        image = opened.convert("RGBA")
    if image.width < 64 or image.height < 32:
        raise Unavailable(f"skin is {image.width}x{image.height}")
    face = image.crop(HEAD_BOX)
    hat = image.crop(HAT_BOX)
    if hat.getchannel("A").getbbox() is not None:
        face = Image.alpha_composite(face, hat)
    return to_png(face.resize((SIZE, SIZE), Image.NEAREST))


def to_png(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def placeholder() -> bytes:
    image = Image.new("RGBA", (8, 8), PLACEHOLDER_SKIN)
    for y, row in enumerate(PLACEHOLDER_ROWS):
        for x, cell in enumerate(row):
            if cell == "#":
                image.putpixel((x, y), PLACEHOLDER_MARK)
    return to_png(image.resize((SIZE, SIZE), Image.NEAREST))


PLACEHOLDER = placeholder()


def png_response(png: bytes) -> Response:
    etag = '"' + hashlib.sha256(png).hexdigest()[:32] + '"'
    if fresh(request.headers.get("If-None-Match"), etag):
        response = make_response("", 304)
    else:
        response = make_response(png, 200)
        response.headers["Content-Type"] = "image/png"
    response.headers["Cache-Control"] = "public, max-age=3600"
    response.headers["ETag"] = etag
    return response


def fresh(header: str | None, etag: str) -> bool:
    if not header:
        return False
    for candidate in header.split(","):
        candidate = candidate.strip()
        if candidate.startswith("W/"):
            candidate = candidate[2:]
        if candidate in ("*", etag):
            return True
    return False
