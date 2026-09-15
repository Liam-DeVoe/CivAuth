from flask import Blueprint, Response, request

from civauth import civ, redirect_response
from civauth.views.authorize import decide, login_flow, login_page, pending, start_login
from civauth.views.join import verify_code
from civauth.views.password import verify_password

bp = Blueprint("login", __name__)


@bp.get("/")
def page() -> Response:
    auth = civ()
    req = pending()
    if req is None or not login_flow(req):
        if auth.session() is not None:
            return redirect_response(auth.config.url("/account"))
        return start_login("/account")
    auth.store.touch_request(req["id"], auth.now())
    return login_page()


@bp.post("/")
@bp.post("/oauth/authorize")
def submit() -> Response:
    method = request.form.get("method")
    if method == "password":
        return verify_password()
    if method == "consent":
        return decide()
    return verify_code()
