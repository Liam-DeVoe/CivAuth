import json
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Profile:
    uuid: str
    name: str


class LoginFailed(Exception):
    pass


AUTHORIZE = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
TOKEN = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
XBOX = "https://user.auth.xboxlive.com/user/authenticate"
XSTS = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_LOGIN = "https://api.minecraftservices.com/authentication/login_with_xbox"
MC_PROFILE = "https://api.minecraftservices.com/minecraft/profile"

SCOPE = "XboxLive.signin"

TIMEOUT = 20

XSTS_ERRORS = {
    "2148916227": "This Xbox account is banned.",
    "2148916233": ("This Microsoft account has no Xbox profile yet."),
    "2148916235": "Xbox Live is not available in this account's country.",
    "2148916236": "This account needs adult verification on the Xbox website.",
    "2148916237": "This account needs adult verification on the Xbox website.",
    "2148916238": ("This is a child account and must be added to a family group."),
}


class MojangChain:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def login_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": SCOPE,
            "state": state,
        }
        return AUTHORIZE + "?" + urlencode(params, quote_via=quote)

    def authenticate(self, code: str) -> Profile:
        ms_token = self._microsoft_token(code)
        xbox_token, user_hash = self._xbox_token(ms_token)
        xsts_token = self._xsts_token(xbox_token)
        mc_token = self._minecraft_token(user_hash, xsts_token)
        return self._minecraft_profile(mc_token)

    def _microsoft_token(self, code: str) -> str:
        status, body = self._post(
            TOKEN,
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
                "scope": SCOPE,
            },
            as_json=False,
        )
        if status != 200:
            raise LoginFailed("Microsoft rejected the sign-in.")
        return _field(body, "access_token", "Microsoft returned no access token.")

    def _xbox_token(self, ms_token: str) -> tuple[str, str]:
        status, body = self._post(
            XBOX,
            {
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": f"d={ms_token}",
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            },
            as_json=True,
        )
        if status != 200:
            raise LoginFailed("Xbox Live rejected the sign-in.")
        data = _decode(body)
        claims = data.get("DisplayClaims")
        xui = claims.get("xui") if isinstance(claims, dict) else None
        first = (
            xui[0] if isinstance(xui, list) and xui and isinstance(xui[0], dict) else {}
        )
        user_hash = first.get("uhs")
        token = data.get("Token")
        if not isinstance(token, str) or not isinstance(user_hash, str):
            raise LoginFailed("Xbox Live returned an unexpected response.")
        return token, user_hash

    def _xsts_token(self, xbox_token: str) -> str:
        status, body = self._post(
            XSTS,
            {
                "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]},
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT",
            },
            as_json=True,
        )
        if status == 401:
            code = _decode(body).get("XErr", "")
            raise LoginFailed(
                XSTS_ERRORS.get(
                    str(code), "Xbox Live would not authorize this account."
                )
            )
        if status != 200:
            raise LoginFailed("Xbox Live would not authorize this account.")
        return _field(body, "Token", "Xbox Live returned an unexpected response.")

    def _minecraft_token(self, user_hash: str, xsts_token: str) -> str:
        status, body = self._post(
            MC_LOGIN,
            {"identityToken": f"XBL3.0 x={user_hash};{xsts_token}"},
            as_json=True,
        )
        if status == 403:
            logger.error(
                "civauth: Minecraft services rejected this application registration (403). "
            )
            raise LoginFailed("Minecraft login is misconfigured on this server.")
        if status != 200:
            raise LoginFailed("Minecraft services rejected the sign-in.")
        return _field(
            body, "access_token", "Minecraft services returned no access token."
        )

    def _minecraft_profile(self, mc_token: str) -> Profile:
        status, body = self._send(
            MC_PROFILE,
            None,
            {"Authorization": f"Bearer {mc_token}", "Accept": "application/json"},
        )
        if status == 404:
            raise LoginFailed(
                "This Microsoft account does not own Minecraft: Java Edition."
            )
        if status != 200:
            raise LoginFailed("Could not read the Minecraft profile.")
        data = _decode(body)
        id_ = data.get("id")
        name = data.get("name")
        if (
            not isinstance(id_, str)
            or not isinstance(name, str)
            or not re.fullmatch(r"[0-9a-fA-F]{32}", id_)
        ):
            raise LoginFailed("Minecraft services returned an unexpected profile.")
        return Profile(id_.lower(), name)

    def _post(
        self, url: str, payload: dict[str, Any], as_json: bool
    ) -> tuple[int, str]:
        if as_json:
            return self._send(
                url,
                json.dumps(payload, separators=(",", ":")),
                {"Content-Type": "application/json", "Accept": "application/json"},
            )
        return self._send(
            url,
            urlencode(payload),
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )

    def _send(
        self, url: str, body: str | None, headers: dict[str, str]
    ) -> tuple[int, str]:
        if not url.startswith("https://"):
            raise ValueError()
        try:
            with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
                if body is None:
                    response = client.get(url, headers=headers)
                else:
                    response = client.post(url, content=body, headers=headers)
        except httpx.HTTPError as error:
            logger.error(
                "civauth: request to %s failed: %s",
                urlsplit(url).hostname,
                type(error).__name__,
            )
            return 0, ""
        return response.status_code, response.text


def _decode(body: str) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _field(body: str, name: str, error: str) -> str:
    value = _decode(body).get(name)
    if not isinstance(value, str) or value == "":
        raise LoginFailed(error)
    return value
