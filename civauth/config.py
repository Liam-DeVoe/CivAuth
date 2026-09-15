from __future__ import annotations

from types import ModuleType
from urllib.parse import urlparse

KEYS = {
    "issuer",
    "microsoft_client_id",
    "microsoft_client_secret",
    "join_secret",
    "join_address",
    "database",
}

class Config:
    def __init__(self, data: dict) -> None:
        unknown = set(data) - KEYS
        if unknown:
            raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))

        issuer = _string(data, "issuer")
        parts = urlparse(issuer)
        if parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment:
            raise ValueError("issuer must be an https URL with no query or fragment")
        self.issuer = issuer.rstrip("/")
        self.issuer_path = parts.path.rstrip("/")

        self.microsoft_client_id = _string(data, "microsoft_client_id")
        self.microsoft_client_secret = _string(data, "microsoft_client_secret")

        self.join_secret = _string(data, "join_secret")
        self.join_address = _string(data, "join_address")
        if len(self.join_secret) < 32:
            raise ValueError("join_secret must be at least 32 characters")

        self.database = _string(data, "database")

    @classmethod
    def from_module(cls, module: ModuleType) -> Config:
        return cls({name: value for name, value in vars(module).items() if not name.startswith("_")})

    def url(self, route: str) -> str:
        return self.issuer + route

    def cookie_path(self) -> str:
        return self.issuer_path or "/"


def _string(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{key} must be a non-empty string")
    return value
