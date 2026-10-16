"""Resource-server validation for the dedicated Authentik mail provider."""
import os
from urllib.parse import urlsplit
import json
import time

import anyio
import httpx2
import jwt

ISSUER = os.getenv("OAUTH_ISSUER", "")
JWKS_URL = os.getenv("OAUTH_JWKS_URL", "") or ISSUER + "jwks/"
BACKCHANNEL_ISSUER = os.getenv("OAUTH_BACKCHANNEL_URL", "") or ISSUER
JWKS_FETCH_URL = (BACKCHANNEL_ISSUER + "jwks/") if BACKCHANNEL_ISSUER != ISSUER else JWKS_URL
RESOURCE = os.getenv("MCP_PUBLIC_URL", "")
METADATA_URL = "https://" + urlsplit(RESOURCE).netloc + "/.well-known/oauth-protected-resource"
CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "")
SCOPES = ["mail:read", "mail:write"]


def validate_config():
    for value in (ISSUER, JWKS_URL, RESOURCE, BACKCHANNEL_ISSUER, JWKS_FETCH_URL):
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError("Invalid OAuth URL configuration")
        _ = parsed.port  # Reject malformed ports.
    if urlsplit(RESOURCE).path != "/mcp" or not ISSUER.endswith("/"):
        raise ValueError("Invalid resource path or issuer")
    if not CLIENT_ID.strip():
        raise ValueError("Missing OAuth client ID")
    if (urlsplit(BACKCHANNEL_ISSUER).hostname != urlsplit(ISSUER).hostname
            or urlsplit(BACKCHANNEL_ISSUER).path != urlsplit(ISSUER).path):
        raise ValueError("OAuth backchannel must keep the issuer host and path")


def resource_metadata():
    return {"resource": RESOURCE, "authorization_servers": [ISSUER],
            "scopes_supported": SCOPES, "bearer_methods_supported": ["header"]}


class AuthentikVerifier:
    def __init__(self):
        validate_config()
        self.keys = {}
        self.expires = 0.0
        self.next_fetch = 0.0
        self.lock = anyio.Lock()

    async def fetch_keys(self):
        # Only operator-configured HTTPS URLs are fetched. JWT jku/x5u are ignored.
        # The canonical endpoint survives proxy port migrations; a validated
        # backchannel covers networks without hairpin routing. No TLS bypass.
        async with httpx2.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
            endpoints = list(dict.fromkeys([JWKS_URL, JWKS_FETCH_URL]))
            for index, endpoint in enumerate(endpoints):
                try:
                    async with client.stream("GET", endpoint, headers={"Host": urlsplit(ISSUER).netloc}) as response:
                        response.raise_for_status()
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            raw.extend(chunk)
                            if len(raw) > 65536:
                                raise ValueError("JWKS too large")
                    break
                except httpx2.RequestError:
                    if index == len(endpoints) - 1:
                        raise
        data = json.loads(raw)
        if not isinstance(data.get("keys"), list) or not 1 <= len(data["keys"]) <= 20:
            raise ValueError("Invalid JWKS")
        keys = {}
        for item in data["keys"]:
            if item.get("kty") != "RSA" or item.get("use", "sig") != "sig" or item.get("alg", "RS256") != "RS256":
                continue
            kid = item.get("kid")
            if not isinstance(kid, str) or not kid or kid in keys:
                raise ValueError("Invalid key ID")
            key = jwt.PyJWK.from_dict(item, algorithm="RS256").key
            if key.key_size < 2048:
                raise ValueError("Weak key")
            keys[kid] = key
        if not keys:
            raise ValueError("No signing keys")
        return keys

    async def key_for(self, kid):
        async with self.lock:
            now = time.monotonic()
            if now >= self.expires or kid not in self.keys:
                if now < self.next_fetch:
                    raise ValueError("Refresh throttled")
                self.next_fetch = now + 30
                keys = await self.fetch_keys()
                self.keys = keys
                self.expires = time.monotonic() + 300
            if kid not in self.keys:
                raise ValueError("Unknown key")
            return self.keys[kid]

    async def role(self, token):
        try:
            if len(token) > 16384 or token.count(".") != 2:
                return "none"
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("crit"):
                return "none"
            kid = header.get("kid")
            if not isinstance(kid, str) or not 1 <= len(kid) <= 256:
                return "none"
            key = await self.key_for(kid)
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
                                audience=RESOURCE, leeway=10,
                                options={"require": ["exp", "iat", "iss", "aud", "sub", "azp", "uid", "scope"]})
            # Authentik adds azp + uid to access tokens, not ordinary ID tokens.
            if claims["azp"] != CLIENT_ID or not claims["sub"] or not claims["uid"]:
                return "none"
            if not isinstance(claims["scope"], str):
                return "none"
            scopes = set(claims["scope"].split())
            if "mail:read" not in scopes or claims.get("mcp_read") is not True:
                return "none"
            return "write" if "mail:write" in scopes and claims.get("mcp_write") is True else "read"
        except Exception:
            # No raw token, claim, response body, or exception is logged/returned.
            return "none"
