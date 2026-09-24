import asyncio
import json
import time
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

import oauth_auth as auth
import server
from test_server import CFG, BASE, call, imap


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, **changes):
    now = int(time.time())
    claims = {"iss": auth.ISSUER, "aud": [auth.CLIENT_ID, auth.RESOURCE], "azp": auth.CLIENT_ID,
              "sub": "fixture-user", "uid": "fixture-access-token", "iat": now, "exp": now + 300,
              "scope": "openid mail:read", "mcp_read": True}
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})


def verifier(key):
    v = auth.AuthentikVerifier()
    v.keys = {"test-key": key.public_key()}
    v.expires = time.monotonic() + 300
    return v


@pytest.mark.parametrize("claims", [
    {"iss": "https://attacker.invalid/"}, {"aud": auth.CLIENT_ID}, {"aud": "another-service"},
    {"azp": "another-client"}, {"exp": 1}, {"iat": 9999999999}, {"sub": ""},
    {"uid": None}, {"scope": "openid"}, {"scope": ["mail:read"]}, {"mcp_read": False},
    {"mcp_read": "true"}, {"exp": None},
])
def test_invalid_claims(key, claims):
    assert asyncio.run(verifier(key).role(token(key, **claims))) == "none"


def test_roles(key):
    assert asyncio.run(verifier(key).role(token(key))) == "read"
    assert asyncio.run(verifier(key).role(token(key, scope="mail:read mail:write"))) == "read"
    assert asyncio.run(verifier(key).role(token(key, scope="mail:read mail:write", mcp_write=True))) == "write"


def test_signature_and_id_token(key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert asyncio.run(verifier(key).role(token(other))) == "none"
    assert asyncio.run(verifier(key).role("bad")) == "none"
    claims = jwt.decode(token(key), options={"verify_signature": False})
    del claims["uid"]
    del claims["azp"]
    signed = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})
    assert asyncio.run(verifier(key).role(signed)) == "none"
    signed = jwt.encode(claims, "a" * 64, algorithm="HS256", headers={"kid": "test-key"})
    assert asyncio.run(verifier(key).role(signed)) == "none"


def test_discovery_and_real_jwt(key, imap):
    app = server.build_app(replace(CFG, oauth_enabled=True))
    app.oauth = verifier(key)
    with TestClient(app, base_url=BASE) as c:
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            r = c.get(path)
            assert r.status_code == 200 and r.json()["resource"] == auth.RESOURCE
        assert "resource_metadata=" in c.get("/mcp").headers["www-authenticate"]
        headers = {"Authorization": "Bearer " + token(key), "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2025-11-25"}
        assert call(c, "list_folders", auth=headers)["ok"]
        assert not call(c, "mark_read", {"uid": 7, "uidvalidity": 99}, headers)["ok"]
        imap.add_flags.assert_not_called()
        headers["Authorization"] = "Bearer " + token(key, scope="mail:read mail:write", mcp_write=True)
        assert call(c, "mark_read", {"uid": 7, "uidvalidity": 99}, headers)["ok"]
        headers["Authorization"] = "Bearer " + token(key, aud="wrong")
        assert c.get("/mcp", headers=headers).status_code == 401


def test_key_refresh_and_failure(key):
    async def check():
        v = auth.AuthentikVerifier()
        count = 0
        async def fetch():
            nonlocal count
            count += 1
            return {"test-key": key.public_key()}
        v.fetch_keys = fetch
        assert await v.role(token(key)) == "read"
        assert await v.role(token(key)) == "read"
        assert count == 1
        v.expires = 0
        assert await v.role(token(key)) == "none"
        v.next_fetch = 0
        async def failed():
            raise RuntimeError("fixture secret must not leak")
        v.fetch_keys = failed
        assert await v.role(token(key)) == "none"
    asyncio.run(check())
