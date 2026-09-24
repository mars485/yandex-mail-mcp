"""Read-only checks of fixed public metadata and JWKS; never prints secrets."""
import asyncio
import sys
import urllib.request
import json

from oauth_auth import AuthentikVerifier, ISSUER, JWKS_URL, RESOURCE


def main():
    with urllib.request.urlopen("http://127.0.0.1:8000/.well-known/oauth-protected-resource", timeout=8) as r:
        assert json.load(r)["resource"] == RESOURCE
    print("MCP OAuth discovery: OK")
    with urllib.request.urlopen(ISSUER + ".well-known/openid-configuration", timeout=8) as r:
        data = json.load(r)
    assert data["issuer"] == ISSUER and data["jwks_uri"] == JWKS_URL
    assert "S256" in data["code_challenge_methods_supported"]
    assert "client_secret_basic" in data["token_endpoint_auth_methods_supported"]
    print("Authentik discovery and PKCE: OK")
    assert {"mail:read", "mail:write", "offline_access"} <= set(data["scopes_supported"])
    print("Mail scopes and offline_access: OK")
    assert asyncio.run(AuthentikVerifier().fetch_keys())
    print("Authentik RSA public keys: OK")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("FAIL: проверьте AUTHENTIK.md; подробности скрыты.", file=sys.stderr)
        sys.exit(1)
