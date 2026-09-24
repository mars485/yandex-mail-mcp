import pytest
import oauth_auth as auth


@pytest.mark.parametrize('name,value', [
    ('ISSUER', 'http://auth.example.com/'),
    ('ISSUER', 'https://auth.example.com/no-trailing-slash'),
    ('JWKS_URL', 'https://user:secret@auth.example.com/jwks/'),
    ('RESOURCE', 'https://mail-mcp.example.com/mcp?token=secret'),
    ('RESOURCE', 'https://mail-mcp.example.com/other'),
    ('RESOURCE', 'https://mail-mcp.example.com/mcp\r\nX:1'),
    ('CLIENT_ID', ''),
])
def test_invalid_oauth_config(monkeypatch, name, value):
    monkeypatch.setattr(auth, name, value)
    with pytest.raises(ValueError):
        auth.AuthentikVerifier()


def test_valid_oauth_config():
    auth.validate_config()
