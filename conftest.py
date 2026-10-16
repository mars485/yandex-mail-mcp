"""Isolated public fixtures: never use the operator's OAuth environment."""
import os

os.environ["OAUTH_ISSUER"] = "https://auth.example.com/application/o/yandex-mail-mcp/"
os.environ["OAUTH_CLIENT_ID"] = "fixture-client"
os.environ["MCP_PUBLIC_URL"] = "https://mail-mcp.example.com/mcp"
os.environ["OAUTH_JWKS_URL"] = ""
os.environ["OAUTH_BACKCHANNEL_URL"] = ""
