import asyncio
import logging
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import MagicMock

import pytest
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.testclient import TestClient
import server


CFG = server.Settings(email="test@example.invalid", password="test-password-not-real",
                      token="a" * 64, read_token="b" * 64)
BASE = "http://127.0.0.1:8000"
AUTH = {"Authorization": "Bearer " + CFG.token, "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25"}


@pytest.fixture
def client():
    with TestClient(server.build_app(CFG), base_url=BASE) as c:
        yield c


def rpc(client, method, params=None, auth=None):
    response = client.post("/mcp", headers=auth or AUTH,
                           json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    assert response.status_code == 200, response.text
    return response.json()["result"]


def call(client, name, args=None, auth=None):
    result = rpc(client, "tools/call", {"name": name, "arguments": args or {}}, auth)
    assert not result.get("isError"), result
    return result["structuredContent"]


@pytest.fixture
def imap(monkeypatch):
    c = MagicMock()
    c.select_folder.return_value = {b"UIDVALIDITY": 99}
    c.fetch.return_value = {7: {b"FLAGS": (), b"RFC822.SIZE": 100}}
    c.list_folders.return_value = [((), b"/", "INBOX"), ((), b"/", "Archive"),
                                   ((b"\\Trash",), b"/", "Bin"), ((), b"/", "Проекты")]
    c.has_capability.return_value = True
    c.add_flags.return_value = {7: (b"\\Seen",)}

    @contextmanager
    def fake(cfg):
        yield c
    monkeypatch.setattr(server, "connection", fake)
    return c


def test_health_and_auth(client):
    assert client.get("/health").json() == {"status": "ok"}
    for method in ("GET", "POST", "DELETE", "OPTIONS"):
        for path in ("/mcp", "/mcp/", "/mcp/other"):
            r = client.request(method, path)
            assert r.status_code == 401
            assert r.headers["www-authenticate"].startswith("Bearer")
    for value in ("Bearer wrong", "Basic " + CFG.token, "Bearer  " + CFG.token):
        assert client.post("/mcp", headers={"Authorization": value}).status_code == 401
    assert client.post("/mcp?access_token=" + CFG.token).status_code == 401
    assert client.post("/mcp", headers=[("Authorization", "Bearer " + CFG.token),
                                      ("Authorization", "Bearer " + CFG.token)]).status_code == 401


def test_protocol_and_annotations(client):
    result = rpc(client, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                  "clientInfo": {"name": "test", "version": "1"}})
    assert result["serverInfo"]["name"] == "Yandex Mail"
    tools = {t["name"]: t for t in rpc(client, "tools/list")["tools"]}
    assert {"list_folders", "search_messages", "read_message", "mark_read", "move_message", "archive_message"} <= set(tools)
    assert len(tools) == 48
    assert not any("delete" in x or "send" in x or "expunge" in x for x in tools if x != "get_sender_stats")
    for name, tool in tools.items():
        assert tool["annotations"]["readOnlyHint"] == (name not in {
            "mark_read", "move_message", "archive_message", "create_folder", "rename_folder", "subscribe_folder",
            "unsubscribe_folder", "set_message_flags", "mark_unread", "mark_flagged", "mark_unflagged", "mark_answered",
            "mark_unanswered", "bulk_set_flags", "copy_message", "bulk_copy_messages", "bulk_move_messages",
            "bulk_archive_messages", "create_label", "rename_label", "apply_labels", "remove_labels"})


def test_host_origin(client):
    for header, value, status in (("Host", "attacker.invalid", 421), ("Origin", "https://attacker.invalid", 403)):
        r = client.post("/mcp", headers={**AUTH, header: value}, json={})
        assert r.status_code == status
    assert client.post("/mcp", headers={**AUTH, "Host": "mail-mcp.example.com"},
                       json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).status_code == 200


def test_read_scope_blocks_writes(client, imap):
    auth = {**AUTH, "Authorization": "Bearer " + CFG.read_token}
    assert call(client, "list_folders", auth=auth)["ok"]
    for name, args in (("mark_read", {}), ("move_message", {"destination": "Archive"}), ("archive_message", {})):
        assert not call(client, name, {"uid": 7, "uidvalidity": 99, **args}, auth)["ok"]
    imap.select_folder.assert_not_called()
    assert call(client, "mark_read", {"uid": 7, "uidvalidity": 99})["ok"]


def test_write_switch(imap):
    with TestClient(server.build_app(replace(CFG, writes=False)), base_url=BASE) as client:
        assert not call(client, "archive_message", {"uid": 7, "uidvalidity": 99})["ok"]
    imap.move.assert_not_called()


def test_read_peek(client, imap):
    raw = b"Subject: Test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello"
    imap.fetch.side_effect = [{7: {b"FLAGS": (), b"RFC822.SIZE": len(raw)}}, {7: {b"BODY[]<0>": raw}}]
    result = call(client, "read_message", {"uid": 7, "uidvalidity": 99})
    assert result["body"] == "Hello"
    imap.select_folder.assert_called_once_with("INBOX", readonly=True)
    assert "BODY.PEEK" in str(imap.fetch.call_args_list[-1])
    imap.add_flags.assert_not_called()


def test_search_unicode_and_pagination(client, imap):
    imap.search.return_value = [5, 7, 9]
    imap.fetch.return_value = {7: {b"FLAGS": (), b"RFC822.SIZE": 42,
                                  b"BODY[HEADER.FIELDS (SUBJECT FROM TO DATE MESSAGE-ID)]<0>": b"Subject: Test\r\n"}}
    result = call(client, "search_messages", {"folder": "Проекты", "query": "счёт", "limit": 1, "offset": 1})
    assert result["uidvalidity"] == 99 and result["next_offset"] == 2
    assert result["messages"][0]["uid"] == 7
    imap.search.assert_called_once_with(["ALL", "TEXT", "счёт"], charset="UTF-8")
    imap.select_folder.assert_called_once_with("Проекты", readonly=True)


def test_write_uidvalidity(client, imap):
    assert not call(client, "mark_read", {"uid": 7, "uidvalidity": 100})["ok"]
    imap.add_flags.assert_not_called()
    assert call(client, "mark_read", {"uid": 7, "uidvalidity": 99})["ok"]
    imap.add_flags.assert_called_once_with([7], ["\\Seen"])


def test_move_and_archive(client, imap):
    assert call(client, "move_message", {"uid": 7, "uidvalidity": 99, "destination": "Проекты"})["ok"]
    imap.move.assert_called_once_with([7], "Проекты")
    assert call(client, "archive_message", {"uid": 7, "uidvalidity": 99})["ok"]
    assert not call(client, "move_message", {"uid": 7, "uidvalidity": 99, "destination": "Bin"})["ok"]
    assert not call(client, "move_message", {"uid": 7, "uidvalidity": 99, "destination": "Missing"})["ok"]
    imap.has_capability.return_value = False
    assert not call(client, "archive_message", {"uid": 7, "uidvalidity": 99})["ok"]
    assert imap.move.call_count == 2
    imap.delete_messages.assert_not_called()
    imap.expunge.assert_not_called()
    imap.close_folder.assert_not_called()
    imap.copy.assert_not_called()


def test_missing_uid_and_large_message(client, imap):
    imap.fetch.return_value = {}
    assert not call(client, "mark_read", {"uid": 7, "uidvalidity": 99})["ok"]
    imap.add_flags.assert_not_called()
    imap.fetch.return_value = {7: {b"RFC822.SIZE": server.MAX_MESSAGE_BYTES + 1}}
    assert not call(client, "read_message", {"uid": 7})["ok"]
    assert "BODY.PEEK" not in str(imap.fetch.call_args)


def test_invalid_search_inputs(client, imap):
    for args in ({"folder": "INBOX\r\nLOGOUT"}, {"query": "x\r\n"}, {"since": "invalid"}, {"limit": 101}):
        assert not call(client, "search_messages", args)["ok"]
    imap.search.assert_not_called()


def test_error_secrets(client, imap, capsys):
    server.configure_logging()
    imap.list_folders.side_effect = RuntimeError("SECRET-password-mail-body")
    result = call(client, "list_folders")
    logging.getLogger("imapclient").error("SECRET-password-mail-body")
    captured = capsys.readouterr()
    assert not result["ok"]
    assert "SECRET" not in str(result) + captured.err + captured.out
    assert "event=tool_failed" in captured.err


@pytest.mark.parametrize("change", [{"token": ""}, {"token": "short"}, {"read_token": CFG.token},
                                    {"password": ""}, {"allowed_hosts": ("*",)}])
def test_config_rejected(change):
    with pytest.raises(ValueError):
        replace(CFG, **change).validate()


def test_modern_sdk_client(imap):
    async def check():
        app = server.build_app(CFG)
        async with app.app.router.lifespan_context(app.app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
                                         headers=AUTH) as http:
                async with Client(streamable_http_client(BASE + "/mcp", http_client=http), mode="2026-07-28") as c:
                    result = await c.list_tools()
                    assert len(result.tools) == 48
                    result = await c.call_tool("list_folders", {})
                    assert result.structured_content["ok"]
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
                      headers={"Authorization": "Bearer " + CFG.read_token}) as http:
                async with Client(streamable_http_client(BASE + "/mcp", http_client=http), mode="2026-07-28") as c:
                    result = await c.call_tool("mark_read", {"uid": 7, "uidvalidity": 99})
                    assert result.structured_content["ok"] is False
                    imap.add_flags.assert_not_called()
    asyncio.run(check())
