"""Проверка HTTP/MCP без вывода токена, заголовков писем или ошибок сервера."""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the token to another endpoint.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--imap", action="store_true", help="Также вызвать list_folders без вывода названий")
    args = parser.parse_args()
    if not args.url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
        raise ValueError("Remote endpoint requires HTTPS")
    token = os.environ["MCP_BEARER_TOKEN"]
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(args.url, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise ValueError("Expected 401") from None
    else:
        raise ValueError("Endpoint did not require authorization")
    print("Unauthorized request: 401 OK")

    def rpc(method, params, ident):
        request = urllib.request.Request(args.url, method="POST",
            data=json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": params}).encode(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"})
        with opener.open(request, timeout=60) as response:
            data = json.load(response)
        if "error" in data:
            raise ValueError("MCP error")
        return data["result"]

    rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "mail-smoke", "version": "1.0"}}, 1)
    print("MCP initialize: OK")
    names = {tool["name"] for tool in rpc("tools/list", {}, 2)["tools"]}
    expected = {"list_folders", "search_messages", "read_message", "mark_read", "move_message", "archive_message"}
    if not expected <= names or len(names) != 48 or any(
            "delete" in name or "expunge" in name or name.startswith("send_") for name in names):
        raise ValueError("Unexpected tools")
    print("48 expected tools, no send/delete/expunge tools: OK")
    if args.imap:
        result = rpc("tools/call", {"name": "list_folders", "arguments": {}}, 3)
        structured = result.get("structuredContent")
        if structured is None:
            structured = json.loads(result["content"][0]["text"])
        if result.get("isError") or not structured.get("ok"):
            raise ValueError("IMAP failed")
        print("IMAP list_folders: OK (names hidden)")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("FAIL: проверка не пройдена; секреты и ответ сервера скрыты.", file=sys.stderr)
        sys.exit(1)
