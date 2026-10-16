"""Bounded IMAP operations. No SMTP, DELETE, EXPUNGE, raw commands or file paths."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import sqlite3
import uuid
from collections import Counter
from datetime import date
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Any

MAX_BATCH = 100
MAX_SCAN = 2000
MAX_CHUNK = 256 * 1024
SAFE_FLAGS = {"\\Seen", "\\Flagged", "\\Answered", "$Forwarded"}
HEADER_FETCH = "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO CC DATE MESSAGE-ID REFERENCES IN-REPLY-TO)]<0.32768>"


def register_tools(operation, cfg, api):
    error = api.MailError

    def bounded(value, low, high):
        if type(value) is not int or not low <= value <= high:
            raise error(f"Допустимо целое число {low}..{high}.")
        return value

    def uids(values):
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_BATCH:
            raise error("Передайте 1..100 UID из свежего поиска.")
        result = list(dict.fromkeys(api.positive(x) for x in values))
        return result

    def safe_text(value, length=1000):
        if not isinstance(value, str) or len(value) > length or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise error("Некорректный текстовый фильтр.")
        return value

    def selected(c, folder, expected=None, write=False):
        return api.select(c, folder, readonly=not write, expected=expected)

    def present(c, values):
        rows = c.fetch(values, ["FLAGS", "RFC822.SIZE"])
        if any(x not in rows for x in values):
            raise error("Не все UID существуют; операция не начата. Повторите поиск.")
        return rows

    def body_bytes(row):
        return next((v for k, v in row.items() if isinstance(k, bytes) and k.startswith(b"BODY[") and isinstance(v, bytes)), None)

    def raw_message(c, uid):
        row = api.existing(c, uid)
        if row[b"RFC822.SIZE"] > api.MAX_MESSAGE_BYTES:
            raise error("Письмо больше лимита 8 MiB.")
        data = c.fetch([uid], [f"BODY.PEEK[]<0.{api.MAX_MESSAGE_BYTES + 1}>"])
        raw = body_bytes(data.get(uid, {}))
        if raw is None or len(raw) > api.MAX_MESSAGE_BYTES:
            raise error("Письмо недоступно или превышает 8 MiB.")
        return raw

    def parsed(c, uid):
        return BytesParser(policy=policy.default).parsebytes(raw_message(c, uid))

    def row_headers(c, values):
        if not values:
            return []
        rows = c.fetch(values, ["FLAGS", "RFC822.SIZE", HEADER_FETCH])
        result = []
        for uid in values:
            if uid not in rows:
                continue
            row = rows[uid]
            raw = body_bytes(row) or b""
            msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
            headers = {k: str(msg.get(k, ""))[:4000] for k in (
                "Subject", "From", "To", "Cc", "Date", "Message-ID", "References", "In-Reply-To")}
            result.append({"uid": uid, "headers": headers, "size": row.get(b"RFC822.SIZE"),
                           "flags": [api.text(x) for x in row.get(b"FLAGS", ())]})
        return result

    def criteria(filters):
        """Structured AND only; IMAPClient quotes values; no raw command interface."""
        allowed = {"text", "sender", "recipient", "cc", "subject", "since", "before", "on",
                   "unread", "flagged", "answered", "min_bytes", "max_bytes", "message_id", "keyword"}
        if not isinstance(filters, dict) or set(filters) - allowed:
            raise error("Неизвестный поисковый фильтр.")
        result = ["ALL"]
        for key, imap in (("text", "TEXT"), ("sender", "FROM"), ("recipient", "TO"), ("cc", "CC"), ("subject", "SUBJECT")):
            if key in filters and filters[key]:
                result.extend([imap, safe_text(filters[key])])
        for key, imap in (("since", "SINCE"), ("before", "BEFORE"), ("on", "ON")):
            if key in filters and filters[key]:
                try:
                    result.extend([imap, date.fromisoformat(safe_text(filters[key], 10))])
                except (ValueError, TypeError):
                    raise error("Дата должна иметь формат YYYY-MM-DD.") from None
        for key, yes, no in (("unread", "UNSEEN", "SEEN"), ("flagged", "FLAGGED", "UNFLAGGED"), ("answered", "ANSWERED", "UNANSWERED")):
            if key in filters:
                if type(filters[key]) is not bool:
                    raise error("Состояние флага должно быть true/false.")
                result.append(yes if filters[key] else no)
        for key, imap in (("min_bytes", "LARGER"), ("max_bytes", "SMALLER")):
            if key in filters:
                result.extend([imap, bounded(filters[key], 0, 1024**3)])
        if filters.get("message_id"):
            result.extend(["HEADER", "Message-ID", safe_text(filters["message_id"])])
        if filters.get("keyword"):
            keyword = safe_text(filters["keyword"], 200)
            if not re.fullmatch(r"[A-Za-z0-9_$.-]+", keyword):
                raise error("Некорректный IMAP keyword.")
            result.extend(["KEYWORD", keyword])
        return result

    def searchable(c, folders, limit=30):
        bounded(len(folders), 0, limit)
        available = {name: flags for flags, _, name in c.list_folders()}
        chosen = folders or [n for n, f in available.items() if not any(
            api.text(x).lower() in {"\\noselect", "\\trash", "\\junk"} for x in f)]
        if len(chosen) > limit:
            raise error("Слишком много папок; укажите не более 30 явно.")
        for name in chosen:
            api.folder_name(name)
            if name not in available:
                raise error("Папка не существует.")
        return list(dict.fromkeys(chosen))

    def destination(c, folder):
        # Also prohibit all descendants of a Trash folder, using its actual delimiter.
        for flags, delim, name in c.list_folders():
            if any(api.text(x).lower() == "\\trash" for x in flags):
                sep = api.text(delim) if delim else ""
                if folder == name or (sep and folder.startswith(name + sep)):
                    raise error("Корзина и её подпапки запрещены.")
        return api.target_folder(c, folder)

    def status(c, folder):
        data = c.folder_status(api.folder_name(folder), ["MESSAGES", "UNSEEN", "UIDNEXT", "UIDVALIDITY"])
        return {api.text(k).lower(): int(v) for k, v in data.items()}

    def search_ids(c, filters, scan_limit=200):
        """Yandex may reject HEADER Message-ID; use an explicitly bounded fallback."""
        try:
            return sorted(c.search(criteria(filters), charset="UTF-8"), reverse=True), False, "imap_search"
        except api.IMAPClient.Error:
            if not filters.get("message_id"):
                raise
        remaining = {k: v for k, v in filters.items() if k != "message_id"}
        candidates = sorted(c.search(criteria(remaining), charset="UTF-8"), reverse=True)
        found = []
        for start in range(0, min(len(candidates), scan_limit), MAX_BATCH):
            for row in row_headers(c, candidates[start:min(start + MAX_BATCH, scan_limit)]):
                if row["headers"]["Message-ID"].strip() == filters["message_id"].strip():
                    found.append(row["uid"])
        return found, len(candidates) > scan_limit, "bounded_header_scan"

    def db():
        path = Path(cfg.state_dir)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(path / "labels.sqlite3", timeout=10)
        connection.execute("CREATE TABLE IF NOT EXISTS labels (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, keyword TEXT NOT NULL UNIQUE)")
        return connection

    def catalog():
        with db() as d:
            return [{"id": x[0], "name": x[1], "keyword": x[2]} for x in d.execute("SELECT id,name,keyword FROM labels ORDER BY name")]

    def label_rows(ids):
        if not 1 <= len(ids) <= 30 or len(ids) != len(set(ids)):
            raise error("Передайте 1..30 уникальных ID меток.")
        found = {x["id"]: x for x in catalog()}
        if any(x not in found for x in ids):
            raise error("Неизвестная метка; вызовите list_labels.")
        return [found[x] for x in ids]

    def label_note():
        return {"backend": "imap_keywords", "native_web_labels": False,
                "note": "Это IMAP-теги MCP. Отображение цветных меток в веб-почте Яндекса не гарантируется."}

    def change_flags(c, values, add, remove):
        if not add and not remove or set(add) & set(remove) or not set(add + remove) <= SAFE_FLAGS:
            raise error("Разрешены только Seen, Flagged, Answered, $Forwarded; без замены полного набора флагов.")
        present(c, values)
        if add:
            c.add_flags(values, add)
        if remove:
            c.remove_flags(values, remove)
        actual = c.get_flags(values)
        if any(uid not in actual or not set(add) <= {api.text(x) for x in actual[uid]}
               or set(remove) & {api.text(x) for x in actual[uid]} for uid in values):
            raise error("Не удалось подтвердить все флаги; проверьте состояние перед повтором.")
        return {"ok": True, "uids": values, "flags": {str(k): [api.text(x) for x in v] for k, v in actual.items()}}

    def batch_transfer(c, values, folder, target, move, dry_run):
        target = destination(c, target)
        if folder.casefold() == target.casefold():
            raise error("Исходная и целевая папки совпадают.")
        present(c, values)
        if move and not c.has_capability("MOVE"):
            raise error("MOVE не поддерживается; обход через удаление запрещён.")
        if not dry_run:
            (c.move if move else c.copy)(values, target)
        return {"ok": True, "dry_run": dry_run, "count": len(values), "uids": values, "destination": target,
                "note": "В целевой папке получите новые UID поиском. Не повторяйте COPY/MOVE после ошибки без проверки."}

    @operation()
    def get_server_capabilities() -> dict[str, Any]:
        """Проверить возможности реального IMAP, TLS, MOVE и ограничения реализации."""
        with api.connection(cfg) as c:
            caps = sorted(api.text(x) for x in c.capabilities())
            meta = c.select_folder("INBOX", readonly=True)
            return {"ok": True, "capabilities": caps, "permanent_flags": [api.text(x) for x in meta.get(b"PERMANENTFLAGS", ())],
                    "max_batch": MAX_BATCH, "max_message_bytes": api.MAX_MESSAGE_BYTES,
                    "max_attachment_chunk_bytes": MAX_CHUNK, "smtp": False, "delete": False,
                    "server_rules": False, "labels": label_note()}

    @operation()
    def get_folder_stats(folder: str = "INBOX") -> dict[str, Any]:
        """Количество писем, непрочитанных, UIDNEXT и UIDVALIDITY без загрузки писем."""
        with api.connection(cfg) as c:
            return {"ok": True, "folder": folder, **status(c, folder)}

    @operation()
    def get_all_folder_stats(folders: list[str] | None = None) -> dict[str, Any]:
        """Статистика до 30 обычных папок; по умолчанию без Спама и Корзины."""
        with api.connection(cfg) as c:
            rows = [{"folder": f, **status(c, f)} for f in searchable(c, folders or [])]
            return {"ok": True, "folders": rows, "messages": sum(x["messages"] for x in rows), "unread": sum(x["unseen"] for x in rows)}

    @operation()
    def get_unread_summary(folders: list[str] | None = None) -> dict[str, Any]:
        """Сводка непрочитанного через STATUS; до 30 папок, без загрузки заголовков."""
        with api.connection(cfg) as c:
            rows = [{"folder": f, "unread": status(c, f)["unseen"]} for f in searchable(c, folders or [])]
            return {"ok": True, "folders": rows, "total_unread": sum(x["unread"] for x in rows)}

    @operation()
    def list_subscribed_folders() -> dict[str, Any]:
        """Список подписанных папок IMAP (не подписки на рекламные рассылки)."""
        with api.connection(cfg) as c:
            return {"ok": True, "folders": [{"name": n, "delimiter": api.text(d) if d else None, "flags": [api.text(x) for x in f]} for f, d, n in c.list_sub_folders()]}

    @operation()
    def list_namespaces() -> dict[str, Any]:
        """Пространства имён и разделители IMAP-папок."""
        with api.connection(cfg) as c:
            if not c.has_capability("NAMESPACE"):
                raise error("NAMESPACE не поддерживается.")
            n = c.namespace()
            return {"ok": True, "personal": n.personal, "other": n.other, "shared": n.shared}

    @operation(write=True)
    def create_folder(name: str) -> dict[str, Any]:
        """Создать папку. Существующая папка возвращается без дублирования; Корзина запрещена."""
        api.folder_name(name)
        with api.connection(cfg) as c:
            rows = c.list_folders()
            for flags, delim, folder in rows:
                if any(api.text(x).lower() == "\\trash" for x in flags) and (name == folder or (delim and name.startswith(folder + api.text(delim)))):
                    raise error("Создание внутри Корзины запрещено.")
            if any(n == name for _, _, n in rows):
                return {"ok": True, "name": name, "created": False}
            if name.casefold() in {"trash", "deleted", "корзина", "удаленные", "удалённые"}:
                raise error("Создание Корзины запрещено.")
            c.create_folder(name)
            return {"ok": c.folder_exists(name), "name": name, "created": True}

    @operation(write=True)
    def rename_folder(folder: str, new_name: str, dry_run: bool = True) -> dict[str, Any]:
        """Переименовать обычную папку; системные папки защищены. По умолчанию предварительная проверка."""
        api.folder_name(new_name)
        with api.connection(cfg) as c:
            destination(c, folder)
            if c.folder_exists(new_name):
                raise error("Новое имя уже существует.")
            rows = c.list_folders()
            protected = {"\\trash", "\\sent", "\\drafts", "\\junk", "\\archive", "\\all"}
            for flags, delim, name in rows:
                sep = api.text(delim) if delim else ""
                if name == folder or (sep and name.startswith(folder + sep)):
                    if name.upper() == "INBOX" or {api.text(x).lower() for x in flags} & protected:
                        raise error("Переименование системной папки или её родителя запрещено.")
                if {api.text(x).lower() for x in flags} & {"\\trash"} and (new_name == name or (sep and new_name.startswith(name + sep))):
                    raise error("Корзина запрещена.")
            if not dry_run:
                c.rename_folder(folder, new_name)
            return {"ok": True, "dry_run": dry_run, "folder": folder, "new_name": new_name}

    @operation(write=True)
    def subscribe_folder(folder: str) -> dict[str, Any]:
        """Подписать IMAP-клиент на существующую папку, не меняя писем."""
        with api.connection(cfg) as c:
            destination(c, folder)
            c.subscribe_folder(folder)
            return {"ok": True, "folder": folder, "subscribed": True}

    @operation(write=True)
    def unsubscribe_folder(folder: str) -> dict[str, Any]:
        """Снять подписку IMAP на обычную папку; письма сохраняются."""
        with api.connection(cfg) as c:
            destination(c, folder)
            if folder.upper() == "INBOX":
                raise error("Снятие подписки с INBOX запрещено.")
            c.unsubscribe_folder(folder)
            return {"ok": True, "folder": folder, "subscribed": False}

    @operation()
    def advanced_search(filters: dict[str, Any], folder: str = "INBOX", limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """Поиск AND: text,sender,recipient,cc,subject,since,before,on,unread,flagged,answered,min_bytes,max_bytes,message_id,keyword. Даты YYYY-MM-DD."""
        bounded(limit, 1, 100); bounded(offset, 0, 200000)
        crit = criteria(filters)
        with api.connection(cfg) as c:
            validity = selected(c, folder)
            found, truncated, method = search_ids(c, filters)
            return {"ok": True, "folder": folder, "uidvalidity": validity, "total": len(found),
                    "truncated": truncated, "search_method": method,
                    "messages": row_headers(c, found[offset:offset + limit]),
                    "next_offset": offset + limit if offset + limit < len(found) else None}

    @operation()
    def search_all_folders(filters: dict[str, Any], folders: list[str] | None = None, per_folder_limit: int = 10) -> dict[str, Any]:
        """Поиск до 30 папок; максимум 10 заголовков на папку; без Спама и Корзины по умолчанию."""
        bounded(per_folder_limit, 1, 10)
        crit = criteria(filters)
        with api.connection(cfg) as c:
            rows = []
            for folder in searchable(c, folders or []):
                validity = selected(c, folder)
                found, truncated, method = search_ids(c, filters, 100)
                rows.append({"folder": folder, "uidvalidity": validity, "total": len(found),
                             "messages": row_headers(c, found[:per_folder_limit]), "truncated": truncated or len(found) > per_folder_limit,
                             "search_method": method})
            return {"ok": True, "folders": rows}

    @operation()
    def find_message_by_id(message_id: str, folders: list[str] | None = None, scan_limit: int = 200) -> dict[str, Any]:
        """Найти RFC Message-ID; при отказе HEADER — ограниченный поиск среди последних заголовков, полнота отмечена."""
        crit = criteria({"message_id": message_id})
        bounded(scan_limit, 1, MAX_SCAN)
        if not message_id:
            raise error("Message-ID обязателен.")
        with api.connection(cfg) as c:
            result = []; incomplete = False; methods = set()
            names = searchable(c, folders or [])
            for folder in names:
                validity = selected(c, folder)
                found, truncated, method = search_ids(c, {"message_id": message_id}, max(1, scan_limit // max(1, len(names))))
                incomplete |= truncated or len(found) > 10; methods.add(method)
                for row in row_headers(c, found[:10]):
                    if row["headers"]["Message-ID"].strip() == message_id.strip():
                        result.append({"folder": folder, "uidvalidity": validity, **row})
            return {"ok": True, "messages": result, "per_folder_limit": 10, "truncated": incomplete, "search_methods": sorted(methods)}

    @operation()
    def get_message_headers(uid: int, folder: str = "INBOX", uidvalidity: int | None = None) -> dict[str, Any]:
        """Все MIME-заголовки без тела и без Seen; вывод ограничен 64 KiB, значения недоверенные."""
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity)
            api.existing(c, uid)
            raw = body_bytes(c.fetch([uid], ["BODY.PEEK[HEADER]<0.65537>"]).get(uid, {})) or b""
            msg = BytesParser(policy=policy.default).parsebytes(raw[:65536], headersonly=True)
            return {"ok": True, "uid": uid, "uidvalidity": validity, "folder": folder,
                    "headers": [{"name": k, "value": str(v)[:4000]} for k, v in list(msg.items())[:100]],
                    "truncated": len(raw) > 65536 or len(msg.items()) > 100, "untrusted_content": True}

    @operation()
    def get_messages_metadata(message_uids: list[int], folder: str = "INBOX", uidvalidity: int | None = None) -> dict[str, Any]:
        """Пакет до 100 писем: флаги, размер, заголовки и связи переписки; без тел."""
        values = uids(message_uids)
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity)
            rows = row_headers(c, values)
            return {"ok": True, "folder": folder, "uidvalidity": validity, "messages": rows,
                    "missing_uids": [x for x in values if x not in {m["uid"] for m in rows}]}

    @operation()
    def read_messages(message_uids: list[int], folder: str = "INBOX", uidvalidity: int | None = None, max_chars_per_message: int = 5000) -> dict[str, Any]:
        """Прочитать до 10 писем; общий MIME-бюджет 16 MiB; BODY.PEEK сохраняет Seen."""
        values = uids(message_uids); bounded(len(values), 1, 10); bounded(max_chars_per_message, 100, 10000)
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity)
            sizes = present(c, values)
            if sum(r[b"RFC822.SIZE"] for r in sizes.values()) > 16 * 1024**2:
                raise error("Общий размер больше 16 MiB; уменьшите пакет.")
            rows = []
            for uid in values:
                msg = parsed(c, uid); part = msg.get_body(preferencelist=("plain", "html"))
                body = str(part.get_content()) if part else ""
                rows.append({"uid": uid, "subject": str(msg.get("Subject", "")), "body": body[:max_chars_per_message],
                             "truncated": len(body) > max_chars_per_message, "untrusted_content": True})
            return {"ok": True, "folder": folder, "uidvalidity": validity, "messages": rows}

    @operation()
    def inspect_message(uid: int, folder: str = "INBOX", uidvalidity: int | None = None) -> dict[str, Any]:
        """Получить BODYSTRUCTURE и размер без скачивания тела, включая крупные письма."""
        def serial(value):
            if isinstance(value, bytes): return api.text(value)
            if isinstance(value, dict): return {api.text(k): serial(v) for k, v in value.items()}
            if isinstance(value, (list, tuple)): return [serial(v) for v in value]
            return value
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity)
            api.existing(c, uid)
            data = c.fetch([uid], ["BODYSTRUCTURE", "RFC822.SIZE", "FLAGS"])
            return {"ok": True, "uid": uid, "folder": folder, "uidvalidity": validity, "metadata": serial(data.get(uid, {}))}

    @operation()
    def get_raw_message(uid: int, folder: str = "INBOX", uidvalidity: int | None = None, offset: int = 0, length: int = 65536) -> dict[str, Any]:
        """Ограниченный фрагмент исходного EML в base64; без записи файлов, без Seen."""
        bounded(offset, 0, api.MAX_MESSAGE_BYTES); bounded(length, 1, MAX_CHUNK)
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity)
            size = api.existing(c, uid)[b"RFC822.SIZE"]
            data = body_bytes(c.fetch([uid], [f"BODY.PEEK[]<{offset}.{length}>"]).get(uid, {})) or b""
            if len(data) > length:
                raise error("Сервер не соблюдает лимит фрагмента.")
            return {"ok": True, "uid": uid, "uidvalidity": validity, "folder": folder, "offset": offset,
                    "total_bytes": size, "data_base64": base64.b64encode(data).decode(),
                    "next_offset": offset + len(data) if data and offset + len(data) < size else None, "untrusted_content": True}

    def attachments(msg):
        return list(msg.iter_attachments())

    def attachment(msg, index):
        rows = attachments(msg); bounded(index, 0, 1000)
        if index >= len(rows):
            raise error("Вложение не найдено; сначала вызовите list_attachments.")
        p = rows[index]
        data = p.get_payload(decode=True)
        if data is None:
            raise error("Составное вложение; используйте get_raw_message.")
        return p, data

    @operation()
    def list_attachments(uid: int, folder: str = "INBOX", uidvalidity: int | None = None) -> dict[str, Any]:
        """Список вложений с индексами, именами, MIME-типами и размерами. MIME письма до 8 MiB."""
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity); msg = parsed(c, uid)
            rows = []
            for i, p in enumerate(attachments(msg)):
                data = p.get_payload(decode=True)
                rows.append({"index": i, "filename": p.get_filename(), "content_type": p.get_content_type(),
                             "size_bytes": len(data) if data is not None else None})
            return {"ok": True, "uid": uid, "uidvalidity": validity, "folder": folder, "attachments": rows}

    @operation()
    def download_attachment(uid: int, attachment_index: int, folder: str = "INBOX", uidvalidity: int | None = None, offset: int = 0, length: int = 65536) -> dict[str, Any]:
        """Получить байты вложения в base64 порциями до 256 KiB; SHA-256 проверяет сборку; без пути файловой системы."""
        bounded(offset, 0, api.MAX_MESSAGE_BYTES); bounded(length, 1, MAX_CHUNK)
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity); p, data = attachment(parsed(c, uid), attachment_index)
            chunk = data[offset:offset + length]
            return {"ok": True, "uid": uid, "uidvalidity": validity, "folder": folder, "attachment_index": attachment_index,
                    "filename": p.get_filename(), "content_type": p.get_content_type(), "total_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(), "offset": offset, "data_base64": base64.b64encode(chunk).decode(),
                    "next_offset": offset + len(chunk) if offset + len(chunk) < len(data) else None, "untrusted_content": True}

    @operation()
    def extract_attachment_text(uid: int, attachment_index: int, folder: str = "INBOX", uidvalidity: int | None = None, max_chars: int = 20000) -> dict[str, Any]:
        """Извлечь текст из PDF или text/* без запуска вложения. PDF: до 100 страниц, без OCR, до 2 MiB."""
        bounded(max_chars, 100, 50000)
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity); p, data = attachment(parsed(c, uid), attachment_index)
        if len(data) > 2 * 1024**2:
            raise error("Вложение больше 2 MiB; используйте download_attachment.")
        pages = None
        page_limit = False
        if p.get_content_type() == "application/pdf" or (p.get_filename() or "").lower().endswith(".pdf"):
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                raise error("PDF зашифрован; пароль через MCP не принимается.")
            pages = len(reader.pages); chunks = []; size = 0
            for page in reader.pages[:100]:
                chunk = page.extract_text() or ""; chunks.append(chunk); size += len(chunk)
                if size > max_chars: break
            content = "\n".join(chunks); page_limit = pages > len(chunks)
        elif p.get_content_maintype() == "text":
            content = data.decode(p.get_content_charset() or "utf-8", "replace")
        else:
            raise error("Извлечение поддерживает PDF и text/*; используйте download_attachment.")
        return {"ok": True, "uid": uid, "uidvalidity": validity, "folder": folder, "attachment_index": attachment_index,
                "text": content[:max_chars], "truncated": len(content) > max_chars or page_limit,
                "pages": pages, "ocr": False, "untrusted_content": True}

    @operation()
    def get_thread(uid: int, folder: str = "INBOX", uidvalidity: int | None = None, folders: list[str] | None = None, since: str = "", scan_limit: int = 200) -> dict[str, Any]:
        """Собрать связи Message-ID/References до 5 папок, до 2000 заголовков; ограниченная выборка, не полный THREAD."""
        bounded(scan_limit, 1, MAX_SCAN)
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity); api.existing(c, uid)
            seed = row_headers(c, [uid])[0]
            def ids(row):
                h = row["headers"]
                return set(re.findall(r"<[^<>\s]+>", h["Message-ID"] + " " + h["References"] + " " + h["In-Reply-To"]))
            linked = ids(seed)
            if not linked:
                return {"ok": True, "messages": [{"folder": folder, "uidvalidity": validity, **seed}], "truncated": True, "note": "Нет идентификаторов связей."}
            names = searchable(c, folders or [folder], 5); all_rows = []; truncated = False
            per = max(1, scan_limit // len(names))
            for name in names:
                val = selected(c, name); found = sorted(c.search(criteria({"since": since}) if since else ["ALL"], charset="UTF-8"), reverse=True)
                truncated |= len(found) > per
                for start in range(0, min(len(found), per), MAX_BATCH):
                    all_rows.extend({"folder": name, "uidvalidity": val, **r} for r in row_headers(c, found[start:min(start+MAX_BATCH, per)]))
            result = {(folder, uid): {"folder": folder, "uidvalidity": validity, **seed}}
            for _ in range(len(all_rows) + 1):
                before = len(result)
                for row in all_rows:
                    if ids(row) & linked:
                        result[(row["folder"], row["uid"])] = row; linked |= ids(row)
                if len(result) == before: break
            return {"ok": True, "messages": list(result.values()), "scanned": len(all_rows), "truncated": truncated,
                    "note": "Связи только по заголовкам; отсутствие ответа не доказывает, что ответа не было."}

    @operation()
    def get_sender_stats(folder: str = "INBOX", since: str = "", scan_limit: int = 500, top: int = 20) -> dict[str, Any]:
        """Частота отправителей по максимум 2000 последним совпадениям; результат отмечает неполную выборку."""
        bounded(scan_limit, 1, MAX_SCAN); bounded(top, 1, 100)
        crit = criteria({"since": since}) if since else ["ALL"]
        with api.connection(cfg) as c:
            validity = selected(c, folder); found = sorted(c.search(crit, charset="UTF-8"), reverse=True)
            counts = Counter()
            for start in range(0, min(scan_limit, len(found)), MAX_BATCH):
                for row in row_headers(c, found[start:min(start+MAX_BATCH, scan_limit)]):
                    addresses = getaddresses([row["headers"]["From"]]); sender = addresses[0][1].lower() if addresses else ""
                    counts[sender or row["headers"]["From"]] += 1
            return {"ok": True, "folder": folder, "uidvalidity": validity, "total_matches": len(found),
                    "scanned": sum(counts.values()), "truncated": len(found) > scan_limit,
                    "senders": [{"sender": k, "count": v} for k, v in counts.most_common(top)]}

    @operation()
    def find_duplicate_messages(folder: str = "INBOX", since: str = "", scan_limit: int = 500) -> dict[str, Any]:
        """Кандидаты в дубли по Message-ID и размеру в ограниченной выборке; ничего не удаляет."""
        bounded(scan_limit, 1, MAX_SCAN)
        with api.connection(cfg) as c:
            validity = selected(c, folder); found = sorted(c.search(criteria({"since": since}) if since else ["ALL"], charset="UTF-8"), reverse=True)
            groups = {}
            for start in range(0, min(len(found), scan_limit), MAX_BATCH):
                for row in row_headers(c, found[start:min(start+MAX_BATCH, scan_limit)]):
                    mid = row["headers"]["Message-ID"].strip()
                    if mid: groups.setdefault((mid, row["size"]), []).append(row["uid"])
            return {"ok": True, "folder": folder, "uidvalidity": validity, "scanned": min(len(found), scan_limit),
                    "truncated": len(found) > scan_limit, "groups": [{"message_id": k[0], "size": k[1], "uids": v} for k, v in groups.items() if len(v) > 1],
                    "note": "Совпадение заголовков не является доказательством идентичности тела."}

    @operation(write=True)
    def set_message_flags(uid: int, uidvalidity: int, add: list[str] | None = None, remove: list[str] | None = None, folder: str = "INBOX") -> dict[str, Any]:
        """Добавить/снять только безопасные системные флаги; остальные флаги сохраняются."""
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, True)
            return change_flags(c, [api.positive(uid)], add or [], remove or [])

    def flag_tool(name, doc, flag, enabled):
        def fn(uid: int, uidvalidity: int, folder: str = "INBOX") -> dict[str, Any]:
            with api.connection(cfg) as c:
                selected(c, folder, uidvalidity, True)
                return change_flags(c, [api.positive(uid)], [flag] if enabled else [], [] if enabled else [flag])
        fn.__name__ = name; fn.__doc__ = doc
        operation(write=True)(fn)

    for name, doc, flag, enabled in [
        ("mark_unread", "Пометить письмо непрочитанным, сохраняя остальные флаги.", "\\Seen", False),
        ("mark_flagged", "Пометить письмо важным стандартным флагом Flagged.", "\\Flagged", True),
        ("mark_unflagged", "Снять стандартный флаг важного письма.", "\\Flagged", False),
        ("mark_answered", "Пометить письмо отвеченным; не отправляет ответ.", "\\Answered", True),
        ("mark_unanswered", "Снять пометку отвеченного письма.", "\\Answered", False),
    ]:
        flag_tool(name, doc, flag, enabled)

    @operation(write=True)
    def bulk_set_flags(message_uids: list[int], uidvalidity: int, add: list[str] | None = None, remove: list[str] | None = None, folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Изменить безопасные флаги до 100 писем. По умолчанию dry_run; результат проверяется чтением флагов."""
        values = uids(message_uids); add = add or []; remove = remove or []
        if not add and not remove or set(add) & set(remove) or not set(add + remove) <= SAFE_FLAGS:
            raise error("Недопустимые флаги.")
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, not dry_run); present(c, values)
            return {"ok": True, "dry_run": True, "uids": values, "add": add, "remove": remove} if dry_run else change_flags(c, values, add, remove)

    @operation(write=True)
    def copy_message(uid: int, uidvalidity: int, destination: str, folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Скопировать письмо, сохранив исходник. По умолчанию dry_run; повтор может создать дубль."""
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, not dry_run)
            return batch_transfer(c, [api.positive(uid)], folder, destination, False, dry_run)

    @operation(write=True)
    def bulk_copy_messages(message_uids: list[int], uidvalidity: int, destination: str, folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Скопировать до 100 писем; исходники остаются; dry_run по умолчанию."""
        values = uids(message_uids)
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, not dry_run)
            return batch_transfer(c, values, folder, destination, False, dry_run)

    @operation(write=True)
    def bulk_move_messages(message_uids: list[int], uidvalidity: int, destination: str, folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Переместить до 100 писем только UID MOVE; Корзина и её подпапки запрещены; dry_run по умолчанию."""
        values = uids(message_uids)
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, not dry_run)
            return batch_transfer(c, values, folder, destination, True, dry_run)

    @operation(write=True)
    def bulk_archive_messages(message_uids: list[int], uidvalidity: int, folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Переместить до 100 писем в настроенный существующий архив; dry_run по умолчанию."""
        values = uids(message_uids)
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, not dry_run)
            return batch_transfer(c, values, folder, cfg.archive, True, dry_run)

    @operation()
    def list_labels() -> dict[str, Any]:
        """Список IMAP-тегов каталога MCP, не список цветных меток веб-почты Яндекса."""
        return {"ok": True, "labels": catalog(), **label_note()}

    @operation(write=True)
    def create_label(name: str) -> dict[str, Any]:
        """Идемпотентно создать именованный IMAP-тег MCP. Это не нативная цветная метка Яндекса."""
        name = safe_text(name, 128).strip()
        if not name:
            raise error("Имя метки обязательно.")
        ident = uuid.uuid4().hex
        with db() as d:
            d.execute("INSERT OR IGNORE INTO labels(id,name,keyword) VALUES(?,?,?)", (ident, name, "mcp_" + ident))
            row = d.execute("SELECT id,name,keyword FROM labels WHERE name=?", (name,)).fetchone()
        return {"ok": True, "label": dict(zip(["id", "name", "keyword"], row)), "created": row[0] == ident, **label_note()}

    @operation(write=True)
    def rename_label(label_id: str, new_name: str) -> dict[str, Any]:
        """Переименовать IMAP-тег в каталоге MCP; стабильный keyword и метки писем сохраняются."""
        label_rows([label_id]); name = safe_text(new_name, 128).strip()
        if not name:
            raise error("Имя обязательно.")
        with db() as d:
            other = d.execute("SELECT id FROM labels WHERE name=?", (name,)).fetchone()
            if other and other[0] != label_id:
                raise error("Метка с таким именем уже существует.")
            d.execute("UPDATE labels SET name=? WHERE id=?", (name, label_id))
        return {"ok": True, "label_id": label_id, "name": name, **label_note()}

    def labels_change(message_uids, uidvalidity, label_ids, folder, add, dry_run):
        values = uids(message_uids); rows = label_rows(label_ids); keywords = [x["keyword"] for x in rows]
        with api.connection(cfg) as c:
            selected(c, folder, uidvalidity, not dry_run); present(c, values)
            meta = c.select_folder(folder, readonly=dry_run)
            if int(meta[b"UIDVALIDITY"]) != uidvalidity:
                raise error("UIDVALIDITY изменился; запись отменена.")
            permanent = {api.text(x) for x in meta.get(b"PERMANENTFLAGS", ())}
            if add and not ({"\\*", "\\\\*"} & permanent) and not set(keywords) <= permanent:
                raise error("IMAP не разрешает пользовательские теги.")
            if not dry_run:
                (c.add_flags if add else c.remove_flags)(values, keywords)
                actual = c.get_flags(values)
                for uid in values:
                    flags = {api.text(x) for x in actual.get(uid, ())}
                    if uid not in actual or (add and not set(keywords) <= flags) or (not add and set(keywords) & flags):
                        raise error("IMAP-теги не подтверждены сервером; проверьте состояние перед повтором.")
        return {"ok": True, "dry_run": dry_run, "uids": values, "labels": rows, "action": "add" if add else "remove", **label_note()}

    @operation(write=True)
    def apply_labels(message_uids: list[int], uidvalidity: int, label_ids: list[str], folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Добавить IMAP-теги до 100 писем, сохранив остальные флаги; dry_run по умолчанию; не нативные метки Яндекса."""
        return labels_change(message_uids, uidvalidity, label_ids, folder, True, dry_run)

    @operation(write=True)
    def remove_labels(message_uids: list[int], uidvalidity: int, label_ids: list[str], folder: str = "INBOX", dry_run: bool = True) -> dict[str, Any]:
        """Снять только указанные IMAP-теги MCP; остальные флаги сохраняются; dry_run по умолчанию."""
        return labels_change(message_uids, uidvalidity, label_ids, folder, False, dry_run)

    @operation()
    def get_message_labels(uid: int, folder: str = "INBOX", uidvalidity: int | None = None) -> dict[str, Any]:
        """Прочитать IMAP-теги письма и сопоставить с каталогом MCP; не веб-метки Яндекса."""
        with api.connection(cfg) as c:
            validity = selected(c, folder, uidvalidity); row = api.existing(c, uid)
            flags = {api.text(x) for x in row.get(b"FLAGS", ())}
        return {"ok": True, "uid": uid, "uidvalidity": validity, "folder": folder,
                "labels": [x for x in catalog() if x["keyword"] in flags], **label_note()}

    @operation()
    def search_by_label(label_id: str, folder: str = "INBOX", limit: int = 20, offset: int = 0) -> dict[str, Any]:
        """Поиск по IMAP-тегу каталога MCP, без загрузки всех писем."""
        bounded(limit, 1, 100); bounded(offset, 0, 200000); row = label_rows([label_id])[0]
        with api.connection(cfg) as c:
            validity = selected(c, folder); found = sorted(c.search(["KEYWORD", row["keyword"]], charset="UTF-8"), reverse=True)
            return {"ok": True, "folder": folder, "uidvalidity": validity, "total": len(found),
                    "messages": row_headers(c, found[offset:offset+limit]), "next_offset": offset+limit if offset+limit < len(found) else None,
                    **label_note()}
