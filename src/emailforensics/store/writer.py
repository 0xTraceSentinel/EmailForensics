from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from emailforensics.blobs import BlobStore
from emailforensics.ingest.parse import ParsedMessage


def start_run(conn: psycopg.Connection, tool_version: str, argv: list[str], custodian: str | None) -> int:
    return conn.execute(
        "INSERT INTO ingest_run (tool_version, argv, custodian) VALUES (%s, %s, %s) RETURNING id",
        (tool_version, Jsonb(argv), custodian),
    ).fetchone()[0]


def finish_run(conn: psycopg.Connection, run_id: int, errors: list[dict]) -> None:
    conn.execute(
        "UPDATE ingest_run SET finished_at = now(), status = %s, errors = %s WHERE id = %s",
        ("completed_with_errors" if errors else "completed", Jsonb(errors), run_id),
    )


def source_exists(conn: psycopg.Connection, sha256: str) -> bool:
    return conn.execute("SELECT 1 FROM source_file WHERE sha256 = %s", (sha256,)).fetchone() is not None


def insert_source(
    conn: psycopg.Connection, run_id: int, path: Path, fmt: str, sha256: str, custodian: str | None
) -> int:
    return conn.execute(
        "INSERT INTO source_file (run_id, path, file_name, format, size_bytes, sha256, custodian)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (run_id, str(path.resolve()), path.name, fmt, path.stat().st_size, sha256, custodian),
    ).fetchone()[0]


@dataclass
class NewMessage:
    item_path: str
    sha256: str
    msg: ParsedMessage
    byte_offset: int | None = None
    byte_length: int | None = None
    envelope_from: str | None = None
    folder_path: list[str] | None = None
    item_state: str | None = None


def payload_bytes(msg: ParsedMessage) -> int:
    n = len(msg.body_text or "") + len(msg.body_html or "") + sum(a.size for a in msg.attachments)
    return n + sum(payload_bytes(child) for _, child in msg.children)


_MESSAGE_COLUMNS = (
    "id", "source_file_id", "parent_id", "item_path", "byte_offset", "byte_length", "sha256", "envelope_from",
    "rfc_message_id", "in_reply_to", "refs", "subject",
    "from_addr", "sender_addr", "to_addrs", "cc_addrs", "bcc_addrs", "reply_to",
    "date_raw", "date_utc", "date_offset_minutes", "headers", "body_text", "body_html", "parse_defects",
    "hash_basis", "folder_path", "item_state", "message_class",
    "client_submit_time", "delivery_time", "creation_time", "last_modification_time", "last_modifier_name",
    "sent_representing", "conversation_index", "conversation_topic", "mapi_recipients", "mapi_props",
)

_ATTACHMENT_COLUMNS = (
    "msg_id", "mime_path", "filename", "content_type", "content_disposition",
    "content_id", "size_bytes", "sha256", "mapi_props",
)

_MAX_PARAMS = 65535


def _insert_rows(cur: psycopg.Cursor, table: str, columns: tuple[str, ...], rows: list[tuple]) -> None:
    head = f"INSERT INTO {table} ({', '.join(columns)}) VALUES "
    one = "(" + ", ".join(["%s"] * len(columns)) + ")"
    step = _MAX_PARAMS // len(columns)
    for i in range(0, len(rows), step):
        chunk = rows[i : i + step]
        cur.execute(head + ", ".join([one] * len(chunk)), [v for row in chunk for v in row])


def _flatten(item: NewMessage, parent: int | None, out: list[tuple[NewMessage, int | None]]) -> None:
    index = len(out)
    out.append((item, parent))
    kind = "att" if item.msg.mapi else "rfc822"
    for mime_path, child in item.msg.children:
        _flatten(NewMessage(f"{item.item_path}/{kind}:{mime_path}", child.sha256, child), index, out)


def _message_row(msg_id: int, parent_id: int | None, source_file_id: int, item: NewMessage) -> tuple:
    msg, mapi = item.msg, item.msg.mapi
    return (
        msg_id, source_file_id, parent_id, item.item_path, item.byte_offset, item.byte_length, item.sha256,
        item.envelope_from,
        msg.rfc_message_id, msg.in_reply_to, msg.references, msg.subject,
        Jsonb(msg.from_addr), Jsonb(msg.sender_addr), Jsonb(msg.to_addrs),
        Jsonb(msg.cc_addrs), Jsonb(msg.bcc_addrs), Jsonb(msg.reply_to),
        msg.date_raw, msg.date_utc, msg.date_offset_minutes,
        Jsonb([{"name": n, "value": v} for n, v in msg.headers]),
        msg.body_text, msg.body_html, Jsonb(msg.defects),
        "mapi" if mapi else "raw", item.folder_path, item.item_state, mapi and mapi.message_class,
        mapi and mapi.client_submit_time, mapi and mapi.delivery_time,
        mapi and mapi.creation_time, mapi and mapi.last_modification_time, mapi and mapi.last_modifier_name,
        Jsonb(mapi.sent_representing if mapi else []), mapi and mapi.conversation_index,
        mapi and mapi.conversation_topic,
        Jsonb(mapi.recipients) if mapi else None, Jsonb(mapi.props) if mapi else None,
    )


def insert_messages(
    conn: psycopg.Connection, blobs: BlobStore, source_file_id: int, items: list[NewMessage]
) -> tuple[int, int]:
    flat: list[tuple[NewMessage, int | None]] = []
    for item in items:
        _flatten(item, None, flat)
    if not flat:
        return 0, 0
    ids = [
        r[0]
        for r in conn.execute(
            "SELECT nextval(pg_get_serial_sequence('message', 'id')) AS id"
            " FROM generate_series(1, %s) ORDER BY id",
            (len(flat),),
        )
    ]
    message_rows = []
    attachment_rows = []
    for (item, parent), msg_id in zip(flat, ids):
        message_rows.append(_message_row(msg_id, ids[parent] if parent is not None else None, source_file_id, item))
        for a in item.msg.attachments:
            attachment_rows.append(
                (
                    msg_id, a.mime_path, a.filename, a.content_type, a.disposition, a.content_id, a.size,
                    a.sha256, Jsonb(a.mapi_props) if a.mapi_props is not None else None,
                )
            )
    with conn.cursor() as cur:
        _insert_rows(cur, "message", _MESSAGE_COLUMNS, message_rows)
        for item, _ in flat:
            for a in item.msg.attachments:
                blobs.put(a.sha256, a.data)
        if attachment_rows:
            _insert_rows(cur, "attachment", _ATTACHMENT_COLUMNS, attachment_rows)
    return len(flat), len(attachment_rows)


def insert_message(
    conn: psycopg.Connection,
    blobs: BlobStore,
    source_file_id: int,
    item_path: str,
    sha256: str,
    msg: ParsedMessage,
    **fields,
) -> tuple[int, int]:
    return insert_messages(conn, blobs, source_file_id, [NewMessage(item_path, sha256, msg, **fields)])
