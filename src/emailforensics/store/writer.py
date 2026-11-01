from __future__ import annotations

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


def insert_message(
    conn: psycopg.Connection,
    blobs: BlobStore,
    source_file_id: int,
    item_path: str,
    sha256: str,
    msg: ParsedMessage,
    *,
    byte_offset: int | None = None,
    byte_length: int | None = None,
    envelope_from: str | None = None,
    parent_id: int | None = None,
    folder_path: list[str] | None = None,
    item_state: str | None = None,
) -> tuple[int, int]:
    mapi = msg.mapi
    msg_id = conn.execute(
        """
        INSERT INTO message (
            source_file_id, parent_id, item_path, byte_offset, byte_length, sha256, envelope_from,
            rfc_message_id, in_reply_to, refs, subject,
            from_addr, sender_addr, to_addrs, cc_addrs, bcc_addrs, reply_to,
            date_raw, date_utc, date_offset_minutes, headers, body_text, body_html, parse_defects,
            hash_basis, folder_path, item_state, message_class,
            client_submit_time, delivery_time, creation_time, last_modification_time, last_modifier_name,
            sent_representing, conversation_index, conversation_topic, mapi_recipients, mapi_props
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s
        ) RETURNING id
        """,
        (
            source_file_id, parent_id, item_path, byte_offset, byte_length, sha256, envelope_from,
            msg.rfc_message_id, msg.in_reply_to, msg.references, msg.subject,
            Jsonb(msg.from_addr), Jsonb(msg.sender_addr), Jsonb(msg.to_addrs),
            Jsonb(msg.cc_addrs), Jsonb(msg.bcc_addrs), Jsonb(msg.reply_to),
            msg.date_raw, msg.date_utc, msg.date_offset_minutes,
            Jsonb([{"name": n, "value": v} for n, v in msg.headers]),
            msg.body_text, msg.body_html, Jsonb(msg.defects),
            "mapi" if mapi else "raw", folder_path, item_state, mapi and mapi.message_class,
            mapi and mapi.client_submit_time, mapi and mapi.delivery_time,
            mapi and mapi.creation_time, mapi and mapi.last_modification_time, mapi and mapi.last_modifier_name,
            Jsonb(mapi.sent_representing if mapi else []), mapi and mapi.conversation_index,
            mapi and mapi.conversation_topic,
            Jsonb(mapi.recipients) if mapi else None, Jsonb(mapi.props) if mapi else None,
        ),
    ).fetchone()[0]

    for att in msg.attachments:
        blobs.put(att.sha256, att.data)
    if msg.attachments:
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO attachment (msg_id, mime_path, filename, content_type, content_disposition,"
                " content_id, size_bytes, sha256, mapi_props) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    (
                        msg_id, a.mime_path, a.filename, a.content_type, a.disposition, a.content_id, a.size,
                        a.sha256, Jsonb(a.mapi_props) if a.mapi_props is not None else None,
                    )
                    for a in msg.attachments
                ],
            )

    n_msgs, n_atts = 1, len(msg.attachments)
    kind = "att" if mapi else "rfc822"
    for mime_path, child in msg.children:
        m, a = insert_message(
            conn, blobs, source_file_id, f"{item_path}/{kind}:{mime_path}", child.sha256, child,
            parent_id=msg_id,
        )
        n_msgs += m
        n_atts += a
    return n_msgs, n_atts
