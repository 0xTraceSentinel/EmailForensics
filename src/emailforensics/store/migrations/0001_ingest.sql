CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE ingest_run (
    id           bigserial PRIMARY KEY,
    tool_version text        NOT NULL,
    argv         jsonb       NOT NULL,
    custodian    text,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text        NOT NULL DEFAULT 'running',
    errors       jsonb       NOT NULL DEFAULT '[]'
);

CREATE TABLE source_file (
    id           bigserial PRIMARY KEY,
    run_id       bigint      NOT NULL REFERENCES ingest_run(id),
    path         text        NOT NULL,
    file_name    text        NOT NULL,
    format       text        NOT NULL CHECK (format IN ('eml', 'mbox')),
    size_bytes   bigint      NOT NULL,
    sha256       char(64)    NOT NULL UNIQUE,
    custodian    text,
    ingested_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE message (
    id                  bigserial PRIMARY KEY,
    source_file_id      bigint   NOT NULL REFERENCES source_file(id),
    parent_id           bigint   REFERENCES message(id),
    item_path           text     NOT NULL,
    byte_offset         bigint,
    byte_length         bigint,
    sha256              char(64) NOT NULL,
    envelope_from       text,
    rfc_message_id      text,
    in_reply_to         text,
    refs                text[]   NOT NULL DEFAULT '{}',
    subject             text,
    from_addr           jsonb    NOT NULL DEFAULT '[]',
    sender_addr         jsonb    NOT NULL DEFAULT '[]',
    to_addrs            jsonb    NOT NULL DEFAULT '[]',
    cc_addrs            jsonb    NOT NULL DEFAULT '[]',
    bcc_addrs           jsonb    NOT NULL DEFAULT '[]',
    reply_to            jsonb    NOT NULL DEFAULT '[]',
    date_raw            text,
    date_utc            timestamptz,
    date_offset_minutes integer,
    headers             jsonb    NOT NULL,
    body_text           text,
    body_html           text,
    parse_defects       jsonb    NOT NULL DEFAULT '[]',
    body_tsv            tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', coalesce(subject, '') || ' ' || coalesce(body_text, ''))
    ) STORED,
    UNIQUE (source_file_id, item_path)
);

CREATE INDEX message_rfc_message_id_idx ON message (rfc_message_id);
CREATE INDEX message_in_reply_to_idx    ON message (in_reply_to);
CREATE INDEX message_sha256_idx         ON message (sha256);
CREATE INDEX message_date_utc_idx       ON message (date_utc);
CREATE INDEX message_body_tsv_idx       ON message USING gin (body_tsv);
CREATE INDEX message_subject_trgm_idx   ON message USING gin (subject gin_trgm_ops);

CREATE TABLE attachment (
    id                  bigserial PRIMARY KEY,
    msg_id              bigint   NOT NULL REFERENCES message(id),
    mime_path           text     NOT NULL,
    filename            text,
    content_type        text     NOT NULL,
    content_disposition text,
    content_id          text,
    size_bytes          bigint   NOT NULL,
    sha256              char(64) NOT NULL,
    UNIQUE (msg_id, mime_path)
);

CREATE INDEX attachment_sha256_idx ON attachment (sha256);
