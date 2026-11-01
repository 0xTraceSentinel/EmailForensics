ALTER TABLE source_file DROP CONSTRAINT source_file_format_check;
ALTER TABLE source_file ADD CONSTRAINT source_file_format_check
    CHECK (format IN ('eml', 'mbox', 'pst', 'ost', 'msg'));

ALTER TABLE message
    ADD COLUMN hash_basis             text        NOT NULL DEFAULT 'raw' CHECK (hash_basis IN ('raw', 'mapi')),
    ADD COLUMN folder_path            text[],
    ADD COLUMN item_state             text        CHECK (item_state IN ('live', 'recoverable', 'orphan')),
    ADD COLUMN message_class          text,
    ADD COLUMN client_submit_time     timestamptz,
    ADD COLUMN delivery_time          timestamptz,
    ADD COLUMN creation_time          timestamptz,
    ADD COLUMN last_modification_time timestamptz,
    ADD COLUMN last_modifier_name     text,
    ADD COLUMN sent_representing      jsonb       NOT NULL DEFAULT '[]',
    ADD COLUMN conversation_index     bytea,
    ADD COLUMN conversation_topic     text,
    ADD COLUMN mapi_recipients        jsonb,
    ADD COLUMN mapi_props             jsonb;

CREATE INDEX message_folder_path_idx   ON message USING gin (folder_path);
CREATE INDEX message_item_state_idx    ON message (item_state);
CREATE INDEX message_message_class_idx ON message (message_class);
CREATE INDEX message_creation_time_idx ON message (creation_time);

ALTER TABLE attachment ADD COLUMN mapi_props jsonb;
