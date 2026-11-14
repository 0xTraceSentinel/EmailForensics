ALTER TABLE source_file
    ADD COLUMN status        text     NOT NULL DEFAULT 'complete' CHECK (status IN ('in_progress', 'complete')),
    ADD COLUMN items_done    bigint   NOT NULL DEFAULT 0,
    ADD COLUMN item_errors   jsonb    NOT NULL DEFAULT '[]',
    ADD COLUMN resumed_runs  bigint[] NOT NULL DEFAULT '{}';

CREATE TABLE analysis_checkpoint (
    run_key        text   NOT NULL,
    scope          text   NOT NULL,
    item           text   NOT NULL,
    data           jsonb  NOT NULL,
    authored_text  text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_key, scope, item)
);
