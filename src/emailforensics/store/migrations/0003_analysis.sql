CREATE TABLE person (
    id        text    PRIMARY KEY,
    name      text,
    names     text[]  NOT NULL DEFAULT '{}',
    base      text,
    role      text,
    board     boolean NOT NULL DEFAULT false,
    custodian boolean NOT NULL DEFAULT false,
    loaded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE person_address (
    address   text PRIMARY KEY,
    person_id text NOT NULL REFERENCES person(id) ON DELETE CASCADE
);

CREATE TABLE decision (
    id             text PRIMARY KEY,
    title          text NOT NULL,
    formal_date    date,
    formal_place   text,
    formal_country text,
    source         text,
    terms          text[] NOT NULL DEFAULT '{}',
    window_start   date,
    window_end     date,
    loaded_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE analysis_run (
    id             bigserial   PRIMARY KEY,
    tool_version   text        NOT NULL,
    argv           jsonb       NOT NULL,
    config         jsonb       NOT NULL,
    config_sha256  char(64)    NOT NULL,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    status         text        NOT NULL DEFAULT 'running',
    stats          jsonb       NOT NULL DEFAULT '{}'
);

CREATE TABLE message_analysis (
    msg_id            bigint  PRIMARY KEY REFERENCES message(id),
    run_id            bigint  NOT NULL REFERENCES analysis_run(id),
    thread_key        text,
    sender_address    text,
    sender_person     text,
    custodian_sent    boolean NOT NULL DEFAULT false,
    sent_utc          timestamptz,
    authored_text     text,
    roles             text[]  NOT NULL DEFAULT '{}',
    phrases           jsonb   NOT NULL DEFAULT '{}',
    questions         integer NOT NULL DEFAULT 0,
    client            text,
    mobile            boolean NOT NULL DEFAULT false,
    client_ips        jsonb   NOT NULL DEFAULT '[]',
    offset_minutes    integer,
    offset_method     text,
    offset_detail     jsonb,
    place             text,
    place_method      text,
    place_strength    text,
    thread_index      jsonb
);

CREATE INDEX message_analysis_thread_idx ON message_analysis (thread_key);
CREATE INDEX message_analysis_sender_idx ON message_analysis (sender_person);

CREATE TABLE location_evidence (
    id          bigserial   PRIMARY KEY,
    run_id      bigint      NOT NULL REFERENCES analysis_run(id),
    person_id   text,
    msg_id      bigint      REFERENCES message(id),
    method      text        NOT NULL,
    place       text,
    start_utc   timestamptz NOT NULL,
    end_utc     timestamptz NOT NULL,
    strength    text        NOT NULL CHECK (strength IN ('strong', 'moderate', 'weak')),
    detail      jsonb       NOT NULL DEFAULT '{}'
);

CREATE INDEX location_evidence_person_idx ON location_evidence (person_id, start_utc);

CREATE TABLE attachment_meta (
    sha256          char(64) PRIMARY KEY,
    run_id          bigint   NOT NULL REFERENCES analysis_run(id),
    kind            text     NOT NULL,
    title           text,
    author          text,
    last_modified_by text,
    company         text,
    application     text,
    template        text,
    created         timestamptz,
    created_offset  integer,
    modified        timestamptz,
    modified_offset integer,
    editors         jsonb    NOT NULL DEFAULT '[]',
    esign           jsonb,
    ips             jsonb    NOT NULL DEFAULT '[]',
    places          text[]   NOT NULL DEFAULT '{}',
    detail          jsonb    NOT NULL DEFAULT '{}'
);

CREATE TABLE decision_message (
    decision_id text   NOT NULL REFERENCES decision(id) ON DELETE CASCADE,
    msg_id      bigint NOT NULL REFERENCES message(id),
    reasons     text[] NOT NULL,
    PRIMARY KEY (decision_id, msg_id)
);

CREATE TABLE sendtime_week (
    person_id        text    NOT NULL,
    week_start       date    NOT NULL,
    days             integer NOT NULL,
    messages         integer NOT NULL,
    median_first_min integer NOT NULL,
    median_last_min  integer NOT NULL,
    shift_min        integer,
    place            text,
    PRIMARY KEY (person_id, week_start)
);

CREATE TABLE anomaly (
    id          bigserial   PRIMARY KEY,
    run_id      bigint      NOT NULL REFERENCES analysis_run(id),
    kind        text        NOT NULL,
    decision_id text,
    msg_id      bigint,
    sha256      char(64),
    at_utc      timestamptz,
    detail      jsonb       NOT NULL DEFAULT '{}'
);

CREATE TABLE review_item (
    id          bigserial PRIMARY KEY,
    run_id      bigint    NOT NULL REFERENCES analysis_run(id),
    reason      text      NOT NULL,
    decision_id text,
    msg_id      bigint,
    sha256      char(64),
    detail      jsonb     NOT NULL DEFAULT '{}'
);
