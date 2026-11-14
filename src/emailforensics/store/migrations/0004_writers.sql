ALTER TABLE message_analysis
    ADD COLUMN writer           jsonb,
    ADD COLUMN fingerprint      text,
    ADD COLUMN clock_check      text,
    ADD COLUMN clock_skew_min   integer,
    ADD COLUMN offset_candidates jsonb;

CREATE INDEX message_analysis_fingerprint_idx ON message_analysis (fingerprint);
