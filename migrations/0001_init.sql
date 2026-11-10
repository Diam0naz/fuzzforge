-- Fuzzforge v1 schema.
--
-- Jobs carry their own opaque bearer token hash. There are no accounts in v1:
-- the link handed back at submission is the only way to read a job.

CREATE TABLE IF NOT EXISTS jobs (
    id               uuid PRIMARY KEY,
    status           text NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'running', 'done', 'failed')),
    token_hash       text NOT NULL UNIQUE,

    bundle_path      text NOT NULL,
    bundle_sha256    text NOT NULL,
    bundle_bytes     bigint NOT NULL,

    invariant_spec   text NOT NULL DEFAULT '',
    contact_email    text,

    worker_id        text,
    attempts         integer NOT NULL DEFAULT 0,

    executions       bigint,
    failure_count    integer,
    report_md        text,
    report_json      jsonb,
    error            text,

    created_at       timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz
);

-- Queue scan. Partial indexes keep these tiny as finished jobs accumulate.
CREATE INDEX IF NOT EXISTS jobs_queued_idx
    ON jobs (created_at)
    WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS jobs_running_idx
    ON jobs (started_at)
    WHERE status = 'running';

CREATE INDEX IF NOT EXISTS jobs_bundle_idx
    ON jobs (bundle_sha256);
