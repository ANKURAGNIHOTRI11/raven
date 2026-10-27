BEGIN;

-- Fail rather than wait indefinitely if the table is busy.
SET LOCAL lock_timeout = '5s';

-- Permit multiple parsed records to reference the same fetched payload.
ALTER TABLE public.raw_documents
    DROP CONSTRAINT IF EXISTS
    raw_documents_source_id_content_sha256_key;

-- Retain efficient lookup by source and payload hash without
-- incorrectly enforcing one row per fetched payload.
CREATE INDEX IF NOT EXISTS raw_documents_source_content_sha256_idx
    ON public.raw_documents (source_id, content_sha256);

COMMIT;
