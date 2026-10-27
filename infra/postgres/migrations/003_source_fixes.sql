-- Sources that cannot work without extra credentials or are blocked upstream.
-- Idempotent: safe to run on every start.
UPDATE sources
   SET enabled = false,
       last_error = 'disabled: needs credentials or blocked upstream'
 WHERE source_id IN ('cisco', 'cisa_ics', 'cisa_advisories')
   AND enabled;
