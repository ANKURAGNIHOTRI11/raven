-- Three sources the crawler logged as healthy harvests of 0 records for days,
-- found with deploy/diagnose_feeds.py. All three served an HTML page with HTTP
-- 200, so nothing in the registry ever showed a failure.
--
--   mandiant     URL was a guess and returns the blog's HTML page, not a feed.
--   msrc_blog    msrc.microsoft.com/blog/feed now redirects to an HTML page.
--   packetstorm  redirects to a terms-of-service acceptance page before serving
--                RSS. Not worked around - re-enable only if the terms are
--                accepted deliberately and a stable feed URL is confirmed.
--
-- No verified replacement URLs. Microsoft coverage should come from the MSRC
-- CVRF/CSAF API (the 'msrc' source), not the blog.
--
--   docker compose exec -T postgres psql -U raven raven < infra/postgres/migrations/005_disable_non_feeds.sql

UPDATE sources
   SET enabled = false,
       last_error = 'disabled: URL serves an HTML page, not a feed (see migration 005)'
 WHERE source_id IN ('mandiant', 'msrc_blog', 'packetstorm');
