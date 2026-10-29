# RAVEN agent rules
- Run `make check` before every commit; never commit with it failing.
- Never read or write `.env`, keys, or `raven_redhat_*` data files.
- Never run `docker compose down -v`, `make reset`, or anything that deletes volumes.
- Never push to `main`; work on `agent/*` branches only.
- Don't weaken policy gates (services/agents/policy.py), auth, or sandbox rules to make a test pass.
- Every bug fix needs a test. Keep diffs small; one concern per commit.
