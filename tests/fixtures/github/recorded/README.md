# Recorded fixtures

Real GitHub API responses from the owner's **own test org**, captured with:

```bash
export GITHUB_TOKEN=...   # read-only, test org only
agentsec run --org <TEST_ORG> --org-alias demo-org \
  --record tests/fixtures/github/recorded/<name>.json --out reports/
```

What the recorder does:

- Records only responses to the client's own GET requests; nothing extra is fetched.
- Keeps only the fields the checks read (`agentsec.recording.KEEP_KEYS`); drops URLs, emails, IDs.
- Replaces member logins with `user-N`; `--org-alias` replaces the org name.
- Never stores request headers (the token is not written).
- Merges paginated pages into one list per path.

Every `*.json` here is replayed by `tests/test_recording.py::test_recorded_fixtures_replay_cleanly`
in strict mode. If the catalog gains a check, re-record.

File contents are dropped except workflow files under `.github/workflows/` (needed by SC-01).
Before committing: review the diff and let the gitleaks pre-commit hook run.
