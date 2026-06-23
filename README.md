# WaybackBlueApp Streamlit - Bulk Excel Edition

New features:
- Two-phase Wayback search that mirrors the actual web.archive.org UI behavior:
  1. **Exact match** on the target itself (`matchType=exact`) - same as a normal Wayback lookup.
  2. **Prefix fallback** (`matchType=prefix`), automatically triggered only when step 1 returns
     zero captures across all target variants - same as clicking "Click here to search for
     all archived pages under this URL prefix" on web.archive.org. This is what surfaces
     things like `twitter.com/<handle>/status/...` pages when the bare profile URL itself
     was never captured.
- CDX requests retry up to 3x on transient failures (timeouts, bad JSON, rate limits) before
  surfacing an error, and the UI distinguishes "fallback wasn't attempted" from
  "fallback ran and still found nothing" so a true zero-result case is never silently
  confused with a bug.
- Bulk PII extraction on visible rows (names, locations, organizations, social profiles,
  URLs, handles/hashtags, emails, phones, addresses, possible DOB) sourced from page text,
  meta tags, OpenGraph/Twitter Card tags, and JSON-LD.
- Excel export with sheets: `captures`, `summary`, `pii_findings`, `errors`.

Deploy files:
- streamlit_app.py
- requirements.txt
- README.md
- .streamlit/secrets.toml.example

Secrets example:
```toml
APP_KEYS = ["your-key-here", "friend-key-here"]
```

