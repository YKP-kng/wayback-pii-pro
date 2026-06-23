# WaybackBlueApp Streamlit - Bulk Excel Edition

New features:
- Automatic fallback URL-index search when direct captures return zero
- Bulk PII extraction on visible rows
- Excel export with sheets: captures, summary, pii_findings, errors

Deploy files:
- streamlit_app.py
- requirements.txt
- README.md
- .streamlit/secrets.toml.example

Secrets example:
```toml
APP_KEYS = ["your-key-here", "friend-key-here"]
```
