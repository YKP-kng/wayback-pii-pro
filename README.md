# WaybackBlueApp Streamlit

## Local run
```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Local API key
Create `.streamlit/secrets.toml`:
```toml
APP_KEYS = ["your-key-here"]
```

If no APP_KEYS are configured, the app runs in local dev mode.

## Deploy to Streamlit Cloud
1. Create a GitHub repo.
2. Upload:
   - streamlit_app.py
   - requirements.txt
   - .streamlit/secrets.toml.example
3. In Streamlit Cloud, create a new app from the repo.
4. Add secrets:
```toml
APP_KEYS = ["key-for-you", "key-for-friend"]
```
5. Share the Streamlit app URL and the relevant key.
