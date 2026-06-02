import os

# Set API_BASE_URL in env or .streamlit/secrets.toml — no blocking probe at import.
API_BASE_URL = (os.getenv("API_BASE_URL") or "http://127.0.0.1:8000").strip().rstrip("/")
