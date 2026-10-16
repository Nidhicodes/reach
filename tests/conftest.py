import os

# Tests never call a real LLM; keep .env out of the test process.
os.environ["REACH_NO_DOTENV"] = "1"
