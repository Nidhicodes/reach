# Reach web UI for a public demo host (Render, Hugging Face Spaces, Koyeb ...).
# The graph lives in FalkorDB Cloud when FALKORDB_HOST is set; otherwise the embedded
# FalkorDBLite engine is used (fine for one instance; data resets on redeploy).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1

# libgomp: FalkorDBLite's embedded module needs OpenMP
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && apt-get clean

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY reach ./reach
COPY examples ./examples
COPY data ./data
RUN uv sync --frozen --no-dev

RUN useradd --create-home reach && mkdir -p /app/state && chown reach /app/state
USER reach

# Public demo: synthetic data only, no auth by design; REACH_PUBLIC turns on the guards in
# reach/web.py. The container binds all interfaces so the platform's proxy can reach it;
# only the platform publishes the port.
ENV REACH_PUBLIC=1 REACH_HOST=0.0.0.0 PORT=7860 REACH_DB_PATH=/app/state/reach_ui.db \
    KIROCREW_SCRATCH=/app/state REACH_RESET_MINUTES=30 REACH_PUBLIC_LLM_PER_HOUR=0
EXPOSE 7860
CMD ["python", "-m", "reach.web"]
