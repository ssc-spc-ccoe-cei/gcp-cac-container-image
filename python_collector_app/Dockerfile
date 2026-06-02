FROM cgr.dev/chainguard/python:latest-dev AS python-build

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_NO_CACHE_DIR=1 \
  PATH="/app/venv/bin:$PATH"

WORKDIR /app

COPY requirements.txt ./
RUN python -m venv /app/venv && \
  pip install --no-cache-dir -r requirements.txt

FROM cgr.dev/chainguard/python:latest

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PORT=8080 \
  PATH="/app/venv/bin:${PATH}"

COPY --from=python-build /app/venv /app/venv
COPY ["app.py", "generate_reports.py", "guardrail_manifest.json", "/app/"]

EXPOSE 8080

ENTRYPOINT ["python", "app.py"]
