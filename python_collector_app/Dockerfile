FROM cgr.dev/chainguard/python:latest-dev AS python-build

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_NO_CACHE_DIR=1 \
  PATH="/home/nonroot/app/venv/bin:$PATH"

WORKDIR /home/nonroot/app

COPY requirements.txt ./
RUN python -m venv /home/nonroot/app/venv && \
  pip install --no-cache-dir -r requirements.txt

FROM cgr.dev/chainguard/python:latest

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PORT=8080 \
  PATH="/home/nonroot/app/venv/bin:${PATH}"

WORKDIR /home/nonroot/app

COPY --from=python-build /home/nonroot/app/venv /home/nonroot/app/venv
COPY ["app.py", "generate_reports.py", "guardrail_manifest.json", "./"]

EXPOSE 8080

ENTRYPOINT ["python", "app.py"]
