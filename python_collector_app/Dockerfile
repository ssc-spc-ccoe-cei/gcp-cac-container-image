FROM cgr.dev/chainguard/python:latest-dev AS python-build

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_NO_CACHE_DIR=1 \
  PATH="/home/nonroot/venv/bin:$PATH"

WORKDIR /home/nonroot

COPY --chown=nonroot:nonroot requirements.txt ./
RUN python -m venv /home/nonroot/venv && \
  pip install --no-cache-dir -r requirements.txt

FROM cgr.dev/chainguard/python:latest

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PORT=8080 \
  PATH="/home/nonroot/venv/bin:${PATH}"

WORKDIR /home/nonroot

COPY --from=python-build --chown=nonroot:nonroot /home/nonroot/venv /home/nonroot/venv
COPY --chown=nonroot:nonroot ["app.py", "generate_reports.py", "guardrail_manifest.json", "./"]

EXPOSE 8080

ENTRYPOINT ["python", "app.py"]
