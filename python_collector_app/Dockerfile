ARG PYTHON_VERSION=3.13
ARG DEBIAN_VERSION=trixie

FROM mirror.gcr.io/library/python:${PYTHON_VERSION}-slim-${DEBIAN_VERSION} AS python-build

ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PIP_NO_CACHE_DIR=1 \
VIRTUAL_ENV="/opt/venv" \
PATH="/opt/venv/bin:$PATH"

WORKDIR /build

COPY requirements.txt ./
RUN apt-get update && \
apt-get install --yes --no-install-recommends \
build-essential \
libffi-dev \
libssl-dev \
pkg-config && \
rm -rf /var/lib/apt/lists/* && \
ln -s /usr/local/bin/python /usr/bin/python && \
/usr/bin/python -m venv "$VIRTUAL_ENV" && \
pip install -r requirements.txt && \
pip uninstall --yes pip setuptools

FROM gcr.io/distroless/python3-debian13:nonroot

ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PORT=8080 \
VIRTUAL_ENV="/opt/venv" \
PATH="/opt/venv/bin:/usr/bin"

WORKDIR /app

COPY --from=python-build --chown=65532:65532 /opt/venv /opt/venv
COPY --chown=65532:65532 ["app.py", "generate_reports.py", "guardrail_manifest.json", "./"]

EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["/opt/venv/bin/python", "app.py"]
