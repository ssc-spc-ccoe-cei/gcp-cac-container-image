ARG PYTHON_VERSION=3.14.10
ARG ALPINE_VERSION=3.24

FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION} AS python-build

ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PIP_NO_CACHE_DIR=1 \
VIRTUAL_ENV="/opt/venv" \
PATH="/opt/venv/bin:$PATH"

WORKDIR /build

COPY requirements.txt ./
RUN python -m venv "$VIRTUAL_ENV" && \
pip install -r requirements.txt && \
pip uninstall --yes pip setuptools

FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PORT=8080 \
VIRTUAL_ENV="/opt/venv" \
PATH="/opt/venv/bin:${PATH}"

RUN python -m pip uninstall --yes pip setuptools && \
addgroup -S -g 65532 nonroot && \
adduser -S -D -H -u 65532 -h /home/nonroot -G nonroot nonroot && \
mkdir -p /home/nonroot && \
chown nonroot:nonroot /home/nonroot

WORKDIR /home/nonroot

COPY --from=python-build --chown=nonroot:nonroot /opt/venv /opt/venv
COPY --chown=nonroot:nonroot ["app.py", "generate_reports.py", "guardrail_manifest.json", "./"]

EXPOSE 8080

USER nonroot

ENTRYPOINT ["python", "app.py"]

