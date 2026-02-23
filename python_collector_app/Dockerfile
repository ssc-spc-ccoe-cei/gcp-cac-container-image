ARG CLOUD_SDK_VERSION=556.0.0
ARG PYTHON_VERSION=3.12.12
ARG ALPINE_VERSION=3.21

FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION} AS python-build
COPY ["app.py", "requirements.txt", "./"]
RUN apk add  --no-cache --virtual .build-deps gcc musl-dev  make automake gcc g++ subversion python3-dev libstdc++ 

RUN pip install --upgrade pip setuptools wheel pyinstaller && \
    pip install --no-cache-dir -r requirements.txt && \
    pyinstaller app.py --onefile -s -n cac-app && \
    apk del .build-deps gcc musl-dev  make automake gcc g++ subversion python3-dev libstdc++ && \
    pip uninstall -r requirements.txt -y

FROM gcr.io/google.com/cloudsdktool/cloud-sdk:${CLOUD_SDK_VERSION}-alpine

RUN addgroup  cac-user \
    && adduser cac-user -D -G cac-user  \
    && mkdir app && chown cac-user:cac-user app

WORKDIR /app

COPY --from=python-build --chown=cac-user /dist/cac-app .

USER cac-user
ENV PORT=8080
CMD [ "/app/cac-app"]
