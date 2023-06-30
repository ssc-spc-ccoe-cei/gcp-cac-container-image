#update following for image update next time
FROM  python:3.11.4-alpine3.18 AS python-build
COPY ["app.py", "requirements.txt", "./"]
RUN apk add  --no-cache --virtual .build-deps gcc musl-dev  make automake gcc g++ subversion python3-dev libstdc++ 

RUN pip install --upgrade pip setuptools wheel pyinstaller && \
    pip install --no-cache-dir -r requirements.txt && \
    pyinstaller app.py --onefile -s -n cac-app && \
    apk del .build-deps gcc musl-dev  make automake gcc g++ subversion python3-dev libstdc++ && \
    pip uninstall -r requirements.txt -y

FROM  python-build AS opa-build
#update OPA in following line.
RUN apk add curl && \
    curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.54.0/opa_linux_amd64_static \
    && chmod 755 ./opa && \
    apk del curl
#update following for image update next time
FROM gcr.io/google.com/cloudsdktool/cloud-sdk:437.0.1-alpine

RUN rm /usr/local/bin/docker
#removing unnesscary packages
RUN rm /google-cloud-sdk/bin/gcloud-crc32c	
RUN rm /google-cloud-sdk/bin/anthoscli	

RUN addgroup  cac-user \
    && adduser cac-user -D -G cac-user  \
    && mkdir opa && chown cac-user:cac-user  opa \
    && mkdir app && chown cac-user:cac-user app


WORKDIR /app

COPY --from=python-build --chown=cac-user /dist/cac-app .
COPY --from=opa-build --chown=cac-user opa .

USER cac-user
ENV PORT 8080
CMD [ "/app/cac-app"]
