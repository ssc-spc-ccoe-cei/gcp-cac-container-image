#!/bin/bash

set -o errexit
set -o pipefail

. ./aggregator_config
CURRENT_DATE=$(date "+%m-%d-%Y")
function config_init {
  ## Gathers required information for installation

  if [ -z "$SERVICE_ACCOUNTS" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update Service Account information in the configuration file '
    tput sgr0
    exit 1
  fi
  if [ -z "$CLOUD_RUN_SERVICE_AGENTS" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update CloudRun Service Agent information in the configuration file '
    tput sgr0
    exit 1
  fi
  if [ -z "$SOURCE_REPO" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update Source Repository information in the configuration file '
    tput sgr0
    exit 1
  fi
  if [ -z "$CONTAINER_REPO" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update Container Repo  information in the configuration file '
    tput sgr0
    exit 1
  fi
  if [ -z "$BUILD_PROJECT" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update Container Repo information in the configuration file '
    tput sgr0
    exit 1
  fi
  if [ -z "$BUCKET_NAME" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update GCS Bucket information in the configuration file '
    tput sgr0
    exit 1
  fi
  if [ -z "$DATA_PROJECT" ]; then
    tput setaf 1
    echo "" 1>&2
    echo $'ERROR: Please update Data Project information in the configuration file '
    tput sgr0
    exit 1
  fi
}
REGISTRY_ROLE="artifactregistry.reader"
SOURCE_REPO_ROLE="source.reader"
BUCKET_ROLE="objectCreator"
TRANSFER_ROLE="legacyBucketWriter"
function source_repo {

  #Get current IAM Policy
  gcloud source repos get-iam-policy ${SOURCE_REPO} --project=$BUILD_PROJECT >bindings.yaml
  #Create backup of existing IAM Policy for source repos
  cp bindings.yaml current-bindings-$CURRENT_DATE.yaml.backup
  #trim version and tags
  head -n -2 bindings.yaml >tmp && mv tmp bindings.yaml
  #Add the binding flags - used only when no bindings exist
  if [[ -z $(grep '[^[:space:]]' bindings.yaml) ]]; then
    echo "bindings:" >bindings.yaml
  fi
  #Add new SA's to policy

  for sa in ${SERVICE_ACCOUNTS[@]}; do
    echo "
- members:
  - serviceAccount:${sa}
  role: roles/${SOURCE_REPO_ROLE}" >>./bindings.yaml
  done
  gcloud source repos set-iam-policy ${SOURCE_REPO} bindings.yaml --project=$BUILD_PROJECT
  rm bindings.yaml
}

function container_registry {
  gcloud config set project $BUILD_PROJECT

  for sa in ${CLOUD_RUN_SERVICE_AGENTS[@]}; do
    gcloud artifacts repositories add-iam-policy-binding ${CONTAINER_REPO} \
      --location=${LOCATION} \
      --member=serviceAccount:${sa} \
      --role=roles/${REGISTRY_ROLE}
  done
}

function gcs_bucket {
  gcloud config set project $DATA_PROJECT
  for sa in ${CLOUD_STORAGE_SERVICE_AGENTS[@]}; do
    gsutil iam ch serviceAccount:${sa}:${TRANSFER_ROLE} \
      gs://${BUCKET_NAME}
  done
}

config_init
source_repo
container_registry
gcs_bucket
