#!/bin/bash

#set -o errexit
set -o pipefail

. ./dev_env_setup 

LOG_FILE="development-setup.log"
DATE=$(date)

PROJECT_ID="$(gcloud config get-value project)"
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)" 2>&1)

PROJECT_ROLES=("iam.workloadIdentityUser" "run.developer" "iam.serviceAccountUser" "storage.admin"  "run.invoker" "run.serviceAgent")
ORG_ROLES=("securitycenter.adminViewer" "logging.viewer" "cloudasset.viewer" "essentialcontacts.viewer" "certificatemanager.viewer" "accesscontextmanager.policyReader" "accesscontextmanager.gcpAccessReader")
CLOUD_BUILD_ROLES=("binaryauthorization.attestorsAdmin" "binaryauthorization.attestorsVerifier" "cloudbuild.serviceAgent" "cloudbuild.workerPoolUser" "clouddeploy.admin" "cloudkms.cryptoKeyDecrypter" "cloudkms.cryptoOperator" "run.admin" "run.serviceAgent" "containeranalysis.ServiceAgent" "iam.serviceAccountUser" )

SERVICE_APIS=("run" "cloudasset" "cloudbuild")
PROJECT_APIS=("run" "storage" "cloudasset"  "securitycenter" "containerregistry" "admin" "cloudidentity" "cloudresourcemanager" "orgpolicy" "accesscontextmanager" "certificatemanager" "essentialcontacts" "cloudkms" "binaryauthorization" "artifactregistry" "cloudbuild" "secretmanager" )

ORG_ID="$(gcloud organizations list --filter=${ORG_NAME} --format="value(ID)" 2>&1)"
ACCOUNT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format="value(projectNumber)" 2>&1)
# lower casing bucket name
BUCKET_NAME="dev-compliance-hub-"$(echo ${ACCOUNT_NUMBER} | tr '[:upper:]' '[:lower:]')
SERVICE_ACCOUNT="cac-dev-${ORG_ID}-sa"
REGISTRIES=("cac-python" "opa"  "gitsync")

LOG_LEVEL="INFO"
DATE=$(date)

function input_language {
  ## Allows user to set preferred install language.
  read -p " 
  ################################################################################
  ##            Compliance as Code Prep Script                                 ##
  ################################################################################

  Select your preferred language for installation.
  Sélectionnez votre langue préférée pour l'installation.
  1) English
  2) Francais
  > " LANGUAGE_INPUT

    LANGUAGE=$(tr '[A-Z]' '[a-z]' <<<$LANGUAGE_INPUT)
    case $LANGUAGE in
    1)
      source ../language_localization/english_ENG.sh
      ;;
    2)
      source ../language_localization/french_FR.sh
      ;;
    *)
      tput setaf 1
      echo "" 1>&2
      echo $'ERROR: Invalid input. Please select an installation language'
      tput sgr0
      exit 1
      ;;
    esac
}
function enable_apis {
  echo "$LANG_APIS"
  for service in ${PROJECT_APIS[@]}; do
    gcloud services enable $service.googleapis.com --project=$PROJECT_ID >>$LOG_FILE 2>&1
  done
}
function service_account_setup {
  gcloud iam service-accounts create ${SERVICE_ACCOUNT} \
    --description="CaC Development Service Account" >>$LOG_FILE 2>&1

  echo "$LANG_SA_SETUP"
  for role in ${PROJECT_ROLES[@]}; do
    gcloud projects add-iam-policy-binding ${PROJECT_ID} \
      --member=serviceAccount:${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com \
      --role=roles/${role} \
      --condition=None >>$LOG_FILE 2>&1
  done

  for role in ${ORG_ROLES[@]}; do
    gcloud organizations add-iam-policy-binding $ORG_ID \
      --member=serviceAccount:${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com \
      --role=roles/${role}>>$LOG_FILE 2>&1
  done
}
function service_identities_create {
  echo "$LANG_SI_CREATE"
  for api in ${SERVICE_APIS[@]}; do
    gcloud beta services identity create --service ${api}.googleapis.com >>$LOG_FILE 2>&1

  done
  gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member=serviceAccount:service-$PROJECT_NUMBER@gcp-sa-cloudasset.iam.gserviceaccount.com \
    --role=roles/storage.objectAdmin \
    --condition=None >>$LOG_FILE 2>&1
       
  for role in ${CLOUD_BUILD_ROLES[@]}; do 
    gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member=serviceAccount:$PROJECT_NUMBER@cloudbuild.gserviceaccount.com \
    --role=roles/${role} \
    --condition=None >>$LOG_FILE 2>&1
  done
    
}
function container_registry {
         
        for registry in ${REGISTRIES[@]}; do
          gcloud artifacts repositories create $registry --repository-format=docker --location=northamerica-northeast1 >>$LOG_FILE 2>&1
        done
}
function storage_bucket {
cat <<EOF > object_lifecycle.json
      {
        "lifecycle": {
          "rule": [
            {
              "action": {
                "type": "Delete"
              },
              "condition": {
                "age": 370,
                "matchesPrefix": [
                  "guardrail-01/validations/05_APPROVAL",
                  "guardrail-02/validations/02_APPROVAL",
                  "guardrail-02/validations/03_APPROVAL",
                  "guardrail-02/validations/06_APPROVAL",
                  "guardrail-02/validations/09_APPROVAL",
                  "guardrail-02/validations/10_APPROVAL",
                  "guardrail-08/validations/01_APPROVAL",
                  "guardrail-08/validations/02_APPROVAL",
                  "guardrail-08/validations/03_APPROVAL",
                  "guardrail-10/validations/01_APPROVAL",
                  "guardrail-11/validations/06_APPROVAL",
                  "guardrail-12/validations/01_APPROVAL",
                  "guardrail-13/validations/01_APPROVAL",
                  "guardrail-13/validations/04_APPROVAL"
                ]
              }
            }
          ]
        }
      }
EOF

  # Create the bucket
  gsutil ls -b gs://$BUCKET_NAME >>$LOG_FILE 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo $CREATE_BUCKET
    echo $CREATE_BUCKET >>$LOG_FILE 2>&1
    gsutil mb -l $REGION gs://$BUCKET_NAME >>$LOG_FILE 2>&1
  fi
  # Set the default storage class for the bucket
  echo $CONFIG_BUCKET
  echo $CONFIG_BUCKET >>$LOG_FILE 2>&1

  gsutil --impersonate-service-account="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" defstorageclass set STANDARD gs://$BUCKET_NAME >>$LOG_FILE 2>&1

  # Set versioning for the bucket
  gsutil --impersonate-service-account="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" versioning set on gs://$BUCKET_NAME >>$LOG_FILE 2>&1
  
  # Set up the object lifecycle policy for Approval Emails
  gcloud storage buckets update gs://$BUCKET_NAME --lifecycle-file=object_lifecycle.json

  # Create the directories
  FOLDER_COUNT=$(gsutil ls gs://$BUCKET_NAME | wc -l | tr -d '[:space:]')

  if [ $FOLDER_COUNT -lt 13 ]; then
    for i in {1..13}; do
      echo $CREATE_FOLDERS >>$LOG_FILE 2>&1
      echo $CREATE_FOLDERS
      mkdir guardrail-$(printf "%02d" $i)
      echo "Please use this space to upload compliance related files" >guardrail-$(printf "%02d" $i)/instructions.txt
      gsutil --impersonate-service-account="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" cp -r guardrail-$(printf "%02d" $i) gs://$BUCKET_NAME >>$LOG_FILE 2>&1
      rm -rf guardrail-$(printf "%02d" $i)
    done
  fi

  gsutil --impersonate-service-account="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" iam ch \
    serviceAccount:service-$PROJECT_NUMBER@gcp-sa-cloudasset.iam.gserviceaccount.com:objectAdmin \
    gs://${BUCKET_NAME} >>$LOG_FILE 2>&1
}

# function clean_up {
#   # Find and delete all directories starting with "guardrail" in the current working directory
#   for dir in $(find . -type d -name "guardrail-*"); do
#     # Delete the directory
#     rm -r "$dir"
#     echo "Deleted $dir"
#   done
# }
















## Setup Logging
input_language
echo "$DATE" >$LOG_FILE 2>&1
echo "$LANG_DEPLOYMENT_PROMPT"
echo "$LANG_DEPLOYMENT_PROMPT" >>$LOG_FILE
enable_apis
service_account_setup
service_identities_create
container_registry
storage_bucket

echo "
################################################################################
##             CaC Development Environment Setup    completed                          
################################################################################
## Service Account Information for SSC:
##
## Compliance Tool Service Account: 
## $SERVICE_ACCOUNT
##
## CloudRun Robot Account: 
## service-$PROJECT_NUMBER@serverless-robot-prod.iam.gserviceaccount.com
##
## Binary Authorization Service Account:
## service-$PROJECT_NUMBER@gcp-sa-binaryauthorization.iam.gserviceaccount.com   
##                                                       
##                                                                                       
## Compliance Proof GCS Bucket: gs://$BUCKET_NAME       
##
################################################################################
"
echo "
################################################################################
##             CaC Development Environment Setup    completed                             
################################################################################
## Service Account Information for SSC:
##
## Compliance Tool Service Account: 
## $SERVICE_ACCOUNT
##
## CloudRun Robot Account: 
## service-$PROJECT_NUMBER@serverless-robot-prod.iam.gserviceaccount.com
##
## Binary Authorization Service Account:
## service-$PROJECT_NUMBER@gcp-sa-binaryauthorization.iam.gserviceaccount.com 
##
## Compliance Proof GCS Bucket: gs://$BUCKET_NAME   
##
################################################################################
" >> $LOG_FILE 2>&1
