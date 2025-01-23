# Application Upgrades & Maintenance


## Gitflow Tagging
Generally performed as part of a release, tagging is a simple way of marking the code at that particular release point.

- example:
```
git tag -a v1.0 -m "This is GCP CaC v1.0"
```


## Updating Images
Because the application is deployed with a side-car architecture, if you want to update any component (whether it's OPA or Git Sync), you will first need to submit a Cloud Build job to update the side-car image versions first before submitting the application's Cloud Build pipeline to release the updated (overall) app.

- example:
```
BUILD_PROJECT=
gcloud config set project $BUILD_PROJECT
PROJECT_ID="$(gcloud config get-value project)"

gcloud builds submit --config buildfiles/opa-cloudbuild.yaml --region northamerica-northeast1 \
  --substitutions=_OPA_VERSION="1.0.0",_REGION="northamerica-northeast1",_PROJECT_ID=$PROJECT_ID

gcloud builds submit --config buildfiles/gitsync-cloudbuild.yaml --region northamerica-northeast1 \
  --substitutions=_GIT_SYNC_VERSION="v4.4.0",_REGION="northamerica-northeast1",_PROJECT_ID=$PROJECT_ID

gcloud builds submit --config buildfiles/cloudbuild.yaml --region northamerica-northeast1 \
  --substitutions=_REGION="northamerica-northeast1",_PROJECT_ID=$PROJECT_ID,_OPA_IMAGE="opa:1.0.0",_GIT_SYNC_VERSION="git-sync:v4.4.0"
```
