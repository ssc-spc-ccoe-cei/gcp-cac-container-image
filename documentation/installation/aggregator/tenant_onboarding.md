# Onboarding Tenants

The script `aggregator.sh` will setup set the following permissions for client provided Service account on required resources in SSC's GCP project:

* Cloud Source Repository Reader
* Artifact Registry Reader
* GCS Bucket Object Creator

The script uses a configuration file `aggregator_setup` to collect the information in the table below:

|Field                          | Type      | Description                                                           | Example                                                                                                           |
|-------------------------------|-----------|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
|SERVICE_ACCOUNTS               | List      | List of client service account emails to grant IAM Roles              | "compliance-automation@example2.iam.gserviceaccount.com" "compliance-automation@example1.iam.gserviceaccount.com" |
|CLOUD_RUN_SERVICE_AGENTS       | List      | List of CloudRun Service Identities to grant Artifact Registry Access | "compliance-automation@example2.iam.gserviceaccount.com" "compliance-automation@example1.iam.gserviceaccount.com" |
|CLOUD_STORAGE_SERVICE_AGENTS   | List      | List of Cloud Storage Service Identities to grant GCS Bucket Access   | "compliance-automation@example2.iam.gserviceaccount.com" "compliance-automation@example1.iam.gserviceaccount.com" |
|BUCKET_NAME                    | String    | GCS Bucket name for compliance results                                | "gs://gcp-cac-solution"                                                                                           |
|CONTAINER_REPO                 | String    | Artifact Registry repository containing the CaC Solution Container    | "northamerica-northeast1-docker.pkg.dev/gcp-cac-solution-build/opa-python"                                        |
|SOURCE_REPO                    | String    | Google Source Repository containing the CaC Solution Policy files     | "https://source.developers.google.com/p/gcp-cac-solution-policies/r/gcp-cac-solution-policies"                    |
|DATA_PROJECT                   | String    | GCP Project to store and visualize compliance results                 | "gcp-cac-solution"

Update the configuration file with the necessary information prior to executing the script.

## Optional Setup

### Enabling Binary Authorization for Clients

In order for clients to verify the CaC solution Image against the signing keys, add the following permissions in the Container Build Project, for the client provided Binary Authorization Robot Account:

```shell
DEPLOYER_SERVICE_ACCOUNT=
BUILD_PROJECT=
gcloud config set project $BUILD_PROJECT
PROJECT_ID="$(gcloud config get-value project)"
ATTESTOR=$(gcloud container binauthz attestors list --filter=NAME:cac --format="value(name)" )

gcloud --project $PROJECT_ID\
beta container binauthz attestors add-iam-policy-binding \
"projects/$PROJECT_ID/attestors/$ATTESTOR" \
--member="serviceAccount:${DEPLOYER_SERVICE_ACCOUNT}" \
--role=roles/binaryauthorization.attestorsVerifier
```

Add an IAM role binding for the Client CaC Solution Service Account, as the user must have the permission to view the attestor to add. If desired, this permission can safely be revoked after the attestor has been added.

```shell
CLOUD_RUN_SERVICE_ACCOUNT=
BUILD_PROJECT=

gcloud config set project $BUILD_PROJECT
PROJECT_ID="$(gcloud config get-value project)"

gcloud --project $PROJECT_ID \
beta container binauthz attestors add-iam-policy-binding \
"projects/$PROJECT_ID/attestors/$ATTESTOR" \ 
--member=$CLOUDRUN_SERVICE_ACCOUNT \
--role=roles/binaryauthorization.attestorsViewer

```

To remove the IAM role binding after the attestor has been added:

```shell
gcloud --project $PROJECT_ID \
beta container binauthz attestors remove-iam-policy-binding \
"projects/$PROJECT_ID/attestors/$ATTESTOR" \ 
--member=$CLOUDRUN_SERVICE_ACCOUNT \
--role=roles/binaryauthorization.attestorsViewer
```

Provide the Attestor Resource ID `"projects/$PROJECT_ID/attestors/$ATTESTOR"` to Clients; they will use this information to configure their Binary Authorization Policy after deploying the CaC Solution