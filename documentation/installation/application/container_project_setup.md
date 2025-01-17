# Compliance as Code Toolkit

This repository contains the application artifacts for the Compliance-as-Code(CaC) tool for SSC.

<!-- TOC start -->
- [Compliance as Code Toolkit](#compliance-as-code-toolkit)
  - [Building the Containerized Application](#building-the-containerized-application)
    - [Before you Begin](#before-you-begin)
    - [Preparing the Build Project](#preparing-the-build-project)
  - [Before you begin](#before-you-begin-1)
  - [Preparing the GCP Environment](#preparing-the-gcp-environment)
    - [Setting up Binary Authorization](#setting-up-binary-authorization)
  - [Connect to GitHub](#connect-to-github)
    - [Create the Repository Connection](#create-the-repository-connection)
    - [Setup Cloud Build Triggers](#setup-cloud-build-triggers)
  - [Adding OPA Server and Git-Sync containers](#adding-opa-server-and-git-sync-containers)
<!-- TOC end -->

## Building the Containerized Application

### Before you Begin

Initial setup of the container build pipeline and associated tooling is required prior to client deployment of CaC in their environment. This repository contains the application code, and associated pipeline files to setup a Cloud Build pipeline for the container image.

![Application Image Build](../assets/architecture_diagrams/cac-Solution-Architecture-Build.png)

The CaC tool container image build setup requires the following GCP Services:

Container Image Build and Storage:

- CloudKMS
- Binary Authorization
- Artifact Registry
- Cloud Build
- CloudRun
- Github Repository
  
The following permissions are required to setup the container build environment:

- Artifact Registry Administrator
- Binary Authorization Attestor Admin
- Binary Authorization Policy Administrator
- Cloud Build Connection Admin
- Cloud Build Editor
- Cloud KMS Admin
- Logs Viewer

### Preparing the Build Project

## Before you begin

The CaC Solution toolkit leverages a Service Account along with several Google Cloud Platform services to create all the necessary resources as well as access the required information in a GCP Organization.

Included in this repository is a script that can be leveraged to setup all of the pre-requisites, including:

- Service Account creation, including Roles
- Project API enablement
- Service Identity Creation, including Roles

**Service Account Permissions**

--

|IAM Role                    | Description                    | Usage                                                         |Tier           |Resource Level |
|----------------------------|--------------------------------|---------------------------------------------------------------|---------------|---------------|
|Role Viewer                 |roles/iam.roleViewer            |Allows the Service Account to list the SA roles being granted. |Infrastructure |Project        |
|Storage Admin               |roles/storage.admin             |Allows the Service Account to create buckets and objects.      |Infrastructure |Project        |
|Cloud Scheduler Admin       |roles/cloudscheduler.admin      |Allows the Service Account to create a new cloud scheduler job.|Infrastructure |Project        |
|Cloud Run Developer         |roles/run.developer             |Allows the Service Account to create Cloud Run services.       |Infrastructure |Project        |
|Cloud Run Invoker           |roles/run.invoker               |Allows the Service Account to trigger Cloud Run on a Schedule  |Infrastructure |Project        |
|Logs Viewer                 |roles/logging.viewer            |Allows the Service Account to read Cloud Audit Logs            |Application    |Organization   |
|Security Center Admin Viewer|roles/securitycenter.adminViewer|Allows the Service Account to list findings and alerts in SCC  |Application    |Organization   |
|Cloud Asset Viewer          |roles/cloudasset.viewer         |Allows the Service Account to list cloud asset inventory.      |Application    |Organization   |

**Project APIs**

--

|GCP API/Service        |Description                        |Usage                                                          |Tier           |
|-----------------------|-----------------------------------|---------------------------------------------------------------|---------------|
|Cloud Run              |"run.googleapis.com"               |PaaS Environment; runs the CaC Solution Container Image        |Infrastructure|
|Container Registry     |"containerregistry.googleapis.com" |Cloud Run dependency service                                   |Infrastructure|
|Cloud Scheduler        |"cloudscheduler.googleapis.com"    |Used to trigger CaC Solution on a schedule                     |Infrastructure|
|Cloud Storage          |"storage.googleapis.com"           |Necesary for uploads of Compliance Data, and storage of results|Infrastructure|
|Cloud Asset Inventory  |"cloudasset.googleapis.com"        |Used to query provisioned GCP infrastructure                   |Application|
|Security Command Center|"securitycenter.googleapis.com"    |Used to query provisioned GCP infrastructure                   |Application|
|Cloud Storage Transfer |"storagetransfer.googleapis.com"   |Used to transfer Compliance results output files               |Application|

## Preparing the GCP Environment

Run the `install.sh` script found in the `deployment/application` directory. The script will prompt for the GCP organization name and use it to provision the Service Account and enable all of the required APIs
Once the script has completed, continue on to the sections below to complete the initial setup for Binary Authorization, as well as configuring the GitHub repository integration with CloudBuild

### Setting up Binary Authorization

1) Create a KMS Keyring and Key:

        BUILD_PROJECT=
        gcloud config set project $BUILD_PROJECT
        PROJECT_ID="$(gcloud config get-value project)"
        KEY_RING="cac-signing-key-ring"
        KEY="cac-signing-key"
        gcloud kms keyrings create $KEY_RING --location northamerica-northeast1
        gcloud kms keys create $KEY --location northamerica-northeast1 --keyring $KEY_RING --purpose asymmetric-signing --default-algorithm rsa-sign-pss-2048-sha256

        gcloud kms keys list --location northamerica-northeast1 --keyring $KEY_RING

2) Create an Attestor in the GCP Console:

<https://console.cloud.google.com/security/binary-authorization/attestors/create>

PKIX key, which you can import the KMS key.  Note the "name" in the `gcloud kms keys list --location northamerica-northeast1 --keyring $KEY_RING` command.  You'll need to append `/cryptoKeyVersions/1` at the end of it to  meet the required format.

## Connect to GitHub

Note: you'll need the Secret Manager Admin role (*roles/secretmanager.admin*) as you need *secretmanager.secrets.create* and *secretmanager.secrets.setIamPolicy* permissions

        BUILD_PROJECT=
        gcloud config set project $BUILD_PROJECT
        PROJECT_ID="$(gcloud config get-value project)"

         gcloud builds connections create github cac-python-connection --region=northamerica-northeast1

After running the gcloud builds connections command, you will see a link to authorize the Cloud Build GitHub App.


Note: This authentication can be used to create additional connections in the same project. We recommend using a robot account, or an account shared by your team, instead of a personal GitHub account to keep your connections secure.
Follow the link to authorize the Cloud Build GitHub App.
After authorizing the app, Cloud Build stores an authentication token as a secret in Secret Manager in your Google Cloud project. You can view your secrets on the Secret Manager page.

Install the Cloud Build GitHub App in your account or in an organization you own.

Permit the installation using your GitHub account and select repository permissions when prompted.

### Create the Repository Connection

| Name              | Description                                                               | Example                                            |
|-------------------|---------------------------------------------------------------------------|----------------------------------------------------|
|REPO_NAME          | The display name in the console for the Connected GitHub Repository       | `cac_repo`                                         |
|REPO_URI           | The full URI of the Github Repository                                     | `https://github.com/canada-ca/cloud-guardrails.git`|
|CONNECTION_NAME    | The name to use as the final container image name                         | `cac-github-connection`                            |
|REGION             | The GCP region to create the connection in                                | `northamerica-northeast1`                          |

To add a GitHub repository to your connection, enter the following command:

      gcloud builds repositories create $REPO_NAME \
      --remote-uri=$REPO_URI \
      --connection=#CONNECTION_NAME --region=$REGION


REPO_NAME is the name of your repository.
REPO_URI is the link to your GitHub repository. For example, https://github.com/cloud-build/test-repo.git.
CONNECTION_NAME is the name of your connection.
REGION is the region for your connection.
You have now linked a repository to your GitHub connection.


### Setup Cloud Build Triggers

| Name                      | Description                                                                   | Example                   |
|---------------------------|-------------------------------------------------------------------------------|---------------------------|
|_ARTIFACT_REPOSITORY_NAME  | The name of the Google Artifact registry used to store the container image    | `cac_repo`                |
|_ATTESTOR_NAME             | The name of the Binary Authorization Attestor to use when signing the image   | `cac-attestor`            |
|_IMAGE_NAME                | The name to use as the final container image name                             | `cac-opa-python`          |
|_KEY_NAME                  | The name of the CloudKMS key used to sign the container image                 | `signing-key`             |
|_KEY_VERSION               | The version number of the CloudKMS key                                        | `1`                       |
|_KEYRING_NAME              | The name of the CloudKMS keyring that houses the signing key                  | `signing-keyring`         |
|_REGION                    | the Artifact registry location                                                |  `northamerica-northeast1`|


## Adding OPA Server and Git-Sync containers

In the [buildfiles](../../../buildfiles/) directory there are 2 cloudbuild configuration files:

- [gitsync-cloudbuild.yaml](../../../buildfiles/gitsync-cloudbuild.yaml): Pulls the public image from the Kubernetes Image registry and imports it to Artifact Registry.
- [opa-cloudbuild.yaml](../../../buildfiles/opa-cloudbuild.yaml): Pulls the public image from Dockerhub and imports it to artifact registry.

These build files take the image tag (version) as an environment variable. This allows SSC to control what versions of the application components are available for consumption
To import a new image version to the Artifact registry, clone this repository and execute the following command:

        BUILD_PROJECT=
        gcloud config set project $BUILD_PROJECT
        PROJECT_ID="$(gcloud config get-value project)"
        
        gcloud builds submit --config buildfiles/opa-cloudbuild.yaml \
        --substitutions=_OPA_VERSION="0.70.0",_REGION="northamerica-northeast1",_PROJECT_ID=$PROJECT_ID  

        gcloud builds submit --config buildfiles/gitsync-cloudbuild.yaml \
        --substitutions=_GIT_SYNC_VERSION="v4.2.3",_REGION="northamerica-northeast1",_PROJECT_ID=$PROJECT_ID 
