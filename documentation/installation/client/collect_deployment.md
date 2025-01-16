# Deploying the CaC Tool

***Please provide the output file information to the SSC Team so appropriate permissions on Cloud Source Repositories, Artifact Registry and GCS can be granted before running the installation script***

![CaC Solution Data Collection](../assets/architecture_diagrams/cac-Solution%20Architecture-Data%20Collection.png)

To start the installation, execute the `collector_setup/collector_setup.sh` script from a command line environment supporting BASH.

The setup script will prompt for input on required information:

|Input                  | Description                                                                    |
|-----------------------|--------------------------------------------------------------------------------|
|Service Account Name   |Short Name of Service Account used to deploy and run CaC Solution               |
|GCP Project            |GCP Project to deploy CaC Solution                                              |
|GCP Organization Name  |GCP Organization Name, used to identify organization in compliance results file |
|Cloud Usage Profile    |Numeric value of Cloud Usage Profile applicable to GCP Organization             |
|GCS Bucket Name        |Provided by SSC, name of the GCS Bucket to upload compliance results information|
|Policy Repo            |Provided by SSC, URL of Source Repository containing the CaC policy files       |

The Collector setup script can also read input from a configuration file. A sample configuration file is included in the `collector` directory:

```shell
SERVICE_ACCOUNT="cac-solution-195864723-sa"
ORG_NAME="example.ca"
SSC_BUCKET_NAME="gs://cac-solution-exampleca/"
POLICY_REPO="https://source.developers.google.com/p/gcp-cac-solution-build/r/cac_policies"
REGION="northamerica-northeast1"
CAC_IMAGE="northamerica-northeast1-docker.pkg.dev/gcp-cac-solution-build/cac-opa-python/cac-solution:c7077c4"
GC_PROFILE="1"
```

## Optional - Enabling Binary Authorization

Binary Authorization is a deploy-time security control that allow you to ensures only trusted container images are deployed in the Cloud Run environment for CaC; enabling Binary Authorization, allows you to verify and enforce that the image is signed by trusted authorities during the development process and then enforce signature validation when deploying.

### Edit a Binary Authorization Policy

1. Update the default Binary Authorization Policy, in the GCP Project that the CaC Solution is deployed in. Navigate to the Binary Authorization section of the UI [Binary Authorization Configuration](https://console.cloud.google.com/security/binary-authorization). Ensure you are in the correct project.

    * Edit the default Policy:

    ![Default Policy](../assets/binauthz/binauth-policy.png)

    * Select "Require Attestations" and add an Attestor:

    ![Adding an Attestor](../assets/binauthz/binauth-attestor.png)

    * Enter the Attestor resource ID as provided by SSC:

    ![Attestor Resource ID](../assets/binauthz/binatuh-attestor2.png)

**Note** This can be done throught the `gcloud cli` but it is recommended to use the Cloud Console.

### Enabling Binary Authorization in Cloud Run

1. Update the existing Cloud Run Service to use the newly updated policy to enforce the use of signed images.

```shell

gcloud config set project <cac-deployment-project>
ORG_ID="$(gcloud organizations list --filter=<ORG_NAME> --format="value(ID)" 2>&1)"
PROJECT_ID="$(gcloud config get-value project)"
SERVICE_ACCOUNT="cac-solution-${ORG_ID}-sa@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud --impersonate-service-account="${SERVICE_ACCOUNT}" \
run services update compliance-analysis --binary-authorization=default
```
