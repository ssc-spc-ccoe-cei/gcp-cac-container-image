# Deploying the CaC Tool

***Please provide the output file information to the SSC Team so appropriate permissions on Cloud Source Repositories, Artifact Registry and GCS can be granted before running the installation script***

![CaC Solution Data Collection](../assets/architecture_diagrams/cac-Solution%20Architecture-Data%20Collection.png)

To start the installation, execute the `collector_setup/collector_setup.sh` script from a command line environment supporting BASH.
The Collector setup script reads configuration information for the application from a configuration file.

| Name                      | Description                                                                   | Example                   |
|---------------------------|-------------------------------------------------------------------------------|---------------------------|
| `_SERVICE_ACCOUNT`        |Name of the Service Account to use for Deployment                              |`cac-dev-37505682288-sa`|
| `_ORG_NAME`               |GCP Organization Name                                                          | `example.ca`|
| `_GC_PROFILE`             |Cloud Usage Profile                                                            |`1`|
| `_SECURITY_CATEGORY_KEY`  |Tag used to identify Privileged Data                                           |`SECURITY_CATEGORY`|
| `_PRIVILEGED_USERS_LIST`  |List of users with Privileged Access                                           |`user:admin-user1@example.ca,user:admin-user2@example.ca`|
| `_REGULAR_USERS_LIST`     |Regular IDs of Privileged Users                                                |`user:user1@example.ca,user:user2@example.ca`|
| `_ALLOWED_DOMAINS`        |List of user domains with GCP access enabled                                   |`ssc.gc.ca`|
| `_DENY_DOMAINS`           |List of user domains that should not have GCP access                           |`outlook.com,gmail.com`|
| `_HAS_GUEST_USERS`        |Binary flag used to indicate if Guest Users have been added                    |`false`|
| `_HAS_FEDERATED_USERS`    |Binary flag used to indicate if Users are federated                            |`true`|
| `_ALLOWED_IPS`            |List of IPs Blocks allowed to access the GCP environment                       |`10.0.7.44,192.168.0.16`|
| `_CUSTOMER_IDS`           |List of GCP Org and/or Workspace Customer IDs                                  |`CUSTOMER_IDS='C03xxxx4x,Abc123,XYZ890`|
| `_CA_ISSUERS`             |List of Acceptable Certifcate Authorities                                      |`"Let's Encrypt,Verisign"`|
| `_POLICY_REPO`            |URL of Source Control repository hosting the CaC Policies                      |"https://source.developers.google.com/p/gcp-cac-solution-build/r/cac_policies"|
| `_REGION`                 |GCP Region to deploy to                                                        |`northamerica-northeast1`|
| `_GIT_SYNC_IMAGE`         |URL of GitSync Container image                                                 |`"northamerica-northeast1-docker.pkg.dev/cacv2-devproj/gitsync/git-sync:v4.2.3"`|
| `_OPA_IMAGE`              |URL of OPA Container Image                                                     |`"northamerica-northeast1-docker.pkg.dev/cacv2-devproj/opa/opa:0.70.0"`|
| `_CAC_IMAGE`              |URL for the CaC Application                                                    | "northamerica-northeast1-docker.pkg.dev/cacv2-devproj/cac-python/cac-python:432552"|

A sample configuration file is included in the `collector` directory

```bash

### GCP Organization Information
BUILD_PROJECT="cacv2-devproj"
# Service Account Short Name
SERVICE_ACCOUNT="cac-solution-37505682288-sa"
# Organization Name
ORG_NAME="lab-rat.ca"
# GC Cloud Usage Profile number
GC_PROFILE="1"
GCP_PROJECT="cacv2-devproj"
# Tag Key used to identify security classification of GCP resources
# example: a GCS bucket can be identified as containing Protected "A" data by tagging it
# SECURITY_CATEGORY: Protected A

SECURITY_CATEGORY_KEY="SECURITY_CATEGORY"

# List of Privileged Users and their regular account names
# Format: 'user:admin1@org.ca,user:admin2@org.ca,user:admin3@org.ca'
PRIVILEGED_USERS_LIST="user:jenn@example.ca"
REGULAR_USERS_LIST="  "

# List of Domains that are allowed/denied to access the GCP environment
# Format: 'ssc.gc.ca,domain2.ca'
ALLOWED_DOMAINS="ssc.gc.ca,domain2.ca"
DENY_DOMAINS="  "
HAS_GUEST_USERS="false"

HAS_FEDERATED_USERS="true"

# List of CIDR Blocks allowed to access the GCP environment
# Format: '10.0.0.0/8,192.168.1.0/24'
ALLOWED_CIDRS="  "

# List of GCP Org and/or Workspace Customer IDs
# run `gcloud organization list` to find yours
# i.e. CUSTOMER_IDS='C03xxxx4x,Abc123,XYZ890'
CUSTOMER_IDS="  "

# List of Acceptable Certifcate Authorities
# Format: "Let's Encrypt,Verisign"
CA_ISSUERS="Let's Encrypt,Verisign "



#############From SSC

POLICY_REPO="https://source.developers.google.com/p/gcp-cac-solution-build/r/cac_policies"
REGION="northamerica-northeast1"
CAC_IMAGE="northamerica-northeast1-docker.pkg.dev/cacv2-devproj/cac-python/cac-python:432552"
GIT_SYNC_IMAGE="northamerica-northeast1-docker.pkg.dev/cacv2-devproj/gitsync/git-sync:v4.2.3"
OPA_IMAGE="northamerica-northeast1-docker.pkg.dev/cacv2-devproj/opa/opa:0.70.0 "
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

### GCP - Enabling Binary Authorization in Cloud Run

#### In the Application Build Project
- **Security** --> **Binary Authorization** --> **ATTESTORS**
- For your attestor, click the 3 dots on the right and *Copy resource ID* (resource ID format: `projects/BUILD_PROJECT_ID/attestors/ATTESTOR_NAME`, i.e. `projects/cac-goat-v2/attestors/cac-attestor-v2`)

#### In the Customer/Client Project
- **Security** --> **Binary Authorization** --> **POLICY**
- **EDIT POLICY** --> *Default rule* --> select *Require attestations*
- *ADD ATTESTORS* --> paste in attestor resource ID from Application Build project (step above)
- (Optional) Check off *Dry-run* mode if which will log violations (if any), but will not enforce

- set `BIN_AUTH_ENABLED="true"` in your collector_config to enable Bin Auth for your deployment