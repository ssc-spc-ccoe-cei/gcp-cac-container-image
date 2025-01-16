# Visualizing Compliance Data with Looker Studio

## Setting Up Service Account Access

Looker Studio can use individual user credentials or service account credentials to access the Compliance Data stored in Big Query. The recommended approach is to restrict access to a designated service account. Users who will only view Looker Studio reports don't need to have permissions on the service account. This configuration allows SSC to control who can edit the data source and allow broader view permissions to the report

### Create a GCP Service account with access to view the Compliance Results Data

**Service Account Permissions**
--

|IAM Role               | Description                                                               | Tier              |
|-----------------------|---------------------------------------------------------------------------|-------------------|
|BigQuery Data Viewer   | Allows the service account read the dataset metadata, data and tables     | Data Set Level    | 
|BigQuery Job User      | Provides permissions to run jobs, including queries, within the project.  | Project Level     |

```shell
gcloud config set project <AGGREGATE_PROJECT_ID>
PROJECT_ID="$(gcloud config get-value project)"
SERVICE_ACCOUNT_NAME=
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
--description="Use for Looker Studio access to BigQuery" 

SERVICE_ACCOUNT="$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com"

SA_ROLES=("bigquery.jobUser" "bigquery.dataViewer")
for role in ${SA_ROLES[@]}; do 
    gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    -member=serviceAccount:${SERVICE_ACCOUNT}\
    --role=roles/${role}
done
```

### Allow the Looker Studio service agent to access your service account

```shell
gcloud config set project <AGGREGATE_PROJECT_ID>
PROJECT_ID="$(gcloud config get-value project)"
SERVICE_ACCOUNT_NAME=
SERVICE_ACCOUNT="$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com"
ORG_ID="$(gcloud organizations list --filter=${ORG_NAME} --format="value(ID)" 2>&1)"

gcloud iam service-accounts add-iam-policy-binding ${SERVICE_ACCOUNT} \
--member="service-${ORG_ID}@gcp-sa-datastudio.iam.gserviceaccount.com" \
--role="roles/iam.serviceAccountTokenCreator"
```

### Enable the service account to access your BigQuery data

To allow Looker Studio to access your data, grant the BigQuery Data Viewer role to the service account at the table or dataset level.

Navigate to BigQuery, open a project, then locate the dataset.
To the right of the dataset name, click View actions "More options" icon.
Click Open.
In the toolbar, click Share icon SHARING > Permissions.
In the panel that opens on the right, click Share icon ADD PRINCIPAL.
In the New principals box, paste the Looker Studio service account email address.
Select the BigQuery Data Viewer role.
Click SAVE.

### OPTIONAL: Granting User Access 

Users who will only view Looker Studio reports don't need to have permissions on the service account.

Looker Studio users who will create or edit data sources need to be granted a role that to access service account. Grant this access at the service account level;

```shell
gcloud iam service-accounts add-iam-policy-binding $SERVICE_ACCOUNT \
--member="user:user@example.com" \
--role="roles/iam.serviceAccountUser"
```

## Generating Reports with Looker Studio

### Creating the Data Sources

From the  [Looker Studio Dashboard](https://lookerstudio.google.com/u/2/navigation/datasources), create a new data sources for each of the tables in the dataset: .

* Nightly Status ( Scheduled Query)
* Overall Compliance Data (Data Set)

![Looker Data Source](../assets/looker_studio/looker_data_source.png)

* Select the Big Query Connector: 

    ![Data Source Connector ](../assets/looker_studio/big_query_connector.png)

* Connect the project and table:

    ![Big Query Project Connection](../assets/looker_studio/bq_project.png)

### Update the Data Sources to use service account credentials, add in the ID of the SA 

The Data source is initially created with the credentials of the person creating it. Update the data source to use the previously created service account credentials:

1. Edit each data source by selecting  "Data Credentials" in the toolbar

    ![Data Credentials](../assets/looker_studio/data_crednetials.png)

* Update the credentials by selecting "Service Account" and entering its email.

    ![Service Account Credentials](../assets/looker_studio/service_account_credentials.png)


## Configuring the Sample Report

![Sample Report](../assets/looker_studio/sample-report.png)

1. Create a new blank report and add both data sources

    ![Report Data Sources](../assets/looker_studio/report_data_sources.png)

### Donut Charts

1. Add a new Donut style Chart

    ![Looker Studio Donut Chart](../assets/looker_studio/looker-donutchart.png)

2. Configure the chart:

* Update the `Dimension` Section in the Chart Setup properties pane, chosing `f0_`. 

    ![Chart Dimension](../assets/looker_studio/dimension-selecgt.png)

**Note** You can open the properties pane for any chart by selecting it and selecting the properties option on the right side of the page

### Bar Charts

1. Add a new Bar style Chart

    ![Looker Studio Bar Chart](../assets/looker_studio/looker-barchart.png)

2. Configure the chart:

* Update the `Dimension` Section in the Chart Setup properties pane, chosing `f0_`. 

    ![Chart Dimension](../assets/looker_studio/dimension-selecgt.png)

* Update Breakdown Dimensions and Metrics:

    ![Chart Configuration](../assets/looker_studio/looker-barchart-config.png)

**Note** You can open the properties pane for any chart by selecting it and selecting the properties option on the right side of the page

### Stacked Column Charts

1. Add a new Stacked Column style Chart:

    ![Looker Column Chart](../assets/looker_studio/looker-columnchart.png)

2. Configure the Chart

* Update the data source, to use the full compliance results and adjust the dimensions and metrics:

    ![Stacked Column Chart Data Source](../assets/looker_studio/looker-stackedcolumn-config.png)

**Note** You can open the properties pane for any chart by selecting it and selecting the properties option on the right side of the page

### Adjusting Charts

You can update the colours and options of any of the charts in the `Style` configuration tab of the chart:

![Updating Colours and Options](../assets/looker_studio/looker-chartcolours.png)

You can update the Display name of the field(s) by clicking on the the pencil symbol beside the name:

![Chart Dimension Display Name](../assets/looker_studio/dimension-displayname.png)
