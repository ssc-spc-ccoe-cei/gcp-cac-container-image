#!/usr/local/bin/python
# -*- coding: latin-1 -*-

import google.cloud.asset_v1 as asset_v1
from google.protobuf.json_format import MessageToDict
import google.cloud.securitycenter as securitycenter
import google.cloud.logging
import google.cloud.storage as storage
from google.api_core.exceptions import NotFound
import google.auth
from googleapiclient.discovery import build
import concurrent.futures
import threading

from flask import Flask, jsonify
import json
from marshmallow import Schema, fields
import requests
from waitress import serve
import os
import logging
import time
import re
from datetime import datetime, timedelta, timezone
from cryptography import x509

# Logger setup
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Environment configurations
port = int(os.environ.get("PORT", 8080))
profile_level = os.environ['GC_PROFILE']
bucket_name = os.environ['GCS_BUCKET']
project = os.environ['GCP_PROJECT']
org_id = os.environ['ORG_ID']
org_name = os.environ['ORG_NAME']
tenant_domain = os.environ['TENANT_DOMAIN']
policy_version = os.environ['POLICY_VERSION']
app_version = os.environ['APP_VERSION']
customer_id = os.environ['CUSTOMER_ID'] # your directory customer ID (`gcloud organizations list`)

# your Workspace domain, if env var not provided,
# it is implied you do not have a Workspace account, then use empty string '' as default
ws_domain = os.environ.get('WORKSPACE_DOMAIN', '')
org_admin_group_email = os.environ.get('ORG_ADMIN_GROUP_EMAIL', f"gcp-organization-admins@{ws_domain}")
breakglass_user_email = os.environ.get('BREAKGLASS_USER_EMAIL', 'breakglass@ssc.gc.ca')

credentials, project_id = google.auth.default()

certmanager_resource_id = f"projects/{project_id}/locations/global"


asset_parent = f"organizations/{org_id}"
content_type_list = ["RESOURCE", "ACCESS_POLICY", "IAM_POLICY"]

# PROFILE is the Profile level i.e. "Profile 1", "Profile 2", etc.
# DATA_CLASSIFICATION is "Unclassified", "Protected A", etc
tag_key_list = ["PROFILE", "profile", "DATA_CLASSIFICATION", "data_classification"]

project_profile_tag_key_list = ["PROJECT_PROFILE", "project_profile"]

lock = threading.Lock()
scc_parent = f"organizations/{org_id}/sources/-"
scc_logs = []
logger_resource_name = [f"organizations/{org_id}"]
customer_id_parent = f"customers/{customer_id}"
days_back_admin = 90
hours_back_cloudaudit = 6
f_name = f"results-{org_name}.json"
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

gcs_folders = [
    'guardrail-01', 'guardrail-02', 'guardrail-03', 'guardrail-04', 'guardrail-05',
    'guardrail-06', 'guardrail-07', 'guardrail-08', 'guardrail-09', 'guardrail-10',
    'guardrail-11', 'guardrail-12', 'guardrail-13', 
]

gcs_folder_objects = []

credentials, project_id = google.auth.default()

logger_export_adminapis_admin = (
    f'logName="organizations/{org_id}/logs/cloudaudit.googleapis.com%2Factivity"'
    f' AND protoPayload.serviceName="admin.googleapis.com"'
    f' AND timestamp>="{(datetime.now(timezone.utc) - timedelta(days=days_back_admin)).isoformat()}"'
)

logger_export_adminapis_cloudaudit = (
    f'logName="organizations/{org_id}/logs/cloudaudit.googleapis.com%2Factivity"'
    f' AND timestamp>="{(datetime.now(timezone.utc) - timedelta(hours=hours_back_cloudaudit)).isoformat()}"'
)

# Schema for JSON outputs
class JSONObjectSchema(Schema):
    policy_version = fields.Str(dump_default=policy_version)
    app_version = fields.Str(dump_default=app_version)
    timestamp = fields.Str(dump_default=timestamp)
    profile_level = fields.Str(dump_default=profile_level)
    organization = fields.Str(dump_default=org_name)
    organization_id = fields.Str(dump_default=org_id)
    tenant_domain = fields.Str(dump_default=tenant_domain)
    guardrail = fields.Str()
    validation = fields.Str()
    description = fields.Str()
    check_type = fields.Str()
    status = fields.Str()
    msg = fields.Str()
    asset_name = fields.Str()
    proj_parent = fields.Str()
    proj_profile = fields.Str()
    

app = Flask(__name__)


#----------------------------------------
# HELPER FUNCTIONS
#----------------------------------------
def decode_cert(cert_data):
    """Decodes cert data
    Args:
        cert_data: encrypted cert data (string)

    Returns:
        cryptography.x509.Certificate class
    """
    try:
        # you need to perform a str.encode on the data as we're not reading a file and passing in a string instead
        cert = x509.load_pem_x509_certificate(str.encode(cert_data))
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(str.encode(cert_data))
        except ValueError:
            print("Error: Cloud not decode certificate. Invalid PEM or DER format.")
            return None

    return cert


def extract_issuer(cert):
    """Extract Issuer Org info
    Args:
        cert: cert (cryptography.x509.Certificate)

    Returns:
        Certificate issuer org (string)
    """
    if cert is None:
        return

    issuer_info = cert.issuer.rfc4514_string()
    split_fields = issuer_info.split(",")
    org_regex = r"\bO=[^\s]+"   # matches O=cert_issuer_org_name_here

    for i in range(len(split_fields)):
        org_regex_match = re.findall(org_regex, split_fields[i])
        if org_regex_match != []:
            match = split_fields[i]
            issuer_org = match.split("=")[1]    # discard the 0= part

    return issuer_org


def gcs_blob_delete(project_id, bucket_name, blob_list):
    """Delete blobs from GCS bucket
    Args:
        project_id: GCP project ID
        bucket_name: Name of GCS bucket (do NOT need to prefix with gs://)
        blob_list: Comma-separated list of file names

    Returns:
        None
    """
    storage_client = storage.Client(credentials=credentials, project=project_id)
    bucket = storage_client.bucket(bucket_name)

    for blob_name in blob_list:
        try:
            blob = bucket.blob(blob_name)
            blob.delete()
        except NotFound:
            logger.info(f"Blob {blob_name} not found in bucket {bucket_name}")


#----------------------------------------
# DATA EXPORT FUNCTIONS
#----------------------------------------
# Export assets to GCS
def export_assets_to_gcs(asset_parent, content_type):
    client = asset_v1.AssetServiceClient(credentials=credentials)
    export_output_name = f"temp_{content_type}.ndjson"
    export_output_path = f"gs://{bucket_name}/{export_output_name}"
    output_config = {"gcs_destination": {"uri": export_output_path}}

    logger.info(f"Exporting {content_type} to {export_output_path}")
    operation = client.export_assets(
        request={"parent": asset_parent, "output_config": output_config, "content_type": content_type}
    )
    operation.result()
    logger.info(f"Completed export for {content_type}")
    return export_output_name

# Batch download JSON from GCS
def download_from_gcs(bucket_name, file_names):
    def process_file(file_name):
        try:
            logger.info(f"Downloading {file_name} from Cloud Storage")
            storage_client = storage.Client(credentials=credentials, project=project_id)
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(file_name)

            # Download and parse JSON data
            json_data = blob.download_as_string().decode("utf-8").splitlines()
            parsed_data = [json.loads(line) for line in json_data if line.strip()]

            logger.info(f"Downloaded {file_name}")
            return parsed_data
        except Exception as e:
            logger.error(f"Error processing {file_name}: {e}")
            return []

    combined_data = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(process_file, file_name): file_name for file_name in file_names}
        for future in concurrent.futures.as_completed(futures):
            try:
                combined_data.extend(future.result())
            except Exception as e:
                logger.error(f"Error in batch processing: {e}")
    return combined_data

# Batch upload JSON to GCS
def batch_upload_json_to_gcs(bucket_name, upload_tasks):
    def upload_task(task):
        json_data, file_name = task
        upload_json_to_gcs(bucket_name, json_data, file_name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(upload_task, task): task for task in upload_tasks}
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error in batch upload: {e}")

# Upload JSON to GCS
def upload_json_to_gcs(bucket_name, json_data, file_name):
    try:
        logger.info(f"Uploading {file_name} to Cloud Storage")
        client = storage.Client(credentials=credentials, project=project_id)
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(file_name)

        data = json.dumps(json_data, separators=(',', ':'))
        blob.upload_from_string(data)
        logger.info(f"Uploaded {file_name} to Cloud Storage")
    except Exception as e:
        logger.error(f"Error uploading {file_name}: {e}")

# Parallelized asset export
def parallelized_asset_export(asset_parent, content_type_list):
    exported_files = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(export_assets_to_gcs, asset_parent, content_type): content_type
            for content_type in content_type_list
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                exported_files.append(future.result())
            except Exception as e:
                logger.error(f"Error in asset export: {e}")

    return download_from_gcs(bucket_name, exported_files)

# SCC Export
def scc_export(scc_logs, scc_parent):
    logger.info("Compiling SCC Data")
    scc_client = securitycenter.SecurityCenterClient(credentials=credentials)
    finding_result_iterator = scc_client.list_findings(
        request={"parent": scc_parent, "filter": 'state="ACTIVE"'}
    )
    for finding_result in finding_result_iterator:
        keyword_ideas_json = MessageToDict(finding_result._pb)
        scc_logs.append(keyword_ideas_json)
    return json.dumps(scc_logs, separators=(',', ':'))

# Logger export
def logger_export(filter_str1, filter_str2, logger_resource_name):
    logger.info("Compiling Logging Data")
    client = google.cloud.logging.Client(credentials=credentials)
    logs = []
    for entry in client.list_entries(filter_=filter_str1, resource_names=logger_resource_name):
        logs.append(entry.to_api_repr())
    for entry in client.list_entries(filter_=filter_str2, resource_names=logger_resource_name):
        logs.append(entry.to_api_repr())
    return json.dumps(logs, separators=(',', ':'))

# GCS folder export
def gcs_export(gcs_folders, gcs_folder_objects, bucket_name):
    logger.info("Compiling GCS Data")
    client = storage.Client(credentials=credentials, project=project_id)
    for folder_name in gcs_folders:
        blobs = client.list_blobs(bucket_name, prefix=f"{folder_name}/")
        files = [blob.name for blob in blobs]
        gcs_folder_objects.append({"name": folder_name, "files": files})
    return json.dumps(gcs_folder_objects, separators=(',', ':'))

# Essential Contacts export
def essentialcontacts_export(asset_parent):
    """Get Essential Contacts
    Args:
        asset_parent: org ID

    Returns:
        List of Essential Contacts
    """
    logger.info("Compiling Essential Contacts Data")
    ec_client = build("essentialcontacts", "v1", credentials=credentials, cache_discovery=False)
    request = ec_client.organizations().contacts().list(parent=asset_parent)
    results = request.execute()
    ec_contacts = []
    try:
        for contact in results["contacts"]:
            ec_contacts.append(contact)
    except KeyError:
        logger.info("WARNING: No Essential Contacts are setup in org")
        pass
    return json.dumps(ec_contacts, separators=(',', ':'))

# Workspace export
def workspace_users_export(ws_domain):
    """Get Google Workspace users
    Args:
        ws_domain: Workspace domain (if any) 

    Returns:
        Workspace users' (config) info
    """
    logger.info("Compiling Workspace User Data")
    ws_users = []
    # if ws_domain is NOT set
    if ws_domain == '':
        logger.info("No Workspace domain set -- cannot query Workspace user data")
        return json.dumps([])
    # if ws_domain is set
    try:
        ws_client = build("admin", "directory_v1", credentials=credentials, cache_discovery=False)
        request = ws_client.users().list(domain=ws_domain)
        results = request.execute()
        ws_users.append(results)
    except Exception as e:
        if e.resp.status == 403:
            logger.error("Permission denied. Ensure you have the necessary permissions/scopes")
        elif e.resp.status >= 500:
            logger.error("Server error, try again later")
        else:
            logger.error(f"An unexpected HTTP error occurred: {e}")
    except google.auth.exceptions.GoogleAuthError as auth_error:
        logger.error(f"Authentication error: {auth_error}")
    return json.dumps(ws_users, separators=(',', ':'))


# Access Context Manager policy access levels export
# NOT BEING USED
def acm_export(asset_parent):
    """Get Access Context Manager policies
    Args:
        asset_parent: org ID 

    Returns:
        List of ACM policies
    """
    logger.info("Compiling Access Context Manager Data")
    acm_client = build("accesscontextmanager", "v1", credentials=credentials, cache_discovery=False)
    request = acm_client.accessPolicies().list(parent=asset_parent)
    results = request.execute()
    # get a list of ACM policies that is not the "default policy"
    acm_policy_list = []
    for policy in results["accessPolicies"]:
        if policy["title"] != "default policy":
            acm_policy_list.append(policy["name"])
    # ACM access levels contain the IP CIDR restrictions
    acm_access_levels = []
    for acm_policy in acm_policy_list:
        request = acm_client.accessPolicies().accessLevels().list(parent=acm_policy)
        results = request.execute()
        acm_access_levels.append({"kind": "accesscontextmanager#accesspolicy", "policyName": acm_policy, "config": results})
    return json.dumps(acm_access_levels, separators=(',', ':'))

# Auth logs of users from Cloud Logging export
def user_auth_ip_export(hours):
    """Retrieves project authentication logs in the last X hours
    Args:
        hours (int): number of hours to filter logs

    Returns:
        A list of authentication log entries (if any)
    """
    auth_log_client = google.cloud.logging.Client(project=project_id)
    now = datetime.now(timezone.utc)
    time_hours_ago = now - timedelta(hours=hours)
    filter_str = f'timestamp >= "{time_hours_ago.isoformat()}" \
                   AND logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity" \
                   -protoPayload.serviceName="iam.googleapis.com" \
                   -protoPayload.serviceName="k8s.io"'
    try:
        entries = auth_log_client.list_entries(filter_=filter_str)
    except Exception as e:
        logger.error(f"Error retrieving logs from Cloud Logging: {e}")
    user_auth_logs_list = []
    try:
        for entry in entries:
            principal_email = entry.payload['authenticationInfo']['principalEmail']
            source_ip = entry.payload['requestMetadata']['callerIp']
            caller_user_agent = entry.payload['requestMetadata']['callerSuppliedUserAgent']
            # excluding cloudshell, gsa and internal auths
            if 'environment/devshell' not in caller_user_agent and not principal_email.endswith('iam.gserviceaccount.com') and source_ip != 'private':
                # insertId can be used to find specific log entry
                user_auth_logs_list.append({"kind": "logging#user#auth", "insertId": entry.insert_id, "principalEmail": principal_email, "sourceIp": source_ip, "timestamp": entry.timestamp.isoformat()})
    except KeyError:
        pass
    return json.dumps(user_auth_logs_list, separators=(',', ':'))

# Org Admin Group member export
def org_admin_group_member_export(customer_id_parent, ws_domain, org_admin_group_email):
    """Get Org Admin group member data
    Args:
        customer_id_parent: customer ID
        ws_domain: Workspace domain
        org_admin_group_email: Org admin group email (if none provided, assumes default of gcp-organization-admins@{ws_domain})

    Returns:
        List of Org Admin members
    """
    logger.info("Compiling Org Admin Group Member Data")
    # if ws_domain is NOT set
    if ws_domain == '':
        logger.info("No Workspace domain set -- cannot query Org Admin Group member data")
        return json.dumps([])
    cloudidentity_client = build("cloudidentity", "v1", credentials=credentials, cache_discovery=False)
    # find group name
    request = cloudidentity_client.groups().list(parent=customer_id_parent)
    results = request.execute()
    try:
        for group in results["groups"]:
            if group["groupKey"]["id"] == org_admin_group_email:
                group_name = group["name"]
        # find group membership
        request = cloudidentity_client.groups().memberships().list(parent=group_name)
        results = request.execute()
        member_list = []
        for membership in results["memberships"]:
            # prepending "user:" to the user email to align with output from GCP role bindings
            user = "user:" + membership["preferredMemberKey"]["id"]
            member_list.append(user)
        # compiling final output JSON
        org_admin_member_list = []
        org_admin_member_list.append({"kind": "cloudidentity#groups#membership", "groupName": group_name, "groupEmail": f"gcp-organization-admins@{ws_domain}", "members": member_list})
    except KeyError:
        logger.error(f"Please validate permissions. KeyError encountered listing group membership for group: {group}")
        return json.dumps([])
    except KeyError:
        logger.error("Please validate permissions. KeyError encountered listing groups")
        return json.dumps([])
    except UnboundLocalError:
        logger.error("Org Admin Group not found. Please validate your ORG_ADMIN_GROUP_EMAIL input")
        return json.dumps([])
    return json.dumps(org_admin_member_list, separators=(',', ':'))

# Resource Tag Value export
def org_resource_tag_value_export(customer_id_parent, tag_key_list):
    """Get assets with Tags
    Args:
        customer_id_parent: customer ID
        tag_key_list: List of tag keys to filter for

    Returns:
        List of assets tagged with provided tag keys
    """
    logger.info("Compiling Org Resource Direct Tagging Data")
    asset_client = asset_v1.AssetServiceClient(credentials=credentials)
    tagged_resources_list = []
    for tag_key in tag_key_list:
        # querying for tagKeys for finding directly attached ONLY
        # querying for effectiveTagKeys for finding directly attached or inherited tags, however, not all resources support effectiveTagKeys
        request = asset_v1.SearchAllResourcesRequest(scope=customer_id_parent, query=f"effectiveTagKeys:{tag_key}")
        page_result = asset_client.search_all_resources(request=request)
        for response in page_result:
            for i in range(len(response.tags)):
                if response.tags[i].tag_key.endswith(tag_key):
                    tagged_object = {"kind": "cloudresourcemanager#tagged#asset", "name": response.name, "parent": response.parent_full_resource_name, "asset_type": response.asset_type, "display_name": response.display_name, "location": response.location, "tag_key": response.tags[i].tag_key, "tag_value": response.tags[i].tag_value}
                    if tagged_object not in tagged_resources_list:
                        tagged_resources_list.append(tagged_object)
                    else:
                        pass
                else:
                    pass
    return json.dumps(tagged_resources_list, separators=(',', ':'))

# Certificate Manager Cert Issuer export - applies only to Direct Tags
def certmanager_export(certmanager_resource_id):
    """Get Certs data
    Args:
        certmanager_resource_id: project and location of the certificate

    Returns:
        List of Certificate Manager certificates with issuer info
    """
    service = build('certificatemanager', 'v1', credentials=credentials, cache_discovery=False)
    request = service.projects().locations().certificates().list(parent=certmanager_resource_id)
    results = request.execute()
    certificates_list = []
    try:
        for i in range(len(results["certificates"])):
            cert_data = results["certificates"][i]["pemCertificate"]
            decoded_cert = decode_cert(cert_data)
            issuer_org = extract_issuer(decoded_cert)
            if issuer_org is None:
                certificates_list.append({"kind": "certificatemanager#certificate#issuer", "name": results["certificates"][i]["name"], "issuer_org": "NONE"})
            else:
                certificates_list.append({"kind": "certificatemanager#certificate#issuer", "name": results["certificates"][i]["name"], "issuer_org": issuer_org})
    except KeyError:
        logger.info(f"No certificates found in project: {project_id}")
        return json.dumps([])
    return json.dumps(certificates_list, separators=(',', ':'))

def breakglass_auth_export(days, breakglass_user_email):
    """Retrieves Organizationa authentication logs in for breakglass user account in the last X days
    Args:
        days (int): number of days to filter logs
        breakglass_user_email (string): breakglass user email

    Returns:
        A list of authentication log entries (if any)
    """
    auth_log_client = google.cloud.logging.Client()
    now = datetime.now(timezone.utc)
    time_days_ago = now - timedelta(days=days)
    filter_str = f'timestamp >= "{time_days_ago.isoformat()}" \
                   AND logName="organizations/{org_id}/logs/cloudaudit.googleapis.com%2Factivity" \
                   AND protoPayload.authenticationInfo.principalEmail="{breakglass_user_email}" \
                   -protoPayload.serviceName="iam.googleapis.com" \
                   -protoPayload.serviceName="k8s.io"'
    try:
        entries = auth_log_client.list_entries(resource_names=[asset_parent], filter_=filter_str)
    except Exception as e:
        logger.error(f"Error retrieving logs: {e}")
    breakglass_auth_logs_list = []
    try:
        for entry in entries:
            principal_email = entry.payload['authenticationInfo']['principalEmail']
            breakglass_auth_logs_list.append({"kind": "logging#breakglass#auth", "principalEmail": principal_email, "timestamp": entry.timestamp.isoformat()})
    except KeyError:
        pass
    return json.dumps(breakglass_auth_logs_list, separators=(',', ':'))

# Project profile tag export
def org_project_profile_tag_export(asset_parent, project_profile_tag_key_list):
    """Get projects with profile tags that override org profile level
    Args:
        asset_parent: org ID (formatted)
        project_profile_tag_key_list: List of tag keys to filter for

    Returns:
        Custom list of projects tagged with provided tag keys
    """
    logger.info("Compiling Org Project with Overriding Profile Tags")
    asset_client = asset_v1.AssetServiceClient(credentials=credentials)
    included_assets = [
        "cloudresourcemanager.googleapis.com/Project",
    ]
    tagged_projects_list = []
    for tag_key in project_profile_tag_key_list:
        # querying for tagKeys for finding directly attached ONLY
        # querying for effectiveTagKeys for finding directly attached or inherited tags, however, not all resources support effectiveTagKeys
        request = asset_v1.SearchAllResourcesRequest(scope=asset_parent, query=f"effectiveTagKeys:{tag_key}")
        page_result = asset_client.search_all_resources(request=request)
        for response in page_result:
            if response.asset_type in included_assets:
                for i in range(len(response.tags)):
                    if response.tags[i].tag_key.endswith(tag_key):
                        tagged_project = {"kind": "cloudresourcemanager#tagged#project", "name": response.name, "parent": response.parent_full_resource_name, "asset_type": response.asset_type, "display_name": response.display_name, "tag_key": response.tags[i].tag_key, "tag_value": response.tags[i].tag_value}
                        if tagged_project not in tagged_projects_list:
                            tagged_projects_list.append(tagged_project)
                        else:
                            pass
                    else:
                        pass
    return json.dumps(tagged_projects_list, separators=(',', ':'))

# Main API endpoint
@app.route('/', methods=['GET'])
def upload_json():
    logger.info("Starting CaC Compliance Evaluation")
    overall_start_time = time.time()

    # Step 1: Export assets in parallel
    logger.info("Step 1 of 13 - Export assets in parallel")
    asset_data = parallelized_asset_export(asset_parent, content_type_list)

    # Prepare batch upload tasks
    upload_tasks = [
        (asset_data, "data/asset.json")
    ]

    # Step 2: SCC export
    logger.info("Step 2 of 13 - SSC export")
    scc_data = json.loads(scc_export(scc_logs, scc_parent))
    upload_tasks.append((scc_data, "data/scc.json"))

    # Step 3: Logger export
    logger.info("Step 3 of 13 - Logger export")
    logger_data = json.loads(logger_export(logger_export_adminapis_admin, logger_export_adminapis_cloudaudit, logger_resource_name))
    upload_tasks.append((logger_data, "data/logger.json"))

    # Step 4: GCS folder export
    logger.info("Step 4 of 13 - GCS folder export")
    gcs_folder_data = json.loads(gcs_export(gcs_folders, gcs_folder_objects, bucket_name))
    upload_tasks.append((gcs_folder_data, "data/gcs.json"))

    # Step 5: Essential Contacts export
    logger.info("Step 5 of 13 - Essential Contacts export")
    essentialcontacts_data = json.loads(essentialcontacts_export(asset_parent))
    upload_tasks.append((essentialcontacts_data, "data/essentialcontacts.json"))

    # Step 6: Workspace Users export
    logger.info("Step 6 of 13 - Workspace Users export")
    ws_user_data = json.loads(workspace_users_export(ws_domain))
    upload_tasks.append((ws_user_data, "data/ws_users.json"))

    # Step 7: 25 hour GCP User auth data export
    logger.info("Step 7 of 13 - GCP User Auth data export")
    user_auth_data = json.loads(user_auth_ip_export(25))
    upload_tasks.append((user_auth_data, "data/user_auth_data.json"))

    # Step 8: Org Admin Group members export
    logger.info("Step 8 of 13 - Org Admin Group members export")
    org_admin_group_member_data = json.loads(org_admin_group_member_export(customer_id_parent, ws_domain, org_admin_group_email))
    upload_tasks.append((org_admin_group_member_data, "data/org_admin_group_members.json"))

    # Step 9: Asset tags export
    logger.info("Step 9 of 13 - Asset tags export")
    org_resource_tag_value_data = json.loads(org_resource_tag_value_export(asset_parent, tag_key_list))
    upload_tasks.append((org_resource_tag_value_data, "data/org_resource_tag_value_export.json"))

    # Step 10: Cert Manager export
    logger.info("Step 10 of 13 - Cert manager export")
    certmanager_data = json.loads(certmanager_export(certmanager_resource_id))
    upload_tasks.append((certmanager_data, "data/certmanager_export.json"))

    # Step 11: 366 days Breakglass Account auth data export
    logger.info("Step 11 of 13 - GCP Breakglass User Auth data export")
    breakglass_auth_data = json.loads(breakglass_auth_export(366, breakglass_user_email))
    upload_tasks.append((breakglass_auth_data, "data/breakglass_auth_data.json"))

    # Step 12: Project profile tag data
    logger.info("Step 12 of 13 - Project Override Profile tag export")
    org_project_tag_data = json.loads(org_project_profile_tag_export(asset_parent, project_profile_tag_key_list))
    upload_tasks.append((org_project_tag_data, "data/org_project_tag_data.json"))

    # Step 13: Compile final data
    logger.info("Step 13 of 13 - Compiling final data")
    final_list = asset_data + scc_data + logger_data + gcs_folder_data + essentialcontacts_data + ws_user_data + user_auth_data + org_admin_group_member_data + org_resource_tag_value_data + certmanager_data + breakglass_auth_data + org_project_tag_data
    compiled_data = {"input": {"data": final_list}}
    upload_tasks.append((compiled_data, "data/compiled.json"))

    # Perform batch upload
    logger.info("Performing batch upload")
    batch_upload_json_to_gcs(bucket_name, upload_tasks)
    overall_end_time = time.time()
    duration_td = timedelta(seconds=overall_end_time - overall_start_time)
    logger.info(f"Time taken to execute operation: {duration_td}")

    time.sleep(5)
    # Evaluate compiled data
    response = requests.post("http://localhost:8181/v1/data/main/guardrail", json=compiled_data)
    if response.ok:
        response_data = response.json()
        try:
            filtered_json_objects = response_data['result']
        except KeyError:
            logger.info(f"KEYERROR - NO RESPONSE_DATA")
        filtered_json_objects = JSONObjectSchema(
            many=True).dump(filtered_json_objects)
        beautified_filtered_json_objects = json.dumps(
            filtered_json_objects, indent=1, separators=(',', ': '))
        beautified_filtered_json_objects = json.loads(
            beautified_filtered_json_objects)
        upload_json_to_gcs(bucket_name, beautified_filtered_json_objects, f_name)
        logger.info("CaC Evaluation Complete")
    else:
        logger.error(f"OPA Evaluation failed: {response.status_code}")

    # Cleanup
    logger.info("Cleaning up temp files from GCS bucket")
    blob_list = ["temp_ACCESS_POLICY.ndjson", "temp_IAM_POLICY.ndjson", "temp_RESOURCE.ndjson"]
    gcs_blob_delete(project_id, bucket_name, blob_list)

    # overall_end_time = time.time()
    # duration_td = timedelta(seconds=overall_end_time - overall_start_time)
    # logger.info(f"Time taken to execute operation: {duration_td}")
    return jsonify(message="CaC Evaluation Complete")


#----------------------------------------
# MAIN FUNCTION
#----------------------------------------
if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=port)
