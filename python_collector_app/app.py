#!/usr/local/bin/python
# -*- coding: latin-1 -*-

import google.cloud.asset_v1 as asset_v1
from google.protobuf.json_format import MessageToDict
import google.cloud.securitycenter as securitycenter
import google.cloud.logging
import google.cloud.storage as storage
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

credentials, project_id = google.auth.default()

certmanager_resource_id = f"projects/{project_id}/locations/global"


asset_parent = f"organizations/{org_id}"
content_type_list = ["RESOURCE", "ACCESS_POLICY", "IAM_POLICY"]

# PROFILE is the Profile level i.e. "Profile 1", "Profile 2", etc.
# SECURITY_CATEGORY is "Unclassified", "Protected A", etc
tag_key_list = ["PROFILE", "SECURITY_CATEGORY"]

lock = threading.Lock()
scc_parent = f"organizations/{org_id}/sources/-"
scc_logs = []
logger_resource_name = [f"organizations/{org_id}"]
customer_id_parent = f"customers/{customer_id}"
days_back_admin = 1
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
    f'protoPayload.request.query="parent=organizations/{org_id}"'
    f' AND protoPayload.serviceName="admin.googleapis.com"'
    f' AND timestamp>="{(datetime.now(timezone.utc) - timedelta(days=days_back_admin)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")}"'
    f' AND timestamp<"{(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z"))}"'
)

logger_export_adminapis_cloudaudit = (
    f'logName="organizations/{org_id}/logs/cloudaudit.googleapis.com%2Factivity"'
    f' AND timestamp>="{(datetime.now(timezone.utc) - timedelta(hours=hours_back_cloudaudit)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")}"'
    f' AND timestamp<"{(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z"))}"'
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
    ec_client = build("essentialcontacts", "v1", credentials=credentials)
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
    results = []
    # if ws_domain is NOT set
    if ws_domain == '':
        logger.info("No Workspace domain set -- cannot query Workspace user data")
        return []
    # if ws_domain is set
    try:
        ws_client = build("admin", "directory_v1", credentials=credentials)
        request = ws_client.users().list(domain=ws_domain)
        results = request.execute()
    except Exception as e:
        if e.resp.status == 403:
            logger.error("Permission denied. Ensure you have the necessary permissions/scopes")
        elif e.resp.status >= 500:
            logger.error("Server error, try again later")
        else:
            logger.error(f"An unexpected HTTP error occurred: {e}")
    except google.auth.exceptions.GoogleAuthError as auth_error:
        logger.error(f"Authentication error: {auth_error}")
    return json.dumps(results, separators=(',', ':'))


# Access Context Manager policy access levels export
def acm_export(asset_parent):
    """Get Access Context Manager policies
    Args:
        asset_parent: org ID 

    Returns:
        List of ACM policies
    """
    logger.info("Compiling Access Context Manager Data")
    acm_client = build("accesscontextmanager", "v1", credentials=credentials)
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

# Org Admin Group member export
def org_admin_group_member_export(customer_id_parent, ws_domain):
    """Get Org Admin group member data
    Args:
        customer_id_parent: customer ID
        ws_domain: Workspace domain (if any) 

    Returns:
        List of Org Admin members
    """
    logger.info("Compiling Org Admin Group Member Data")
    # if ws_domain is NOT set
    if ws_domain == '':
        logger.info("No Workspace domain set -- cannot query Org Admin Group member data")
        return []
    cloudidentity_client = build("cloudidentity", "v1", credentials=credentials)
    # find group name
    request = cloudidentity_client.groups().list(parent=customer_id_parent)
    results = request.execute()
    for group in results["groups"]:
        if group["groupKey"]["id"] == f"gcp-organization-admins@{ws_domain}":
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
    return json.dumps(org_admin_member_list, separators=(',', ':'))

# Resource Tag Value export
def org_resource_tag_value_export(customer_id_parent, tag_key_list):
    """Get assets with Tags
    Args:
        customer_id_parent: customer ID
        take_key_list: List of tag keys to filter for

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
                new_object = {"kind": "cloudresourcemanager#tagged#asset", "name": response.name, "parent": response.parent_full_resource_name, "asset_type": response.asset_type, "display_name": response.display_name, "location": response.location, "tag_key": response.tags[i].tag_key, "tag_value": response.tags[i].tag_value}
                if new_object not in tagged_resources_list:
                    tagged_resources_list.append(new_object)
                else:
                    pass
    return json.dumps(tagged_resources_list, separators=(',', ':'))

# Certificate Manager Cert Issuer export - applies only to Direct Tags
def certmanager_export(certmanager_resource_id):
    """Get assets with Tags
    Args:
        certmanager_resource_id: project and location of the certificate

    Returns:
        List of Certificate Manager certificates with issuer info
    """
    service = build('certificatemanager', 'v1')
    request = service.projects().locations().certificates().list(parent=certmanager_resource_id)
    results = request.execute()
    certificates_list = []
    for i in range(len(results["certificates"])):
        cert_data = results["certificates"][i]["pemCertificate"]
        decoded_cert = decode_cert(cert_data)
        issuer_org = extract_issuer(decoded_cert)
        if issuer_org is None:
            certificates_list.append({"kind": "certificatemanager#certificate#issuer", "name": results["certificates"][i]["name"], "issuer_org": "NONE"})
        else:
            certificates_list.append({"kind": "certificatemanager#certificate#issuer", "name": results["certificates"][i]["name"], "issuer_org": issuer_org})
    return json.dumps(certificates_list, separators=(',', ':'))


# Main API endpoint
@app.route('/', methods=['GET'])
def upload_json():
    logger.info("Starting CaC Compliance Evaluation")
    overall_start_time = time.time()

    # Step 1: Export assets in parallel
    logger.info("Step 1 of 11 - Export assets in parallel")
    asset_data = parallelized_asset_export(asset_parent, content_type_list)

    # Prepare batch upload tasks
    upload_tasks = [
        (asset_data, "data/asset.json")
    ]

    # Step 2: SCC export
    logger.info("Step 2 of 11 - SSC export")
    scc_data = json.loads(scc_export(scc_logs, scc_parent))
    upload_tasks.append((scc_data, "data/scc.json"))

    # Step 3: Logger export
    logger.info("Step 3 of 11 - Logger export")
    logger_data = json.loads(logger_export(logger_export_adminapis_admin, logger_export_adminapis_cloudaudit, logger_resource_name))
    upload_tasks.append((logger_data, "data/logger.json"))

    # Step 4: GCS folder export
    logger.info("Step 4 of 11 - GCS folder export")
    gcs_folder_data = json.loads(gcs_export(gcs_folders, gcs_folder_objects, bucket_name))
    upload_tasks.append((gcs_folder_data, "data/gcs.json"))

    # Step 5: Essential Contacts export
    logger.info("Step 5 of 11 - Essential Contacts export")
    essentialcontacts_data = json.loads(essentialcontacts_export(asset_parent))
    upload_tasks.append((essentialcontacts_data, "data/essentialcontacts.json"))

    # Step 6: Workspace Users export
    logger.info("Step 6 of 11 - Workspace Users export")
    ws_user_data = json.loads(workspace_users_export(ws_domain))
    upload_tasks.append((ws_user_data, "data/ws_users.json"))

    # Step 7: Access Context Manager (ACM) access levels export
    logger.info("Step 7 of 11 - Access Context Manager export")
    acm_data = json.loads(acm_export(asset_parent))
    upload_tasks.append((acm_data, "data/acm.json"))

    # Step 8: Org Admin Group members export
    logger.info("Step 8 of 11 - Org Admin Group members export")
    org_admin_group_member_data = json.loads(org_admin_group_member_export(customer_id_parent, ws_domain))
    upload_tasks.append((org_admin_group_member_data, "data/org_admin_group_members.json"))

    # Step 9: Asset tags export
    logger.info("Step 9 of 11 - Asset tags export")
    org_resource_tag_value_data = json.loads(org_resource_tag_value_export(asset_parent, tag_key_list))
    upload_tasks.append((org_resource_tag_value_data, "data/org_resource_tag_value_export.json"))

    # Step 10: Cert Manager export
    logger.info("Step 10 of 11 - Cert manager export")
    certmanager_data = json.loads(certmanager_export(certmanager_resource_id))
    upload_tasks.append((certmanager_data, "data/certmanager_export.json"))

    # Step 11: Compile final data
    logger.info("Step 11 of 11 - Compiling final data")
    final_list = asset_data + scc_data + logger_data + gcs_folder_data + essentialcontacts_data + ws_user_data + acm_data + org_admin_group_member_data + org_resource_tag_value_data + certmanager_data
    compiled_data = {"input": {"data": final_list}}
    upload_tasks.append((compiled_data, "data/compiled.json"))

    # Perform batch upload
    logger.info("Performing batch upload")
    batch_upload_json_to_gcs(bucket_name, upload_tasks)
    overall_end_time = time.time()
    duration_td = timedelta(seconds=overall_end_time - overall_start_time)
    logger.info(f"Time taken to execute operation: {duration_td}")

    # Evaluate compiled data
    response = requests.post("http://localhost:8181/v1/data/main/guardrail", json=compiled_data)
    if response.ok:
        filtered_json_objects = response.json().get('result', [])
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

    # overall_end_time = time.time()
    # duration_td = timedelta(seconds=overall_end_time - overall_start_time)
    # logger.info(f"Time taken to execute operation: {duration_td}")
    return jsonify(message="CaC Evaluation Complete")


#----------------------------------------
# MAIN FUNCTION
#----------------------------------------
if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=port)
