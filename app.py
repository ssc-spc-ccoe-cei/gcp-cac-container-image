#!/usr/local/bin/python
# -*- coding: latin-1 -*-

import multiprocessing
import google.cloud.asset_v1 as asset_v1
from google.protobuf.json_format import MessageToDict
import google.cloud.securitycenter as securitycenter
import google.cloud.logging
import google.cloud.storage as storage
import google.auth

from flask import Flask
from flask import jsonify
import json
from marshmallow import Schema, fields


import requests
from waitress import serve
import subprocess
import os

import logging
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

port = int(os.environ.get("PORT", 8080))

profile_level = os.environ['GC_PROFILE']
bucket_name = os.environ['GCS_BUCKET']
project = os.environ['GCP_PROJECT']
org_id = os.environ['ORG_ID']
org_name = os.environ['ORG_NAME']

branch = os.environ['BRANCH']
repo_url = os.environ['POLICY_REPO']
repo_name = repo_url.split("/")[-1]
dest_dir = "/app/policies"

asset_parent = f"organizations/{org_id}"
# content_type = ["RESOURCE"]
content_type = ["RESOURCE", "ACCESS_POLICY", "IAM_POLICY"]

asset_export_data = []

# The parent of the findings, e.g. organization/folder/project
scc_parent = f"organizations/{org_id}/sources/-"

# ssc placeholder array
scc_logs = []

logger_resource_name = [f"organizations/{org_id}"]
# howmany days to fetch from
days_back_admin = 1
hours_back_cloudaudit = 26

f_name = f"results-{org_name}.json"
export_output_name = "temp.ndjson"
export_output_path = f"gs://{bucket_name}/{export_output_name}"

timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

class JSONObjectSchema(Schema):
    timestamp = fields.Str(dump_default=timestamp)
    profile_level = fields.Str(dump_default=profile_level)
    organization = fields.Str(dump_default=org_name)
    organization_id = fields.Str(dump_default=org_id)
    guardrail = fields.Str()
    description = fields.Str()
    check_type = fields.Str()
    status = fields.Str()
    msg = fields.Str()
    asset_name = fields.Str()



output_config = {
    "gcs_destination": {
        "uri": export_output_path
    }
}

# define logger_export_adminapis_admin
logger_export_adminapis_admin = (
    f'protoPayload.request.query="parent=organizations/{org_id}"'
    f' AND protoPayload.serviceName="admin.googleapis.com"'
    f' AND timestamp>="{(datetime.now(timezone.utc) - timedelta(days=days_back_admin)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")}"'
    f' AND timestamp<"{(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z"))}"'
)

# define logger_export_adminapis_cloudaudit
logger_export_adminapis_cloudaudit = (
    f'logName="organizations/{org_id}/logs/cloudaudit.googleapis.com%2Factivity"'
    f' AND timestamp>="{(datetime.now(timezone.utc) - timedelta(hours=hours_back_cloudaudit)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")}"'
    f' AND timestamp<"{(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z"))}"'
)


# Define the list of folder names.
gcs_folders = ['guardrail-01', 'guardrail-02', 'guardrail-03', 'guardrail-04', 'guardrail-05', 'guardrail-06',
               'guardrail-07', 'guardrail-08', 'guardrail-09', 'guardrail-10', 'guardrail-11', 'guardrail-12']

# Define a list to hold the folder objects.
gcs_folder_objects = []
pool = multiprocessing.Pool()

app = Flask(__name__)



def run_server(destination):
    # Opa server mode

    subprocess.Popen(f"/app/opa run --server --addr localhost:8181 {destination}/{repo_name}/policies/ --format=values",
                     shell=True, start_new_session=True)
    time.sleep(1.0)


def clone_or_pull_repo(repo_url, dest_dir, repo_name):
    if os.path.exists(f"{dest_dir}/{repo_name}"):
        # If the destination directory exists, check if it's the correct repository
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"], cwd=f"{dest_dir}/{repo_name}", capture_output=True)
        remote_url = result.stdout.strip().decode("utf-8")
        if remote_url == repo_url:
            # If it's the correct repository, run 'git pull' to update it
            logger.info("Updating existing policies")
            subprocess.run(["git", "pull", "origin", branch],
                           cwd=f"{dest_dir}/{repo_name}")
            logger.info("Update completed.")

        else:
            # If it's not the correct repository, print an error message
            print(
                f"Destination directory already exists but is not the correct repository ({remote_url} instead of {repo_url}).")
    else:
        # If the destination directory does not exist, run 'git clone' to clone the repository
        logger.info("Policies not found, cloning repository")
        os.mkdir(dest_dir)
        subprocess.run(["git", "clone", repo_url], cwd=dest_dir)
        subprocess.run(["git", "switch", branch],
                       cwd=f"{dest_dir}/{repo_name}")
        subprocess.run(["ls", dest_dir])
        print("Cloning completed.")

# upload string to blob


def upload_json_to_gcs(bucket_name, json_data, file_name):
    logger.info(f"Uploading {file_name} to Cloud Storage")
    client = storage.Client(credentials=credentials, project=project_id)
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(file_name)

    # convert the JSON data to a string
    data = json.dumps(json_data)
    if file_name.startswith("results"):
        data = ((data[1:-1]).replace("}, {", "}{").replace('}{','}\n{'))
        
    # upload the string data to the bucket
    blob.upload_from_string(data)
    



credentials, project_id = google.auth.default()
# run opa server

clone_or_pull_repo(repo_url, dest_dir, repo_name)

run_server(dest_dir)


# asset export and data parsing section:


def opa_input_data(data):
    data = {
        "input": {
            "data": data
        }
    }
    opa_ready = json.dumps(data)
    data = json.loads(opa_ready)
    return data


def asset_export(parent, output_config, content_type):

    client = asset_v1.AssetServiceClient(
        credentials=credentials)
    operation = client.export_assets(request={"parent": parent, "output_config": output_config,
                                              "content_type": content_type})
    logger.info(f"Getting Cloud Asset Inventory metadata for content type: {content_type}")
    logger.info(operation.result())
    time.sleep(1.0)


def string_to_json(string):
    # Split the string on newline
    split_string = string.split("\n")
    # Format each split string as a separate JSON object
    json_objects = [json.loads(s) for s in split_string if s]
    # Join the JSON objects together using a comma
    return json.dumps(json_objects, separators=(',', ':'))


def download_json_from_gcs(bucket_name, file_name):
    # Connect to Google Cloud Storage
    logger.info(f"Getting {file_name} from Cloud Storage")
    storage_client = storage.Client(
        credentials=credentials, project=project_id)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)

    # Download the asset export file
    json_data = blob.download_as_string().decode("utf-8")
    # Repair the asset export to actual json
    valid_json = string_to_json(json_data)
    data = json.loads(valid_json)

    # Delete the file from GCS
    blob.delete()

    return data


# scc export function

def scc_export(scc_logs, scc_parent):
    logger.info("Compiling SCC Data")
    scc_client = securitycenter.SecurityCenterClient(
        credentials=credentials)
    finding_result_iterator = scc_client.list_findings(
        request={"parent": scc_parent, "filter": 'state="ACTIVE"'}
    )
    for i, finding_result in enumerate(finding_result_iterator):

        keyword_ideas_json = MessageToDict(finding_result._pb)
        scc_logs.append(keyword_ideas_json)
    return json.dumps(scc_logs, ensure_ascii=False, separators=(',', ': '))


def logger_export(filter_str1, filter_str2, logger_resource_name):
    # query and print all matching logs
    logger.info("Compiling Logging Data")
    client = google.cloud.logging.Client(
        credentials=credentials)
    logs = []
    for entry in client.list_entries(filter_=filter_str1, resource_names=logger_resource_name):

        logs.append(entry.to_api_repr())

    for entry in client.list_entries(filter_=filter_str2, resource_names=logger_resource_name):

        logs.append(entry.to_api_repr())

    return (json.dumps(logs, separators=(',', ': ')))

# Iterate over the list of folder names.


def gcs_export(gcs_folders, gcs_folder_objects, bucket_name):
    for folder_name in gcs_folders:
        # Get the list of files in the folder.
        file_names = get_files_in_folder(folder_name, bucket_name)
        # Create the folder object.
        folder_object = {
            "name": folder_name,
            "files": file_names
        }
        # Append the folder object to the list of folder objects.
        gcs_folder_objects.append(folder_object)
    return json.dumps(gcs_folder_objects, separators=(',', ': '))

# Define a function to retrieve the list of objects in a folder.


def get_files_in_folder(folder_name, bucket):
    logger.info("Compiling GCS Data")
    client = storage.Client(credentials=credentials, project=project_id)

    # Get a reference to the bucket containing the folder.
    bucket = client.get_bucket(bucket)
    # Get a list of blobs in the folder.
    blobs = bucket.list_blobs(prefix=folder_name + '/')
    # Extract the names of the blobs.
    file_names = [blob.name.split('/')[-1] for blob in blobs]
    # Return the list of file names.
    return file_names


# main api invocation end point:

@app.route('/', methods=['GET'])

def upload_json():
    pool.apply
    logger.info("Starting CaC Compliance Evaluation")
    # loop the asset exports
    for i in content_type:
        asset_export(asset_parent, output_config, i)
        data = download_json_from_gcs(
            bucket_name, export_output_name)
        asset_export_data.extend(data)
    # first chunk of final Opa input
    asset_data = asset_export_data
    upload_json_to_gcs(bucket_name, asset_data, "data/asset.json")
    # scc scans

    scc_data = json.loads(scc_export(scc_logs, scc_parent))
    upload_json_to_gcs(bucket_name, scc_data, "data/scc.json")
    for objf in scc_data:
        asset_data.append(objf)
    # second chunk of final Opa input

    logger_data = json.loads(logger_export(logger_export_adminapis_admin,
                                           logger_export_adminapis_cloudaudit, logger_resource_name))
    upload_json_to_gcs(bucket_name, logger_data, "data/logger.json")
    for objfg in logger_data:
        asset_data.append(objfg)

    gcs_folder_data = json.loads(gcs_export(
        gcs_folders, gcs_folder_objects, bucket_name))
    upload_json_to_gcs(bucket_name, gcs_folder_data, "data/gcs.json")
    for obj in gcs_folder_data:
        asset_data.append(obj)
    final_list = asset_data
    data = opa_input_data(final_list)
    upload_json_to_gcs(bucket_name, data, "data/compiled.json")
    logger.info("Evaluating Compiled Information")
    response = requests.post(
        "http://localhost:8181/v1/data/main/guardrail", json=data)
    if response.ok:
        response_data = response.json()
        filtered_json_objects = response_data['result']
        filtered_json_objects = JSONObjectSchema(
            many=True).dump(filtered_json_objects)
        beautified_filtered_json_objects = json.dumps(
            filtered_json_objects, indent=1, separators=(',', ': '))
        beautified_filtered_json_objects = json.loads(
            beautified_filtered_json_objects)
        upload_json_to_gcs(
            bucket_name, beautified_filtered_json_objects, f_name)
        logger.info("CaC Evaluation Complete")
    else:
        print(response.status_code)
    return jsonify(message="CaC Evaluation Complete")


# close the process pool


if __name__ == '__main__':

    serve(app, host='0.0.0.0', port=port)

