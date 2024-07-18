""" Recipe: Wiz License Usage per Project """

# pylint:disable=invalid-name

import argparse
import csv
import logging
import os
import signal
import sys
import time

from datetime import datetime, timedelta
from io import StringIO

from azure.core.exceptions import AzureError
from azure.storage.blob import BlobServiceClient

import boto3
import requests

from datetime import date

# pylint:disable=pointless-string-statement

"""
1. INTRODUCTION

This script gets Wiz license usage for each Wiz Project.
You can configure the time period to retrieve and whether to get licensing
for all or specific Projects.
The results are output to a CSV file to allow for detailed analysis.

First, ensure that all of the specified Python packages are installed.
You can install them using pip/pip3 or another Python package manager.
"""


####
# Global Variables
####


HEADERS = {'Content-Type': 'application/json'}

# Optional, for use when running behind a proxy.
# Dictionary mapping protocol to the URL of the proxy to be used.
# Example: {‘https’: ‘10.10.10.10:3128’}
# See https://requests.readthedocs.io/en/latest/api/ for details.
PROXIES = {}

"""
2. CONFIGURE CREDENTIALS

This script needs a Service Account with credentials to retrieve data.
Please create a Service Account in Wiz with "project:read" and "license:read" permissions.
Copy the credentials and set them in '', or set them as environment variables (preferred).
See https://docs.wiz.io/wiz-docs/docs/using-the-wiz-api for details.
"""

CLIENT_ID     = os.environ.get('WIZ_CLIENT_ID',     '')
CLIENT_SECRET = os.environ.get('WIZ_CLIENT_SECRET', '')

"""
3. VALIDATE THE API AND AUTH ENDPOINTS

This script needs an API endpoint to retrieve data.
Copy your API endpoint from here: https://app.wiz.io/user/profile, and set it in ''.
"""

API_URL  = os.environ.get('WIZ_API_URL', '')

AUTH_URL = 'https://auth.app.wiz.io/oauth/token'

"""
4. INPUT AND OUTPUT FILES

The script can optionally read Project names from an input CSV file.
Results are written to an output CSV file.
You can set the default filenames here, or specify filenames on the command line.
"""

DEFAULT_CSV_INPUT_FILE  = 'input_project_names.csv'
DEFAULT_CSV_OUTPUT_FILE = 'output_license_results'

# Optional, for use when running as a Lambda Function.
DEFAULT_OUTPUT_BUCKET_TYPE = os.environ.get("WIZ_OUTPUT_BUCKET_TYPE", '')
DEFAULT_OUTPUT_BUCKET_NAME = os.environ.get("WIZ_OUTPUT_BUCKET_NAME", '')


####
# Command Line Arguments
####


parser = argparse.ArgumentParser(description = 'Get Wiz License Usage per Project')
parser.add_argument(
    '--all',
    dest='all_projects',
    action='store_true',
    help='Get License Usage for all Projects (disables --csv_input_file)',
    default=False
)
parser.add_argument(
    '--days',
    dest='days_ago',
    help='Get License Usage for the last (default: 30) days',
    type=int,
    default=30
)
parser.add_argument(
    '--csv_input_file',
    dest='csv_input_file',
    help='Get License Usage only for Projects listed by name in this CSV file',
    default=DEFAULT_CSV_INPUT_FILE
)
parser.add_argument(
    '--csv_output_file',
    dest='csv_output_file',
    help='Output to this CSV file (a datetime will be appended)',
    default=DEFAULT_CSV_OUTPUT_FILE
)
parser.add_argument(
    '--include_archived',
    dest='include_archived',
    action='store_true',
    help='Include Archived Projects',
    default=False
)
parser.add_argument(
    '--bucket_name',
    dest='bucket_name',
    action='store_true',
    help='Output CSV file to this s3 Bucket - Required if bucket_type is set',
    default=DEFAULT_OUTPUT_BUCKET_NAME
)
parser.add_argument(
    '--bucket_type',
    dest='bucket_type',
    help='Output CSV file to this type of Bucket - Required if bucket_name is provided',
    action='store_true',
    default=DEFAULT_OUTPUT_BUCKET_TYPE
)
parser.add_argument(
    '--use_billing_codes',
    help='Use billing codes defined in the Additional Identifiers property of \
        Projects (example: billing_code=ABC123)',
    default=False
)
args = parser.parse_args()

# The --all argument disables the --csv_input_file argument.
if args.all_projects:
    args.csv_input_file = ''


####
# Library Methods
####


def signal_handler(_signal_received, _frame):
    """ Control-C """
    print("\nExiting")
    sys.exit(0)


def request_wiz_api_token():
    """ Retrieve an OAuth access token to be used with the Wiz API """
    token = None
    request_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    request_data = {
        'audience':     'wiz-api',
        'grant_type':   'client_credentials',
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(url=AUTH_URL, headers=request_headers,
                             proxies=PROXIES, data=request_data, timeout=60)
    if response.ok:
        try:
            response_json = response.json()
            token = response_json.get('access_token')
            if not token:
                response_message = response_json.get('message')
                # pylint:disable=broad-exception-raised
                raise Exception(f'Error retrieving token from the Wiz API: {response_message}')
            HEADERS['Authorization'] = f'Bearer {token}'
        except ValueError as exception:
            # pylint:disable=broad-exception-raised,raise-missing-from
            raise Exception(f'Error parsing Wiz API response: {exception}')
    else:
        if retryable_response_status_code(response.status_code):
            # pylint:disable=broad-exception-raised,line-too-long
            raise Exception(f'Error (retryable) authenticating to the Wiz API: {response.status_code}')
        # pylint:disable=broad-exception-raised
        raise Exception(f'Error authenticating to the Wiz API: {response.status_code} - {response}')
    return token


def query_wiz_api(api_query, api_query_variables):
    """ Query WIZ API with Pagination and Retries with Exponential Waits """
    exponential_waits = [1, 2, 4, 8, 16, 32]
    query_result = {}
    page_info = {'hasNextPage': True}
    while page_info['hasNextPage']:
        request_data = {'query': api_query, 'variables': api_query_variables}
        response = requests.post(url=API_URL, headers=HEADERS, proxies=PROXIES,
                                 json=request_data, timeout=300)
        if response.ok:
            try:
                page_result = response.json()
            except ValueError as exception:
                # pylint:disable=broad-exception-raised,raise-missing-from
                raise Exception(f'Error parsing Wiz API response: {exception}')
        while retryable_response_status_code(response.status_code):
            for exponential_wait in exponential_waits:
                time.sleep(exponential_wait)
                response = requests.post(url=API_URL, headers=HEADERS, proxies=PROXIES,
                                         json=request_data, timeout=300)
                if response.ok:
                    try:
                        page_result = response.json()
                    except ValueError as exception:
                       # pylint:disable=broad-exception-raised,raise-missing-from
                        raise Exception(f'Error parsing Wiz API response: {exception}')
        if not response.ok:
            # pylint:disable=broad-exception-raised,raise-missing-from
            raise Exception(f'Error querying Wiz API: {response.status_code} - {response}')
        query_key = list(page_result['data'].keys())[0]
        if query_result:
            query_result['data'][query_key]['nodes'].extend(page_result['data'][query_key]['nodes'])
        else:
            query_result = page_result
        if 'pageInfo' in page_result['data'][query_key]:
            page_info = page_result['data'][query_key]['pageInfo']
            api_query_variables['after'] = page_info['endCursor']
        else:
            page_info = {'hasNextPage': False}
    return query_result


def retryable_response_status_code(status_code):
    """ Parse a status code """
    retry_status_codes = [425, 429, 500, 502, 503, 504]
    result = False
    if int(status_code) in retry_status_codes:
        result = True
    return result


####
# Get Projects
####


# GraphQL query to execute.

project_query = """
    query ProjectsTable(
        $filterBy: ProjectFilters
        $first: Int
        $after: String
        $orderBy: ProjectOrder
      ) {
        projects(
          filterBy: $filterBy
          first: $first
          after: $after
          orderBy: $orderBy
        ) {
          nodes {
            id
            name
            archived
            businessUnit
            identifiers
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
"""

# Variables for the GraphQL query to execute.

project_query_variables = {
    "first": 100,
    "filterBy": {
        "includeArchived": args.include_archived
    },
    "maxResults": 100,
    "quick": False
}


####
# Get License Usage
####


# GraphQL query to execute.

license_query = """
query WorkloadLicensesUsage(
    $startDate: DateTime!
    $endDate: DateTime!
    $maxResults: Int
    $project: [String!]
  ) {
    billableWorkloadTrend(
      startDate: $startDate
      endDate: $endDate
      maxResults: $maxResults
      project: $project
    ) {
      averageVirtualMachineCount
      averageContainerHostCount
      averageServerlessCount
      averageServerlessContainerCount
      accumulatedSensorCount
      averageRegistryContainerImageScanCount
      accumulatedBucketScanCount
      accumulatedIaasDatabaseScannedGB
      accumulatedPaasDatabaseScannedGB
      accumulatedNonOSDiskScansCount
      totalWorkloadCount
    }
  }
"""

# Variables for the GraphQL query to execute.

license_query_variables = {
    'startDate':            "",
    'endDate':              "",
    "maxResults":         100,
    "includeSensorCount": True,
    "project":            []
}


# Wiz uses 7:00 AM as a specific time to query Workload Licenses Usage.
# For these snapshots, we do not need to be as specific.

def get_query_dates():
    """ Query Dates as Strings """

    now = datetime.now()
    end_datetime   = now.replace(microsecond=0)
    start_datetime = end_datetime - timedelta(days=args.days_ago)
    return {'startDate': f'{start_datetime.isoformat()}.000Z',
            'endDate': f'{end_datetime.isoformat()}.000Z'}

def write_blob(csv_output_file, output_file_name):
    """ Write CSV file to BLOB """
    connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    if not connect_str:
        logging.error('ERROR: No connection string defined as env \
                      AZURE_STORAGE_CONNECTION_STRING')
        sys.exit(1)
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        blob_client = blob_service_client.get_blob_client(container=DEFAULT_OUTPUT_BUCKET_NAME,
                                                          blob=output_file_name)
        csv_output_file.seek(0)
        blob_client.upload_blob(csv_output_file.read())
    except AzureError as e:
        logging.error("ERROR: %s", e)

def write_s3(csv_output_file, output_file_name):
    """ Write CSV file to S3 """
    csv_output_file.seek(0)
    s3 = boto3.client('s3')
    s3.put_object(Body=csv_output_file.read(), Bucket=args.bucket_name, Key=output_file_name)

# Use the Additional Identifiers property of a Project to store Billing Code,
# expecting one element of the array of identifiers to be in the following format.
#
# Example: billing_code=ABC123
#
# An alternative would be to use the 'businessUnit' property of a Project to store Billing Code.

def get_billing_code_from_project_identifiers(project):
    """ Read Billing Code from Project 'identifiers' """

    for identifier in project['identifiers']:
        k_v = identifier.split('=')
        if len(k_v) == 2:
            k = k_v[0].lstrip().rstrip().lower()
            if k == "billing_code":
                return k_v[1].lstrip().rstrip()
    return project['name']


####
# Main
####


# pylint:disable=too-many-locals,too-many-statements

def main():
    """ Wiz License Usage per Project """

    logging.basicConfig(level = logging.INFO, format='%(message)s')

    if (args.bucket_name and not args.bucket_type) or (not args.bucket_name and args.bucket_type):
        logging.error('--bucket_name and --bucket_type are co-dependant')
        sys.exit(1)

    logging.info('Getting Wiz License Usage for the last %s days ...', args.days_ago)

    query_dates = get_query_dates()
    license_query_variables['startDate'] = query_dates['startDate']
    license_query_variables['endDate']   = query_dates['endDate']
    output_file_name = f"{args.csv_output_file}_{query_dates['endDate'].split('.')[0]}.csv".replace(':','-')
    input_project_names = []
    csv_output = []

    # Get licensing only for Projects named in this "CSV" file.
    if os.path.isfile(args.csv_input_file):
        logging.info('Reading input file %s ...', args.csv_input_file)
        with open(args.csv_input_file, 'r', encoding='utf8') as csv_input_file:
            for row in csv_input_file:
                input_project_names.append(row.strip())

    if args.bucket_name:
        # Create an in-memory text stream (a file-like object).
        csv_output_file = StringIO()
    else:
        # pylint:disable=consider-using-with
        csv_output_file = open(output_file_name, 'w', encoding='utf8')

    csv_writer = csv.writer(csv_output_file)
    csv_writer.writerow([
        'billing_code',
        'project_name',
        'project_id',
        'averageVirtualMachineCount',
        'averageContainerHostCount',
        'averageServerlessCount',
        'averageServerlessContainerCount',
        'accumulatedSensorCount',
        'averageRegistryContainerImageScanCount',
        'accumulatedBucketScanCount',
        'accumulatedIaasDatabaseScannedGB',
        'accumulatedPaasDatabaseScannedGB',
        'accumulatedNonOSDiskScansCount',
        'totalWorkloadCount',
        'startDate',
        'endDate'
    ])

    logging.info('Getting Wiz API Token ...')
    request_wiz_api_token()

    logging.info('Getting Wiz Projects ...')
    projects_result = query_wiz_api(project_query, project_query_variables)
    projects = projects_result['data']['projects']['nodes']

    target_projects = len(input_project_names) or len(projects)

    logging.info('Getting License Usage for %s of %s Wiz Projects ...',
                 target_projects, len(projects))
    logging.info('')

    for project in projects:
        if input_project_names and project['name'] not in input_project_names:
            continue
        if not project['name'].startswith("lic-"):
            continue
        license_query_variables['project'] = [project['id']]
        billable_workloads = query_wiz_api(license_query,
                                           license_query_variables)['data']['billableWorkloadTrend']
        if args.use_billing_codes:
            billing_code = get_billing_code_from_project_identifiers(project)
        else:
            billing_code = ''
        logging.info('- Project ID: %s - Project Name: %s - Workload Count: %s',
                     project['id'], project['name'], billable_workloads['totalWorkloadCount'])
        csv_line = [
            billing_code,
            project['name'],
            project['id'],
            billable_workloads['averageVirtualMachineCount'],
            billable_workloads['averageContainerHostCount'],
            billable_workloads['averageServerlessCount'],
            billable_workloads['averageServerlessContainerCount'],
            billable_workloads['accumulatedSensorCount'],
            billable_workloads['averageRegistryContainerImageScanCount'],
            billable_workloads['accumulatedBucketScanCount'],
            billable_workloads['accumulatedIaasDatabaseScannedGB'],
            billable_workloads['accumulatedPaasDatabaseScannedGB'],
            billable_workloads['accumulatedNonOSDiskScansCount'],
            billable_workloads['totalWorkloadCount'],
            query_dates['startDate'].split('.')[0],
            query_dates['endDate'].split('.')[0]
        ]
        csv_output.append(csv_line)

    csv_writer.writerows(csv_output)

    logging.info('')
    if args.bucket_name:
        # Seek back to beginning of the in-memory text stream (a file-like object)
        # before the read() in put_object().
        csv_output_file.seek(0)
        #s3 = boto3.client('s3')
        #s3.put_object(Body=csv_output_file.read(), Bucket=args.bucket_name, Key=output_file_name)
        if args.bucket_type == 'S3':
            write_s3(csv_output_file, output_file_name)
        elif args.bucket_type == 'BLOB':
            write_blob(csv_output_file, output_file_name)
        logging.info('Done, detailed results written to bucket: Bucket: %s Key: %s',
                     args.bucket_name, output_file_name)
    else:
        logging.info('Done, detailed results written to: %s', output_file_name)

    csv_output_file.close()
    logging.info('')
    return f'detailed results written to: {output_file_name}'


####
# Entrypoint
####

if __name__ == '__main__':
    signal.signal(signal.SIGINT,signal_handler)
    main()


"""
5. RUN THE SCRIPT

You can now run the script to retrieve the results!

Examples:

python3 wiz_license_usage_per_project.py
python3 wiz_license_usage_per_project.py --all

Specify Project names in an input CSV file, or use the "--all" flag to retrieve licensing for all Projects.
Use the "--help" flag for detailed documentation.
"""
