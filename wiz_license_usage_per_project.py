#!/usr/bin/env python3
"""
Wiz License Usage per Project - Updated for new API endpoints

This script retrieves license usage metrics from the Wiz API for each project
in your Wiz tenant. It's designed to help track and analyze workload consumption
across different projects for billing and capacity planning purposes.

Key Features:
- Authenticates using service account credentials from environment variables
- Automatically discovers the API endpoint from the authentication token
- Finds the active advanced license or allows manual override
- Filters projects by configurable prefix (default: "lic-")
- Outputs detailed usage metrics to CSV format
- Supports cloud storage (S3 and Azure Blob) for output
- Handles billing codes from project identifiers

Usage:
    python wiz_license_usage_updated.py --all --days 30
    python wiz_license_usage_updated.py --csv_input_file projects.csv
    python wiz_license_usage_updated.py --all --use_billing_codes --bucket_name my-bucket --bucket_type S3
"""

import argparse
import csv
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta
from io import StringIO

import requests
import jwt

# AWS and Azure imports for cloud storage
# These are optional - the script will work without them if not using cloud storage
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    
try:
    from azure.core.exceptions import AzureError
    from azure.storage.blob import BlobServiceClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

# Environment variables are expected to be set in the pipeline
# Required variables: WIZ_CLIENT_ID, WIZ_CLIENT_SECRET

####
# Global Variables and Configuration
####

# Headers for API requests - will be updated with authorization token after authentication
HEADERS = {'Content-Type': 'application/json'}

# Optional proxy configuration for environments that require it
# Format: {'https': 'http://proxy.example.com:8080'}
PROXIES = {}

# Wiz Service Account credentials
# These should be set in environment variables for security
# Create a service account in Wiz with "project:read" and "license:read" permissions
CLIENT_ID = os.environ.get('WIZ_CLIENT_ID', '')
CLIENT_SECRET = os.environ.get('WIZ_CLIENT_SECRET', '')

# Default file paths for input/output
DEFAULT_CSV_INPUT_FILE = 'input_project_names.csv'  # Optional file containing project names to filter
DEFAULT_CSV_OUTPUT_FILE = 'output_license_results'  # Base name for output (datetime will be appended)

# Cloud storage configuration (optional)
# These can be used when running in serverless environments or for centralized storage
DEFAULT_OUTPUT_BUCKET_TYPE = os.environ.get("WIZ_OUTPUT_BUCKET_TYPE", '')  # 'S3' or 'BLOB'
DEFAULT_OUTPUT_BUCKET_NAME = os.environ.get("WIZ_OUTPUT_BUCKET_NAME", '')  # Bucket/container name

####
# Command Line Arguments
####

parser = argparse.ArgumentParser(description='Get Wiz License Usage per Project')
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
    help='Output CSV file to this s3/blob Bucket - Required if bucket_type is set',
    default=DEFAULT_OUTPUT_BUCKET_NAME
)
parser.add_argument(
    '--bucket_type',
    dest='bucket_type',
    help='Output CSV file to this type of Bucket (S3 or BLOB) - Required if bucket_name is provided',
    choices=['S3', 'BLOB'],
    default=DEFAULT_OUTPUT_BUCKET_TYPE
)
parser.add_argument(
    '--use_billing_codes',
    action='store_true',
    help='Use billing codes defined in the Additional Identifiers property of Projects (example: billing_code=ABC123)',
    default=False
)
parser.add_argument(
    '--project_prefix',
    dest='project_prefix',
    help='Filter projects by prefix (default: lic-)',
    default='lic-'
)
args = parser.parse_args()

# The --all argument disables the --csv_input_file argument
if args.all_projects:
    args.csv_input_file = ''

####
# Library Methods
####

def signal_handler(_signal_received, _frame):
    """
    Handle Control-C (SIGINT) gracefully
    Allows users to cleanly exit the script with Ctrl+C
    """
    print("\nExiting")
    sys.exit(0)

def request_wiz_api_token():
    """
    Authenticate with Wiz and retrieve an OAuth access token.
    
    This function:
    1. Sends service account credentials to Wiz auth endpoint
    2. Receives an OAuth2 access token
    3. Decodes the token to extract the data center location
    4. Constructs the appropriate API URL for that data center
    5. Sets up authorization headers for subsequent API calls
    
    The API URL is dynamically determined from the token because Wiz has
    multiple regional endpoints (us20, us35, eu1, etc.) and we need to
    use the correct one for the tenant.
    
    Returns:
        str: The access token
        
    Raises:
        Exception: If authentication fails or token cannot be decoded
    """
    global API_URL
    
    # OAuth2 requires form-encoded data, not JSON
    HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
    
    # Standard OAuth2 client credentials grant
    auth_payload = {
        'audience': 'wiz-api',  # Fixed audience for Wiz API
        'grant_type': 'client_credentials',  # OAuth2 grant type for service accounts
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    # Authenticate with Wiz
    response = requests.post(
        url="https://auth.app.wiz.io/oauth/token",  # Global auth endpoint
        headers=HEADERS_AUTH, 
        data=auth_payload, 
        timeout=180  # 3 minute timeout for auth
    )
    
    if response.ok:
        try:
            response_json = response.json()
            token = response_json.get('access_token')
            if not token:
                response_message = response_json.get('message')
                raise Exception(f'Error retrieving token from the Wiz API: {response_message}')
            
            # Add token to headers for all future API calls
            HEADERS['Authorization'] = f'Bearer {token}'
            
            # Extract data center from token to construct correct API URL
            # The token is a JWT that contains claims about the tenant
            try:
                # Decode without verification since we just received it from Wiz
                decoded = jwt.decode(token, options={'verify_signature': False})
                dc = decoded.get('dc', '')  # Data center identifier (us20, us35, eu1, etc.)
                if dc:
                    # Construct the regional API endpoint
                    API_URL = f'https://api.{dc}.app.wiz.io/graphql'
                    logging.info(f'Using API URL: {API_URL}')
                else:
                    raise Exception('Could not determine data center from token')
            except Exception as e:
                raise Exception(f'Error decoding token: {e}')
                
        except ValueError as exception:
            raise Exception(f'Error parsing Wiz API response: {exception}')
    else:
        raise Exception(f'Error authenticating to the Wiz API: {response.status_code} - {response}')
    
    return token

def query_wiz_api(api_query, api_query_variables):
    """
    Execute a GraphQL query against the Wiz API with automatic pagination handling.
    
    The Wiz API uses cursor-based pagination for large result sets. This function
    automatically handles pagination by:
    1. Making the initial query
    2. Checking if there are more pages
    3. Using the cursor from pageInfo to fetch subsequent pages
    4. Aggregating all results into a single response
    
    Args:
        api_query (str): The GraphQL query string
        api_query_variables (dict): Variables for the GraphQL query
        
    Returns:
        dict: Complete query results with all pages combined
        
    Raises:
        Exception: If the API returns an error or invalid response
    """
    query_result = {}
    page_info = {'hasNextPage': True}  # Start assuming there might be pages
    
    # Continue fetching while there are more pages
    while page_info['hasNextPage']:
        request_data = {'query': api_query, 'variables': api_query_variables}
        response = requests.post(url=API_URL, headers=HEADERS, proxies=PROXIES,
                                 json=request_data, timeout=300)  # 5 minute timeout for large queries
        
        if response.ok:
            try:
                page_result = response.json()
            except ValueError as exception:
                raise Exception(f'Error parsing Wiz API response: {exception}')
                
            # Check for GraphQL-level errors (different from HTTP errors)
            if 'errors' in page_result:
                raise Exception(f'GraphQL errors: {page_result["errors"]}')
                
            # Extract the top-level query key (e.g., 'projects', 'licenses')
            query_key = list(page_result['data'].keys())[0]
            
            # Aggregate results from multiple pages
            if query_result:
                # Append nodes from this page to existing results
                if 'nodes' in page_result['data'][query_key]:
                    query_result['data'][query_key]['nodes'].extend(page_result['data'][query_key]['nodes'])
            else:
                # First page - initialize result
                query_result = page_result
                
            # Check if there are more pages
            if 'pageInfo' in page_result['data'][query_key]:
                page_info = page_result['data'][query_key]['pageInfo']
                # Add cursor for next page to variables
                api_query_variables['after'] = page_info['endCursor']
            else:
                # No pagination info means single page result
                page_info = {'hasNextPage': False}
        else:
            raise Exception(f'Error querying Wiz API: {response.status_code} - {response}')
    
    return query_result

def get_active_license():
    """
    Discover and return the active Wiz license ID for usage queries.
    
    This function queries the tenant's licenses and attempts to find the most
    appropriate license for usage tracking:
    1. First preference: Active "Advanced" license (non-trial)
    2. Second preference: Any active license (non-trial)
    3. Fallback: Default license ID if none found
    
    The license ID is needed to query workload usage metrics. Different license
    types (Advanced, Standard, etc.) may have different metrics available.
    
    Returns:
        str: The license ID to use for usage queries
    """
    # GraphQL query to get all licenses for the tenant
    # We use conditional includes to minimize response size
    query = """
    query TenantLicensesTableWithProjectContext($projectId: ID, $includeProjectDetails: Boolean!, $includeTrialSuggestions: Boolean!) {
      viewerV2 {
        tenant {
          licenses {
            id 
            name 
            sku 
            status 
            isTrial 
            startAt 
            endAt
          }
        }
      }
      tenantLicenseTrialSuggestions @include(if: $includeTrialSuggestions) {
        type
      }
      projectWorkloadQuota: project(id: $projectId) @include(if: $includeProjectDetails) {
        id
      }
    }
    """
    
    # We don't need project details or trial suggestions for this query
    variables = {
        "projectId": None,
        "includeProjectDetails": False,
        "includeTrialSuggestions": False
    }
    
    try:
        result = query_wiz_api(query, variables)
        licenses = result['data']['viewerV2']['tenant']['licenses']
        
        # First preference: Find active advanced license (most common for enterprise)
        for lic in licenses:
            if lic['status'] == 'ACTIVE' and 'advanced' in lic['name'].lower() and not lic['isTrial']:
                logging.info(f'Found active advanced license: {lic["name"]} (ID: {lic["id"]})')
                return lic['id']
        
        # Second preference: Any active non-trial license
        for lic in licenses:
            if lic['status'] == 'ACTIVE' and not lic['isTrial']:
                logging.info(f'Using active license: {lic["name"]} (ID: {lic["id"]})')
                return lic['id']
        
        # Fallback: Use a default license ID
        # This is a known valid license ID that should work for most queries
        default_id = "865082ef-cc8c-4062-9c67-d3e62699da44"
        logging.warning(f'No active license found, using default: {default_id}')
        return default_id
        
    except Exception as e:
        logging.error(f'Error getting license: {e}')
        # If license query fails, continue with default rather than failing entirely
        default_id = "865082ef-cc8c-4062-9c67-d3e62699da44"
        logging.warning(f'Using default license: {default_id}')
        return default_id

####
# Get Projects
####

# GraphQL query to get projects
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

# Variables for the projects query
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

# GraphQL query for license usage
license_query = """
query WorkloadLicenseUsageSummaryWithProjectContext($startAt: DateTime!, $endAt: DateTime!, $project: [String!], $license: ID!, $includeRegistryContainerImageScanCount: Boolean!, $includeComputeScanCount: Boolean!) {
  billableWorkloadTrendV2(
    startDate: $startAt
    endDate: $endAt
    project: $project
    license: $license
  ) {
    ... on CloudBillableWorkloadTrendData {
      averageComputeWorkloadCount
      averageVirtualMachineCount
      averageContainerHostCount
      averageServerlessCount
      averageServerlessContainerCount
      averageAssetsMetadataCount
      totalWorkloadCount
      accumulatedBucketScanCount
      monthlyAverageBucketScanCount
      accumulatedNonOSDiskScansCount
      monthlyAverageNonOSDiskScansCount
      monthlyAverageNonOSDiskWorkloadCount
      accumulatedPaasDatabaseScanCount
      monthlyAveragePaasDatabaseScanCount
      accumulatedDataWarehouseScanCount
      monthlyAverageNonOSContainerHostScanCount
      accumulatedNonOSContainerHostScanCount
      monthlyAverageDataWarehouseScanCount
      monthlyAverageDSPMWorkloadCount
      averageUvmWorkloadCount
      averageUvmVirtualMachineAssetCount
      averageUvmNetworkAddressAssetCount
      averageAsmWorkloadCount
      averageAsmApiApplicationEndpointCount
      averageAsmHttpApplicationEndpointCount
      averageAsmNonHttpApplicationEndpointCount
      accumulatedRegistryContainerImageScanCount @include(if: $includeRegistryContainerImageScanCount)
      monthlyAverageRegistryContainerImageScanCount @include(if: $includeRegistryContainerImageScanCount)
      accumulatedRegistryContainerImageWorkloadCount @include(if: $includeRegistryContainerImageScanCount)
      monthlyAverageRegistryContainerImageWorkloadCount @include(if: $includeRegistryContainerImageScanCount)
      monthlyAverageVirtualMachineImageScanCount
      monthlyAverageVirtualMachineImageWorkloadCount
      accumulatedVirtualMachineImageScanCount
      monthlyAverageComputeScansWorkloadCount @include(if: $includeComputeScanCount)
      accumulatedContainerHostScanCount @include(if: $includeComputeScanCount)
      accumulatedServerlessScanCount @include(if: $includeComputeScanCount)
      accumulatedContainerImageScanCount @include(if: $includeComputeScanCount)
      accumulatedVirtualMachineDiskScanCount @include(if: $includeComputeScanCount)
      monthlyAverageServerlessScanCount @include(if: $includeComputeScanCount)
      monthlyAverageContainerImageScanCount @include(if: $includeComputeScanCount)
      monthlyAverageContainerHostScanCount @include(if: $includeComputeScanCount)
      monthlyAverageVirtualMachineDiskScanCount @include(if: $includeComputeScanCount)
    }
    ... on DefendBillableWorkloadTrendData {
      averageVirtualMachineCount
      averageContainerHostsCount
      averageServerlessCount
      averageBucketCount
      averageDefendAssetWorkloadCount
      averagePaasDatabaseCount
      averageDataWarehouseCount
      extraIngestionWorkloads
      logsCap
      accumulatedExtraIngestedLogsCount
    }
    ... on DefendV2BillableWorkloadTrendData {
      totalWorkloadCount
      licensedWorkloadQuota
      totalAccumulatedIngestedBytes
      totalIngestionWorkloadCount
      freeTierWorkloadQuota
      freeTierWorkloadCount
      accumulatedManagementLogsIngestedBytes
      accumulatedManagementLogsWorkloadCount
      accumulatedDataLogsIngestedBytes
      accumulatedDataLogsWorkloadCount
      accumulatedNetworkLogsIngestedBytes
      accumulatedNetworkLogsWorkloadCount
      accumulatedIdentityLogsIngestedBytes
      accumulatedIdentityLogsWorkloadCount
      accumulatedVCSLogsIngestedBytes
      accumulatedVCSLogsWorkloadCount
    }
    ... on LogRetentionBillableWorkloadTrendData {
      totalWorkloadCount
      licensedWorkloadQuota
      accumulatedManagementLogsWorkloadCount
      accumulatedDataLogsWorkloadCount
      accumulatedNetworkLogsWorkloadCount
      accumulatedIdentityLogsWorkloadCount
      accumulatedVCSLogsWorkloadCount
    }
    ... on SensorBillableWorkloadTrendData {
      averageKubernetesSensorCount
      averageVMSensorCount
      averageServerlessContainerSensorCount
      averageSensorWorkloadCount
      averageWorkloadScanningKubernetesSensorCount
      averageWorkloadScanningVirtualMachineSensorCount
      averageWorkloadScanningSensorWorkloadCount
      averageKubernetesSensorsWithRuntimeEventsCount
      averageVmSensorsWithRuntimeEventsCount
      averageServerlessContainerSensorsWithRuntimeEventsCount
      averageSensorWorkloadWithRuntimeEventsCount
    }
    ... on CodeBillableWorkloadTrendData {
      totalActiveUsersWorkloadCount
    }
  }
}
"""

def get_query_dates():
    """ Query Dates as Strings formatted for GraphQL """
    now = datetime.now()
    end_datetime = now.replace(microsecond=0)
    start_datetime = end_datetime - timedelta(days=args.days_ago)
    return {
        'startDate': f'{start_datetime.isoformat()}.000Z',
        'endDate': f'{end_datetime.isoformat()}.000Z'
    }

def write_blob(csv_output_file, output_file_name):
    """ Write CSV file to Azure BLOB """
    if not HAS_AZURE:
        logging.error('ERROR: Azure storage libraries not installed. Run: pip install azure-storage-blob')
        sys.exit(1)
        
    connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    if not connect_str:
        logging.error('ERROR: No connection string defined as env AZURE_STORAGE_CONNECTION_STRING')
        sys.exit(1)
        
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        blob_client = blob_service_client.get_blob_client(
            container=args.bucket_name,
            blob=output_file_name
        )
        csv_output_file.seek(0)
        blob_client.upload_blob(csv_output_file.read())
    except AzureError as e:
        logging.error("ERROR: %s", e)

def write_s3(csv_output_file, output_file_name):
    """ Write CSV file to S3 """
    if not HAS_BOTO3:
        logging.error('ERROR: boto3 not installed. Run: pip install boto3')
        sys.exit(1)
        
    csv_output_file.seek(0)
    s3 = boto3.client('s3')
    s3.put_object(Body=csv_output_file.read(), Bucket=args.bucket_name, Key=output_file_name)

def get_billing_code_from_project_identifiers(project):
    """
    Extract billing code from project identifiers for cost allocation.
    
    Wiz projects can have multiple identifiers that link them to external systems.
    This function extracts a billing code based on the --use_billing_codes flag:
    
    With --use_billing_codes:
        - Searches for a "billing_code=XXX" pattern in identifiers
        - Falls back to project name if not found
        - Useful when you've explicitly tagged projects with billing codes
        
    Without --use_billing_codes (default):
        - Uses the first identifier if available (often an AWS account ID, subscription ID, etc.)
        - Returns empty string if no identifiers
        - This is the legacy behavior for backward compatibility
    
    Args:
        project (dict): Project object with 'identifiers' array
        
    Returns:
        str: The billing code to use in the CSV output
    """
    
    if args.use_billing_codes:
        # Look for explicit billing_code=XXX format in identifiers
        # This allows organizations to tag projects with specific billing codes
        for identifier in project.get('identifiers', []):
            if '=' in identifier:
                k_v = identifier.split('=')
                if len(k_v) == 2:
                    k = k_v[0].lstrip().rstrip().lower()
                    if k == "billing_code":
                        return k_v[1].lstrip().rstrip()
        # If no billing_code found, use project name as fallback
        return project['name']
    else:
        # Default behavior: use first identifier if available
        # This often contains AWS account IDs, Azure subscription IDs, etc.
        identifiers = project.get('identifiers', [])
        if identifiers:
            return identifiers[0]
        return ''

####
# Main
####

def main():
    """
    Main execution function for the Wiz License Usage script.
    
    This function orchestrates the entire process:
    1. Validates configuration and credentials
    2. Authenticates with Wiz API
    3. Discovers the active license
    4. Retrieves all projects
    5. Filters projects based on criteria
    6. Queries usage metrics for each project
    7. Outputs results to CSV (local or cloud storage)
    """
    
    # Set up basic logging configuration
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    # Validate cloud storage arguments are used together
    if (args.bucket_name and not args.bucket_type) or (not args.bucket_name and args.bucket_type):
        logging.error('--bucket_name and --bucket_type are co-dependant')
        sys.exit(1)
    
    # Validate that we have credentials to authenticate
    if not CLIENT_ID or not CLIENT_SECRET:
        logging.error('ERROR: Missing WIZ_CLIENT_ID or WIZ_CLIENT_SECRET in environment variables')
        logging.error('Please set these in your pipeline environment')
        logging.error('You can create a service account in Wiz with project:read and license:read permissions')
        sys.exit(1)
    
    logging.info('Getting Wiz License Usage for the last %s days ...', args.days_ago)
    
    # Calculate the date range for the query
    query_dates = get_query_dates()
    # Generate output filename with timestamp (colons replaced for filesystem compatibility)
    output_file_name = f"{args.csv_output_file}_{query_dates['endDate'].split('.')[0]}.csv".replace(':', '-')
    input_project_names = []
    csv_output = []
    
    # If user provided a CSV file with specific project names, load them
    # This allows filtering to a subset of projects
    if args.csv_input_file and os.path.isfile(args.csv_input_file):
        logging.info('Reading input file %s ...', args.csv_input_file)
        with open(args.csv_input_file, 'r', encoding='utf8') as csv_input_file:
            for row in csv_input_file:
                input_project_names.append(row.strip())
    
    # Set up output destination (memory buffer for cloud, file for local)
    if args.bucket_name:
        # For cloud storage, write to memory first then upload
        csv_output_file = StringIO()
    else:
        # For local storage, write directly to file
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
    
    # Get active license
    logging.info('Getting active license ...')
    license_id = get_active_license()
    
    # Set up license query variables
    license_query_variables = {
        "license": license_id,
        "includeRegistryContainerImageScanCount": True,
        "includeComputeScanCount": False,
        "startAt": query_dates['startDate'],
        "endAt": query_dates['endDate'],
        "project": []
    }
    
    logging.info('Getting Wiz Projects ...')
    projects_result = query_wiz_api(project_query, project_query_variables)
    projects = projects_result['data']['projects']['nodes']
    
    # Filter for projects with specified prefix
    filtered_projects = [p for p in projects if p['name'].startswith(args.project_prefix)]
    
    # Further filter by input file if provided
    if input_project_names:
        filtered_projects = [p for p in filtered_projects if p['name'] in input_project_names]
    
    target_projects = len(filtered_projects)
    
    logging.info('Getting License Usage for %s of %s Wiz Projects ...', target_projects, len(projects))
    logging.info('')
    
    # Main processing loop - iterate through each project and get its usage data
    for project in filtered_projects:
        try:
            # Set the project ID for this specific query
            license_query_variables['project'] = [project['id']]
            
            # Query the Wiz API for this project's license usage metrics
            billable_workloads = query_wiz_api(license_query, license_query_variables)['data']['billableWorkloadTrendV2']
            
            # Extract billing code based on configuration
            billing_code = get_billing_code_from_project_identifiers(project)
            
            # Extract workload metrics with fallbacks for missing or renamed fields
            # The API response structure can vary based on license type
            total_workload = billable_workloads.get('totalWorkloadCount', 0)
            
            # VM and container metrics
            avg_vm_count = billable_workloads.get('averageVirtualMachineCount', 0)
            # Handle field name variations (Count vs Counts)
            avg_container_host = billable_workloads.get('averageContainerHostCount', 0) or billable_workloads.get('averageContainerHostsCount', 0)
            
            # Serverless metrics
            avg_serverless = billable_workloads.get('averageServerlessCount', 0)
            avg_serverless_container = billable_workloads.get('averageServerlessContainerCount', 0)
            
            # Calculate total sensor count by summing individual sensor types
            # Sensors are Wiz's runtime protection agents
            sensor_count = (
                billable_workloads.get('averageKubernetesSensorCount', 0) +
                billable_workloads.get('averageVMSensorCount', 0) +
                billable_workloads.get('averageServerlessContainerSensorCount', 0)
            )
            
            # Extract scan metrics for different resource types
            registry_scan = billable_workloads.get('monthlyAverageRegistryContainerImageScanCount', 0)
            bucket_scan = billable_workloads.get('accumulatedBucketScanCount', 0)
            paas_db_scan = billable_workloads.get('accumulatedPaasDatabaseScanCount', 0)
            non_os_disk_scan = billable_workloads.get('accumulatedNonOSDiskScansCount', 0)
            
            logging.info('- Project ID: %s - Project Name: %s - Workload Count: %s',
                         project['id'], project['name'], total_workload)
            
            # Build CSV row with all metrics in the expected order
            # Note: Some fields are hardcoded to 0 as they're not available in the new API
            csv_line = [
                billing_code,
                project['name'],
                project['id'],
                avg_vm_count,
                avg_container_host,
                avg_serverless,
                avg_serverless_container,
                sensor_count,
                registry_scan,
                bucket_scan,
                0,  # accumulatedIaasDatabaseScannedGB - deprecated field, kept for compatibility
                paas_db_scan,
                non_os_disk_scan,
                total_workload,
                query_dates['startDate'].split('.')[0],  # Remove milliseconds from timestamp
                query_dates['endDate'].split('.')[0]
            ]
            csv_output.append(csv_line)
            
        except Exception as e:
            # Log error but continue processing other projects
            logging.error('Error processing project %s: %s', project['name'], str(e))
            
            # Add row with zeros for failed project so it's still visible in output
            # This helps identify projects that had issues
            csv_line = [
                get_billing_code_from_project_identifiers(project),
                project['name'],
                project['id'],
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # All metrics as 0
                query_dates['startDate'].split('.')[0],
                query_dates['endDate'].split('.')[0]
            ]
            csv_output.append(csv_line)
    
    # Write all collected data rows to the CSV
    csv_writer.writerows(csv_output)
    
    logging.info('')
    
    # Handle output based on destination (cloud or local)
    if args.bucket_name:
        # For cloud storage, rewind the in-memory buffer and upload
        csv_output_file.seek(0)
        
        # Upload to appropriate cloud provider
        if args.bucket_type == 'S3':
            write_s3(csv_output_file, output_file_name)
        elif args.bucket_type == 'BLOB':
            write_blob(csv_output_file, output_file_name)
            
        logging.info('Done, detailed results written to bucket: Bucket: %s Key: %s',
                     args.bucket_name, output_file_name)
    else:
        # For local storage, just close the file
        logging.info('Done, detailed results written to: %s', output_file_name)
    
    # Clean up resources
    csv_output_file.close()
    logging.info('')
    
    # Return filename for programmatic use (e.g., in Lambda functions)
    return f'detailed results written to: {output_file_name}'

####
# Entrypoint
####

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main()