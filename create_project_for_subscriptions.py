""" Creates a Wiz Project for each Subscription """

# pylint:disable=invalid-name

import argparse
import os
import signal
import sys
import time
import requests


####
# Configuration
####

API_URL       = os.environ.get('WIZ_API_URL')
CLIENT_ID     = os.environ.get('WIZ_CLIENT_ID')
CLIENT_SECRET = os.environ.get('WIZ_CLIENT_SECRET')

AUTH_URL      = 'https://auth.app.wiz.io/oauth/token'
HEADERS       = {'Content-Type': 'application/json'}

parser = argparse.ArgumentParser(description='Creates a Wiz Project for each Subscription')
parser.add_argument(
    '--environment',
    dest = 'environment',
    help = 'Use this Environment when linking Subscriptions to Projects (Default: OTHER)',
    default = 'OTHER'
)
parser.add_argument(
    '--prefix',
    dest = 'prefix',
    help = 'Append prefix to Subscription to be used as Project Name',
    default = ''
)
parser.add_argument(
    '--parent',
    dest = 'parent',
    help = 'Store Projects in Parent Project Folder (Default: None)',
    default = ''
)
parser.add_argument(
    '--progress', '-p',
    action='store_true',
    help='(Optional) - Output query progress.'
)
parser.add_argument(
    '--verbose', '-v',
    action='store_true',
    help='(Optional) - Output verbose information.'
)
parser.add_argument(
    '--ignore', '-i',
    dest='ignore',
    help='(Optional) - Ignore Subscriptions including this entry (e.g. "Visual Studio")'
)
args = parser.parse_args()

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
    request_data = {
        'audience':     'wiz-api',
        'grant_type':   'client_credentials',
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    request_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url=AUTH_URL, headers=request_headers, data=request_data, timeout=60)
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
    time.sleep(1)
    exponential_waits = [1, 2, 4, 8, 16, 32]
    query_result = {}
    page_info = {'hasNextPage': True}
    while page_info['hasNextPage']:
        if args.progress:
            print('.', end='', flush=True)
        request_data = {'query': api_query, 'variables': api_query_variables}
        response = requests.post(url=API_URL, headers=HEADERS, json=request_data, timeout=300)
        if response.ok:
            try:
                page_result = response.json()
            except ValueError as exception:
                # pylint:disable=broad-exception-raised,raise-missing-from
                raise Exception(f'Error parsing Wiz API response: {exception}')
        while retryable_response_status_code(response.status_code):
            for exponential_wait in exponential_waits:
                time.sleep(exponential_wait)
                response = requests.post(url=API_URL, headers=HEADERS, json=request_data, timeout=300)
                if response.ok:
                    try:
                        page_result = response.json()
                    except ValueError as exception:
                       # pylint:disable=broad-exception-raised,raise-missing-from
                        raise Exception(f'Error parsing Wiz API response: {exception}')
        if not response.ok:
            # pylint:disable=broad-exception-raised,raise-missing-from
            raise Exception(f'Error querying Wiz API: {response.status_code} - {response}')
        if page_result['data']:
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
        elif page_result['errors']:
            print(f'Error: GraphQL Return Message: {page_result["errors"][0]["message"]}')
            page_info = {'hasNextPage': False}
        else:
            print('Error: Unknown GraphQL Return Message')
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
# Queries and Variables
####


subscriptions_query = """
    query CloudAccountsPage(
        $filterBy: CloudAccountFilters
        $first: Int
        $after: String
      ) {
        cloudAccounts(filterBy: $filterBy, first: $first, after: $after) {
          nodes {
            id
            name
            externalId
            cloudProvider
            linkedProjects {
              id
              name
            }
          }
          pageInfo {
            hasNextPage
            endCursor
          }
          totalCount
        }
      }
"""


subscriptions_query_variables = {
  "first": 100,
  "filterBy": {
    "search": None
  },
  "quick": False
}


####

projects_query = """
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
            cloudAccountLinks {
              cloudAccount {
                id
              }
              environment
              shared
          }
          }
          pageInfo {
            hasNextPage
            endCursor
          }
          totalCount
        }
      }
"""


projects_query_variables = {
  "first": 100,
  "filterBy": {
    "root": True
  },
  "orderBy": {
    "field": "NAME",
    "direction": "ASC"
  }
}

####

create_project_query = """
  mutation CreateProject($input: CreateProjectInput!) {
      createProject(input: $input) {
        project {
          id
        }
      }
    }
"""

create_project_query_variables = {
    "input": {
        "name": "",
        "description": "",
        "identifiers": [],
        "businessUnit": "",
        "cloudOrganizationLinks": [],
        "cloudAccountLinks": [],
        "isFolder": False,
        "parentProjectId": None,
        "projectOwners": [],
        "repositoryLinks": [],
        "riskProfile": {
            "businessImpact": "LBI",
            "hasAuthentication": "UNKNOWN",
            "hasExposedAPI": "UNKNOWN",
            "isCustomerFacing": "UNKNOWN",
            "isInternetFacing": "UNKNOWN",
            "isRegulated": "UNKNOWN",
            "regulatoryStandards": [],
            "sensitiveDataTypes": [],
            "storesData": "UNKNOWN"
        },
        "securityChampions": []
    }
}

####

update_project_query = """
  mutation UpdateProject($input: UpdateProjectInput!) {
    updateProject(input: $input) {
      project {
        id
      }
    }
  }
"""

update_project_query_variables = {
    "input": {
        "id": "",
        "patch": {
            "cloudAccountLinks": ""
        }
    }
}



####
# Main
####


def create_parent_project(project_name: str):
    """ Create Parent Project """
    create_project_query_variables['input']['name'] = project_name
    create_project_query_variables['input']['isFolder'] = True
    result = query_wiz_api(create_project_query, create_project_query_variables)
    return result['data']['createProject']['project']


def create_project_with_subscription(parent_project_id: str, project_name: str, subscription_id: str, external_id: str):
    """ Create Project """
    cloud_account_links = {'cloudAccount': subscription_id, 'environment': args.environment, 'shared': False}
    create_project_query_variables['input']['name'] = project_name
    create_project_query_variables['input']['cloudAccountLinks'] = cloud_account_links
    create_project_query_variables['input']['parentProjectId'] = parent_project_id
    create_project_query_variables['input']['identifiers'] = ['billing_code='+external_id]
    query_wiz_api(create_project_query, create_project_query_variables)


def add_subscription_to_project(project_id: str, subscription_id: str):
    """ Update Project """
    cloud_account_links = {'cloudAccount': subscription_id, 'environment': args.environment, 'shared': False}
    update_project_query_variables['input']['id'] = project_id
    update_project_query_variables['input']['patch']['cloudAccountLinks'] = cloud_account_links
    query_wiz_api(update_project_query, update_project_query_variables)

def get_projects(projects_query: str, projects_query_variables: str):
    projects_result = query_wiz_api(projects_query, projects_query_variables)
    projects_query_key = list(projects_result['data'].keys())[0]
    projects = projects_result['data'][projects_query_key]['nodes']
    if args.verbose:
        print()
        print(projects_query)
        print()
        for project in projects:
            print()
            print(project)
            print()
    else:
        print()
    return projects


# pylint:disable=too-many-branches,too-many-statements
def main():
    """ Main """

    print('Getting Wiz API Token ...')
    request_wiz_api_token()

    print('Getting Subscriptions ...', end='', flush=True)
    subscriptions_result = query_wiz_api(subscriptions_query, subscriptions_query_variables)
    subscriptions_query_key = list(subscriptions_result['data'].keys())[0]
    subscriptions = subscriptions_result['data'][subscriptions_query_key]['nodes']
    if args.verbose:
        print()
        print(subscriptions_query)
        print()
        for subscription in subscriptions:
            print()
            print(subscription)
            print()

    if not subscriptions:
        print('Exiting, no subscriptions found.')
        return

    print()
    print('Getting Projects ...', end='', flush=True)
    projects = get_projects(projects_query, projects_query_variables)

    # Map list to dictionary for faster access.
    projects_by_name = {}
    for project in projects:
        projects_by_name[project['name']] = project

    # Get or create the Parent Project.
    if args.parent:
        if args.parent in projects_by_name:
            parent_project = projects_by_name[args.parent]
        else:
            print(f'Creating Parent Project: {args.parent}')
            parent_project = create_parent_project(project_name=args.parent)
        parent_project_id = parent_project['id']
    else:
        parent_project_id = None

    if parent_project_id:
        sub_projects_query_variables = {
            "first": 100,
            "filterBy": {
                "root": False,
                "parentProjectId": parent_project_id
            },
            "orderBy": {
                "field": "IS_FOLDER",
                "direction": "DESC"
            },
            "analyticsSelection": {},
            "fetchOverdueAndCreatedVsResolvedTrend": True
        }
        projects = get_projects(projects_query, sub_projects_query_variables)

        projects_by_name = {}
        for project in projects:
            projects_by_name[project['name']] = project

    for subscription in subscriptions:
        if not args.ignore or (args.ignore and args.ignore not in subscription['name']):
            project_subscription_name = f'{args.prefix}{subscription["name"]}'
            if subscription['linkedProjects']:
                for linked_project in subscription['linkedProjects']:
                    if linked_project['name'] == project_subscription_name:
                        print(f'Skipping Subscription: {subscription["name"]} already linked to Project: {linked_project["name"]}')
                        continue
            if project_subscription_name in projects_by_name:
                print(f'Adding Subscription: {subscription["name"]} to Project: {project_subscription_name}', end='', flush=True)
                if args.parent:
                    print(f' In Parent Folder: {args.parent}')
                else:
                    print()
                add_subscription_to_project(project_id=projects_by_name[project_subscription_name]['id'], subscription_id=subscription['id'])
            else:
                print(f'Creating Project: {project_subscription_name} with Subscription: {subscription["name"]}', end='', flush=True)
                if args.parent:
                    print(f' In Parent Folder: {args.parent}')
                else:
                    print()
                create_project_with_subscription(parent_project_id=parent_project_id, project_name=project_subscription_name, subscription_id=subscription['id'], external_id=subscription['externalId'])
        else:
            print(f'Ignoring Subscription: {subscription["name"]}')
    print()
    print('Done.')


if __name__ == '__main__':
    signal.signal(signal.SIGINT,signal_handler)
    main()
