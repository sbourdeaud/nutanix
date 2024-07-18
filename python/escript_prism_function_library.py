# region headers
"""
# * author:       stephane.bourdeaud@nutanix.com, mehdi.naccache@nutanix.com, alekh.neema@nutanix.com,
# *               chris.glover@nutanix.com, gopinath.sekar@nutanix.com, marija.jelicic@nutanix.com
# * version:      2021/05/10
# task_name:      n/a
# description:    This is a collection of functions meant to be used in escript
#                 for interfacing with Prism Central.  Note that some functions
#                 require other functions in this library, so make sure you copy
#                 all the ones you need in your escript.
"""
# endregion

#region base request function (required by all other functions)

import requests,json,getpass
from datetime import datetime, timedelta

# For token-based authentication, omit user and password (so that they default to None), and add the following header to
# the headers list: 'Authorization': 'Bearer <token value>'
def process_request(url, method, user=None, password=None, cert=None, files=None,headers=None, payload=None, params=None, secure=False, timeout=120, retries=5, exit_on_failure=True):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    sleep_between_retries=5
    
    while retries > 0:
        try:

            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password) if user else None,
                    cert=cert if cert else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    files=files if files else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.RequestException as error_code:
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            retries -= 1
            sleep(sleep_between_retries)
            continue
        
        if response.ok:
            return response
        elif response.status_code == 409:
            print(response.text)
            retries -= 1
            if retries == 0:
                if exit_on_failure:
                    exit(response.status_code)
                else:
                    return response
            sleep(sleep_between_retries)
            continue
        else:
            print(response.text)
            if exit_on_failure:
                exit(response.status_code)
            else:
                return response
 
#endregion


#region CONSTANTS
DEVELOPER = [
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "image"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "marketplace_item"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "app_icon"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "category"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "app_task"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "app_variable"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "virtual_network"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "resource_type"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "custom_provider"},
        "right_hand_side": {"collection": "ALL"},
    },
]

OPERATOR = [
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "app_icon"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "category"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "resource_type"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "custom_provider"},
        "right_hand_side": {"collection": "ALL"},
    },
]

CONSUMER = [
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "image"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "marketplace_item"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "app_icon"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "category"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "app_task"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "app_variable"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "virtual_network"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "resource_type"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "custom_provider"},
        "right_hand_side": {"collection": "ALL"},
    },
]

PROJECT_ADMIN = [
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "image"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "marketplace_item"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "directory_service"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "role"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"uuid_list": []},
        "left_hand_side": {"entity_type": "project"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "user"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "user_group"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "SELF_OWNED"},
        "left_hand_side": {"entity_type": "environment"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "app_icon"},
    },
    {
        "operator": "IN",
        "right_hand_side": {"collection": "ALL"},
        "left_hand_side": {"entity_type": "category"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "app_task"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "app_variable"},
        "right_hand_side": {"collection": "SELF_OWNED"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "virtual_network"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "resource_type"},
        "right_hand_side": {"collection": "ALL"},
    },
    {
        "operator": "IN",
        "left_hand_side": {"entity_type": "custom_provider"},
        "right_hand_side": {"collection": "ALL"},
    },
]

CUSTOM_ROLE_PERMISSIONS_FILTERS = [
    {
        "permission": "view_image",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "image"},
            "right_hand_side": {"collection": "ALL"},
        },
    },
    {
        "permission": "view_app_icon",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "app_icon"},
        },
    },
    {
        "permission": "view_name_category",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "category"},
        },
    },
    {
        "permission": "create_or_update_name_category",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "category"},
        },
    },
    {
        "permission": "view_environment",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "environment"},
            "right_hand_side": {"collection": "SELF_OWNED"},
        },
    },
    {
        "permission": "view_marketplace_item",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "marketplace_item"},
            "right_hand_side": {"collection": "SELF_OWNED"},
        },
    },
    {
        "permission": "view_user",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "user"},
        },
    },
    {
        "permission": "view_user_group",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "user_group"},
        },
    },
    {
        "permission": "view_role",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "role"},
        },
    },
    {
        "permission": "view_directory_service",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "directory_service"},
        },
    },
    {
        "permission": "search_directory_service",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "directory_service"},
        },
    },
    {
        "permission": "view_identity_provider",
        "filter": {
            "operator": "IN",
            "right_hand_side": {"collection": "ALL"},
            "left_hand_side": {"entity_type": "identity_provider"},
        },
    },
    {
        "permission": "view_app_task",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "app_task"},
            "right_hand_side": {"collection": "SELF_OWNED"},
        },
    },
    {
        "permission": "view_app_variable",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "app_variable"},
            "right_hand_side": {"collection": "SELF_OWNED"},
        },
    },
    {
        "permission": "view_image",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "resource_type"},
            "right_hand_side": {"collection": "ALL"},
        },
    },
    {
        "permission": "view_image",
        "filter": {
            "operator": "IN",
            "left_hand_side": {"entity_type": "custom_provider"},
            "right_hand_side": {"collection": "ALL"},
        },
    },
]

DEFAULT_CONTEXT = {
    "scope_filter_expression_list": [
        {
            "operator": "IN",
            "left_hand_side": "PROJECT",
            "right_hand_side": {"uuid_list": []},
        }
    ],
    "entity_filter_expression_list": [
        {
            "operator": "IN",
            "left_hand_side": {"entity_type": "ALL"},
            "right_hand_side": {"collection": "ALL"},
        }
    ],
}
#endregion


#region functions


def add_category_to_vm(api_server, username, passwd, category_map ,vm_uuid, secure=False):
    """ delete subnets in the Recovery plan

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        category_map: List of categories in key value format eg. {'category1':'value1','category2':'value2'}.
        vm_uuid: Uuid of the VM.

    Returns:
        Task execution (json response).
    """

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    retry = 5
    while True:
        url = "https://{}:9440/api/nutanix/v3/vms/{}".format(api_server,vm_uuid)
        method = 'GET'
        vm_resp = process_request(url=url, method=method, user=username, password=passwd, headers=headers, secure=False)
        vm_resp = json.loads(vm_resp.content)
        del vm_resp['status']
        vm_resp['metadata']['use_categories_mapping'] = True

        for category_name,category_value in category_map.items():
            vm_resp['metadata']['categories_mapping'][category_name] = [ category_value ]

        method = 'PUT'
        resp = process_request(url=url, method=method, user=username, password=passwd, headers=headers, payload=vm_resp, secure=False)

        if resp.status_code == 409:
            if retry > 0:
                retry -= 1 
                print("VM Payload upload failed with status 409. Retrying !!!")
                continue      
            else:
                print("Maximum retries attempted. Exiting ")      
                exit(1)
        elif resp.ok:
            json_resp = json.loads(resp.content)
            print("json_resp: {}".format(json_resp))
            task_uuid = json_resp['status']['execution_context']['task_uuid']
            return task_uuid

        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(resp))
            print(json.dumps(json.loads(resp.content), indent=4))
            raise


def prism_get_clusters(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of clusters from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
    Returns:
        A list of clusters (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="cluster",entity_api_root="clusters",secure=secure,print_f=print_f,filter=filter)


def prism_get_cluster(api_server,username,passwd,cluster_name=None,cluster_uuid=None,secure=False,print_f=True):
    
    """Returns from Prism Central the uuid and details of a given cluster name.
       If a cluster_uuid is specified, it will skip retrieving all clusters (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_name: Name of the cluster(optional).
        cluster_uuid: Uuid of the cluster (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the cluster (cluster_uuid) and the json content
        of the cluster details (cluster_details)
    """

    cluster_uuid, cluster = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                                             entity_type="cluster",entity_api_root="clusters",entity_name=cluster_name,entity_uuid=cluster_uuid,
                                             secure=secure,print_f=print_f)
    return cluster_uuid, cluster


def prism_get_cluster_utilization_average(api_server,username,passwd,average_period_days=30,secure=False):
    """Returns from Prism Element the average resource utilization over the given time period (30 days by default).
    This function retrieves CPU, Memory and Storage utilization metrics for the specified period and 
    computes the average for each metric.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        average_period_days: Number of days over which to calculate the average resource utilization.
                             Defaults to 30 days.
        
    Returns:
        The following integers:
            - For CPU utilization: cpu_utilization_average based on the metric hypervisor_cpu_usage_ppm
            - For Memory utilization: memory_utilization_average based on the metric hypervisor_memory_usage_ppm
            - For Storage utilization: storage_utilization_average based on the metric controller_num_iops
    """
    start_time_in_usecs = int(((datetime.now() + timedelta(days = -average_period_days)) - datetime(1970, 1, 1)).total_seconds() *1000000)
    end_time_in_usecs = int(((datetime.now() + timedelta(days = -1)) - datetime(1970, 1, 1)).total_seconds() *1000000)
    interval_in_secs = 60

    params = {
        "metrics" : "hypervisor_cpu_usage_ppm,hypervisor_memory_usage_ppm,controller_num_iops",
        "start_time_in_usecs" : start_time_in_usecs,
        "end_time_in_usecs" : end_time_in_usecs,
        "interval_in_secs" : interval_in_secs
    }
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/cluster/stats/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,user=username,password=passwd,headers=headers,params=params,secure=secure)
    if resp.ok:
        cluster_metrics_values = json.loads(resp.content)
        cpu_metrics = [stat['values'] for stat in cluster_metrics_values['stats_specific_responses'] if stat['metric'] == "hypervisor_cpu_usage_ppm"]
        memory_metrics = [stat['values'] for stat in cluster_metrics_values['stats_specific_responses'] if stat['metric'] == "hypervisor_memory_usage_ppm"]
        storage_metrics = [stat['values'] for stat in cluster_metrics_values['stats_specific_responses'] if stat['metric'] == "controller_num_iops"]
        cpu_utilization_average = sum(cpu_metrics[0]) / len(cpu_metrics[0]) /10000
        memory_utilization_average = sum(memory_metrics[0]) / len(memory_metrics[0]) /10000
        storage_utilization_average = int(sum(storage_metrics[0]) / len(storage_metrics[0]))
        print("CPU Utilization Average for the last {} days is: {} %".format(average_period_days,round(cpu_utilization_average,2)))
        print("Memory Utilization Average for the last {} days is: {} %".format(average_period_days,round(memory_utilization_average,2)))
        print("Storage Utilization Average for the last {} days is: {} iops".format(average_period_days,storage_utilization_average))
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise

    return cpu_utilization_average, memory_utilization_average, storage_utilization_average


def prism_get_vms(api_server,username,secret,secure=False):
    """Retrieve the list of VMs from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of VMs (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/vms/list"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    length = 200

    # Compose the json payload
    payload = {
        "kind": "vm",
        "offset": 0,
        "length": length
    }
    #endregion
    while True:
        print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url,method,username,secret,headers,payload,secure)

        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            entities.extend(json_resp['entities'])
            key = 'length'
            if key in json_resp['metadata']:
                if json_resp['metadata']['length'] == length:
                    print("Processing results from {} to {} out of {}".format(
                        json_resp['metadata']['offset'], 
                        json_resp['metadata']['length']+json_resp['metadata']['offset'],
                        json_resp['metadata']['total_matches']))
                    payload = {
                        "kind": "vm",
                        "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                        "length": length
                    }
                else:
                    return entities
                    break
            else:
                return entities
                break
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise


def prism_get_vm(api_server,username,secret,vm_name,vm_uuid=None,secure=False):
    """Returns from Prism Central the uuid and details of a given VM name.
       If a vm_uuid is specified, it will skip retrieving all vms (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name: Name of the virtual machine.
        
    Returns:
        A string containing the UUID of the VM (vm_uuid) and the json content
        of the VM details (vm_details)
    """
    vm_details = {}

    if vm_uuid is None:
        #get the list vms from Prism
        vm_list = prism_get_vms(api_server,username,secret,secure)
        for vm in vm_list:
            if vm['spec']['name'] == vm_name:
                vm_uuid = vm['metadata']['uuid']
                vm_details = vm.copy()
                break
    else:
        headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
        }
        api_server_port = "9440"
        api_server_endpoint = "/api/nutanix/v3/vms/{0}".format(vm_uuid)
        url = "https://{}:{}{}".format(
            api_server,
            api_server_port,
            api_server_endpoint
        )
        method = "GET"
        print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url,method,username,secret,headers,secure)
        if resp.ok:
            vm_details = json.loads(resp.content)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise
    return vm_uuid, vm_details


def prism_get_images(api_server,username,secret,secure=False):
    """Retrieve the list of images from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of images (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/images/list"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    length = 50

    # Compose the json payload
    payload = {
        "kind": "image",
        "offset": 0,
        "length": length
    }
    #endregion
    while True:
        print("Making a {} API call to {}".format(method, url))
        resp = process_request(url,method,username,secret,headers,payload,secure)

        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            entities.extend(json_resp['entities'])
            key = 'length'
            if key in json_resp['metadata']:
                if json_resp['metadata']['length'] == length:
                    print("Processing results from {} to {} out of {}".format(
                        json_resp['metadata']['offset'], 
                        json_resp['metadata']['length']+json_resp['metadata']['offset'],
                        json_resp['metadata']['total_matches']))
                    payload = {
                        "kind": "image",
                        "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                        "length": length
                    }
                else:
                    return entities
                    break
            else:
                return entities
                break
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise


def prism_get_image(api_server,username,secret,image_name,image_uuid=None,secure=False):
    """Returns from Prism Cnetral the uuid and details of a given image name.
       If an image_uuid is specified, it will skip retrieving all images (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_name: Name of the virtual machine.
        
    Returns:
        A string containing the UUID of the image (image_uuid) and the json content
        of the image details (image_details)
    """
    image_details = {}

    if image_uuid is None:
        #get the list vms from Prism
        image_list = prism_get_images(api_server,username,secret,secure)
        for image in image_list:
            if image['spec']['name'] == image_name:
                image_uuid = image['metadata']['uuid']
                image_details = image.copy()
                break
    else:
        headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
        }
        api_server_port = "9440"
        api_server_endpoint = "/api/nutanix/v3/images/{0}".format(image_uuid)
        url = "https://{}:{}{}".format(
            api_server,
            api_server_port,
            api_server_endpoint
        )
        method = "GET"
        print("Making a {} API call to {}".format(method, url))
        resp = process_request(url,method,username,secret,headers,secure)
        if resp.ok:
            image_details = json.loads(resp.content)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise

    return image_uuid, image_details


def prism_mount_ngt(api_server,username,secret,vm_name,vm_uuid=None,cluster_uuid=None,secure=False):
    """Mounts the NGT iso image for the given vm.
       If a vm_uuid is specified, it will skip over retrieving all vms (faster)
       If a cluster_uuid is specified, it will skip over retrieving all clusters (faster)

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm: Name of the virtual machine.
        
    Returns:
        A boolean (true/false) based on success.
    """
    
    #get vm details to figure out its uuid and its cluster uuid
    if vm_uuid is None:
        print("Retrieving details for virtual machine {}...".format(vm_name))
        vm_uuid, vm_details=prism_get_vm(api_server,username,secret,vm_name)
        print("Uuid of virtual machine {0} is {1}".format(vm_name,vm_uuid))
        cluster_name=vm_details['status']['cluster_reference']['name']
        print("Virtual machine {0} is hosted on cluster {1}".format(vm_name,cluster_name))
    elif cluster_uuid is None:
        print("Retrieving details for virtual machine {}...".format(vm_name))
        vm_uuid, vm_details=prism_get_vm(api_server,username,secret,vm_name,vm_uuid)
        cluster_name=vm_details['status']['cluster_reference']['name']
        print("Virtual machine {0} is hosted on cluster {1}".format(vm_name,cluster_name))
    else:
        cluster_name=cluster_uuid
    
    #get the cluster details to figure out its ip
    print("Retrieving details for cluster {}...".format(cluster_name))
    cluster_uuid, cluster_details = prism_get_cluster(api_server,username,secret,cluster_name,cluster_uuid)
    cluster_ip=cluster_details['spec']['resources']['network']['external_ip']
    cluster_name=cluster_details['spec']['name']
    print("Cluster {0} has ip {1}".format(cluster_name,cluster_ip))

    #send the mount request to the cluster ip for the given vm
    print("Sending request to mount NGT iso for virtual machine {0} on cluster {1}...".format(vm_name,cluster_name))
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/PrismGateway/services/rest/v1/vms/{}/guest_tools/mount".format(vm_uuid)
    url = "https://{}:{}{}".format(
        cluster_ip,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,secure=False)

    if resp.ok:
        # print the content of the response
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        print("Successfully mounted NGT iso for virtual machine {0} on cmuster {1}".format(vm_name,cluster_name))
        return True
    else:
        # print the content of the response (which should have the error message)
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        return False


def prism_get_filers(api_server,username,secret,secure=False):
    """Retrieve the list of filers from Prism Element.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of filers (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/PrismGateway/services/rest/v1/vfilers/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        entities.extend(json_resp['entities'])
        return entities
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def prism_get_filer(api_server,username,secret,uuid,secure=False):
    """Retrieves a given filer from Prism Element.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        uuid: Uuid of the filer to retrieve.
        
    Returns:
        A json description of the filer.
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/PrismGateway/services/rest/v1/vfilers/{0}".format(uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        return json_resp
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def prism_get_filer_shares(api_server,username,secret,uuid,secure=False):
    """Retrieve the list of shares for a given filer from Prism Element.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        uuid: Uuid of the filer to retrieve.
        
    Returns:
        A list of share entities described in json.
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/PrismGateway/services/rest/v1/vfilers/{0}/shares".format(uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        entities.extend(json_resp['entities'])
        return entities
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def pc_get_directory_service_uuid(api_server,username,passwd,directory_service_name,secure=False):
    """
        Retrieves directory service uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_service_name: Name of the directory service to retrieve
        
    Returns:
        Uuid of the directory service (string).
    """
    directory_service_uuid, directory = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="directory_service",entity_api_root="directory_services",entity_name=directory_service_name,secure=secure)
    return directory_service_uuid


def prism_get_entities(api_server,username,passwd,entity_type,entity_api_root,secure=False,print_f=True,filter=None):

    """Retrieve the list of entities from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        An array of entities (entities part of the json response).
    """

    entities = []
    #region prepare the api call
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/{}/list".format(entity_api_root)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    length = 100

    # Compose the json payload
    payload = {
        "kind": entity_type,
        "offset": 0,
        "length": length
    }
    if filter:
        payload["filter"] = filter
    #endregion
    while True:
        if print_f:
            print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url,method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            #json_resp = resp
            entities.extend(json_resp['entities'])
            key = 'length'
            if key in json_resp['metadata']:
                if json_resp['metadata']['length'] == length:
                    if print_f:
                        print("Processing results from {} to {} out of {}".format(
                            json_resp['metadata']['offset'], 
                            json_resp['metadata']['length']+json_resp['metadata']['offset'],
                            json_resp['metadata']['total_matches']))
                    payload = {
                        "kind": entity_type,
                        "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                        "length": length
                    }
                else:
                    return entities
            else:
                return entities
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise


def prism_get_entity(api_server,username,passwd,entity_type,entity_api_root,entity_name=None,entity_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given entity name.
       If an entity_uuid is specified, it will skip retrieving all entities by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity (optional).
        entity_uuid: Uuid of the entity (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the entity (entity_uuid) and the json content
        of the entity details (entity_details)
    """
    
    entity_details = {}

    if entity_uuid is None:
        #get the entities list from Prism
        entity_list = prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                                          entity_type=entity_type,entity_api_root=entity_api_root,
                                          secure=secure,print_f=print_f)
        entity_obj_list = [ entity for entity in entity_list if entity['status']['name'] == entity_name ] 
        if len(entity_obj_list) !=1:
            print("ERROR - found {} instance(s) of the entity {}".format(len(entity_obj_list),entity_name))
            exit(1)

        for entity in entity_list:
            fetched_name = ""
            if "name" in entity['spec']:
                fetched_name = entity['spec']['name']
            elif "name" in entity['status']:
                fetched_name = entity['status']['name']
            else:
                print("ERROR - fetched entity name could not be extracted for entity {}".format(entity['metadata']['uuid']))
                raise
            if fetched_name == entity_name:
                entity_uuid = entity['metadata']['uuid']
                entity_details = entity.copy()
                break
        if entity_details == {} :
            print("ERROR - Entity {} not found".format(entity_name))
            exit(1)
    else:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        api_server_port = "9440"
        api_server_endpoint = "/api/nutanix/v3/{}/{}".format(entity_api_root,entity_uuid)
        url = "https://{}:{}{}".format(
            api_server,
            api_server_port,
            api_server_endpoint
        )
        method = "GET"
        if print_f:
            print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
        if resp.ok:
            entity_details = json.loads(resp.content)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise
    return entity_uuid, entity_details


def prism_get_entity_uuid(api_server,username,passwd,entity_type,entity_api_root,entity_name=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid of a given entity name.
       
    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity 
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the entity (entity_uuid) and the json content
        of the entity details (entity_details)
    """
    
    #get the entities list from Prism
    entity_list = prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                                        entity_type=entity_type,entity_api_root=entity_api_root,
                                        secure=secure,print_f=print_f)
    entity_uuid = None
    for entity in entity_list:
        fetched_name = ""
        if "name" in entity['spec']:
            fetched_name = entity['spec']['name']
        elif "name" in entity['status']:
            fetched_name = entity['status']['name']
        else:
            print("ERROR - fetched entity name could not be extracted for entity {}".format(entity['metadata']['uuid']))
            raise
        if fetched_name == entity_name:
            entity_uuid = entity['metadata']['uuid']
            break
    if entity_uuid is None:
        print("Error: Enitity ID could not be retrieved for entity '{}' of kind '{}'".format(entity_name,entity_type))
        raise
    return entity_uuid


def prism_delete_entity(api_server,username,passwd,entity_type,entity_api_root,entity_name=None,entity_uuid=None,secure=False,print_f=True):

    """Deletes an entity given entity uuid or entity name.
       If an entity_uuid is specified, it will skip retrieving all entities to find uuid, by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity (optional).
        entity_uuid: Uuid of the entity (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        Task uuid when entity deletion request returns task uuid under $.status.state.execution_context.task_uuid
        task uuid is returned as None when the returned json is of a different format for some entity type
    """

    entity_uuid, entity_details = prism_get_entity(api_server,username,passwd,
                                                   entity_type,entity_api_root,
                                                   entity_name=entity_name,entity_uuid=entity_uuid,
                                                   secure=secure,print_f=print_f)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/{}/{}".format(entity_api_root,entity_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "DELETE"
    if print_f:
        print("{} API call to {} with secure set to {}".format(entity_type, url, secure))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        if print_f:
            print("INFO - {} {} deletion task initiated with success".format(entity_type, entity_details["status"]["name"]))
        res = json.loads(resp.content)
        #when entity deletion request returns the common $.status.state.execution_context.task_uuid
        if "status" in res and "execution_context" in res["status"] \
                    and "task_uuid" in res["status"]["execution_context"]:
            return res["status"]["execution_context"]["task_uuid"]
        #otherwise return None. for example, app deletion returned json has a different format ($.status.ergon_task_uuid).
        #it has to be monitored by a specific function, not using the standard entities library
        else:
            return None
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def prism_add_categories_to_entity(api_server,username,passwd,entity_type,entity_api_root,added_categories,entity_name=None,entity_uuid=None,secure=False,print_f=True):

    """adds categories to entity given uuid or entity name.
       If an entity_uuid is specified, it will skip retrieving all entities to find uuid, by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity (optional).
        entity_uuid: Uuid of the entity (optional).
        added_categories: categories to add in the form:
            {
                "catgory1": "value1",
                "catgory2": "value2",
                ...
            }
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        Task uuid
    """

    entity_uuid, entity_details = prism_get_entity(api_server,username,passwd,
                                                   entity_type,entity_api_root,
                                                   entity_name=entity_name,entity_uuid=entity_uuid,
                                                   secure=secure,print_f=print_f)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/{}/{}".format(entity_api_root,entity_uuid)
    url = "https://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)
    method = "PUT"
    new_categories = entity_details["metadata"]["categories"]
    for cat in added_categories:
        new_categories[cat] = added_categories[cat]
    payload = entity_details
    del(payload["status"])
    payload["metadata"]["categories"] = new_categories

    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.ok:
        result = resp.json()
        task_uuid = result['status']['execution_context']['task_uuid']
        task_state = result['status']['state']
        print('INFO - Entity categories updated with status code: {}'.format(resp.status_code))
        print('INFO - task: {}, state: {}'.format(task_uuid, task_state))
        return task_uuid
    else:
        print('ERROR - Entity categories update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)   


def prism_get_vpc(api_server,username,passwd,project_name=None,project_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given project name.
       If a project_uuid is specified, it will skip retrieving all projects (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project (optional).
        project_uuid: Uuid of the project (optional).
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors

    Returns:
        A string containing the UUID of the Project (project_uuid) and the json content
        of the project details (project)
    """

    project_uuid, project = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="project",entity_api_root="projects",entity_name=project_name,entity_uuid=project_uuid,
                              secure=secure,print_f=print_f)
    return project_uuid, project


def prism_flow_vpc_add_externally_routable_ips(api_server,username,passwd,vpc_uuid,externally_routable_prefix_list,secure=False):

    """adds externally routable ranges to a vpc.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vpc_uuid: uuid of the vpc to be updated
        externally_routable_prefix_list: list of ip ranges (in CIDR) that will be routed externally in the form:
            ["10.10.10.0/24", "10.10.10.0/18", ...]
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        the uuid of the vpc update task
    """

    url = 'https://{}:9440/api/nutanix/v3/vpcs/{}'.format(api_server,vpc_uuid)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    resp = process_request(url,'GET',user=username,password=passwd,headers=headers,payload=None,secure=secure)
    if resp.ok:
        vpc = json.loads(resp.content)
    else:
        print("ERROR - occured while fetching VPC with uuid{}".format(vpc_uuid))
        exit(1)

    payload = vpc
    new_prefix_list = [
                        "{}/{}".format(prefix["ip"],prefix["prefix_length"])
                     for prefix in  payload["status"]["resources"]["externally_routable_prefix_list"]
                ]

    new_prefix_list.extend(externally_routable_prefix_list)
    new_prefix_list = list(set(new_prefix_list))

    new_prefix_list_payload = [
                                                                        {
                                                                            "ip": prefix.split('/')[0], "prefix_length": int(prefix.split('/')[1])
                                                                        } for prefix in  new_prefix_list
                ]

    payload["spec"]["resources"]["externally_routable_prefix_list"] = new_prefix_list_payload
    del(payload["status"])
    resp = process_request(url,'PUT',user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.status_code == 202:
        result = resp.json()
        task_uuid = result['status']['execution_context']['task_uuid']
        task_state = result['status']['state']
        print('INFO - VPC updated with status code: {}'.format(resp.status_code))
        print('INFO - task: {}, state: {}'.format(task_uuid, task_state))
        return task_uuid
    else:
        print('ERROR - VPC update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)


def prism_flow_create_vpc(api_server,username,passwd,vpc_name,ext_subnet_uuid_list,dns_list_csv,externally_routable_prefix_list,secure=False):

    """Creates a flow VPC.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vpc_name: name of the vpc to be created
        ext_subnet_uuid_list: list (array) of uuids of the external subnets that will be associated with the created vpc
                                maximum one NATed network and one No-NAT network can be listed here
        dns_list_csv: list of DNS resolvers ip addresses to be associated with this vpc ("ip1,ip2,...")
        externally_routable_prefix_list: list of ip ranges (in CIDR) that will be routed externally in the form:
            [
                {
                    "ip": "192.168.10.0",
                    "prefix_length": 24
                },
                ...
            ]
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        the uuid of the created vpc and the uuid of the creation task
    """

    url = 'https://{}:9440/api/nutanix/v3/vpcs'.format(api_server)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = {
        "api_version": "3.1.0",
        "metadata": {
            "kind": "vpc"
        },
        "spec": {
            "name": vpc_name,
            "resources": {
                "common_domain_name_server_ip_list": [
                    {
                        "ip": ip
                    } for ip in (dns_list_csv.split(',') if dns_list_csv!="" else [])
                ],
                "external_subnet_list": [
                    {
                        "external_subnet_reference": {
                            "kind": "subnet",
                            "uuid": uuid
                        }
                    } for uuid in ext_subnet_uuid_list
                ],
                "externally_routable_prefix_list": externally_routable_prefix_list
            }
        }
    }
    resp = process_request(url,'POST',user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.status_code == 202:
        result = json.loads(resp.content)
        task_uuid = result['status']['execution_context']['task_uuid']
        vpc_uuid = result['metadata']['uuid']
        print('INFO - VPC created with status code: {}'.format(resp.status_code))
        print('INFO - VPC uuid: {}'.format(vpc_uuid))
    else:
        print('ERROR - VPC creation failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)

    return vpc_uuid, task_uuid


def prism_flow_set_default_route(api_server,username,passwd,vpc_uuid,ext_subnet_uuid,secure=False):

    """adds a static default route to a vpc.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vpc_uuid: uuid of the vpc to be updated
        ext_subnet_uuid: uuid of the external subnet (must be already associated with the vpc)
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        the uuid of the vpc update task
    """

    url = 'https://{}:9440/api/nutanix/v3/vpcs/{}/route_tables'.format(api_server,vpc_uuid)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = {
        "api_version":"3.1.0",
        "metadata":{
            "kind":"vpc_route_table",
            "uuid": vpc_uuid
        },
        "spec":{
            "resources":{
                "static_routes_list":[
                ],
                "default_route_nexthop":{
                    "external_subnet_reference":{
                        "kind": "subnet",
                        "uuid": ext_subnet_uuid
                    }
                }
            }
        }
    }
    resp = process_request(url,'PUT',user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.status_code == 202:
        result = json.loads(resp.content)
        task_uuid = result['status']['execution_context']['task_uuid']
        print('INFO - VPC Updated with status code: {}'.format(resp.status_code))
    else:
        print('ERROR - VPC Update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)
    return task_uuid


def prism_delete_vpc(api_server,username,passwd,vpc_name=None,vpc_uuid=None,secure=False,print_f=True):

    """Deletes a vpc given its name or uuid.
       If a vpc_uuid is specified, it will skip retrieving all vpcs (faster) to find the designated vpc name.


    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vpc_name: Name of the vpc (optional).
        vpc_uuid: uuid of the vpc (optional).
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors

    Returns:
        vpc deletion task uuid
    """

    task_uuid = prism_delete_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="vpc",entity_api_root="vpcs",entity_name=vpc_name,entity_uuid=vpc_uuid,
                              secure=secure,print_f=print_f)
    return task_uuid


def pc_generate_uuid(api_server,username,passwd,secure=False):

    """Generates a nww uuid.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        a new uuid
    """
 
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/idempotence_identifiers"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        "count": 1,
        "valid_duration_in_minutes": 527040
    }
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.ok:
        return resp.json()['uuid_list'][0]
    else:
        print("ERROR: Failed to generate uuid")


def prism_get_disk_images(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of images from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of Images (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="image",entity_api_root="images",
                              secure=secure,print_f=print_f,filter=filter)


def prism_get_disk_image(api_server,username,passwd,image_name=None,image_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given image name.
       If a image_uuid is specified, it will skip retrieving all images (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_name: Name of the image (optional).
        image_uuid: Uuid of the image (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the image (image_uuid) and the json content
        of the image details (image)
    """

    image_uuid, image = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="image",entity_api_root="images",entity_name=image_name,entity_uuid=image_uuid,
                              secure=secure,print_f=print_f)
    return image_uuid, image


def prism_get_projects(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of Projects from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search

    Returns:
        A list of Projects (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="project",entity_api_root="projects",secure=secure,print_f=print_f,filter=filter)


def prism_get_project(api_server,username,passwd,project_name=None,project_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given project name.
       If a project_uuid is specified, it will skip retrieving all projects (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project (optional).
        project_uuid: Uuid of the project (optional).
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors

    Returns:
        A string containing the UUID of the Project (project_uuid) and the json content
        of the project details (project)
    """

    project_uuid, project = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="project",entity_api_root="projects",entity_name=project_name,entity_uuid=project_uuid,
                              secure=secure,print_f=print_f)
    return project_uuid, project


def prism_delete_project(api_server,username,passwd,project_name=None,project_uuid=None,secure=False,print_f=True):

    """Deletes a project given its name or uuid.
       If a project_uuid is specified, it will skip retrieving all projects (faster) to find the designated project name.
       this is not a cascaded deletion. Request will fails if following conditions are not met:
       - Project has no VMs (will never happen for a standalone Calm appliance)
       - Project has no applications
       - Project has no blueprints
       - Project has no runbooks
       - Project has no endpoints
       - Project has no jobs
       - Project has no approval policies

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project (optional).
        project_uuid: uuid of the project (optional).
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors

    Returns:
        Project deletion task uuid
    """

    task_uuid = prism_delete_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="project",entity_api_root="projects",entity_name=project_name,entity_uuid=project_uuid,
                              secure=secure,print_f=print_f)
    return task_uuid


def prism_get_project_internal(api_server,username,passwd,project_name,project_uuid=None,secure=False,print_f=True):
    """Returns from Prism Central the uuid and details of a given project name.
       If a project_uuid is specified, it will skip retrieving all projects (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project.
        project_uuid: Uuid of the project (optional).
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors

    Returns:
        A string containing the UUID of the Project (project_uuid) and the json content
        of the project details (project_details)
    """
    project_details = {}

    if project_uuid is None:
        #get the list vms from Prism
        project_list = prism_get_projects(api_server,username,passwd,secure,print_f=print_f)
        for project in project_list:
            if project['spec']['name'] == project_name:
                project_uuid = project['metadata']['uuid']
                #project_details = project.copy()
                break

    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{0}".format(project_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    if print_f:
        print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        project_details = json.loads(resp.content)
    else:
        return None,None

    return project_uuid, project_details


def add_subnet_to_project_infrastructure(api_server,username,passwd,project_uuid,subnet_uuid,subnet_name,secure=False):

    ## pc_projects.py, pc_entities.py, http_requests.py
    project_uuid, project = prism_get_project(api_server=api_server,username=username,passwd=passwd,
                                                project_name=None,project_uuid=project_uuid,
                                                secure=secure)


    account_uuid = project['status']['resources']['account_reference_list'][0]["uuid"]

    ## pc_ssp_environments.py
    account_uuid, account = prism_ssp_get_account(api_server=api_server,username=username,passwd=passwd,
                                                    account_name=None,account_uuid=account_uuid,
                                                    secure=secure)
    subnet_reference = project['status']['resources']["subnet_reference_list"]
    external_network = project['status']['resources']["external_network_list"]
    subnet_reference_to_add = []
    external_network_to_add = []
    account_name = account["status"]["name"]
    if account_name == "NTNX_LOCAL_AZ":
        subnet_reference_to_add = [
                {
                    "kind": "subnet",
                    "name": subnet_name,
                    "uuid": subnet_uuid
                }
            ]
    else:
        external_network_to_add = [
                {
                    "name": subnet_name,
                    "uuid": subnet_uuid
                }
            ]
    subnet_reference.extend(subnet_reference_to_add)
    external_network.extend(external_network_to_add)
    project['spec']['resources']["subnet_reference_list"] = subnet_reference
    project['spec']['resources']["external_network_list"] = external_network

    del(project["status"])

    url = 'https://{}:9440/api/nutanix/v3/projects/{}'.format(api_server, project_uuid)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = project
    resp = process_request(url,'PUT',user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.status_code == 202:
        result = resp.json()
        task_uuid = result['status']['execution_context']['task_uuid']
        task_state = result['status']['state']
        project_uuid = result['metadata']['uuid']
        print('INFO - Project subnets updated with status code: {}'.format(resp.status_code))
        print('INFO - task: {}, state: {}'.format(task_uuid, task_state))
        return task_uuid
    else:
        print('ERROR - project subnets update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)


def add_subnet_to_project_environment(api_server,username,passwd,environment_uuid,subnet_uuid,secure=False):

    ## pc_projects.py, pc_entities.py, http_requests.py
    environment_uuid, environment = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                                                        entity_type="environment",entity_api_root="environments",entity_name=None,entity_uuid=environment_uuid,
                                                        secure=secure)
    subnet_references = environment['status']['resources']["infra_inclusion_list"][0]["subnet_references"]
    subnet_references.append({"uuid": subnet_uuid})

    environment['spec']['resources']["infra_inclusion_list"][0]["subnet_references"] = subnet_references
    del(environment["status"])

    url = 'https://{}:9440/api/nutanix/v3/environments/{}'.format(api_server, environment_uuid)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = environment
    resp = process_request(url,'PUT',user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.ok:
        print('INFO - Project environment updated with status code: {}'.format(resp.status_code))
    else:
        print('ERROR - project environment update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)


def pc_get_az_urls(api_server,username,passwd,secure=False):
    """ Retrieve Availability Zone URL (UUID) from Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password. 
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        List of AZ info containing name, type and AZ url (UUID)

    """
    az_list = []
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/groups"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"

    # Compose the json payload
    payload = {
        "entity_type": "availability_zone",
        "group_attributes": [
        ],
        "group_count": 3,
        "group_member_attributes": [
            {
                "attribute": "name"
            },
            {
                "attribute": "region"
            },
            {
                "attribute": "type"
            },
            {
                "attribute": "reachable"
            },
            {
                "attribute": "cloud_trust_uuid"
            },
            {
                "attribute": "url"
            }
        ],
        "group_member_count": 40,
        "group_member_offset": 0,
        "group_member_sort_attribute": "name",
        "group_member_sort_order": "ASCENDING",
        "group_offset": 0,
        "grouping_attribute": " "
    }

    resp = process_request(url,method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.ok:
        json_resp = json.loads(resp.content)
        print("json_resp: {}".format(json_resp))
        for entity in json_resp['group_results'][0]['entity_results']:
            az_name = ""
            az_type = ""
            az_url = ""
            for data in entity['data']:
                if data['name'] == 'name':
                    az_name = data['values'][0]['values'][0]
                if data['name'] == 'type':
                    az_type = data['values'][0]['values'][0]
                if data['name'] == 'url':
                    az_url = data['values'][0]['values'][0]
            az = {'name': az_name, 'type': az_type, 'url': az_url}
            az_list.append(az)
        
        return(az_list)

    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def pc_create_recovery_plan(api_server,username,passwd,rp_name,local_az_url,primary_cluster_uuid,recovery_cluster_uuid,tenant_vpc_uuid,subnet_nic1,subnet_nic2,vm_category=None,secure=False):
    """ Create Recovery Plan using category 

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password. 
        rp_name : Name of Recovery plan
        local_az_url : URL(UUID) of local availability zone 
        vm_category : Dict containing category key and value. VM tagged with this category will be added to RP. 
                        If category is none, RP without VM entity will be created.
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        Task execution (json response).
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/recovery_plans"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"

    # Compose the json payload
    payload = {
        "metadata": {
            "kind": "recovery_plan"
        },
        "spec": {
            "name": rp_name,
            "resources": {
                "parameters": {
                    "availability_zone_list": [
                        {
                            "availability_zone_url": local_az_url,
                            "cluster_reference_list" : [
                                {"uuid": primary_cluster_uuid,"kind": "cluster"}
                            ]
                        },
                        {
                            "availability_zone_url": local_az_url,
                            "cluster_reference_list" : [
                                {"uuid": recovery_cluster_uuid,"kind": "cluster"}
                            ]

                        }
                    ],
                    "primary_location_index": 0,
                    "network_mapping_list": [
                        {
                        "availability_zone_network_mapping_list": [
                            {
                                "cluster_reference_list": [
                                    {
                                       "kind": "cluster",
                                        "uuid": primary_cluster_uuid
                                    }
                                ],
                                "recovery_network": {
                                    "vpc_reference": {
                                        "kind": "vpc",
                                        "uuid": tenant_vpc_uuid
                                    },
                                    "name": subnet_nic1,
                                },
                                "availability_zone_url": local_az_url
                            }, 
                            {
                                "cluster_reference_list": [
                                    {
                                        "kind": "cluster",
                                        "uuid": recovery_cluster_uuid
                                    }
                                ],
                                "recovery_network": {
                                    "vpc_reference": {
                                        "kind": "vpc",
                                        "uuid": tenant_vpc_uuid
                                    },
                                    "name": subnet_nic1,
                                },
                                "availability_zone_url": local_az_url
                            }
                        ]
                    }, 
                    {
                        "availability_zone_network_mapping_list": [
                            {
                                "cluster_reference_list": [
                                    {
                                        "kind": "cluster",
                                        "uuid": primary_cluster_uuid
                                    }
                                ],
                                "recovery_network": {
                                    "vpc_reference": {
                                        "kind": "vpc",
                                        "uuid": tenant_vpc_uuid
                                    },
                                    "name": subnet_nic2,
                                },
                                "availability_zone_url": local_az_url
                            }, 
                            {
                                "cluster_reference_list": [
                                    {
                                        "kind": "cluster",
                                        "uuid": recovery_cluster_uuid
                                    }
                                ],
                                "recovery_network": {
                                    "vpc_reference": {
                                        "kind": "vpc",
                                        "uuid": tenant_vpc_uuid
                                    },
                                    "name": subnet_nic2,
                                },
                                "availability_zone_url": local_az_url
                            }
                        ]
                    }
                ]
                
                },
                "stage_list": [
                    {
                        "stage_work": {
                            "recover_entities": {
                                "entity_info_list": [
                                    {
                                        "categories": vm_category
                                    }
                                ]
                            }
                        }
                    }
                ],

                
            }
        }
    }
    if not vm_category:
        del payload['spec']['resources']['stage_list']
    
    print("payload is {}".format(payload))
    resp = process_request(url,method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    
    if resp.ok:
        json_resp = json.loads(resp.content)
        print("json_resp: {}".format(json_resp))
        return json_resp
    
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def pc_start_failover(api_server,username,passwd,local_az_url,primary_cluster_uuid,recovery_cluster_uuid,rp_name=None,rp_uuid=None,secure=False):
    """ Initiate Failover with Recovery plan Name or UUID 

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password. 
        rp_name: Name of the Recovery Plan (optional).
        rp_uuid: Uuid of the Recovery Plan (optional).
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        Task execution (json response). 
    """

    if rp_uuid is None and rp_name is None:
        print("Either the name or UUID of Entity is required to proceed !!! ")
        return False
    
    if rp_uuid is None and rp_name:
        rp_uuid = prism_get_entity_uuid(api_server=api_server,username=username,passwd=passwd,
                              entity_type="recovery_plan",entity_api_root="recovery_plans",entity_name=rp_name,secure=secure)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/recovery_plan_jobs"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"

    rp_job_name = "Failover " + str(datetime.today())
    payload = {
        "metadata": {
           "kind" : "recovery_plan_job"
        },
        "spec": {
            "name": rp_job_name,
            "resources": {
                "recovery_plan_reference": { "uuid": rp_uuid, "kind" : "recovery_plan" },
                "execution_parameters": {
                    "action_type": "MIGRATE",
                    "failed_availability_zone_list": [
                            {
                                "availability_zone_url": local_az_url,
                                "cluster_reference_list" : [
                                    {"uuid": primary_cluster_uuid,"kind": "cluster"}
                                ]
                            }
                        ],
                    "recovery_availability_zone_list": [
                            {
                                "availability_zone_url": local_az_url,
                                "cluster_reference_list" : [
                                    {"uuid": recovery_cluster_uuid,"kind": "cluster"}
                                ]

                            }
                        ],
                     "should_continue_on_validation_failure": True
                }
            }
        }
    }


    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure,payload=payload)

    if resp.ok:
        json_resp = json.loads(resp.content)
        print("\n\n json resp: \n {} \n\n".format(json_resp))
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise

    return json_resp


def pc_add_subnet_recovery_plan(api_server, username, passwd, recovery_plan_name, tenant_vpc_uuid, subnet_name, secure=False):
    """ Add subnets in the Recovery plan 

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password. 
        rp_name: Name of the Recovery Plan .
        tenant_vpc_uuid: Uuid of the tenant.
        subnet_name: name of the subnet for the mapping.
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        Task execution (json response). 
    """
    entity_type = 'recovery_plan'
    entity_api_root = 'recovery_plans'
    recovery_plan_uuid, recovery_plan_response = prism_get_entity(api_server, username, passwd, entity_type, entity_api_root, entity_name=recovery_plan_name)
    print("RP : {}, {}".format(recovery_plan_uuid,recovery_plan_name))

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/recovery_plans"
    url = "https://{}:{}{}/{}".format(api_server,api_server_port,api_server_endpoint,recovery_plan_uuid)
    method = "PUT"

    nw_az_item=recovery_plan_response['spec']['resources']['parameters']['network_mapping_list'][0]['availability_zone_network_mapping_list']
    del recovery_plan_response['status']

    payload = {
                "are_networks_stretched": True,
                "availability_zone_network_mapping_list":[
                    {
                        "cluster_reference_list": [
                            {
                                "kind": "cluster",
                                "uuid": nw_az_item[0]['cluster_reference_list'][0]['uuid']
                            }
                        ],
                        "recovery_network": {
                            "vpc_reference": {
                                "kind": "vpc",
                                "uuid": tenant_vpc_uuid
                            },
                            "name": subnet_name,
                        },
                        "availability_zone_url": nw_az_item[0]['availability_zone_url']
                    },
                    {
                        "cluster_reference_list": [
                            {
                                "kind": "cluster",
                                "uuid": nw_az_item[1]['cluster_reference_list'][0]['uuid']
                            }
                        ],
                        "recovery_network": {
                            "vpc_reference": {
                                "kind": "vpc",
                                "uuid": tenant_vpc_uuid
                            },
                            "name": subnet_name,
                        },
                        "availability_zone_url": nw_az_item[1]['availability_zone_url']
                }
        ]
    }
    print("Appending AZ payload to the network mapping list")
    nw_map_list = pc_remove_stale_subnet_from_rp(api_server, username, passwd, recovery_plan_response,tenant_vpc_uuid=tenant_vpc_uuid)
    recovery_plan_response["spec"]["resources"]["parameters"]["network_mapping_list"] = nw_map_list
    recovery_plan_response['spec']['resources']['parameters']['network_mapping_list'].append(payload)

    resp = process_request(url, method, user=username, password=passwd, headers=headers, payload=recovery_plan_response, secure=secure)
    
    if resp.ok:
        json_resp = json.loads(resp.content)
        print("json_resp: {}".format(json_resp))
        task_uuid = json_resp['status']['execution_context']['task_uuid']
        return task_uuid
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(recovery_plan_response))
        print(json.dumps(json.loads(resp.content), indent=4))
        raise


def pc_remove_stale_subnet_from_rp(api_server, username, passwd, recovery_plan_response,tenant_vpc_uuid=None):
    """ delete subnets in the Recovery plan 

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password. 
        recovery_plan_response: Recovery Plan response data from which stale subnets have to be removed.
        tenant_vpc_uuid: Uuid of the tenant to be removed (in case of VPC/Tenant deletion)
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        nw_map_list: network_mapping_list without state entries (json response). 
    """
    subnet_list = prism_get_entities(api_server, username, passwd, "subnet", "subnets")
    
    vpc_subnet_list = { subnet["spec"]["name"]:subnet["spec"]["resources"]['vpc_reference']['uuid'] for subnet in subnet_list if 'vpc_reference' in subnet["spec"]["resources"] }
    vpc_uuid_list = list(set(vpc_subnet_list.values()))
    
    if tenant_vpc_uuid != None and tenant_vpc_uuid in vpc_uuid_list: 
        vpc_uuid_list.remove(tenant_vpc_uuid)

    nw_map_item = recovery_plan_response["spec"]["resources"]["parameters"]["network_mapping_list"]

    subnet_flag_list = []
    nw_map_list = []
    for nw_map in nw_map_item:
        vpc_uuid = nw_map["availability_zone_network_mapping_list"][0]["recovery_network"]["vpc_reference"]["uuid"]
        subnet_name = nw_map['availability_zone_network_mapping_list'][0]['recovery_network']['name']
        if subnet_name in vpc_subnet_list and vpc_subnet_list[subnet_name] == vpc_uuid and vpc_uuid in vpc_uuid_list:
            if subnet_name in subnet_flag_list:
                print("Found Repetitive Subnet:{} with VPC uuid:{}".format(subnet_name,vpc_uuid))
                continue
            nw_map_list.append(nw_map)
            subnet_flag_list.append(subnet_name)
        else:
            print("Found Stale Subnet:{} with VPC uuid:{}".format(subnet_name,vpc_uuid))
    print("Total Subnet Count:",len(vpc_subnet_list))
    print("Subnet Count in RP : {}".format(len(nw_map_item)))
    print("Subnet Count without Stale entries : {}".format(len(nw_map_list)))
    return nw_map_list


def pc_del_subnet_recovery_plan(api_server, username, passwd, recovery_plan_name, tenant_vpc_uuid, subnet_name, secure=False):
    """ delete subnets in the Recovery plan 

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password. 
        rp_name: Name of the Recovery Plan .
        tenant_vpc_uuid: Uuid of the tenant.
        subnet_name: name of the subnet for the mapping.
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        Task execution (json response). 
    """
    entity_type = 'recovery_plan'
    entity_api_root = 'recovery_plans'
    recovery_plan_uuid, recovery_plan_response = prism_get_entity(api_server, username, passwd, entity_type, entity_api_root, entity_name=recovery_plan_name)
    print("RP : {}, {}".format(recovery_plan_uuid,recovery_plan_name))

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/recovery_plans"
    url = "https://{}:{}{}/{}".format(api_server,api_server_port,api_server_endpoint,recovery_plan_uuid)
    
    method = "PUT"

    del recovery_plan_response['status']
    nw_map_list = pc_remove_stale_subnet_from_rp(api_server, username, passwd, recovery_plan_response,tenant_vpc_uuid=tenant_vpc_uuid)
    recovery_plan_response["spec"]["resources"]["parameters"]["network_mapping_list"] = nw_map_list

    # for i in range(len(nw_map_item)):
    #     az_nm_rn_item = nw_map_item[i]['availability_zone_network_mapping_list'][0]['recovery_network']
    #     if az_nm_rn_item['name'] == subnet_name and az_nm_rn_item['virtual_network_reference']['uuid'] == tenant_vpc_uuid:
    #         recovery_plan_response['spec']['resources']['parameters']['network_mapping_list'].pop(i)
    #         print("Deleting Subnet {} from the RP".format(subnet_name))
    #         break

    resp = process_request(url, method, user=username, password=passwd, headers=headers, payload=recovery_plan_response, secure=secure)
    
    if resp.ok:
        json_resp = json.loads(resp.content)
        print("json_resp: {}".format(json_resp))
        task_uuid = json_resp['status']['execution_context']['task_uuid']
        return task_uuid
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(recovery_plan_response))
        print(json.dumps(json.loads(resp.content), indent=4))
        raise
    

def prism_get_roles(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of Roles from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of roles (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="role",entity_api_root="roles",secure=secure,print_f=print_f,filter=filter)


def prism_get_role(api_server,username,passwd,role_name=None,role_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given role name.
       If a role_uuid is specified, it will skip retrieving all roles (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        role_name: Name of the role (optional).
        role_uuid: Uuid of the role (optional).
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the role (role_uuid) and the json content
        of the role details (role)
    """

    role_uuid, role = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="role",entity_api_root="roles",entity_name=role_name,entity_uuid=role_uuid,
                              secure=secure,print_f=print_f)
    return role_uuid, role


def pc_get_role_uuid(api_server,username,passwd,role_name=None,secure=False):
    """
        Retrieve a role uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        role_name: Role name to retrieve
        secure: boolean to verify or not the api server's certificate (True/False)
        
    Returns:
        Role uuid (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/roles/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'role','filter':'name=={}'.format(role_name)}
    # endregion

    # Making the call
    print("Retrieving role {} uuid on {}".format(role_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.ok:
        json_resp = json.loads(resp.content)
    else:
        return None 

    if json_resp['entities']:
        return json_resp['entities'][0]['metadata']['uuid']
    else:
        return None
    

def get_category_uuid_v4(api_server,username,passwd,category,secure=False):

    """Retrieve the UUID of Category from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        category : Dictionary containing the Category Key and Value . 
        
    Returns:
        UUID (str) of Category if found or False(bool) if not found.
    """

    key = list(category.keys())[0]
    value = list(category.values())[0]
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/prism/v4.0.a1/config/categories?$filter=fqName eq '{}/{}'".format(key,value)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"

    print("HTTP {} request to {} ".format(method,url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)

    if resp.ok:
        json_resp = json.loads(resp.content)
        if (json_resp.get("metadata").get("totalAvailableResults") == 1 ):
            return json_resp["data"][0]["extId"]
        else:
            print("Given Category {}:{} couldn't be found !!!".format(key,value))
            return False


def pc_get_security_policy(api_server,username,passwd,extId,secure=False):

    """Retrieve the Security Policy from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        extId : UUId of Security Policy. 
        
    Returns:
        Security Policy Details (response) if found. False(bool) if not found.
    """

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/microseg/v4.0.a1/config/policies/{}".format(extId)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"

    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        return resp
    else:
        print("Failure to retrieve secuity policy with extId:{}".format(extId))
        return False

  
def pc_list_security_policy(api_server,username,passwd,secure=False):

    """Retrieve the List of Security Policies from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        Security Policy List (response) if found. False(bool) if not found.
    """

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/microseg/v4.0.a1/config/policies"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"

    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        return json.loads(resp.content)
    else:
        print("Failure to retrieve list of security policy ")
        return False


def pc_get_security_policy_by_secured_category(api_server,username,passwd,secured_group_uuids,secure=False):

    """Retrieve the Security Policy UUID, filtered by Secured Entity from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        secured_group_uuids : List of Category UUIds 
        
    Returns:
        UUID (str) of Security Policy if found or None if not found.
    """    

    json_resp = pc_list_security_policy(api_server=api_server,username=username,passwd=passwd,secure=secure)
    extId = None 
    for policy in json_resp["data"]:
        secured_group = policy["securedGroups"]
        if  set(secured_group_uuids) == set(secured_group):
            extId = policy["extId"]
            break
        
    return extId


def create_inbound_rule(secured_group_uuid,source_type,source_category_uuid,source_subnet,source_protocol,source_network_ports,description=""):

    """Create Inbound rules with the provided input.

    Args:
        secured_group_uuid: List of Category UUIDs for secured group Entity.
        source_type: 'Category' or 'Subnet' depending upon the input:.
        source_category_uuid: Single source Category UUID if type is 'Category'.
        source_subnet: Subnet if type is 'Subnet'. Ex: '10.10.2.0/24' 
        source_protocol : Protocol to be allowed by rules. 'TCP' or 'UDP' or 'ICMP' or 'All'
        source_network_ports :  Ports allowed in the above network. Ex: 5000 or 6000-7000 or Any.   
                                In case of ICMP 'type-code' . EX 10-15 or Any
        
    Returns:
        Dictionary containing the rule specification for inbound.
    """    

    if source_type == 'Category':
        if source_category_uuid != None:
            source = {"srcCategoryReferences": [source_category_uuid]}
        else:
            print("Source Category UUID is expected !!!")
            return False
    elif source_type == 'Subnet':
        if source_subnet != None:
            subnet = source_subnet.split("/")
            network = subnet[0]
            mask = int(subnet[1])
            source = {"srcSubnet" : {"value" : network,"prefixLength": mask}}
        else:
            print("Source Subnet CIDR is expected !!!")
            return False
    elif source_type == 'All':
        source = {"srcAllowSpec":"ALL"}
    else:
        print("Invalid Source Type !!!")
        return False

    if source_protocol == 'All':
        inbound_services = { "isAllProtocolAllowed" : True }
    elif source_protocol == 'TCP' or source_protocol == 'UDP' :
        protocol_mapping = {"TCP": "tcpServices","UDP":"udpServices"}
        source_start_port = source_network_ports[0]
        source_end_port = source_network_ports[1] if len(source_network_ports)>1 else source_network_ports[0]
        if source_start_port == "Any" :
            source_start_port = 0
            source_end_port = 65535
        else:
            source_start_port = int(source_start_port)
            source_end_port =  int(source_end_port)
        inbound_services = {
                    protocol_mapping[source_protocol]:[ {"startPort": source_start_port, "endPort": source_end_port} ]
                }
    elif source_protocol == 'ICMP':
        type = source_network_ports[0]
        code = source_network_ports[1] if len(source_network_ports)>1 else source_network_ports[0]
        if type == "Any" :
            inbound_services = { "icmpServices": [ {"isAllAllowed": True } ] }
        else:
            inbound_services = {
                "icmpServices": [ {"type": int(type), "code": int(code)} ]
                }

    rule = {
        "description" : description,
        "type": "APPLICATION",
        "spec": {
                "$objectType": "microseg.v4.config.ApplicationRuleSpec",   #todo change to b1 spec , now its working
                "securedGroupCategoryReferences": secured_group_uuid,         
        }

    }
    rule.get("spec").update(source)
    rule.get("spec").update(inbound_services)

    print("Inbound Rule is , {}".format(rule))
    return rule


def create_outbound_rule(secured_group_uuid,dest_type,dest_category_uuid,dest_subnet,dest_protocol,dest_network_ports,description=""):

    """Create Outbound rules with the provided input.

    Args:
        secured_group_uuid: List of Category UUIDs for secured group Entity.
        dest_type: 'Category' or 'Subnet' depending upon the input:.
        dest_category_uuid: Single source Category UUID if type is 'Category'.
        dest_subnet: Subnet if type is 'Subnet'. Ex: '10.10.2.0/24' 
        dest_protocol : Protocol to be allowed by rules. 'TCP' or 'UDP' or 'ICMP' or 'All'
        dest_network_ports :  Ports allowed in the above network. Ex: 5000 or 6000-7000 or Any.   
                                In case of ICMP 'type-code' . EX 10-15 or Any
        
    Returns:
        Dictionary containing the rule specification for outbound.
    """  

    if dest_type == 'Category':
        if dest_category_uuid != None:
            dest = {"destCategoryReferences": [dest_category_uuid]}
        else:
            print("dest Category UUID is expected !!!")
            return False
    elif dest_type == 'Subnet':
        if dest_subnet != None:
            subnet = dest_subnet.split("/")
            network = subnet[0]
            mask = int(subnet[1])
            dest = {"destSubnet" : {"value" : network,"prefixLength": mask}}
        else:
            print("dest Subnet CIDR is expected !!!")
            return False
    elif dest_type == 'All':
        dest = {"destAllowSpec":"ALL"}
    else:
        print("Invalid dest Type !!!")
        return False


    if dest_protocol == 'All':
        outbound_services = { "isAllProtocolAllowed" : True }
    elif dest_protocol == 'TCP' or dest_protocol == 'UDP' :
        protocol_mapping = {"TCP": "tcpServices","UDP":"udpServices"}
        dest_start_port = dest_network_ports[0]
        dest_end_port = dest_network_ports[1] if len(dest_network_ports)>1 else dest_network_ports[0]
        if dest_start_port == "Any" :
            dest_start_port = 0
            dest_end_port = 65535
        else:
            dest_start_port = int(dest_start_port)
            dest_end_port =  int(dest_end_port)        
                
        outbound_services = {
                    protocol_mapping[dest_protocol]:[ {"startPort": dest_start_port, "endPort": dest_end_port} ]
                }
    elif dest_protocol == 'ICMP':
        type = dest_network_ports[0]
        code = dest_network_ports[1] if len(dest_network_ports)>1 else dest_network_ports[0]
        if type == "Any" :
            outbound_services = { "icmpServices": [ {"isAllAllowed": True } ] }
        else:
            outbound_services = {
                "icmpServices": [ {"type": int(type), "code": int(code)} ]
                }

    rule = {
        "description" : description,
        "type": "APPLICATION",
        "spec": {
                "$objectType": "microseg.v4.config.ApplicationRuleSpec",
                "securedGroupCategoryReferences": secured_group_uuid,         
        }

    }
    rule.get("spec").update(dest)
    rule.get("spec").update(outbound_services)

    print("outbound Rule is , {}".format(rule))
    return rule

 
def create_intragroup_rule(secured_group_uuid,secured_group_action):

    """Create Intragroup rules with the provided input.

    Args:
        secured_group_uuid: List of Category UUIDs for secured group Entity.
        secured_group_action: "ALLOW" or "DENY".
       
    Returns:
        Dictionary containing the rule specification for Intragroup.
    """  

    if not (secured_group_action ==  "ALLOW" or secured_group_action == "DENY"):
        print("Either 'ALLOW' or 'DENY; is expected for secured_group_action")
        return False

    rule = {
        "type": "INTRA_GROUP",
        "spec" : {
            "$objectType": "microseg.v4.config.IntraEntityGroupRuleSpec",
            "securedGroupCategoryReferences" : secured_group_uuid,
            "securedGroupAction" : secured_group_action
        }
    }
    print("IntraGroup Rule is , {}".format(rule))
    return rule


def create_secuity_policy_v4(api_server,username,passwd,name,rules,type="APPLICATION",description="",state="MONITOR",vpcReferences=None,isHitlogEnabled=False,isIpv6TrafficAllowed=False,secure=False):

    """Create Security Policy with the provided rules.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        name: Name of Security Policy
        rules : Rules (dict) containing inbound, intragroup and/or outbound rules.  
        type : "APPLICATION" . Currently only Application is supported
        description : Description of Security Policy
        state: "ENFORCE" or "MONITOR" or "SAVE". Default is "MONITOR"
        vpcReferences : VPC UUID to apply policy to Subnet inside a VPC
        isHitlogEnabled : bool FALSE or TRUE
        isIpv6TrafficAllowed : bool FALSE or TRUE
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        Response Content containing the task ID for security policy Creation.
    """  

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'NTNX-Request-Id' : str(uuid.uuid4())
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/microseg/v4.0.a1/config/policies"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"

    # Compose the json payload
    payload = {
        "name" : name, 
        "type" : type,
        "description": description,
        "state": state,
        "isHitlogEnabled":isHitlogEnabled,
        "isIpv6TrafficAllowed" :isIpv6TrafficAllowed,
        "rules" : rules
    }    

    if vpcReferences:
        payload.update({"scope" :"VPC_LIST","vpcReferences" : vpcReferences})

    print("payload is ",payload) 

    resp = process_request(url=url,method=method,payload=payload,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        return json.loads(resp.content)
    else:
        print("Failed to create a new security Policy")
        return False


def pc_update_security_policy_v4(api_server, username, passwd, extId, rules, secure=False):

    """Update Security Policy with the provided rules.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        extId : ID of Security Policy to update
        rules : Rules (dict) containing inbound, intragroup and/or outbound rules.  
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        Response Content containing the task ID for security policy Update.
    """  


    response = pc_get_security_policy(api_server=api_server, username=username, passwd=passwd, secure=secure,
                                      extId=extId)
    header = dict(response.headers)
    etag = header.get("Etag", None)
    security_details = json.loads(response.content)
    data = security_details.get("data", None)
    scope = data.get("scope",None)
    vpcReferences = data.get("vpcReferences",None)


    payload = {
        "name": data.get("name", None),
        "type": data.get("type", None),
        "rules": rules
    }

    if vpcReferences:
        payload.update({"scope" :scope,"vpcReferences" : vpcReferences})

    print("payload is ", payload)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'IF-Match': etag,
        'NTNX-Request-Id': str(uuid.uuid4())
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/microseg/v4.0.a1/config/policies/{}".format(extId)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "PUT"

    resp = process_request(url=url, method=method, payload=payload, user=username, password=passwd, headers=headers,
                           secure=secure)
    if resp.ok:
        return json.loads(resp.content)
    else:
        print("Failed to update the security Policy")
        return False


def pc_delete_security_policy_v4(api_server, username, passwd, extId,secure=False):

    """Delete Security Policy by ID.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        extId : ID of Security Policy to update
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        Response Content containing the task ID for security policy deletion.
    """  

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'NTNX-Request-Id' : str(uuid.uuid4())
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/microseg/v4.0.a1/config/policies/{}".format(extId)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "DELETE"

    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        return json.loads(resp.content)
    else:
        print("Failed to delete security Policy with extID:{}".format(extId))
        return False    


def prism_ssp_get_apps(api_server, username, passwd, secure=False, print_f=True, filter=None):

    """Retrieve the list of Applications from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of apps (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="app",entity_api_root="apps",secure=secure,print_f=print_f,filter=filter)


def prism_ssp_get_app(api_server,username,passwd,app_name=None,app_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given app name.
       If a app_uuid is specified, it will skip retrieving all apps (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        app_name: Name of the app (optional).
        app_uuid: Uuid of the app (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the app (app_uuid) and the json content
        of the app details (app)
    """

    app_uuid, app = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="app",entity_api_root="apps",entity_name=app_name,entity_uuid=app_uuid,
                              secure=secure,print_f=print_f)
    return app_uuid, app


def prism_ssp_monitor_app_provisioning(api_server, username, passwd, application_uuid, nbRetiries, waitInterval, secure=False):

    """Given an application uuid, loop until the application deployment finishes
    exits with error if the deployment fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        application_uuid: uuid of the application for which the deployment is monitored
        nbRetiries: number of retries before timeout
        waitInterval: wait interval (in seconds) between retries
        secure: boolean to verify or not the api server's certificate (True/False)
                   
    Returns:
        No value is returned
    """
 
    for x in range(nbRetiries):
        url = "https://{}:9440/api/nutanix/v3/apps/{}".format(api_server, application_uuid)
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }    
        r = process_request(url=url, method="GET", user=username, password=passwd, headers=headers, payload=None, secure=secure)
        if r.ok:
            resp = json.loads(r.content)
            if resp["status"]["state"].lower() == "error" or resp["status"]["state"].lower() == "failure" :
                print("Application deployment failed.")
                exit(1)
            elif resp["status"]["state"].lower() == "running":
                print("Application deployment finished with success.")
                return
            else:
                print("Application deployment still in progress, waiting...")
                sleep(waitInterval)
        else:
            print("Could not check status for application {}. please check status on Calm interface. exiting Execution".format(application_uuid))
            exit(1)


def prism_ssp_get_apps_in_project(api_server, username, passwd, project_name, secure=False, print_f=True, filter=None):

    """Retrieve the list of Applications in a specified project from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: project for which the apps are fetched
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of apps entities (entities part of the json response).
    """

    apps = prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="app",entity_api_root="apps",secure=secure,print_f=print_f,filter=filter)
    return [
        app for app in apps if app["metadata"]["project_reference"]["name"]==project_name
    ]


def prism_ssp_get_vms_in_app(api_server, username, passwd, application_name=None ,app_uuid=None, hypervisor_type=None, secure=False, print_f=True, filter=None):

    """Retrieve the list of VMs platform data in a specified application from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        app_name: Name of the app for which the VMs are fetched (optional).
        app_uuid: Uuid of the app for which the VMs are fetched (optional).
        hypervisor_type: type of hypervisor to filter VMs on. Optional. Condition omitted if 'None'. for example use "AHV_VM" to return only AHV VMs
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of apps entities (entities part of the json response).
    """
    app_uuid, app = prism_ssp_get_app(api_server=api_server,username=username,passwd=passwd,
                                      app_name=application_name,app_uuid=app_uuid,secure=secure,print_f=print_f)
    VM_list = []
    for deployment in app["status"]["resources"]["deployment_list"]:
        VM_list.extend(
            [
                json.loads(vm["platform_data"]) for vm in deployment["substrate_configuration"]["element_list"]
                                                    if vm["type"] == (hypervisor_type if hypervisor_type else vm["type"])
            ]
        )
    return VM_list


def prism_ssp_delete_app(api_server,username,passwd,app_name=None,app_uuid=None,secure=False,print_f=True):

    """Deletes an app given app uuid or app name.
       If an app_uuid is specified, it will skip retrieving all entities to find uuid, by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        app_type: kind (type) of app as referenced in the app json object
        app_api_root: v3 apis root for this app type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the app api root here is "projects"
        app_name: Name of the app (optional).
        app_uuid: Uuid of the app (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        No value is returned
    """

    prism_delete_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="app",entity_api_root="apps",entity_name=app_name,entity_uuid=app_uuid,
                              secure=secure,print_f=print_f)
    

def prism_ssp_get_accounts_list(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of Accounts from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of Accounts (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="account",entity_api_root="accounts",secure=secure,print_f=print_f,filter=filter)


def prism_ssp_get_account(api_server,username,passwd,account_name=None,account_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given account name.
       If an account_uuid is specified, it will skip retrieving all accounts (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        account_name: Name of the account (optional).
        account_uuid: Uuid of the account (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the account (account_uuid) and the json content
        of the account details (account)
    """

    account_uuid, account = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="account",entity_api_root="accounts",entity_name=account_name,entity_uuid=account_uuid,
                              secure=secure,print_f=print_f)
    return account_uuid, account


def prism_ssp_get_marketplace_items_list(api_server,username,passwd,secure=False,print_f=True,filter=None):


    """Retrieve the list of marketplace items  from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of marketplace items (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="marketplace_item",entity_api_root="calm_marketplace_items",secure=secure,print_f=print_f,filter=filter)


def prism_ssp_get_marketplace_item(api_server,username,passwd,marketplace_item_name=None,marketplace_item_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given marketplace item name.
       If a marketplace_item_uuid is specified, it will skip retrieving all marketplace items (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        marketplace_item_name: Name of the marketplace item (optional).
        marketplace_item_uuid: Uuid of the marketplace item (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the marketplace item (marketplace_item_uuid) and the json content
        of the marketplace item details (marketplace_item)
    """

    marketplace_item_uuid, marketplace_item = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="marketplace_item",entity_api_root="calm_marketplace_items",entity_name=marketplace_item_name,entity_uuid=marketplace_item_uuid,
                              secure=secure,print_f=print_f)
    return marketplace_item_uuid, marketplace_item


def prism_get_subnets(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of subnets from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of subnets (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",secure=secure,print_f=print_f,filter=filter)


def prism_get_subnet(api_server,username,passwd,subnet_name=None,subnet_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given subnet name.
       If a subnet_uuid is specified, it will skip retrieving all subnets (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        subnet_name: Name of the subnet (optional).
        subnet_uuid: Uuid of the subnet (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the Subnet (subnet_uuid) and the json content
        of the subnet details (subnet)
    """

    subnet_uuid, subnet = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",entity_name=subnet_name,entity_uuid=subnet_uuid,
                              secure=secure,print_f=print_f)
    return subnet["metadata"]["uuid"], subnet


def prism_get_subnet_uuid(api_server,username,passwd,subnet_name,secure=False,print_f=True):

    """Returns from Prism Central the uuid given subnet name.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        subnet_name: Name of the subnet
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the Subnet
    """

    subnet_uuid, subnet = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",entity_name=subnet_name,entity_uuid=None,
                              secure=secure,print_f=print_f)
    return subnet["metadata"]["uuid"]


def prism_create_overlay_subnet_managed(api_server,username,passwd,subnet_name,
                                        subnet_ip,prefix_length,default_gateway_ip,dns_list_csv,ip_pool_start,ip_pool_end,vpc_uuid,
                                        secure=False):

    """createa an overlay subnet.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        subnet_name: Name of the subnet to be created
        subnet_ip: ip of the ip to be created. example: "192.168.35.0"
        prefix_length: mask length (string) of the subnet to be created. example: "24"
        default_gateway_ip: ip address of the default gateway to be associated with the created subnet
        dns_list_csv: list of DNS resolvers ip addresses to be associated with this subnet ("ip1,ip2,...")
        ip_pool_start: first ip address of the ip pool
        ip_pool_end: last ip address of the ip pool
        vpc_uuid: uuid of the vpc where the subnet will be created
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        the uuid of the created subnet and the uuid of the creation task
    """

    url = 'https://{}:9440/api/nutanix/v3/subnets'.format(api_server)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = {
        "metadata": {
            "kind": "subnet"
        },
        "spec": {
            "name": subnet_name,
            "resources": {
                "ip_config": {
                    "subnet_ip": subnet_ip,
                    "prefix_length": int(prefix_length),
                    "default_gateway_ip": default_gateway_ip,
                    "pool_list": [
                        {
                            "range": "{} {}".format(ip_pool_start,ip_pool_end)
                        }
                    ],
                    "dhcp_options": {
                        "domain_search_list": dns_list_csv.split(','),
                    }
                },
                "subnet_type": "OVERLAY",
                "vpc_reference": {
                    "kind": "vpc",
                    "uuid": vpc_uuid
                }
            }
        },
        "api_version": "3.1.0"
    }

    print(json.dumps(payload))

    resp = process_request(url,'POST',user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.status_code == 202:
        result = json.loads(resp.content)
        task_uuid = result['status']['execution_context']['task_uuid']
        subnet_uuid = result['metadata']['uuid']
        print('INFO - Subnet {}/{} created with status code: {}'.format(subnet_ip,prefix_length,resp.status_code))
        print('INFO - Subnet uuid: {}'.format(subnet_uuid))
    else:
        print('ERROR - Subnet {}/{} creation failed, status code: {}, msg: {}'.format(subnet_ip,prefix_length,resp.status_code, resp.content))
        exit(1)

    return subnet_uuid, task_uuid


def prism_delete_subnet(api_server,username,passwd,subnet_name=None,subnet_uuid=None,secure=False,print_f=True):

    """Deletes a subnet given its name or uuid.
       If a subnet_uuid is specified, it will skip retrieving all subnets (faster) to find the designated subnet name.


    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        subnet_name: Name of the subnet (optional).
        subnet_uuid: uuid of the subnet (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        subnet deletion task uuid
    """

    task_uuid = prism_delete_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",entity_name=subnet_name,entity_uuid=subnet_uuid,
                              secure=secure,print_f=print_f)
    return task_uuid


def prism_monitor_task_apiv4(api_server,username,passwd,task_uuid,secure=False):

    """Given a Prism Central task uuid, loop until the task is completed
    exits if the task fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        task_uuid: Prism Central task uuid (generally returned by another action 
                   performed on PC).
        secure: boolean to verify or not the api server's certificate (True/False)
                   
    Returns:
        No value is returned
    """
    
    task_status_details = {}
    task_status = "RUNNING"

    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/prism/v4.0.a1/config/tasks/{0}".format(task_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print("Making a {} API call to {}".format(method, url))
    
    while True:
        resp = process_request(url,method,user=username,password=passwd,headers=headers,secure=secure)
        #print(json.loads(resp.content))
        if resp.ok:
            task_status_details = json.loads(resp.content)
            task_status = task_status_details.get('data',{}).get('status')
            task_prog_percent = task_status_details.get('data',{}).get('progressPercentage')
            task_sub_steps = task_status_details.get('data',{}).get('subSteps')
            if task_status == "SUCCEEDED":
                print ("Task has completed successfully")
                return task_status_details
            elif task_status == "FAILED":
                error_message = task_status_details.get("data",{}).get("errorMessages",None)
                legacy_error = task_status_details.get("data",{}).get("legacyErrorMessage",None)
                print ("Task has failed !!!\nError Message: {} \nLegacyErrorMsg: {}".format(error_message,legacy_error) )
                exit(1)
            else:
                print ("Task status is {} and percentage completion is {}. \nWaiting for 30 seconds.".format(task_status,task_prog_percent))
                if task_sub_steps:
                    print("\nSteps Completed: {}".format(task_sub_steps)) 
                sleep(30)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            exit(resp.status_code)
            

def prism_monitor_task_apiv3(api_server,username,passwd,task_uuid,secure=False):

    """Given a Prism Central task uuid, loop until the task is completed
    exits if the task fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        task_uuid: Prism Central task uuid (generally returned by another action 
                   performed on PC).
        secure: boolean to verify or not the api server's certificate (True/False)
                   
    Returns:
        No value is returned
    """
    
    task_status_details = {}
    task_status = "RUNNING"

    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/tasks/{0}".format(task_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print("Making a {} API call to {}".format(method, url))
    
    while True:
        resp = process_request(url,method,user=username,password=passwd,headers=headers,secure=secure)
        #print(json.loads(resp.content))
        if resp.ok:
            task_status_details = json.loads(resp.content)
            task_status = resp.json()['status']
            if task_status == "SUCCEEDED":
                print ("Task has completed successfully")
                return task_status_details
            elif task_status == "FAILED":
                print ("Task has failed: {}".format(   resp.json()['error_detail'] if 'error_detail' in resp.json() else "No Info" )       )
                exit(1)
            else:
                print ("Task status is {} and percentage completion is {}. Current step is {}. Waiting for 30 seconds.".format(task_status,resp.json()['percentage_complete'],resp.json()['progress_message']))
                sleep(30)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            exit(resp.status_code)

    return task_status_details


def monitor_multiple_tasks_apiv3(api_server,username,passwd,task_uuid_list, nb_retries=120, wait_interval=30, secure=False):

    """Given a Prism Central list of tasks uuids, loop until all tasks finish or some task fails
    exits if the one of the tasks fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        task_uuid_list: comma-separated list of tasks uuids
        nb_retries: number of retires before timeout
        wait_interval: interval between retries in seconds
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        No value is returned
    """

    if task_uuid_list == "":
        return
    for x in range(nb_retries):
        tasks_status_list = []
        for task_uuid in task_uuid_list.split(','):
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            api_server_port = "9440"
            api_server_endpoint = "/api/nutanix/v3/tasks/{0}".format(task_uuid)
            url = "https://{}:{}{}".format(
                api_server,
                api_server_port,
                api_server_endpoint
            )
            method = "GET"
            resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
            if resp.ok:
                task_status_details = json.loads(resp.content)
                task_status = resp.json()['status']
            else:
                print("ERROR - Failed to fetch task {} ".format(task_uuid))
                task_status_details = None
                task_status = "Fetch Failed"

            tasks_status_list.append(
                {
                    "uuid": task_uuid,
                    "state": task_status,
                    "details" : task_status_details
                }
            )

        print(">>>>> current tasks status:")
        overall_state = "SUCCEEDED"
        for task_status in tasks_status_list:
            print("Task UUID : {} \n\tStatus :{}".format(task_status["uuid"],task_status.get("state")))
            if task_status["state"].upper() == "FETCH FAILED":
                overall_state = "FAILED"                
                print("Could not Fetch the Task Status Details ")
            elif task_status["state"].upper() == "FAILED":
                overall_state = "FAILED"
                print("\tReason for failure : {}".format(task_status["details"]["error_detail"] if 'error_detail' in task_status["details"] else "No Info"))
                print("Complete response : {} ".format(task_status["details"]))
            elif task_status["state"].upper() != "SUCCEEDED" and overall_state != "FAILED":
                overall_state = "inprogress"
            for i in range(20): print("-")
        
        if overall_state == "FAILED":
            print("ERROR - Some Tasks failed. Refer above for the error details")
            exit(1)
        elif overall_state == "SUCCEEDED":
            print("INFO - All tasks finished Successfully.")
            return
        else:
            print("INFO - Tasks are still in progress, waiting...")
            sleep(wait_interval)
    #here the monitoring times out
    print("ERROR - Tasks monitoring timed out")
    exit(1)
    

def pc_get_acp_user_id(api_server,username,passwd,acp_user,secure=False):
    """
        Retrieves distinguished_name user entity_id on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        acp_user: Name of user to retrieve
        
    Returns:
        distinguished_name group id (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/groups"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'entity_type':'abac_user_capability',
        'group_member_attributes':[{'attribute':'user_uuid'}],
        'query_name':'prism:BaseGroupModel',
        'filter_criteria':'username=={}'.format(acp_user)
    }
    # endregion

    # Making the call
    print("Retreiving user uuid {}".format(acp_user))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.ok:
	    json_resp = json.loads(resp.content)
    else:
        return None
   
    if json_resp['group_results']:
        return json_resp['group_results'][0]['entity_results'][0]['entity_id']
    else:
        return None


def pc_calm_search_users(api_server,username,passwd,directory_service_uuid,search_name,secure=False):
    """
        Retrieves distinguished_name group on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_service_uuid: Uuid of the directory service
        group_name: group name to retrieve on the directory service
        
    Returns:
        distinguished_name group (string).
    """
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/calm/v3.0/calm_users/search"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'query':search_name,
        'provider_uuid': directory_service_uuid,
        'user_type':"ACTIVE_DIRECTORY",
        'is_wildcard_search':True
    }
    # endregion

    # Making the call
    print("Retrieving {} uuid".format(search_name))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.ok:
	    json_resp = json.loads(resp.content)
    else:
        return None

    # filterng
    search_value = None
    for entity in json_resp['search_result_list']:
        if entity['type'] == "Group":
            for attribute in entity['attribute_list']:
                if attribute['name'] == "distinguishedName":
                    search_value = attribute['value_list'][0]
        elif entity['type'] == "Person":
            for attribute in entity['attribute_list']:
                if attribute['name'] == "userPrincipalName":
                    search_value = attribute['value_list'][0]
    
    # return
    return search_value


def get_filter_list(role,project_uuid, cluster_uuids=None):

    # Default context for acp
    default_context = DEFAULT_CONTEXT

    # Setting project uuid in default context
    default_context["scope_filter_expression_list"][0]["right_hand_side"]["uuid_list"] = [project_uuid]

    entity_filter_expression_list = []
    if role == "Project Admin":
        entity_filter_expression_list = PROJECT_ADMIN
        entity_filter_expression_list[4]["right_hand_side"]["uuid_list"] = [
            project_uuid
        ]

    elif role == "Developer":
        entity_filter_expression_list = DEVELOPER

    elif role == "Consumer":
        entity_filter_expression_list = CONSUMER

    elif role == "Operator" and cluster_uuids:
        entity_filter_expression_list = OPERATOR

    else: #TODO work on custom Roles
        pass
        #entity_filter_expression_list = get_filters_custom_role(role_uuid, client)

    if cluster_uuids:
        entity_filter_expression_list.append(
            {
                "operator": "IN",
                "left_hand_side": {"entity_type": "cluster"},
                "right_hand_side": {"uuid_list": cluster_uuids},
            }
        )

    context_list = [default_context]
    if entity_filter_expression_list:
        context_list.append(
            {"entity_filter_expression_list": entity_filter_expression_list}
        )

    filter_list = {"context_list": context_list}
    return filter_list


def pc_set_project_acp_user(api_server,username,passwd,project_uuid,acp_user_id,user_role_uuid,role_name,secure=False):
    """
        Set group and role on a given Calm project

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        acp_user_id: user entity id to add to the calm project.
        user_role_uuid: role uuid to add to the calm project.
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers)
    if resp.ok:
        project_json = json.loads(resp.content)
    else:
        return None

    #project_json = resp
    
    user = {'kind': 'user','uuid': acp_user_id}
    # update existing access_control_policy_list
    found = False
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)
        user_ref_list = acccess_control_policy['acp']['resources']['user_reference_list']
        acp_role_id = acccess_control_policy['acp']['resources']['role_reference']['uuid']
        if acp_role_id == user_role_uuid:
            user_ref_list.append(user)
            found= True 
            break
        
    
    if not found:
        #print("Not Found")
        #create new ACP payload and append to acp_list 
        filter_list = get_filter_list(role_name,project_uuid)
        add_acp_user = {
                        'operation': 'ADD',
                        'acp': {
                            'name': 'nuCalmAcp-'+str(uuid.uuid4()),
                            'description': 'ACPDescription-'+str(uuid.uuid4()),
                            'resources': {
                                'role_reference': {
                                    'uuid': user_role_uuid,
                                    'kind': 'role'
                                },
                                'user_reference_list': [
                                    {
                                        'kind': 'user',
                                        'uuid': acp_user_id
                                    }
                                ],
                                'filter_list': filter_list
                                }
                            
                            },
                        'metadata': {'kind': 'access_control_policy'}
                        }

        project_json['spec']['access_control_policy_list'].append(add_acp_user)

    project_json['spec']['project_detail']['resources']['user_reference_list'].append(user)

    # update json
    project_json.pop('status', None) # don't need status for the update
    #project_json['metadata'].pop('owner_reference', None)
    #project_json['metadata'].pop('create_time', None)
    payload = project_json
    
    #print("The payload is \n")
    #print(payload)
    
    # Making the call
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload)

    if resp.ok:
        return json.loads(resp.content)
    else:
        return None
   

def prism_get_vm(api_server,username,passwd,vm_name=None,vm_uuid=None,secure=False,print_f=True):
    
    """Returns from Prism Central the uuid and details of a given vm name.
       If a vm_uuid is specified, it will skip retrieving all vms (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name: Name of the vm(optional).
        vm_uuid: Uuid of the vm (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the vm (vm_uuid) and the json content
        of the vm details (vm_details)
    """

    vm_uuid, vm = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                                             entity_type="vm",entity_api_root="vms",entity_name=vm_name,entity_uuid=vm_uuid,
                                             secure=secure,print_f=print_f)
    return vm_uuid, vm


def prism_put_vm(api_server,username,passwd,vm_uuid,payload,secure=False):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/vms/{}".format(vm_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "PUT"
    #print(" VM API PUT call '{}' with payload '{}' ".format(url,payload))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    task_uuid = None 
    if resp.ok:
        print("INFO - API PUT call initiated with success for VM : '{}'".format(vm_uuid))
        res = json.loads(resp.content)
        if "status" in res and "execution_context" in res["status"] \
                    and "task_uuid" in res["status"]["execution_context"]:
            task_uuid = res["status"]["execution_context"]["task_uuid"]
            task_status_details = prism_monitor_task_apiv3(api_server=api_server,username=username,passwd=passwd,secure=secure,task_uuid=task_uuid)
            return resp, task_status_details
    elif resp.status_code == 409:
        return resp, False 
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        return resp , False 


def prism_power_on_vm(api_server,username,passwd,vm_uuid,secure=False):

    retry = 5
    while True:
        vm_uuid, vm_json = prism_get_vm(api_server=api_server,username=username,passwd=passwd,vm_uuid=vm_uuid,secure=False)
        power_state = vm_json['spec']['resources']['power_state']

        if power_state == 'ON':
            print("Vm is already in Power-on state !!!")
            return False
        
        del vm_json['status']
        vm_json['spec']['resources']['power_state'] = 'ON'
        payload = vm_json

        print("API Call Initiated to power on VM : '{}'".format(vm_uuid))
        put_response,task_status_details=prism_put_vm(api_server=api_server,username=username,passwd=passwd,vm_uuid=vm_uuid,payload=payload,secure=False)
        if put_response.status_code == 409:
            if retry > 0:
                retry -= 1 
                print("VM Payload upload failed with status 409. Retrying !!!")
                continue        
            else:
                print("Maximum retries attempted. Exiting ")      
                return False
        else:
            if task_status_details.get("status") == "SUCCEEDED":
                print("VM is succesfully powered ON ")
                return True


def prism_power_off_vm(api_server,username,passwd,vm_uuid,secure=False):

    vm_uuid, vm_json = prism_get_vm(api_server=api_server,username=username,passwd=passwd,vm_uuid=vm_uuid,secure=False)
    power_state = vm_json['spec']['resources']['power_state']

    if power_state == 'OFF':
        print("Vm is already in Shutdown state !!!")
        return False

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/vms/{}/acpi_shutdown".format(vm_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    payload = {}
    print("API call to shutdown VM {}".format(vm_uuid))
#    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    if resp.ok:
        print("INFO - Shutdown task initiated with success for VM : '{}'".format(vm_uuid))
        res = json.loads(resp.content)
        task_uuid = res.get("task_uuid")

        task_status_details=prism_monitor_task_apiv3(api_server=api_server,username=username,passwd=passwd,secure=secure,task_uuid=task_uuid)
        if task_status_details.get("status") == "SUCCEEDED":
            return True

    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def prism_clone_vm(api_server,username,passwd,vm_uuid,clone_vm_name,secure=False):

    SECURITY_ZONE = '@@{SECURITY_ZONE}@@'
    SECURITY_ZONE = "ACCESSZONE"
    zone = "sddc.vwgroup.com"

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    vm_uuid, result = prism_get_vm(api_server=api_server,username=username,passwd=passwd,vm_uuid=vm_uuid,secure=secure,print_f=True)
    vm_nic_list = result["spec"]["resources"]["nic_list"]
    vmName = clone_vm_name
    adminVmName = vmName +'b'
    nic_list = []
    ip_ref = ""
    ip = ""
    for nic in vm_nic_list:
        subnet_name = nic['subnet_reference']['name']
        subnet_network = subnet_name.split("_")[2]
        if SECURITY_ZONE in subnet_name:
#            print("subnet name in prod", subnet_name)
            ip_ref,ip = get_ip_from_infoblox(subnet_network,vmName,zone)
        elif 'admin'.lower() in subnet_name.lower():
#            print("subnet name in admin", subnet_name)
            ip_ref,ip = get_ip_from_infoblox(subnet_network,adminVmName,zone)

        print("Reserved IP is ", ip)
        nic_list.append({
            "is_connected": False, 
            "subnet_reference": nic['subnet_reference'],
            "ip_endpoint_list" : [ {"ip": ip} ]
        })
        
    payload = {
        "override_spec": {
            "name": clone_vm_name,
            "nic_list": nic_list
        }
    }
    #print("Payload is ", payload)
    api_server_endpoint = "/api/nutanix/v3/vms/{}/clone".format(vm_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    resp = process_request(url=url, method=method, user=username, password=passwd, headers=headers,payload=payload,secure=secure)

    if resp.status_code == 202:
        result = resp.json()
        task_uuid = result["task_uuid"]
        print('INFO - task: {}'.format(task_uuid))
        prism_monitor_task_apiv3(api_server=api_server,username=username,passwd=passwd,secure=secure,task_uuid=task_uuid)
    else:
        print('ERROR - cloning VM failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def prism_mount_enable_ngt_on_vm(api_server,username,passwd,vm_uuid=None,vm_name=None,secure=False,print_f=True):
    
    """Function to mount and enable NGT on VM

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name: Name of the vm(optional).
        vm_uuid: Uuid of the vm (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    """
    vm_uuid, payload = prism_get_vm(api_server=api_server,username=username,passwd=passwd,vm_uuid=vm_uuid)
    del payload['status']
    payload["spec"]["resources"].update(
        {
            "guest_tools": {
                "nutanix_guest_tools": {
                    "iso_mount_state": "MOUNTED",
                    "state": "ENABLED",
                    "enabled_capability_list": ["SELF_SERVICE_RESTORE","VSS_SNAPSHOT"]
                }
            }
        }
    )
    resp, task_status_details = prism_put_vm(api_server=api_server,username=username,passwd=passwd,vm_uuid=vm_uuid,payload=payload)
    return resp, task_status_details


# endregion

prism = input(("Prism:"))
user = input(("User:"))
try:
    pwd = getpass.getpass()
except Exception as error:
    print('ERROR', error)

prism_get_cluster_utilization_average(api_server=prism,username=user,secret=pwd,average_period_days=7,secure=False)

""" filers = prism_get_filers(prism,user,pwd)
print(json.dumps(filers,indent=4))

print("First File Server Name: {0}".format(filers[0]['name']))
filer_uuid = filers[0]['uuid']

filer = prism_get_filer(prism,user,pwd,filer_uuid)
print(json.dumps(filer,indent=4)) 

filer_shares = prism_get_filer_shares(prism,user,pwd,filer_uuid)
print(json.dumps(filer_shares,indent=4))"""

