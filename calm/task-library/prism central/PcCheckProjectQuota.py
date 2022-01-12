# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v1/20220111
# task_name:    PcCheckProjectQuota
# description:  Given a project name, check the project quota against provided resources. 
#               If there are not enough available resources in the quota, returns a failure code.
#               Using PCv3 API: https://www.nutanix.dev/api_references/prism-central-v3/#/ZG9jOjQ1Mg-nutanix-intentful-api
# inputvars:    See inputvars region below
# outputvars:   none

import requests


#region inputvars
pc_user = "@@{prism_central.username}@@"
pc_password = "@@{prism_central.secret}@@"

#* input variables
prism_central_ip = "@@{prism_central_ip}@@"
project_reference = json.loads('@@{project_reference}@@')
master_config = "@@{master_config}@@"
worker_node_cpu_count = int("@@{worker_node_cpu}@@")
worker_node_vram_bytes = int("@@{worker_node_memory}@@")*1024*1024*1024
worker_node_storage_bytes = (int("@@{worker_node_disk_size}@@")+40)*1024*1024*1024
worker_node_qty = int("@@{worker_node_qty}@@")

#? master and etcd nodes configuration depends on master_config (Single Master, or Active-Passive/Active-Active)
#? worker nodes is based on user input and stored in worker_node_cpu, worker_node_memory, worker_node_disk_size, worker_node_qty
#? for disk size, add +40GB for system disks for each node VM
if master_config == "Single Master":
    master_node_cpu_count = 2
    master_node_vram_bytes = 4*1024*1024*1024
    master_node_storage_bytes = (120+40)*1024*1024*1024
    master_node_qty = 1
    etcd_node_cpu_count = 4
    etcd_node_vram_bytes = 8*1024*1024*1024
    etcd_node_storage_bytes = (40+40)*1024*1024*1024
    etcd_node_qty = 1
else:
    master_node_cpu_count = 4
    master_node_vram_bytes = 4*1024*1024*1024
    master_node_storage_bytes = (120+40)*1024*1024*1024
    master_node_qty = 2
    etcd_node_cpu_count = 4
    etcd_node_vram_bytes = 8*1024*1024*1024
    etcd_node_storage_bytes = (40+40)*1024*1024*1024
    etcd_node_qty = 3

#worker node(s) + master node(s) + etcd node(s) 
required_vcpus_count = (int(worker_node_cpu_count) * int(worker_node_qty)) + (master_node_cpu_count * master_node_qty) +  (etcd_node_cpu_count * etcd_node_qty)
required_vram_bytes = (int(worker_node_vram_bytes) * int(worker_node_qty)) + (master_node_vram_bytes * master_node_qty) +  (etcd_node_vram_bytes * etcd_node_qty)
required_storage_bytes = (int(worker_node_storage_bytes) * int(worker_node_qty)) + (master_node_storage_bytes * master_node_qty) +  (etcd_node_storage_bytes * etcd_node_qty)
#endregion inputvars

#region functions

def process_request(url, method, user, password, headers, payload=None, secure=False):
    if payload is not None:
        payload = json.dumps(payload)
    
    #configuring web request behavior
    timeout=30
    retries = 5
    sleep_between_retries = 5
    
    while retries > 0:
        try:

            if method == 'POST':
                    r = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                r = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'GET':
                r = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                    r = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                    r = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
        except requests.exceptions.HTTPError as e:
            print ("Http Error!")
            print("status code: {}".format(r.status_code))
            print("reason: {}".format(r.reason))
            print("text: {}".format(r.text))
            print("elapsed: {}".format(r.elapsed))
            print("headers: {}".format(r.headers))
            if payload is not None:
                print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(r.content),
                indent=4
            ))
            exit(r.status_code)
        except requests.exceptions.ConnectionError as e:
            print ("Connection Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(e).__name__, m = str(e)))
                exit(1)
            else:
                print('Error: {c}, Message: {m}'.format(c = type(e).__name__, m = str(e)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
            print('Error: {c}, Message: {m}'.format(c = type(e).__name__, m = str(e)))
            exit(1)
        except requests.exceptions.Timeout as e:
            print ("Timeout Error!")
            if retries == 1:
                raise Exception(e)
            else:
                print('Error! Code: {c}, Message: {m}'.format(c = type(e).__name__, m = str(e)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
        except requests.exceptions.RequestException as e:
            print ("Error!")
            exit(r.status_code)
        break
    
    if r.ok:
        return r
    if r.status_code == 401:
        print("status code: {0}".format(r.status_code))
        print("reason: {0}".format(r.reason))
        exit(r.status_code)
    elif r.status_code == 500:
        print("status code: {0}".format(r.status_code))
        print("reason: {0}".format(r.reason))
        print("text: {0}".format(r.text))
        exit(r.status_code)
    else:
        print("Request failed!")
        print("status code: {0}".format(r.status_code))
        print("reason: {0}".format(r.reason))
        print("text: {0}".format(r.text))
        print("raise_for_status: {0}".format(r.raise_for_status()))
        print("elapsed: {0}".format(r.elapsed))
        print("headers: {0}".format(r.headers))
        if payload is not None:
            print("payload: {0}".format(payload))
        print(json.dumps(
            json.loads(r.content),
            indent=4
        ))
        exit(r.status_code)


def prism_get_projects(api_server,username,secret,secure=False):
    """Retrieve the list of Projects from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of Projects (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects/list"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    length = 200

    # Compose the json payload
    payload = {
        "kind": "project",
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
                        "kind": "project",
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


def prism_get_project(api_server,username,secret,project_name=None,project_uuid=None,secure=False):
    """Returns from Prism Central the uuid and details of a given project name.
       If a project_uuid is specified, it will skip retrieving all vms (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project.
        project_uuid: Uuid of the project (optional).
        
    Returns:
        A string containing the UUID of the Project (project_uuid) and the json content
        of the project details (project_details)
    """
    project_details = {}

    if project_uuid is None:
        #get the list vms from Prism
        project_list = prism_get_projects(api_server,username,secret,secure)
        for project in project_list:
            if project['spec']['name'] == project_name:
                project_uuid = project['metadata']['uuid']
                project_details = project.copy()
                break
    else:
        headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
        }
        api_server_port = "9440"
        api_server_endpoint = "/api/nutanix/v3/projects/{0}".format(project_uuid)
        url = "https://{}:{}{}".format(
            api_server,
            api_server_port,
            api_server_endpoint
        )
        method = "GET"
        print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url,method,username,secret,headers,secure)
        if resp.ok:
            project_details = json.loads(resp.content)
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
    return project_uuid, project_details

#endregion functions


#region main execution

print("Provisioning request required vCPUs: {}".format(required_vcpus_count))
print("Provisioning request required memory GB: {}".format(required_vram_bytes/1024/1024/1024))
print("Provisioning request required storage GB: {}".format(required_storage_bytes/1024/1024/1024))


#region get project quotas
project_uuid,project_details = prism_get_project(prism_central_ip,pc_user,pc_password,project_uuid=project_reference['uuid'])
#get resource total allocated quota from the project definition
project_cpu_quota = [limit['limit'] for limit in project_details['spec']['resources']['resource_domain']['resources'] if limit['resource_type'] == 'VCPUS']
print("Project vCPU quota: {}".format(project_cpu_quota[0]))
project_memory_bytes_quota = [limit['limit'] for limit in project_details['spec']['resources']['resource_domain']['resources'] if limit['resource_type'] == 'MEMORY']
print("Project memory GB quota: {}".format(int(project_memory_bytes_quota[0])/1024/1024/1024))
project_storage_bytes_quota = [limit['limit'] for limit in project_details['spec']['resources']['resource_domain']['resources'] if limit['resource_type'] == 'STORAGE']
print("Project storage GB quota: {}".format(int(project_storage_bytes_quota[0])/1024/1024/1024))
#endregion get project quotas

#region get project allocated resources
#retrieve list of project vms and their current resource allocation
#region api call
headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
}
api_server_port = "9440"
api_server_endpoint = "/api/nutanix/v3/groups"
url = "https://{}:{}{}".format(
    prism_central_ip,
    api_server_port,
    api_server_endpoint
)
method = "POST"
payload = {
    "entity_type": "mh_vm",
    "group_member_count": 500,
    "group_member_offset": 0,
    "group_member_attributes": [
        {
            "attribute": "memory_size_bytes"
        },
        {
            "attribute": "capacity_bytes"
        },
        {
            "attribute": "num_vcpus"
        },
        {
            "attribute": "project_reference"
        },
        {
            "attribute": "project_name"
        }
    ],
    "query_name": "prism:EBQueryModel",
    "availability_zone_scope": "GLOBAL",
    "filter_criteria": "(platform_type!=aws,platform_type==[no_val]);project_reference=in={}".format(project_uuid)
}
print("Making a {} API call to {}".format(method, url))
r = process_request(url,method,pc_user,pc_password,headers,payload)
#endregion api call

#compute total current resource allocation
resp = json.loads(r.content)


project_cpu_allocated = 0
project_memory_bytes_allocated = 0
project_storage_bytes_allocated = 0

if int(resp['filtered_entity_count']) > 0:
    entities=[entities for entities in resp['group_results'][0]['entity_results']]
    vm_data = [data['data'] for data in entities]

    for vm in vm_data:
        for values in vm:
            if values['name'] == 'num_vcpus':
                for value in values['values']:
                    project_cpu_allocated = project_cpu_allocated + int(value['values'][0])
            elif values['name'] == 'memory_size_bytes':
                    for value in values['values']:
                        project_memory_bytes_allocated = project_memory_bytes_allocated + int(value['values'][0])
            elif values['name'] == 'capacity_bytes':
                    for value in values['values']:
                        project_storage_bytes_allocated = project_storage_bytes_allocated + int(value['values'][0])
                
    print("Project allocated vCPUs: {}".format(project_cpu_allocated))
    print("Project allocated memory GB: {}".format(project_memory_bytes_allocated/1024/1024/1024))
    print("Project allocated storage GB: {}".format(project_storage_bytes_allocated/1024/1024/1024))
else:
    print("Project allocated vCPUs: 0")
    print("Project allocated memory GB: 0")
    print("Project allocated storage GB: 0")
#endregion get project allocated resources

#region figure out if request complies with quotas
#compute resources available in the project (quota - allocated)
project_available_vcpus = int(project_cpu_quota[0]) - project_cpu_allocated
print("Project available vCPUs: {}".format(project_available_vcpus))
project_available_memory_bytes = int(project_memory_bytes_quota[0]) - project_memory_bytes_allocated
print("Project available memory bytes: {}".format(project_available_memory_bytes))
project_available_storage_bytes = int(project_storage_bytes_quota[0]) - project_storage_bytes_allocated
print("Project available storage bytes: {}".format(project_available_storage_bytes))

#determine if there are enough resource available to process the request
if (project_available_vcpus - required_vcpus_count) <= 0:
    print("There aren't enough resources left in the project quota to accomodate this request!")
    exit(1)
elif (project_available_memory_bytes - required_vram_bytes) <= 0:
    print("There aren't enough resources bytes left in the project quota to accomodate this request!")
    exit(1)
elif (project_available_storage_bytes - required_storage_bytes) <= 0:
    print("There aren't enough resources bytes left in the project quota to accomodate this request!")
    exit(1)
else:
    print("Project resources quota can accomodate this request.")
    exit(0)
#endregion figure out if request complies with quotas

#endregion main execution
