# region headers
# * author:       stephane.bourdeaud@nutanix.com
# * version:      2022/01/07
# task_name:      n/a
# description:    This is a collection of functions meant to be used in escript
#                 for interfacing with Prism Central.  Note that some functions
#                 require other functions in this library, so make sure you copy
#                 all the ones you need in your escript.
# endregion

#region base request function (required by all other functions)

import requests

def process_request(url, method, user, password, headers, payload=None, secure=False):
    if payload is not None:
        payload = json.dumps(payload)
    
    #configuring web request behavior
    timeout=10
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

#endregion

#region functions

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


def prism_get_clusters(api_server,username,secret,secure=False):
    """Retrieve the list of clusters from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of clusters (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/clusters/list"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    length = 50

    # Compose the json payload
    payload = {
        "kind": "cluster",
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
                        "kind": "cluster",
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
            exit(resp.status_code)


def prism_get_cluster(api_server,username,secret,cluster_name,cluster_uuid=None,secure=False):
    """Returns from Prism Central the uuid and details of a given cluster name.
    If a cluster_uuid is specified, it will skip retrieving all clusters (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_name: Name of the cluster.
        
    Returns:
        A string containing the UUID of the VM (vm_uuid) and the json content
        of the VM details (vm_details)
    """
    cluster_details = {}

    if cluster_uuid is None:
        #get the list of clusters from Prism Central
        cluster_list = prism_get_clusters(api_server,username,secret)
        for cluster in cluster_list:
            if cluster['spec']['name'] == cluster_name:
                cluster_uuid = cluster['metadata']['uuid']
                cluster_details = cluster.copy()
                break
    else:
        headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
        }
        api_server_port = "9440"
        api_server_endpoint = "/api/nutanix/v3/clusters/{0}".format(cluster_uuid)
        url = "https://{}:{}{}".format(
            api_server,
            api_server_port,
            api_server_endpoint
        )
        method = "GET"
        print("Making a {} API call to {}".format(method, url))
        resp = process_request(url,method,username,secret,headers,secure)
        if resp.ok:
            cluster_details = json.loads(resp.content)
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

    return cluster_uuid, cluster_details


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
            exit(resp.status_code)


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
            exit(resp.status_code)

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


def prism_get_task(api_server,username,secret,task_uuid,secure=False):
    """Given a Prism Central task uuid, loop until the task is completed
    and return the status (success or error).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        task_uuid: Prism Central task uuid (generally returned by another action 
                   performed on PC).
        
    Returns:
        The task completion status.
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
    
    while (task_status is "RUNNING"):
        resp = process_request(url,method,username,secret,headers,secure)
        #print(json.loads(resp.content))
        if resp.ok:
            task_status_details = json.loads(resp.content)
            task_status = resp.json()['status']
            if task_status == "SUCCEEDED":
                print ("Task has completed successfully")
                return task_status_details
            elif task_status == "FAILED":
                print ("Task has failed: {}".format(resp.json()['error_detail']))
                return task_status_details
            else:
                print ("Task status is {} and percentage completion is {}. Waiting for 30 seconds.".format(task_status,resp.json()['percentage_complete']))
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

    return task_status_details


# endregion