# region headers
"""
# * author:       stephane.bourdeaud@nutanix.com
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

def process_request(url, method, user, password, headers, payload=None, secure=False):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    #configuring web request behavior
    timeout=10
    retries = 5
    sleep_between_retries = 5

    while retries > 0:
        try:

            if method is 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.HTTPError as error_code:
            print ("Http Error!")
            print("status code: {}".format(response.status_code))
            print("reason: {}".format(response.reason))
            print("text: {}".format(response.text))
            print("elapsed: {}".format(response.elapsed))
            print("headers: {}".format(response.headers))
            if payload is not None:
                print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            print ("Connection Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            else:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            exit(1)
        except requests.exceptions.Timeout as error_code:
            print ("Timeout Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            print('Error! Code: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            sleep(sleep_between_retries)
            retries -= 1
            print ("retries left: {}".format(retries))
            continue
        except requests.exceptions.RequestException as error_code:
            print ("Error!")
            exit(response.status_code)
        break

    if response.ok:
        return response
    if response.status_code == 401:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        exit(response.status_code)
    elif response.status_code == 500:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        exit(response.status_code)
    else:
        print("Request failed!")
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        print("raise_for_status: {0}".format(response.raise_for_status()))
        print("elapsed: {0}".format(response.elapsed))
        print("headers: {0}".format(response.headers))
        if payload is not None:
            print("payload: {0}".format(payload))
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)
 
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
            raise


def prism_get_cluster(api_server,username,secret,cluster_name,cluster_uuid=None,secure=False):
    """Returns from Prism Central the uuid and details of a given cluster name.
    If a cluster_uuid is specified, it will skip retrieving all clusters (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_name: Name of the cluster.
        
    Returns:
        A string containing the UUID of the cluster (cluster_uuid) and the json content
        of the cluster details (cluster_details)
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
            raise

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



# endregion

prism = raw_input(("Prism:"))
user = raw_input(("User:"))
try:
    pwd = getpass.getpass()
except Exception as error:
    print('ERROR', error)


filers = prism_get_filers(prism,user,pwd)
print(json.dumps(filers,indent=4))

print("First File Server Name: {0}".format(filers[0]['name']))
filer_uuid = filers[0]['uuid']

filer = prism_get_filer(prism,user,pwd,filer_uuid)
print(json.dumps(filer,indent=4))

filer_shares = prism_get_filer_shares(prism,user,pwd,filer_uuid)
print(json.dumps(filer_shares,indent=4))