#region functions


def prism_get_vms(api_server,username,secret):
    """Retrieve the list of VMs from Prism.

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
    length = 50

    # Compose the json payload
    payload = {
        "kind": "vm",
        "offset": 0,
        "length": length
    }
    #endregion
    while True:
        print("Making a {} API call to {}".format(method, url))
        resp = urlreq(
            url,
            verb=method,
            auth='BASIC',
            user=username,
            passwd=secret,
            params=json.dumps(payload),
            headers=headers,
            verify=False
        )

        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            print("Processing results from {} to {} out of {}".format(
                json_resp['metadata']['offset'], 
                json_resp['metadata']['length']+json_resp['metadata']['offset'],
                json_resp['metadata']['total_matches']))
            entities.extend(json_resp['entities'])
            if json_resp['metadata']['length'] == length:
                payload = {
                    "kind": "vm",
                    "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                    "length": length
                }
            else:
                return entities
                break
        else:
            print("Request failed")
            print("Headers: {}".format(headers))
            print("Payload: {}".format(json.dumps(payload)))
            print('Status code: {}'.format(resp.status_code))
            print('Response: {}'.format(
                json.dumps(
                    json.loads(resp.content), 
                    indent=4)))
            exit(1)


def prism_get_vm(api_server,username,secret,vm_name):
    """Returns from Prism the uuid and details of a given VM name.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name: Name of the virtual machine.
        
    Returns:
        A string containing the UUID of the VM (vm_uuid) and the json content
        of the VM details (vm_details)
    """
    vm_uuid = ""
    vm_details = {}

    #get the list vms from Prism
    vm_list = prism_get_vms(api_server,username,secret)
    for vm in vm_list:
        if vm['spec']['name'] == vm_name:
            vm_uuid = vm['metadata']['uuid']
            vm_details = vm.copy()
            break
    return vm_uuid, vm_details


def prism_get_clusters(api_server,username,secret):
    """Retrieve the list of clusters from Prism.

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
        "kind": "vm",
        "offset": 0,
        "length": length
    }
    #endregion
    while True:
        print("Making a {} API call to {}".format(method, url))
        resp = urlreq(
            url,
            verb=method,
            auth='BASIC',
            user=username,
            passwd=secret,
            params=json.dumps(payload),
            headers=headers,
            verify=False
        )

        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            print("Processing results from {} to {} out of {}".format(
                json_resp['metadata']['offset'], 
                json_resp['metadata']['length']+json_resp['metadata']['offset'],
                json_resp['metadata']['total_matches']))
            entities.extend(json_resp['entities'])
            if json_resp['metadata']['length'] == length:
                payload = {
                    "kind": "cluster",
                    "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                    "length": length
                }
            else:
                return entities
                break
        else:
            print("Request failed")
            print("Headers: {}".format(headers))
            print("Payload: {}".format(json.dumps(payload)))
            print('Status code: {}'.format(resp.status_code))
            print('Response: {}'.format(
                json.dumps(
                    json.loads(resp.content), 
                    indent=4)))
            exit(1)


def prism_get_cluster(api_server,username,secret,cluster_name):
    """Returns from Prism the uuid and details of a given cluster name.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_name: Name of the virtual machine.
        
    Returns:
        A string containing the UUID of the VM (vm_uuid) and the json content
        of the VM details (vm_details)
    """
    cluster_uuid = ""
    cluster_details = {}

    #get the list vms from Prism
    cluster_list = prism_get_clusters(api_server,username,secret)
    for cluster in cluster_list:
        if cluster['spec']['name'] == cluster_name:
            cluster_uuid = cluster['metadata']['uuid']
            cluster_details = cluster.copy()
            break
    return cluster_uuid, cluster_details


def prism_get_images(api_server,username,secret):
    """Retrieve the list of images from Prism.

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
        resp = urlreq(
            url,
            verb=method,
            auth='BASIC',
            user=username,
            passwd=secret,
            params=json.dumps(payload),
            headers=headers,
            verify=False
        )

        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            print("Processing results from {} to {} out of {}".format(
                json_resp['metadata']['offset'], 
                json_resp['metadata']['length']+json_resp['metadata']['offset'],
                json_resp['metadata']['total_matches']))
            entities.extend(json_resp['entities'])
            if json_resp['metadata']['length'] == length:
                payload = {
                    "kind": "cluster",
                    "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                    "length": length
                }
            else:
                return entities
                break
        else:
            print("Request failed")
            print("Headers: {}".format(headers))
            print("Payload: {}".format(json.dumps(payload)))
            print('Status code: {}'.format(resp.status_code))
            print('Response: {}'.format(
                json.dumps(
                    json.loads(resp.content), 
                    indent=4)))
            exit(1)


def prism_get_image(api_server,username,secret,image_name):
    """Returns from Prism the uuid and details of a given image name.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_name: Name of the virtual machine.
        
    Returns:
        A string containing the UUID of the image (image_uuid) and the json content
        of the image details (image_details)
    """
    image_uuid = ""
    image_details = {}

    #get the list vms from Prism
    image_list = prism_get_images(api_server,username,secret)
    for image in image_list:
        if image['spec']['name'] == image_name:
            image_uuid = image['metadata']['uuid']
            image_details = image.copy()
            break
    return image_uuid, image_details


# endregion