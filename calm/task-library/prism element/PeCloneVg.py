# region capture Calm variables
username = "@@{pc.username}@@"
username_secret = "@@{pc.secret}@@"
api_server = "@@{pc_ip}@@"
master_vm_name = "@@{master_vm}@@"
target_vm_string = "@@{target_vms}@@"
# endregion

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
    length = 300

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
            print("Request failed")
            print("Headers: {}".format(headers))
            print("Payload: {}".format(json.dumps(payload)))
            print('Status code: {}'.format(resp.status_code))
            print('Response: {}'.format(
                json.dumps(
                    json.loads(resp.content), 
                    indent=4)))
            exit(1)
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
        "kind": "cluster",
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
            print("Request failed")
            print("Headers: {}".format(headers))
            print("Payload: {}".format(json.dumps(payload)))
            print('Status code: {}'.format(resp.status_code))
            print('Response: {}'.format(
                json.dumps(
                    json.loads(resp.content), 
                    indent=4)))
            exit(1)
#endregion

#region get information
#get all vms from Prism Central
vm_list = prism_get_vms(api_server,username,username_secret)
#todo: figure out uuids for target vms (create variable with list of target vms)
#figure out uuids for vms
target_vms = target_vm_string.split(",")
for vm in vm_list:
    if vm['status']['name'] == master_vm_name:
        master_vm_uuid = vm['metadata']['uuid']
        print('Master VM uuid: {}'.format(vm['metadata']['uuid']))
        master_vm_cluster = vm['status']['cluster_reference']['name']
        print('Cluster name: {}'.format(vm['status']['cluster_reference']['name']))
    for target in target_vms:
        if vm['status']['name'] == target:
            target_vm_uuid = vm['metadata']['uuid']
            print('Target VM uuid: {}'.format(vm['metadata']['uuid']))

#get all clusters from Prism Central
cluster_list = prism_get_clusters(api_server,username,username_secret)
#figure out the ip of our AHV cluster where our vms are running
for cluster in cluster_list:
    if cluster['status']['name'] == master_vm_cluster:
        print('Master VM cluster ip: {}'.format(cluster['status']['resources']['network']['external_ip']))

#region get volume groups from the AHV cluster
#endregion
#endregion

#region foreach target vm
#region clone master vm volume group
#endregion

#region delete target vm volume group
#endregion

#region attach volume group to target vm
#endregion
#endregion
