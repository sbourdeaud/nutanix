# region capture Calm variables
username = "@@{pc.username}@@"
username_secret = "@@{pc.secret}@@"
api_server = "@@{pc_ip}@@"
master_vm_name = "@@{master_vm}@@"
master_vm_disk = "@@{master_vm_disk}@@"
master_vm_disk_size = "@@{master_vm_disk_size}@@"
master_vm_disk_size_bytes = int(master_vm_disk_size) * 1024 * 1024 * 1024
# endregion

# region functions
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
# endregion

# region get information
#get all vms from Prism Central
print("-----Getting virtual machines details from Prism Central {}".format(api_server))
vm_list = prism_get_vms(api_server,username,username_secret)
#todo: figure out uuids for target vms (create variable with list of target vms)
#figure out uuids for vms
for vm in vm_list:
    if vm['status']['name'] == master_vm_name:
        master_vm_uuid = vm['metadata']['uuid']
        print('Master VM uuid: {}'.format(vm['metadata']['uuid']))
        master_vm_cluster = vm['status']['cluster_reference']['name']
        print('Cluster name: {}'.format(vm['status']['cluster_reference']['name']))

#get all clusters from Prism Central
print("-----Getting cluster details from Prism Central {}".format(api_server))
cluster_list = prism_get_clusters(api_server,username,username_secret)
#figure out the ip of our AHV cluster where our vms are running
for cluster in cluster_list:
    if cluster['status']['name'] == master_vm_cluster:
        prism_element_cluster_ip = cluster['status']['resources']['network']['external_ip']
        print('Master VM cluster ip: {}'.format(cluster['status']['resources']['network']['external_ip']))

#region get vdisk uuid for master vm
print("Getting master VM {} disk UUID for disk {} from Prism Element {}".format(master_vm_name,master_vm_disk,prism_element_cluster_ip))
# region prepare api call
api_server_port = "9440"
api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/" + master_vm_uuid + "?include_vm_disk_config=true"
url = "https://{}:{}{}".format(
    prism_element_cluster_ip,
    api_server_port,
    api_server_endpoint
)
method = "GET"
headers = {
    'Accept': 'application/json'
}
# endregion
# region make api call
# make the API call and capture the results in the variable called "resp"
print("Making a {} API call to {}".format(method, url))
resp = urlreq(url, verb=method, auth='BASIC', user=username, passwd=username_secret,\
              headers=headers, verify=False
             )

# deal with the result/response
if resp.ok:
    print("Request was successful. Status code: {}".format(resp.status_code))
    json_resp = json.loads(resp.content)
    for vmdisk in json_resp['vm_disk_info']:
        if vmdisk['disk_address']['disk_label'] == master_vm_disk:
            master_vmdisk_uuid = vmdisk['disk_address']['vmdisk_uuid']
            storage_container_uuid = vmdisk['storage_container_uuid']
            print("master_vmdisk_uuid= {}".format(master_vmdisk_uuid))
            print("storage_container_uuid= {}".format(storage_container_uuid))
else:
    print("Request failed")
    print("Headers: {}".format(headers))
    print('Status code: {}'.format(resp.status_code))
    print('Response: {}'.format(json.dumps(json.loads(resp.content), indent=4)))
    exit(1)
# endregion
#endregion

#endregion
# endregion

# region update vm disk
print("-----Processing virtual machine {}".format(master_vm_uuid))
print("-----Updating disk uuid {} on virtual machine {}; changing size to {} GiB".format(master_vmdisk_uuid,master_vm_uuid,master_vm_disk_size))

# region prepare api call
api_server_port = "9440"
api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/" + master_vm_uuid + "/disks/update"
url = "https://{}:{}{}".format(
    prism_element_cluster_ip,
    api_server_port,
    api_server_endpoint
)
method = "PUT"
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}
payload = {
    "vm_disks": [
        {
            "disk_address": {
                "vmdisk_uuid": master_vmdisk_uuid
            },
            "vm_disk_create": {
                "storage_container_uuid": storage_container_uuid,
                "size": master_vm_disk_size_bytes
            }
        }
    ]
}
# endregion

# region make api call
# make the API call and capture the results in the variable called "resp"
print("Making a {} API call to {}".format(method, url))
resp = urlreq(url, verb=method, auth='BASIC', user=username, passwd=username_secret,\
            headers=headers, verify=False, params=json.dumps(payload)
            )

# deal with the result/response
if resp.ok:
    print("Request was successful. Status code: {}".format(resp.status_code))
else:
    print("Request failed")
    print("Payload: {}".format(json.dumps(payload)))
    print("Headers: {}".format(headers))
    print('Status code: {}'.format(resp.status_code))
    print('Response: {}'.format(json.dumps(json.loads(resp.content), indent=4)))
    exit(1)
# endregion

# endregion
