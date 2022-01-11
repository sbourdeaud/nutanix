# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v1/20220107
# task_name:    PcUpdateVmProject
# description:  Given a list of vms and a project reference, update all those vms project with the new project reference.
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
vm_list = @@{k8s_cluster_node_vms}@@
#endregion inputvars

#region functions

def process_request(url, method, user, password, headers, payload=None, secure=False):
    if payload is not None:
        payload = json.dumps(payload)
    
    #configuring web request behavior
    timeout=60
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

#endregion functions

#region main processing
#* get all vms
vms = prism_get_vms(prism_central_ip,pc_user,pc_password)

#*foreach given vm in the list
for vm in vm_list:
    #* figure out spec and metadata payload for that vm
    for vm_object in vms:
        if vm_object['spec']['name'] == vm:
            vm_uuid = vm_object['metadata']['uuid']
            vm_details = vm_object.copy()
            break
    vm_details.pop('status')
    del vm_details['metadata']['entity_version']
    #print("before: {}".format(vm_details))
    #* update project reference
    if vm_details['metadata']['project_reference']['name'] != project_reference['name']:
        vm_details['metadata']['project_reference'] = project_reference
        print("updated metadata section: {}".format(json.dumps(vm_details['metadata'])))
        print("vm_uuid: {}".format(vm_uuid))
        
        #* update vm with put
        #region prepare the api call
        url = "https://{}:9440/api/nutanix/v3/vms/{}".format(prism_central_ip,vm_uuid)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        method = 'PUT'
        #initial payload
        payload = vm_details
        #print("payload: {}".format(json.dumps(payload)))
        #endregion prepare the api call
        #region make the api call
        print("Making a {} API call to {}".format(method, url))
        resp = process_request(url, method, pc_user, pc_password, headers, payload)
        print ("Updated virtual machine {} with project {}".format(vm_details['spec']['name'],project_reference['name']))
        print(json.loads(resp.content))
        #endregion make the api call
    else:
        print("Project for vm {} is already {}. Skipping.".format(vm_details['spec']['name'],project_reference['name']))

exit(0)


#endregion main processing