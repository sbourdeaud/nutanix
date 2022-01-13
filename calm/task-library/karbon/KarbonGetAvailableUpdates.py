# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v1/20220107
# task_name:    KarbonGetK8sUpdates
# description:  Retrieves list of available upgrade versions for the given cluster name. 
#               Using Karbon API: https://www.nutanix.dev/api_references/karbon/#/ZG9jOjQ1Mg-karbon-api-reference
# inputvars:    See inputvars region below
# outputvars:   k8s_versions and os_versions (as list)

import requests


#region inputvars
#* credentials
pc_user = "@@{prism_central.username}@@"
pc_password = "@@{prism_central.secret}@@"

#* input variables
prism_central_ip = "@@{prism_central_ip}@@"
cluster_name = "@@{cluster_name}@@"
#endregion inputvars

#region functions

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

#endregion functions

#region prepare the api call
url = "https://{}:9440/karbon/v1-beta.1/k8s/clusters/available-updates".format(prism_central_ip,cluster_name)
headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
method = 'GET'
#endregion prepare the api call


#region make the api call
resp = process_request(url, method, pc_user, pc_password, headers)
#* output vars defined here
#k8s_versions_list = [clusters['ntnx_k8s_releases'] for clusters in resp if clusters['name'] == cluster_name]
#k8s_versions = [version_number['version'] for version_number in version for version in k8s_versions_list]

k8s_versions = []
os_versions = []

for clusters in json.loads(resp.content):
    #print("clusters: {}".format(clusters))
    if clusters['name'] == cluster_name:
        if clusters['ntnx_k8s_releases']:
            for k8s_version in clusters['ntnx_k8s_releases']:
                #print("versions: {}".format(versions))
                k8s_versions.append(k8s_version['version'])
        if clusters['node_os_images']:
            for os_version in clusters['node_os_images']:
                os_versions.append(os_version['version'])


print("k8s_versions={}".format(json.dumps(k8s_versions)))
print("os_versions={}".format(json.dumps(os_versions)))

exit(0)
#endregion make the api call