# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v1/20220106
# task_name:    KarbonGetClusterHealth
# description:  Retrieves health status for a Karbon managed K8s cluster. 
#               Loops until health status can be retrieved or times out after 20 minutes.
#               Using Karbon API: https://www.nutanix.dev/api_references/karbon/#/ZG9jOjQ1Mg-karbon-api-reference
# inputvars:    See inputvars region below
# outputvars:   none

import requests


#region inputvars
#* credentials
pc_user = "@@{prism_central.username}@@"
pc_password = "@@{prism_central.secret}@@"

#* input variables
prism_central_ip = "@@{prism_central_ip}@@"
cluster_name = "@@{cluster_name}@@"
#endregion inputvars


#region other variables
time_out = 20
#endregion other variables


#region prepare the api call
url = "https://{}:9440/karbon/v1/k8s/clusters/{}/health".format(prism_central_ip,cluster_name)
headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
method = 'GET'
#endregion prepare the api call


#region make the api call
count = 0
while(count < time_out):
    print("Making a GET request to {}".format(url))
    resp = requests.get(url, headers=headers, auth=(pc_user, pc_password), verify=False)
    if resp.ok:
        print ("Successfully retrieved health status for the cluster")
        print(json.loads(resp.content))
        exit(0)
    elif (resp.status_code == 412):
        print ("Cluster Health: K8s cluster deployment not ready.  Sleeping for 60 seconds")
        count = count + 1
        sleep(60)
    else:
        print ("Could not retrieve the cluster health status")
        print(json.loads(resp.content))
        exit(1)

print ("Error: Operation Timeout after 20 mins")
exit(1)
#endregion make the api call