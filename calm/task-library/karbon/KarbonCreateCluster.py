# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v1/20220106
# task_name:    KarbonCreateCluster
# description:  Deploys a Karbon K8s cluster. Using Karbon API: https://www.nutanix.dev/api_references/karbon/#/ZG9jOjQ1Mg-karbon-api-reference
# inputvars:    See inputvars region below
# outputvars:   create_task_uuid

import requests


#region inputvars
#* credentials
pc_user = "@@{prism_central.username}@@"
pc_password = "@@{prism_central.secret}@@"
storage_class_user = "@@{storage_class_user.username}@@"
storage_class_user_password = "@@{storage_class_user.secret}@@"

#* input variables
worker_node_memory = 1024 * int("@@{worker_node_memory}@@")
worker_node_disk = 1024 * int("@@{worker_node_disk_size}@@")
worker_node_cpu = int("@@{worker_node_cpu}@@")
worker_node_qty = int("@@{worker_node_qty}@@")

cluster_name = "@@{cluster_name}@@"
worker_node_pool = "@@{cluster_name}@@" + "-worker-node-pool"
master_node_pool = "@@{cluster_name}@@" + "-master-node-pool"
etcd_node_pool = "@@{cluster_name}@@" + "-etcd-node-pool"
file_system = "ext4"
storage_container_name = "@@{storage_container_name}@@"
k8s_version = "@@{k8s_version}@@"
image_name = "@@{image_name}@@"
master_config = "@@{master_config}@@"

pe_cluster_uuid = "@@{pe_cluster_uuid}@@"
subnet_uuid = "@@{subnet_uuid}@@"

pod_cidr_range = "@@{pod_cidr_range}@@"
service_cidr_range = "@@{service_cidr_range}@@"
k8s_cni = "@@{k8s_cni}@@"
calico_cidr = "@@{calico_cidr}@@"
master_vip = "@@{master_vip}@@"
master_vip2 = "@@{master_vip2}@@"
external_lb = "@@{external_lb}@@"
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
url = "https://localhost:9440/karbon/v1/k8s/clusters"
headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
method = 'POST'
#initial payload
payload = {
  "cni_config": {
    "node_cidr_mask_size": 24,
    "pod_ipv4_cidr": pod_cidr_range,
    "service_ipv4_cidr": service_cidr_range
  },
  "etcd_config": {
   
  },
  "masters_config": {
    
  },
  "metadata": {
    "api_version": "v1.0.0"
  },
  "name": cluster_name,
  "storage_class_config": {
    "default_storage_class": True,
    "name": "default-storageclass",
    "reclaim_policy": "Delete",
    "volumes_config": {
      "file_system": file_system,
      "flash_mode": False,
      "password": storage_class_user_password,
      "prism_element_cluster_uuid": pe_cluster_uuid,
      "storage_container": storage_container_name,
      "username": storage_class_user
    }
  },
  "version": k8s_version,
  "workers_config": {
    "node_pools": [
    {
      "ahv_config": {
        "cpu": worker_node_cpu,
        "disk_mib": worker_node_disk,
        "memory_mib": worker_node_memory,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": worker_node_pool,
      "node_os_version": image_name,
      "num_instances": worker_node_qty
    }]
  }
}
#adding cni specific configuration
if (k8s_cni == "Flannel"):
  print ("Configuring Flannel CNI")
  payload['cni_config']['flannel_config'] = {
    "ip_pool_configs": [{
      "cidr": pod_cidr_range
    }]   
  }
else:
  print ("Configuring Calico CNI")
  payload['cni_config']['calico_config'] = {
    "ip_pool_configs": [{
      "cidr": calico_cidr
    }]   
  }
#variations for master/etcd pools and lb configuration
if (master_config == "Single Master"):
  print ("Configuring Single Master")
  master_pool = {
    "node_pools": [
    {
      "ahv_config": {
        "cpu": 2,
        "disk_mib": 122880,
        "memory_mib": 4096,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": master_node_pool,
      "node_os_version": image_name,
      "num_instances": 1
    }],
    "single_master_config": { 
      "external_ipv4_address": master_vip
    }
  }
  payload['masters_config'] = master_pool  
  etcd_pool = {
    "node_pools": [
    {
      "ahv_config": {
        "cpu": 4,
        "disk_mib": 40960,
        "memory_mib": 8192,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": etcd_node_pool,
      "node_os_version": image_name,
      "num_instances": 1
    }]
  }
  payload['etcd_config'] = etcd_pool
elif (master_config == "Active-Passive"):
  print ("Configuring Active-Passive Master")
  master_pool = { 
    "active_passive_config": {
      "external_ipv4_address": master_vip
    },
    "node_pools": [
    {
      "ahv_config": {
        "cpu": 4,
        "disk_mib": 122880,
        "memory_mib": 4096,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": master_node_pool,
      "node_os_version": image_name,
      "num_instances": 2
    }]
  }
  payload['masters_config'] = master_pool
  etcd_pool = {
    "node_pools": [
    {
      "ahv_config": {
        "cpu": 4,
        "disk_mib": 40960,
        "memory_mib": 8192,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": etcd_node_pool,
      "node_os_version": image_name,
      "num_instances": 3
    }]
  }
  payload['etcd_config'] = etcd_pool
else:
  print ("Configuring Active-Active LoadBalancer Master")
  master_pool = {
    "external_lb_config": {
      "external_ipv4_address": external_lb,
      "master_nodes_config": [
      {
        "ipv4_address": master_vip,
        "node_pool_name": cluster_name
      },
      {
        "ipv4_address": master_vip2,
        "node_pool_name": cluster_name
      }
    ]},
    "node_pools": [
    {
      "ahv_config": {
        "cpu": 4,
        "disk_mib": 122880,
        "memory_mib": 4096,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": master_node_pool,
      "node_os_version": image_name,
      "num_instances": 2
    }]
  }
  payload['masters_config'] = master_pool
  etcd_pool = {
    "node_pools": [
    {
      "ahv_config": {
        "cpu": 4,
        "disk_mib": 40960,
        "memory_mib": 8192,
        "network_uuid": subnet_uuid,
        "prism_element_cluster_uuid": pe_cluster_uuid
      },
      "name": etcd_node_pool,
      "node_os_version": image_name,
      "num_instances": 3
    }]  
  }
  payload['etcd_config'] = etcd_pool
#endregion prepare the api call


#region make the api call
print(json.dumps(payload))
resp = process_request(url, method, pc_user, pc_password, headers, payload)
print ("Creation of task to create cluster was successful", json.dumps(json.loads(resp.content), indent=4))
create_task_uuid = resp.json()['task_uuid']
print ("task_uuid={}".format(create_task_uuid))
exit(0)
#endregion make the api call
