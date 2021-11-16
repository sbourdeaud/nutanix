import os,requests,json,time
from prometheus_client import start_http_server, Gauge, Enum

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

            if method == 'GET':
                #print("secure is {}".format(secure))
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
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
                time.sleep(sleep_between_retries)
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

def prism_get_cluster(api_server,username,secret,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /clusters.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Cluster uuid as cluster_uuid. Cluster details as cluster_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/clusters/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure=secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        cluster_uuid = json_resp['entities'][0]['uuid']
        cluster_details = json_resp['entities'][0]
        return cluster_uuid, cluster_details
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

def prism_get_vm(vm_name,api_server,username,secret,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /vms using a vm name as a filter criteria.

    Args:
        vm_name: The VM name to search for.
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        VM details as vm_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = f"/PrismGateway/services/rest/v1/vms/?filterCriteria=vm_name%3D%3D{vm_name}"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure=secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        vm_details = json_resp['entities']
        return vm_details[0]
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

class NutanixMetrics:
    """
    Representation of Prometheus metrics and loop to fetch and transform
    application metrics into Prometheus metrics.
    """
    
    def __init__(self, app_port=9440, polling_interval_seconds=5, prism='127.0.0.1', user='admin', pwd='Nutanix/4u', prism_secure=False, vm_list=''):
        self.app_port = app_port
        self.polling_interval_seconds = polling_interval_seconds
        self.prism = prism
        self.user = user
        self.pwd = pwd
        self.prism_secure = prism_secure
        self.vm_list = vm_list
        
        cluster_uuid, cluster_details = prism_get_cluster(api_server=prism,username=user,secret=pwd,secure=self.prism_secure)
        
        if self.vm_list:
            vm_list_array = self.vm_list.split(',')
            vm_details = prism_get_vm(vm_name=vm_list_array[0],api_server=prism,username=user,secret=pwd,secure=self.prism_secure)
            for key,value in vm_details['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_vms_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['vm']))
            for key,value in vm_details['usageStats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_vms_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['vm']))
        
        # Prometheus metrics to collect
        for key,value in cluster_details['stats'].items():
            #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
            key_string = f"nutanix_clusters_stats_{key}"
            key_string = key_string.replace(".","_")
            key_string = key_string.replace("-","_")
            setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))
        for key,value in cluster_details['usage_stats'].items():
            #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
            key_string = f"nutanix_clusters_usage_stats_{key}"
            key_string = key_string.replace(".","_")
            key_string = key_string.replace("-","_")
            setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))

    def run_metrics_loop(self):
        """Metrics fetching loop"""

        while True:
            self.fetch()
            time.sleep(self.polling_interval_seconds)

    def fetch(self):
        """
        Get metrics from application and refresh Prometheus metrics with
        new values.
        """
        
        cluster_uuid, cluster_details = prism_get_cluster(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure)
        
        for key, value in cluster_details['stats'].items():
            #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
            key_string = f"nutanix_clusters_stats_{key}"
            key_string = key_string.replace(".","_")
            key_string = key_string.replace("-","_")
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(value)
        for key, value in cluster_details['usage_stats'].items():
            #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
            key_string = f"nutanix_clusters_usage_stats_{key}"
            key_string = key_string.replace(".","_")
            key_string = key_string.replace("-","_")
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(value)
        
        if self.vm_list:
            vm_list_array = self.vm_list.split(',')
            for vm in vm_list_array:
                vm_details = prism_get_vm(vm_name=vm,api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure)
                for key, value in vm_details['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_vms_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(vm=vm_details['vmName']).set(value)
                for key, value in vm_details['usageStats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_vms_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(vm=vm_details['vmName']).set(value)
        

def main():
    """Main entry point"""

    polling_interval_seconds = int(os.getenv("POLLING_INTERVAL_SECONDS", "30"))
    app_port = int(os.getenv("APP_PORT", "9440"))
    exporter_port = int(os.getenv("EXPORTER_PORT", "8000"))

    nutanix_metrics = NutanixMetrics(
        app_port=app_port,
        polling_interval_seconds=polling_interval_seconds,
        prism=os.getenv('PRISM'),
        user = os.getenv('PRISM_USERNAME'),
        pwd = os.getenv('PRISM_SECRET'),
        prism_secure=bool(os.getenv("PRISM_SECURE", False)),
        vm_list=os.getenv('VM_LIST')
    )
    
    start_http_server(exporter_port)
    nutanix_metrics.run_metrics_loop()

if __name__ == "__main__":
    main()