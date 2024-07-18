""" describe what the script does

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.

    Returns:
        (json response).
"""


#region IMPORT
from argparse import ArgumentParser
from time import sleep
from datetime import datetime, timedelta

import getpass
import json
import requests
#endregion IMPORT


# region HEADERS
"""
# * author:       stephane.bourdeaud@nutanix.com
# * version:      2024/07/18

# description:    
"""
# endregion HEADERS


#region CLASS
class PrintColors:
    """Used for colored output formatting.
    """
    OK = '\033[92m' #GREEN
    SUCCESS = '\033[96m' #CYAN
    DATA = '\033[097m' #WHITE
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    STEP = '\033[95m' #PURPLE
    RESET = '\033[0m' #RESET COLOR
#endregion CLASS


#region FUNCTIONS
def main(args,secret,secure=False):
    '''description.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            exclusion_file: path to the software exclusion json file.
        Returns:
    '''

    #* retrieving cluster stats
    prism_get_cluster_utilization_average(api_server=args.prism,username=args.username,passwd=secret,average_period_days=args.days,secure=secure)


def process_request(url, method, user=None, password=None, cert=None, files=None,headers=None, payload=None, params=None, secure=False, timeout=120, retries=5, exit_on_failure=True):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    sleep_between_retries=5

    while retries > 0:
        try:

            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password) if user else None,
                    cert=cert if cert else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    files=files if files else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.RequestException as error_code:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {type(error_code).__name__} {str(error_code)}.{PrintColors.RESET}")
            retries -= 1
            sleep(sleep_between_retries)
            continue
        
        if response.ok:
            return response
        elif response.status_code == 409:
            print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {response.text}.{PrintColors.RESET}")
            retries -= 1
            if retries == 0:
                if exit_on_failure:
                    exit(response.status_code)
                else:
                    return response
            sleep(sleep_between_retries)
            continue
        else:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.text}.{PrintColors.RESET}")
            if exit_on_failure:
                exit(response.status_code)
            else:
                return response


def prism_get_cluster_utilization_average(api_server,username,passwd,average_period_days=30,secure=False):
    """Returns from Prism Element the average resource utilization over the given time period (30 days by default).
    This function retrieves CPU, Memory and Storage utilization metrics for the specified period and 
    computes the average for each metric.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        average_period_days: Number of days over which to calculate the average resource utilization.
                             Defaults to 30 days.
        
    Returns:
        The following integers:
            - For CPU utilization: cpu_utilization_average based on the metric hypervisor_cpu_usage_ppm
            - For Memory utilization: memory_utilization_average based on the metric hypervisor_memory_usage_ppm
            - For Storage utilization: storage_utilization_average based on the metric controller_num_iops
    """
    start_time_in_usecs = int(((datetime.now() + timedelta(days = -average_period_days)) - datetime(1970, 1, 1)).total_seconds() *1000000)
    end_time_in_usecs = int(((datetime.now() + timedelta(days = -1)) - datetime(1970, 1, 1)).total_seconds() *1000000)
    interval_in_secs = 60

    params = {
        "metrics" : "hypervisor_cpu_usage_ppm,hypervisor_memory_usage_ppm,controller_num_iops",
        "start_time_in_usecs" : start_time_in_usecs,
        "end_time_in_usecs" : end_time_in_usecs,
        "interval_in_secs" : interval_in_secs
    }
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/cluster/stats/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url}.{PrintColors.RESET}")
    resp = process_request(url,method,user=username,password=passwd,headers=headers,params=params,secure=secure)
    if resp.ok:
        cluster_metrics_values = json.loads(resp.content)
        cpu_metrics = [stat['values'] for stat in cluster_metrics_values['stats_specific_responses'] if stat['metric'] == "hypervisor_cpu_usage_ppm"]
        memory_metrics = [stat['values'] for stat in cluster_metrics_values['stats_specific_responses'] if stat['metric'] == "hypervisor_memory_usage_ppm"]
        storage_metrics = [stat['values'] for stat in cluster_metrics_values['stats_specific_responses'] if stat['metric'] == "controller_num_iops"]
        cpu_utilization_average = sum(cpu_metrics[0]) / len(cpu_metrics[0]) /10000
        memory_utilization_average = sum(memory_metrics[0]) / len(memory_metrics[0]) /10000
        storage_utilization_average = int(sum(storage_metrics[0]) / len(storage_metrics[0]))
        print(f"{PrintColors.DATA}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] CPU Utilization Average for the last {average_period_days} days is: {round(cpu_utilization_average,2)} %.{PrintColors.RESET}")
        print(f"{PrintColors.DATA}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Memory Utilization Average for the last {average_period_days} days is: {round(memory_utilization_average,2)} %.{PrintColors.RESET}")
        print(f"{PrintColors.DATA}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Storage Utilization Average for the last {average_period_days} days is: {round(storage_utilization_average,2)} iops.{PrintColors.RESET}")
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed: {resp.status_code} {resp.reason} {resp.text}.{PrintColors.RESET}")
        raise

    return cpu_utilization_average, memory_utilization_average, storage_utilization_average
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = ArgumentParser()
    parser.add_argument("-p", "--prism", type=str, help="prism server.")
    parser.add_argument("-u", "--username", type=str, help="username for prism server.")
    parser.add_argument("-d", "--days", type=int, help="number of days to use when calculating the average utilization.")
    args = parser.parse_args()
    
    if not args.days:
        args.days = 7
    
    # * prompting user for the password
    try:
        pwd = getpass.getpass()
    except Exception as error:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")
    
    main(args,secret=pwd)