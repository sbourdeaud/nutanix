""" Computes the CPU, RAM (%) network (bandwidth) and storage (iops) average utilization for the specified period of time (days)
    for all VMs managed in the designated Prism Central instance.
    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.
        days: number of days to use when calculating the average utilization.
        keyring_service_id: name of the keyring service id to retrieve the username password from.
        csv: export results to csv.

    Returns:
        Print to console ouput and csv if csv arg is specified.
"""


#region IMPORT
from argparse import ArgumentParser
from time import sleep
from datetime import datetime, timedelta

import getpass
import json
import requests
import keyring
#endregion IMPORT


# region HEADERS
# * author:       stephane.bourdeaud@nutanix.com
# * version:      2024/07/18
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
        Returns:
    '''

    #* retrieving cluster stats
    prism_get_vm_utilization_average(api_server=args.prism,username=args.username,passwd=secret,average_period_days=args.days,timeout=args.timeout,secure=secure)


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


def prism_get_vm_utilization_average(api_server,username,passwd,average_period_days=30,timeout=120,secure=False):
    """Returns from Prism Central (2024.1 and above) the average resource utilization over the given time period (30 days by default).
    This function retrieves average CPU, Memory, Network and Storage utilization metrics for the specified period.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        average_period_days: Number of days over which to calculate the average resource utilization.
                             Defaults to 30 days.
        
    Returns:
        A dict with the following structure:
            - vm name
            - cluster name
            - cpu_utilization_average based on the metric hypervisorCpuUsagePpm
            - memory_utilization_average based on the metric memoryUsagePpm
            - storage_utilization_average based on the metric controllerNumIops
            - network_utilization_average based on the sum of metrics hypervisorNumReceivedBytes and hypervisorNumTransmittedBytes
    """
    
    start_time = (datetime.now() - timedelta(days=average_period_days)).isoformat()
    end_time = datetime.now().isoformat()
    interval_in_secs = 60

    params = {
        "$startTime" : f"{start_time}Z",
        "$endTime" : f"{end_time}Z",
        "$select" : "*",
        "$statType" : "AVG",
        "$samplingInterval" : interval_in_secs
    }
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/vmm/v4.0.b1/ahv/stats/vms"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url}.{PrintColors.RESET}")
    resp = process_request(url,method,user=username,password=passwd,headers=headers,params=params,secure=secure,timeout=timeout)
    if resp.ok:
        vm_stats = json.loads(resp.content)
        for vm in vm_stats['data']:
            if 'hypervisorCpuUsagePpm' in vm['stats'][0]:
                cpu_utilization_average = vm['stats'][0]['hypervisorCpuUsagePpm'] /10000
            else:
                cpu_utilization_average = 0
            if 'memoryUsagePpm' in vm['stats'][0]:
                memory_utilization_average = vm['stats'][0]['memoryUsagePpm'] /10000
            else:
                memory_utilization_average = 0
            if 'controllerNumIops' in vm['stats'][0]:
                storage_utilization_average = vm['stats'][0]['controllerNumIops']
            else:
                storage_utilization_average = 0
            if 'hypervisorNumReceivedBytes' in vm['stats'][0] and 'hypervisorNumTransmittedBytes' in vm['stats'][0]:
                network_utilization_average = vm['stats'][0]['hypervisorNumReceivedBytes'] + vm['stats'][0]['hypervisorNumTransmittedBytes']
            else:
                network_utilization_average = 0
            
            print(f"{PrintColors.DATA}{vm['vmExtId']},{round(cpu_utilization_average,2)},{round(memory_utilization_average,2)},{storage_utilization_average},{network_utilization_average}{PrintColors.RESET}")
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed: {resp.status_code} {resp.reason} {resp.text}.{PrintColors.RESET}")
        raise

    return vm_stats
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = ArgumentParser()
    parser.add_argument("-p", "--prism", type=str, help="prism server.")
    parser.add_argument("-u", "--username", type=str, help="username for prism server.")
    parser.add_argument("-d", "--days", type=int, help="number of days to use when calculating the average utilization.")
    parser.add_argument("-k", "--keyring_service_id", type=str, help="name of the service id to retrieve the password from that matches the username.")
    args = parser.parse_args()
    
    if not args.prism:
        args.prism = input(("Prism:"))
    if not args.username:
        args.username = input(("Username:"))
    if not args.days:
        args.days = 7
    if args.days > 1:
        args.timeout = 300
    else:
        args.timeout = 120
    
    # * figuring out the password
    if args.keyring_service_id:
        pwd = keyring.get_password(args.keyring_service_id, args.username)
        if not pwd:
            try:
                pwd = getpass.getpass()
            except Exception as error:
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")
    else:
        try:
            pwd = getpass.getpass()
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")
    
    main(args,secret=pwd)

   
""" Keyring add example:
import keyring
# the service is just a namespace for your app
service_id = 'IM_YOUR_APP!'
keyring.set_password(service_id, 'dustin', 'my secret password')
password = keyring.get_password(service_id, 'dustin') # retrieve password 
see https://pypi.org/project/keyring/ """
