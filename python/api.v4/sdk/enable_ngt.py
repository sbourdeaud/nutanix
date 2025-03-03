""" gets misc entities list from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.

    Returns:
        html report file.
"""


#region IMPORT
from time import sleep
from humanfriendly import format_timespan
from urllib.parse import urlparse
from urllib.parse import parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import math
import datetime
import argparse
import getpass
import urllib3
import pandas
import keyring
import tqdm

import ntnx_vmm_py_client
#endregion IMPORT


# region HEADERS
"""
# * author:       stephane.bourdeaud@nutanix.com
# * version:      2024/12/17

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
def fetch_entities(client,module,entity_api,function,page,limit):
    entity_api_module = getattr(module, entity_api)
    entity_api = entity_api_module(api_client=client)
    list_function = getattr(entity_api, function)
    response = list_function(_page=page,_limit=limit)
    return response

def enable_ngt(client,vm_uuid):
    api = ntnx_vmm_py_client.VmApi(api_client=client)
    vm_object = api.get_vm_by_id(vm_uuid)
    etag_value = client.get_etag(vm_object)
    capabilities = ['VSS_SNAPSHOT']
    body = ntnx_vmm_py_client.GuestToolsInsertConfig(capabilities=capabilities, is_config_only=True)
    thread = api.insert_vm_guest_tools(vm_uuid, body, async_req=True, if_match=etag_value)
    result = thread.get()
    return result

def main(api_server,username,secret,target_vms,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''

    LENGTH=100
    #region vms
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_vmm_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    #* getting list of virtual machines
    client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_vmm_py_client.VmApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching VMs...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_vms(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_vmm_py_client,
                    entity_api='VmApi',
                    client=client,
                    function='list_vms',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    vm_list = entity_list

    #* building list of vm uuids to process
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Figuring out which VMs will need processing...{PrintColors.RESET}")
    vms_to_process=[]
    for entity in target_vms:
        for vm_entity in vm_list:
            if vm_entity.name == entity:
                vms_to_process.append(vm_entity)
    vm_uuids = [vm_entity.ext_id for vm_entity in vms_to_process]
    
    #* processing vm uuids
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Enabling NGT on {len(vm_uuids)} VMs...{PrintColors.RESET}")
    with tqdm.tqdm(total=len(vm_uuids), desc="Processing tasks") as progress_bar:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                enable_ngt,
                client=client,
                vm_uuid=vm_uuid
                ) for vm_uuid in vm_uuids]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    # Process the result if needed
                    #print(f"{PrintColors.SUCCESS}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Task completed: {result}{PrintColors.RESET}")
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    #endregion vms
    
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, help="True of False to control SSL certs verification.")
    parser.add_argument("--vm",
        "-v",  
        type=str,
        help="Comma separated list of VM names you want to process."
    )
    parser.add_argument("--csv",
        "-c",  
        type=str,
        help="Path and name of csv file with vm names (header: vm_name and then one vm name per line)."
    )
    args = parser.parse_args()
    
    # * check for password (we use keyring python module to access the workstation operating system password store in an "ntnx" section)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for user {args.username} from the password store.{PrintColors.RESET}")
    pwd = keyring.get_password("ntnx",args.username)
    if not pwd:
        try:
            pwd = getpass.getpass()
            keyring.set_password("ntnx",args.username,pwd)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")
            
    if args.vm:
        target_vms = args.vm.split(',')
    elif args.csv:
        data=pandas.read_csv(args.csv)
        target_vms = data['vm_name'].tolist()
    else:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify at least one vm name or a csv file!{PrintColors.RESET}")
            
    main(api_server=args.prism,username=args.username,secret=pwd,target_vms=target_vms,secure=args.secure)