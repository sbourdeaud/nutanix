""" perform various actions to manage Nutanix Guest Tools (NGT) on a list of VMs.

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.
        secure: True or False to control SSL certs verification.
        vm: Comma separated list of VM names you want to process.
        csv: Path and name of csv file with vm names (header: vm_name and then one vm name per line).
        threads: Maximum number of threads for parallel processing (defaults to 5).
        action: NGT action you want to take (enable, mount, upgrade).

    Returns:
        html report file.
"""


#region IMPORT
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import math
import time
import argparse
import getpass

from humanfriendly import format_timespan

import urllib3
import pandas as pd
import keyring
import tqdm

import ntnx_vmm_py_client
#endregion IMPORT


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
    '''fetch_entities function.
        Args:
            client: a v4 Python SDK client object.
            module: name of the v4 Python SDK module to use.
            entity_api: name of the entity API to use.
            function: name of the function to use.
            page: page number to fetch.
            limit: number of entities to fetch.
        Returns:
    '''
    entity_api_module = getattr(module, entity_api)
    entity_api = entity_api_module(api_client=client)
    list_function = getattr(entity_api, function)
    response = list_function(_page=page,_limit=limit)
    return response


def insert_ngt(client,vm_uuid,is_config_only=False,run_async=False):
    '''insert_ngt function (uses insert_vm_guest_tools with is_config_only set to True).
        Args:
            client: a v4 Python SDK client object.
            vm_uuid: ext_id/uuid of the vm object to target.
        Returns:
    '''
    api = ntnx_vmm_py_client.VmApi(api_client=client)
    vm_object = api.get_vm_by_id(vm_uuid)
    etag_value = client.get_etag(vm_object)
    capabilities = ['VSS_SNAPSHOT']
    body = ntnx_vmm_py_client.GuestToolsInsertConfig(capabilities=capabilities, is_config_only=is_config_only)
    thread = api.insert_vm_guest_tools(vm_uuid, body, async_req=run_async, if_match=etag_value)
    result = thread.get()
    return result


def upgrade_ngt(client,vm_uuid,run_async=False):
    '''upgrade_ngt function (uses insert_vm_guest_tools with is_config_only set to True).
        Args:
            client: a v4 Python SDK client object.
            vm_uuid: ext_id/uuid of the vm object to target.
        Returns:
    '''
    api = ntnx_vmm_py_client.VmApi(api_client=client)
    vm_object = api.get_vm_by_id(vm_uuid)
    etag_value = client.get_etag(vm_object)
    body = ntnx_vmm_py_client.GuestToolsUpgradeConfig(reboot_preference=None)
    thread = api.upgrade_vm_guest_tools(vm_uuid, body, async_req=run_async, if_match=etag_value)
    result = thread.get()
    return result


def main(api_server,username,secret,target_vms,action,max_workers=5,run_async=False,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''

    start_time = time.time()
    limit=100
    #region vms
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_vmm_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False

    #* getting list of virtual machines
    client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_vmm_py_client.VmApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching VMs...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_vms(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/limit)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_vmm_py_client,
                    entity_api='VmApi',
                    client=client,
                    function='list_vms',
                    page=page_number,
                    limit=limit
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    vm_list = entity_list

    #* building list of vm uuids to process
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Figuring out which VMs will need processing...{PrintColors.RESET}")
    vms_to_process=[]
    for entity in target_vms:
        for vm_entity in vm_list:
            if vm_entity.name == entity:
                vms_to_process.append(vm_entity)
    vm_uuids = [vm_entity.ext_id for vm_entity in vms_to_process]

    #* processing vm uuids
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Enabling NGT on {len(vm_uuids)} VMs...{PrintColors.RESET}")
    if action == "enable":
        with tqdm.tqdm(total=len(vm_uuids), desc="Processing tasks") as progress_bar:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(
                    insert_ngt,
                    client=client,
                    vm_uuid=vm_uuid,
                    is_config_only=True,
                    run_async=run_async,
                    ) for vm_uuid in vm_uuids]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        # Process the result if needed
                        #print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Task completed: {result}{PrintColors.RESET}")
                    except Exception as e:
                        print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                    finally:
                        progress_bar.update(1)
    elif action == "mount":
        with tqdm.tqdm(total=len(vm_uuids), desc="Processing tasks") as progress_bar:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(
                    insert_ngt,
                    client=client,
                    vm_uuid=vm_uuid,
                    is_config_only=False,
                    run_async=run_async,
                    ) for vm_uuid in vm_uuids]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        # Process the result if needed
                        #print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Task completed: {result}{PrintColors.RESET}")
                    except Exception as e:
                        print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                    finally:
                        progress_bar.update(1)
    elif action == "upgrade":
        with tqdm.tqdm(total=len(vm_uuids), desc="Processing tasks") as progress_bar:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(
                    upgrade_ngt,
                    client=client,
                    vm_uuid=vm_uuid,
                    run_async=run_async,
                    ) for vm_uuid in vm_uuids]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        # Process the result if needed
                        #print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Task completed: {result}{PrintColors.RESET}")
                    except Exception as e:
                        print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                    finally:
                        progress_bar.update(1)
    #endregion vms

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"{PrintColors.STEP}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUM] Process completed in {format_timespan(elapsed_time)}{PrintColors.RESET}")


#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--prism","-p",
        help="prism server."
    )
    parser.add_argument("--username", "-u",
        default='admin', help="username for prism server."
    )
    parser.add_argument("--secure", "-s",
        default=False, help="True of False to control SSL certs verification."
    )
    parser.add_argument("--vm","-v",
        type=str,
        help="Comma separated list of VM names you want to process."
    )
    parser.add_argument("--csv","-c",
        type=str,
        help="Path and name of csv file with vm names (header: vm_name and then one vm name per line)."
    )
    parser.add_argument("--threads","-t",
        type=int,
        default=5,
        help="Maximum number of threads for parallel processing (defaults to 5)."
    )
    parser.add_argument("--action", "-a",
        choices=["enable","mount","upgrade"],
        help="NGT action you want to take."
    )
    parser.add_argument("--run_async", "-ra",
        default=False,
        help="True of False to control if actions are sent asynchronously or not (defaults to False)."
    )
    args = parser.parse_args()

    # * check for password (we use keyring python module to access the workstation operating system password store in an "ntnx" section)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for user {args.username} from the password store.{PrintColors.RESET}")
    pwd = keyring.get_password("ntnx",args.username)
    if not pwd:
        try:
            pwd = getpass.getpass()
            keyring.set_password("ntnx",args.username,pwd)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")

    if args.vm:
        target_vms = args.vm.split(',')
    elif args.csv:
        data=pd.read_csv(args.csv)
        target_vms = data['vm_name'].tolist()
    else:
        print(f"{PrintColors.FAIL}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify at least one vm name or a csv file!{PrintColors.RESET}")
        exit(1)
    main(api_server=args.prism,username=args.username,secret=pwd,target_vms=target_vms,max_workers=args.threads,action=args.action,run_async=args.run_async,secure=args.secure)
