""" counts security policies present in PC.

    Args:
        prism: The IP or FQDN of Prism Central.
        username: The Prism Central user name.
        secure: True or False to control SSL certs verification.
        prefix: Optional prefix of security policy names (only policies starting with this prefix will be counted).

    Returns:
        Count of FNS security policies created in Prism Central.
"""


#region IMPORT
from concurrent.futures import ThreadPoolExecutor, as_completed

import math
import time
import datetime
import argparse
import getpass

from humanfriendly import format_timespan

import urllib3
import keyring
import tqdm
from tabulate import tabulate
from colorama import just_fix_windows_console
from termcolor import colored

import ntnx_microseg_py_client
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


def main(api_server,username,secret,max_workers=5,secure=False,prefix=None):
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

    #region policies
    
    #region GET policies
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_microseg_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    client = ntnx_microseg_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_microseg_py_client.NetworkSecurityPoliciesApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Security Policies...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_network_security_policies(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/limit)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_microseg_py_client,
                    entity_api='NetworkSecurityPoliciesApi',
                    client=client,
                    function='list_network_security_policies',
                    page=page_number,
                    limit=limit
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
    security_policies_list = entity_list
    #endregion GET policies
    
    #region variables
    if prefix:
        total_security_policies_count = len([policy for policy in security_policies_list if policy.name.startswith(prefix)])
    else:
        total_security_policies_count = len(security_policies_list)
    save_security_policies_count, monitor_security_policies_count, enforce_security_policies_count = 0, 0, 0
    save_security_policies_vlan_count, monitor_security_policies_vlan_count, enforce_security_policies_vlan_count = 0, 0, 0
    save_security_policies_vpc_count, monitor_security_policies_vpc_count, enforce_security_policies_vpc_count = 0, 0, 0
    
    isolation_security_policies_total_count = 0
    isolation_save_security_policies_count, isolation_monitor_security_policies_count, isolation_enforce_security_policies_count = 0, 0, 0
    isolation_security_policies_vlan_count = 0
    isolation_save_security_policies_vlan_count, isolation_monitor_security_policies_vlan_count, isolation_enforce_security_policies_vlan_count = 0, 0, 0
    isolation_security_policies_vpc_count = 0
    isolation_save_security_policies_vpc_count, isolation_monitor_security_policies_vpc_count, isolation_enforce_security_policies_vpc_count = 0, 0, 0
    
    application_security_policies_total_count = 0
    application_save_security_policies_count, application_monitor_security_policies_count, application_enforce_security_policies_count = 0, 0, 0
    application_security_policies_vlan_count = 0
    application_save_security_policies_vlan_count, application_monitor_security_policies_vlan_count, application_enforce_security_policies_vlan_count = 0, 0, 0
    application_security_policies_vpc_count = 0
    application_save_security_policies_vpc_count, application_monitor_security_policies_vpc_count, application_enforce_security_policies_vpc_count = 0, 0, 0
    
    quarantine_security_policies_total_count = 0
    quarantine_save_security_policies_count, quarantine_monitor_security_policies_count, quarantine_enforce_security_policies_count = 0, 0, 0
    quarantine_security_policies_vlan_count = 0
    quarantine_save_security_policies_vlan_count, quarantine_monitor_security_policies_vlan_count, quarantine_enforce_security_policies_vlan_count = 0, 0, 0
    quarantine_security_policies_vpc_count = 0
    quarantine_save_security_policies_vpc_count, quarantine_monitor_security_policies_vpc_count, quarantine_enforce_security_policies_vpc_count = 0, 0, 0
    
    unknown_security_policies_count = 0
    #endregion variables

    #region count policies
    for policy in security_policies_list:
        if prefix:
            if not policy.name.startswith(prefix):
                continue
        if policy.type == 'ISOLATION':
            isolation_security_policies_total_count += 1
            if policy.state == 'SAVE':
                isolation_save_security_policies_count += 1
            elif policy.state == 'MONITOR':
                isolation_monitor_security_policies_count += 1
            elif policy.state == 'ENFORCE':
                isolation_enforce_security_policies_count += 1
            if policy.scope == 'ALL_VLAN':
                isolation_security_policies_vlan_count += 1
                if policy.state == 'SAVE':
                    isolation_save_security_policies_vlan_count += 1
                elif policy.state == 'MONITOR':
                    isolation_monitor_security_policies_vlan_count += 1
                elif policy.state == 'ENFORCE':
                    isolation_enforce_security_policies_vlan_count += 1
            elif policy.scope in ['VPC_LIST','ALL_VPC']:
                isolation_security_policies_vpc_count += 1
                if policy.state == 'SAVE':
                    isolation_save_security_policies_vpc_count += 1
                elif policy.state == 'MONITOR':
                    isolation_monitor_security_policies_vpc_count += 1
                elif policy.state == 'ENFORCE':
                    isolation_enforce_security_policies_vpc_count += 1
            else:
                unknown_security_policies_count += 1
        elif policy.type == 'APPLICATION':
            application_security_policies_total_count += 1
            if policy.state == 'SAVE':
                application_save_security_policies_count += 1
            elif policy.state == 'MONITOR':
                application_monitor_security_policies_count += 1
            elif policy.state == 'ENFORCE':
                application_enforce_security_policies_count += 1
            if policy.scope == 'ALL_VLAN':
                application_security_policies_vlan_count += 1
                if policy.state == 'SAVE':
                    application_save_security_policies_vlan_count += 1
                elif policy.state == 'MONITOR':
                    application_monitor_security_policies_vlan_count += 1
                elif policy.state == 'ENFORCE':
                    application_enforce_security_policies_vlan_count += 1
            elif policy.scope in ['VPC_LIST','ALL_VPC']:
                application_security_policies_vpc_count += 1
                if policy.state == 'SAVE':
                    application_save_security_policies_vpc_count += 1
                elif policy.state == 'MONITOR':
                    application_monitor_security_policies_vpc_count += 1
                elif policy.state == 'ENFORCE':
                    application_enforce_security_policies_vpc_count += 1
            else:
                unknown_security_policies_count += 1
        elif policy.type == 'QUARANTINE':
            quarantine_security_policies_total_count += 1
            if policy.state == 'SAVE':
                quarantine_save_security_policies_count += 1
            elif policy.state == 'MONITOR':
                quarantine_monitor_security_policies_count += 1
            elif policy.state == 'ENFORCE':
                quarantine_enforce_security_policies_count += 1
            if policy.scope == 'ALL_VLAN':
                quarantine_security_policies_vlan_count += 1
                if policy.state == 'SAVE':
                    quarantine_save_security_policies_vlan_count += 1
                elif policy.state == 'MONITOR':
                    quarantine_monitor_security_policies_vlan_count += 1
                elif policy.state == 'ENFORCE':
                    quarantine_enforce_security_policies_vlan_count += 1
            elif policy.scope in ['VPC_LIST','ALL_VPC']:
                quarantine_security_policies_vpc_count += 1
                if policy.state == 'SAVE':
                    quarantine_save_security_policies_vpc_count += 1
                elif policy.state == 'MONITOR':
                    quarantine_monitor_security_policies_vpc_count += 1
                elif policy.state == 'ENFORCE':
                    quarantine_enforce_security_policies_vpc_count += 1
            else:
                unknown_security_policies_count += 1
    
    total_vlan_security_policies_count = isolation_security_policies_vlan_count + application_security_policies_vlan_count + quarantine_security_policies_vlan_count
    total_vpc_security_policies_count = isolation_security_policies_vpc_count + application_security_policies_vpc_count + quarantine_security_policies_vpc_count
    save_security_policies_count = isolation_save_security_policies_count + application_save_security_policies_count + quarantine_save_security_policies_count
    monitor_security_policies_count = isolation_monitor_security_policies_count + application_monitor_security_policies_count + quarantine_monitor_security_policies_count
    enforce_security_policies_count = isolation_enforce_security_policies_count + application_enforce_security_policies_count + quarantine_enforce_security_policies_count
    save_security_policies_vlan_count = isolation_save_security_policies_vlan_count + application_save_security_policies_vlan_count + quarantine_save_security_policies_vlan_count
    monitor_security_policies_vlan_count = isolation_monitor_security_policies_vlan_count + application_monitor_security_policies_vlan_count + quarantine_monitor_security_policies_vlan_count
    enforce_security_policies_vlan_count = isolation_enforce_security_policies_vlan_count + application_enforce_security_policies_vlan_count + quarantine_enforce_security_policies_vlan_count
    save_security_policies_vpc_count = isolation_save_security_policies_vpc_count + application_save_security_policies_vpc_count + quarantine_save_security_policies_vpc_count
    monitor_security_policies_vpc_count = isolation_monitor_security_policies_vpc_count + application_monitor_security_policies_vpc_count + quarantine_monitor_security_policies_vpc_count
    enforce_security_policies_vpc_count = isolation_enforce_security_policies_vpc_count + application_enforce_security_policies_vpc_count + quarantine_enforce_security_policies_vpc_count
    #endregion count policies
    
    #endregion policies

    #region tabulate
    
    just_fix_windows_console()
    
    print(colored("ALL Security Policies:", 'black', 'on_white'))
    all_security_policies_report = [
        {"Type": "Quarantine", "Saved": quarantine_save_security_policies_count, "Monitored": quarantine_monitor_security_policies_count, "Enforced": quarantine_enforce_security_policies_count},
        {"Type": "Application", "Saved": application_save_security_policies_count, "Monitored": application_monitor_security_policies_count, "Enforced": application_monitor_security_policies_count},
        {"Type": "Isolation", "Saved": isolation_save_security_policies_count, "Monitored": isolation_monitor_security_policies_count, "Enforced": isolation_enforce_security_policies_count}
    ]
    print(colored(tabulate(all_security_policies_report, headers="keys", tablefmt="fancy_grid"), 'white'))

    print(colored("VLAN Security Policies:", 'white', 'on_green'))
    vlan_security_policies_report = [
        {"Type": "Quarantine", "Saved": quarantine_save_security_policies_vlan_count, "Monitored": quarantine_monitor_security_policies_vlan_count, "Enforced": quarantine_enforce_security_policies_vlan_count},
        {"Type": "Application", "Saved": application_save_security_policies_vlan_count, "Monitored": application_monitor_security_policies_vlan_count, "Enforced": application_monitor_security_policies_vlan_count},
        {"Type": "Isolation", "Saved": isolation_save_security_policies_vlan_count, "Monitored": isolation_monitor_security_policies_vlan_count, "Enforced": isolation_enforce_security_policies_vlan_count}
    ]
    print(colored(tabulate(vlan_security_policies_report, headers="keys", tablefmt="fancy_grid"), 'green'))

    print(colored("VPC Security Policies:", 'white', 'on_blue'))
    vpc_security_policies_report = [
        {"Type": "Quarantine", "Saved": quarantine_save_security_policies_vpc_count, "Monitored": quarantine_monitor_security_policies_vpc_count, "Enforced": quarantine_enforce_security_policies_vpc_count},
        {"Type": "Application", "Saved": application_save_security_policies_vpc_count, "Monitored": application_monitor_security_policies_vpc_count, "Enforced": application_monitor_security_policies_vpc_count},
        {"Type": "Isolation", "Saved": isolation_save_security_policies_vpc_count, "Monitored": isolation_monitor_security_policies_vpc_count, "Enforced": isolation_enforce_security_policies_vpc_count}
    ]
    print(colored(tabulate(vpc_security_policies_report, headers="keys", tablefmt="fancy_grid"), 'blue'))

    #endregion tabulate
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"{PrintColors.STEP}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUM] Process completed in {format_timespan(elapsed_time)}{PrintColors.RESET}")


#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--prism","-p",
        type=str,
        help="prism server."
    )
    parser.add_argument("--username", "-u",
        type=str,
        default='admin', 
        help="username for prism server."
    )
    parser.add_argument("--secure",
        default=False, 
        help="True of False to control SSL certs verification."
    )
    parser.add_argument("--prefix",
        help="Optional prefix of security policy names (only policies starting with this prefix will be counted)."
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
    
    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure,prefix=args.prefix)
