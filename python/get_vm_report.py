""" generate a report on all vms in target prism central.

    Args:
        prism: The IP or FQDN of Prism Element.
        username: The Prism user name.
        secure: boolean to indicate if certs should be verified.

    Returns:
        results in console output.
"""

#region #*IMPORT
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import getpass
import argparse
import datetime
import requests
import keyring
import urllib3
from humanfriendly import format_timespan
import pandas
import datapane
#endregion #*IMPORT

#region #*FUNCTIONS
def get_total_entities(api_server, username, password, entity_type, entity_api_root, secure=False):

    """Retrieve the total number of entities from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        password: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        secure: boolean to verify or not the api server's certificate (True/False)
        
    Returns:
        total number of entities as integer.
    """

    url = f'https://{api_server}:9440/api/nutanix/v3/{entity_api_root}/list'
    headers = {'Content-Type': 'application/json'}
    payload = {'kind': entity_type, 'length': 1, 'offset': 0}

    try:
        response = requests.post(
            url=url,
            headers=headers,
            auth=(username, password),
            json=payload,
            verify=secure,
            timeout=30
        )
        response.raise_for_status()
        return response.json().get('metadata', {}).get('total_matches', 0)
    except requests.exceptions.RequestException:
        return 0


def get_entities_batch(api_server, username, password, offset, entity_type, entity_api_root, length=100, secure=False):

    """Retrieve the list of entities from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        password: The Prism user name password.
        offset: Offset on object count.
        length: Page length (defaults to 100).
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        secure: boolean to verify or not the api server's certificate (True/False)
        
    Returns:
        An array of entities (entities part of the json response).
    """

    url = f'https://{api_server}:9440/api/nutanix/v3/{entity_api_root}/list'
    headers = {'Content-Type': 'application/json'}
    payload = {'kind': entity_type, 'length': length, 'offset': offset}
    
    try:
        response = requests.post(
            url=url,
            headers=headers,
            auth=(username, password),
            json=payload,
            verify=secure,
            timeout=30
        )
        response.raise_for_status()
        return response.json().get('entities', [])
    except requests.exceptions.RequestException:
        return []


def main(api_server,username,secret,secure=False):
    '''description.
        Args:
            api_server: URL string to Prism Element instance.
        Returns:
    '''

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #region #* fetching vms
    #* fetching number of entities
    length=500
    vm_list=[]
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Getting VMs from {api_server}.{PrintColors.RESET}")
    vm_count = get_total_entities(
        api_server=api_server,
        username=username,
        password=secret,
        entity_type='vm',
        entity_api_root='vms',
        secure=secure
    )

    #* fetching entities
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(
            get_entities_batch,
            api_server=api_server,
            username=username,
            password=secret,
            entity_type='vm',
            entity_api_root='vms',
            offset= offset,
            length=length
            ) for offset in range(0, vm_count, length)]
        for future in as_completed(futures):
            vms = future.result()
            vm_list.extend(vms)
    
    #* format output
    vm_list_output = []
    for entity in vm_list:
        entity_output = {
            'name': entity['status']['name'],
            'uuid': entity['metadata']['uuid'],
            'cluster': entity['status']['cluster_reference']['name'],
            'num_vcpus_per_socket': entity['status']['resources']['num_vcpus_per_socket'],
            'num_sockets': entity['status']['resources']['num_sockets'],
            'memory_size_mib': entity['status']['resources']['memory_size_mib'],
            'power_state': entity['status']['resources']['power_state'],
            'protection_type': entity['status']['resources']['protection_type'],
            'machine_type': entity['status']['resources']['machine_type'],
            'guest_tools_version': '',
            'guest_tools_enabled': '',
            'guest_tools_capabilities': '',
            'is_agent_vm': entity['status']['resources']['is_agent_vm'],
            'memory_overcommit_enabled': entity['status']['resources']['memory_overcommit_enabled'],
            'gpu_console_enabled': entity['status']['resources']['gpu_console_enabled'],
            'boot_type': entity['status']['resources']['boot_config']['boot_type']
        }
        
        #getting ngt information
        if hasattr(entity['status']['resources'], 'guest_tools'):
            entity_output['guest_tools_version'] = entity['status']['resources']['guest_tools']['nutanix_guest_tools']['available_version']
            entity_output['guest_tools_enabled'] = entity['status']['resources']['guest_tools']['nutanix_guest_tools']['state']
            entity_output['guest_tools_capabilities'] = entity['status']['resources']['guest_tools']['nutanix_guest_tools']['enabled_capability_list']


        vm_list_output.append(entity_output)
    #endregion fetching vms


    #* producing report
    html_file_name = "get_pc_report.html"

    vm_df = pandas.DataFrame(vm_list_output)
    

    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting results to file {html_file_name}.{PrintColors.RESET}")

    datapane_app = datapane.App(
        datapane.DataTable(vm_df,label="vms")
    )
    datapane_app.save(html_file_name)

#endregion #*FUNCTIONS

#region #*CLASS
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
#endregion #*CLASS

if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--prism",
        "-p", 
        type=str, 
        help="prism server."
    )
    parser.add_argument("--username",
        "-u",  
        type=str, 
        default='admin', 
        help="username for prism server."
    )
    parser.add_argument("--secure",
        "-s",  
        type=bool, 
        default=False, 
        help="True of False to control SSL certs verification."
    )
    args = parser.parse_args()

    # * check for password (we use keyring python module to access the workstation operating system 
    # * password store in an "ntnx" section)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for user {args.username} from the password store.{PrintColors.RESET}")
    pwd = keyring.get_password("ntnx",args.username)
    if not pwd:
        try:
            pwd = getpass.getpass()
            keyring.set_password("ntnx",args.username,pwd)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")

    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure)
