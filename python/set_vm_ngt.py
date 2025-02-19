""" enables or disables NGT for the specified vms.

    Args:
        prism: The IP or FQDN of Prism Element.
        username: The Prism user name.
        vm: comma separated list of vm names.
        csv: csv file with vm names.
        ngt_enabled: desired ngt state (True or False).
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
import pandas
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


def get_cluster_v1(api_server, username, password, secure=False):
    """Retrieve the cluster details from Prism Element (v1 API call).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        password: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False)
        
    Returns:
        Cluster payload.
    """
    url = f'https://{api_server}:9440/PrismGateway/services/rest/v1/clusters'
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.get(
            url=url,
            headers=headers,
            auth=(username, password),
            verify=secure,
            timeout=30
        )
        response.raise_for_status()
        return response.json().get('entities', {})
    except requests.exceptions.RequestException:
        return 0


def get_vms_v1(api_server, username, password, secure=False):
    """Retrieve the list of vm entities from Prism Element (v1 API call).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        password: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False)
        
    Returns:
        An array of entities (entities part of the json response).
    """
    url = f'https://{api_server}:9440/PrismGateway/services/rest/v1/vms'
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.get(
            url=url,
            headers=headers,
            auth=(username, password),
            verify=secure,
            timeout=30
        )
        response.raise_for_status()
        return response.json().get('entities', {})
    except requests.exceptions.RequestException:
        return 0


def set_ngt_enabled_v1(api_server, username, password, vm_uuid, cluster_uuid, secure=False):
    print(f"{vm_uuid}::{cluster_uuid}")


def main(api_server,username,secret,target_vms,ngt_enabled,secure=False):
    '''description.
        Args:
            api_server: URL string to Prism Element instance.
        Returns:
    '''

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching cluster details from {api_server}.{PrintColors.RESET}")
    cluster_details = get_cluster_v1(api_server=api_server, username=username, password=secret, secure=secure)
    cluster_uuid = cluster_details[0]['uuid']
    #print(cluster_uuid)    

   
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
    
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Figuring out which VMs will need processing...{PrintColors.RESET}")
    vms_to_process=[]
    for entity in target_vms:
        for vm_entity in vm_list:
            if vm_entity['status']['name'] == entity:
                vms_to_process.append(vm_entity)
    vm_uuids = [vm_entity['metadata']['uuid'] for vm_entity in vms_to_process]
    
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Processing NGT status for {len(vms_to_process)} VMs: {target_vms} with uuids: {vm_uuids}...{PrintColors.RESET}")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(
            set_ngt_enabled_v1,
            api_server=api_server,
            username=username,
            password=secret,
            vm_uuid=vm_uuid,
            cluster_uuid=cluster_uuid,
            ) for vm_uuid in vm_uuids]
        for future in as_completed(futures):
            ngt_actions = future.result()
    
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
    parser.add_argument(
        "-p", 
        "--prism", 
        type=str, 
        help="prism server."
    )
    parser.add_argument(
        "-u", 
        "--username", 
        type=str, 
        default='admin', 
        help="username for prism server."
    )
    parser.add_argument(
        "-s", 
        "--secure", 
        type=bool, 
        default=False, 
        help="True of False to control SSL certs verification."
    )
    parser.add_argument(
        "-v", 
        "--vm", 
        type=str,
        help="Comma separated list of VM names you want to process."
    )
    parser.add_argument(
        "-ne", 
        "--ngt_enabled", 
        type=bool, 
        default=True,
        help="Whether NGT should be enabled (True and default value) or disabled (False)."
    )
    parser.add_argument(
        "-c", 
        "--csv", 
        type=str,
        help="Path and name of csv file with vm names (header: vm_name and then one vm name per line)."
    )
    args = parser.parse_args()

    if args.vm:
        target_vms = args.vm.split(',')
    elif args.csv:
        data=pandas.read_csv(args.csv)
        target_vms = data['vm_name'].tolist()
    else:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify at least one vm name or csv file!{PrintColors.RESET}")
    
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

    main(api_server=args.prism,username=args.username,secret=pwd,target_vms=target_vms,ngt_enabled=args.ngt_enabled)
