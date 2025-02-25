""" deletes the specified vms.

    Args:
        prism: The IP or FQDN of Prism Element.
        username: The Prism user name.
        vm: comma separated list of vm names.
        csv: csv file with vm names.
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


def delete_vm(api_server, username, password, vm_uuid, secure=False):
    """Delete specified VM using API v3..

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        password: The Prism user name password.
        vm_uuid: The UUID of the VM to delete.
        secure: boolean to verify or not the api server's certificate (True/False)
        
    Returns:
        nothing.
    """
    url = f'https://{api_server}:9440/api/nutanix/v3/vms/{vm_uuid}'
    headers = {'Content-Type': 'application/json'}

    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Deleting VM {vm_uuid}{PrintColors.RESET}")
    
    try:
        response = requests.delete(
            url=url,
            headers=headers,
            auth=(username, password),
            verify=secure,
            timeout=30
        )
        response.raise_for_status()
        print(f"{PrintColors.SUCCESS}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Deleted VM {vm_uuid}{PrintColors.RESET}")
        return response.json().get('entities', {})
    except requests.exceptions.RequestException:
        print(f"{PrintColors.WARNING}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Could not delete VM {vm_uuid}{PrintColors.RESET}")
        return 0
    


def main(api_server,username,secret,target_vms,secure=False):
    '''description.
        Args:
            api_server: URL string to Prism Element instance.
        Returns:
    '''

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Deleting {len(vms_to_process)} VMs...{PrintColors.RESET}")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(
            delete_vm,
            api_server=api_server,
            username=username,
            password=secret,
            vm_uuid=vm_uuid
            ) for vm_uuid in vm_uuids]
        for future in as_completed(futures):
            deleted_vms = future.result()
    
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

    if args.vm:
        target_vms = args.vm.split(',')
    elif args.csv:
        data=pandas.read_csv(args.csv)
        target_vms = data['vm_name'].tolist()
    else:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify at least one vm name or csv file!{PrintColors.RESET}")
    
    #print(f"{target_vms}")
    
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

    main(api_server=args.prism,username=args.username,secret=pwd,target_vms=target_vms)
