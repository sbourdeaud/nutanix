""" gets vm to category list from Prism Central

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.
        secure: boolean to indicate if certs should be verified.

    Returns:
        csv file.
"""



#region #*IMPORT
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass
import argparse
import datetime
import requests
import keyring
import urllib3
import tqdm
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
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            exclusion_file: path to the software exclusion json file.
        Returns:
    '''

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    length=500
    vm_list=[]

    #* what we're about to do
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Getting VMs from {api_server}.{PrintColors.RESET}")
    vm_count = get_total_entities(
        api_server=api_server,
        username=username,
        password=secret,
        entity_type='vm',
        entity_api_root='vms',
        secure=secure
    )

    with tqdm.tqdm(total=int(vm_count/length), desc="Processing tasks") as progress_bar:
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
                try:
                    vms = future.result()
                    vm_list.extend(vms)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)

    with open(f"{api_server}_vm_categories.csv", "w", encoding='utf-8') as file:
        file.write("vm_name,category_name,category_value\n")
    for vm in vm_list:
        for category in vm['metadata']['categories_mapping'].keys():
            for value in vm['metadata']['categories_mapping'][category]:
                #print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] vm_name:{vm['spec']['name']}, category_name:{category}, category_value:{value}.{PrintColors.RESET}")
                with open(f"{api_server}_vm_categories.csv", "a", encoding='utf-8') as file:
                    file.write(f"{vm['spec']['name']},{category},{value}\n")
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Wrote results to {api_server}_vm_categories.csv.{PrintColors.RESET}")


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

    main(api_server=args.prism,username=args.username,secret=pwd)
