""" creates a VM migration plan in Move, checks status and allows for cutover.

    Args:
        move: The IP or FQDN of the Move instance.
        username: The Move user name.
        secret: The Move user name password.

    Returns:
        stdout text.
"""


#region IMPORT
from argparse import ArgumentParser
import datetime

import getpass
import json
import requests
import keyring
import urllib3
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
def main(api_server,username,secret,source,target,vm,cluster,network,storage_container,os_username,os_secret,secure=False):
    '''description.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            exclusion_file: path to the software exclusion json file.
        Returns:
    '''

    #* general configuration
    #region config
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    move_url = f"https://{api_server}/move/v2"
    timeout = 30
    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #endregion config


    #* login to Move instance
    #region login
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Logging in to Move instance...{PrintColors.RESET}")
    payload = {
        "Spec": {
            "username": username,
            "password": secret
        }
    }
    endpoint = "/users/login"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        login_response = response.json()
        token = login_response["Status"]["Token"]
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        #print(json.dumps(login_response, indent=4))
    except requests.exceptions.RequestException as e:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
    #endregion login


    #* get migration plans
    """ print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching migration plans...{PrintColors.RESET}")
    payload = {
        "EntityType": "VM"
    }
    endpoint = "/plans/list"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        entity_response = response.json()
        print(json.dumps(entity_response, indent=4))
    except requests.exceptions.RequestException as e:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
 """


    #* get providers
    #region GET providers
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching providers...{PrintColors.RESET}")
    payload = {
        "EntityType": "VM"
    }
    endpoint = "/providers/list"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        providers = response.json()
        source_provider = next(iter([provider["Spec"] for provider in providers["Entities"] if provider["Spec"]["Name"] == source]))
        target_provider = next(iter([provider["Spec"] for provider in providers["Entities"] if provider["Spec"]["Name"] == target]))
        if source_provider and target_provider:
            print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Source Provider {source} is a {source_provider['TypeDescription']} instance running version {source_provider['Version']}{PrintColors.RESET}")
            print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Target Provider {target} is a {target_provider['TypeDescription']} instance running version {target_provider['Version']}{PrintColors.RESET}")
            source_provider_uuid = source_provider['UUID']
            target_provider_uuid = target_provider['UUID']
            try:
                cluster_configuration = next(iter([cluster_spec for cluster_spec in target_provider["AOSProperties"]["Clusters"] if cluster_spec["Name"] == cluster]))
                cluster_uuid = cluster_configuration["UUID"]
                try:
                    storage_container_uuid = next(iter([container_spec["UUID"] for container_spec in cluster_configuration["Containers"] if container_spec["Name"] == storage_container]))
                except StopIteration:
                    print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not find storage container {storage_container} in target provider {target} on cluster {cluster}!{PrintColors.RESET}")
                    exit (1)
                try:
                    network_uuid = next(iter([network_spec["UUID"] for network_spec in cluster_configuration["Networks"] if network_spec["Name"] == network]))
                except StopIteration:
                    print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not find network {network} in target provider {target} on cluster {cluster}!{PrintColors.RESET}")
                    exit (1)
            except StopIteration:
                print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not find cluster {cluster} in target provider {target}!{PrintColors.RESET}")
                exit (1)
        else:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not find either the source or target provider specified!{PrintColors.RESET}")
            exit (1)
        #print(json.dumps(providers, indent=4))
    except requests.exceptions.RequestException as e:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
    #endregion GET providers


    #* get source provider workload inventory
    #region GET source inventory
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching source inventory...{PrintColors.RESET}")
    payload = {
        "RefreshInventory": True,
        "ShowVMs": "all"
    }
    endpoint = f"/providers/{source_provider_uuid}/workloads/list"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        source_inventory = response.json()
    except requests.exceptions.RequestException as e:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
    #endregion GET source inventory


    #* find VM and networks information
    #region figure out object IDs
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Searching for virtual machine {vm} in source inventory amongst {source_inventory['MetaData']['Count']} VMs...{PrintColors.RESET}")
    try:
        vm_configuration = next(iter([vm_spec for vm_spec in source_inventory["Entities"] if vm_spec["VMName"] == vm]))
        print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] VM {vm_configuration['VMName']} is in state {vm_configuration['PowerState']} on cluster {vm_configuration['ClusterName']} running {vm_configuration['OSType']} and has {vm_configuration['NumEthernetCards']} vNIC(s).{PrintColors.RESET}")
        vm_uuid = vm_configuration["VMUuid"]
        vm_id = vm_configuration["VmID"]
        try:
            vm_network = next(iter([network_spec for network_spec in vm_configuration["Networks"]]))
            vm_network_id = vm_network["ID"]
        except StopIteration:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Virtual machine {vm} does not appear to be connected to any network!{PrintColors.RESET}")
            exit (1)
    except StopIteration:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Could not find virtual machine {vm} in source inventory!{PrintColors.RESET}")
        exit (1)
    #endregion figure out object IDs


    #* create migration plan
    #region POST migration plan
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Creating migration plan...{PrintColors.RESET}")
    payload =  {
        "Spec": {
            "Name": vm,
            "NetworkMappings": [
                {
                    "SourceNetworkID": vm_network_id,
                    "TargetNetworkID": network_uuid
                }
            ],
            "Settings": {
                "Bandwidth": None,
                "GuestPrepMode": "auto",
                "NicConfigMode": "retain",
                "Schedule": {
                    "RWEndTimeAtEpochSec": 0,
                    "RWStartTimeAtEpochSec": 0,
                    "ScheduleAtEpochSec": 0
                },
                "SkipIPRetentionUI": False,
                "SkipUninstallGuestToolsUI": False,
                "VMTimeZone": "UTC"
            },
            "SourceInfo": {
                "ProviderUUID": source_provider_uuid
            },
            "TargetInfo": {
                "AOSProviderAttrs": {
                    "ClusterUUID": cluster_uuid,
                    "ContainerUUID": storage_container_uuid
                },
                "ProviderUUID": target_provider_uuid
            },
            "Workload": {
                "Type": "VM",
                "VMs": [
                    {
                        "AllowUVMOps": True,
                        "DiskConfig": {
                            "AddCdrom": True
                        },
                        "EnableMemoryOvercommit": False,
                        "GuestPrepMode": "auto",
                        "InstallNGT": True,
                        "RetainMacAddress": True,
                        "RetainUserData": True,
                        "SkipCdrom": False,
                        "SkipIPRetention": False,
                        "TimeZone": "UTC",
                        "UninstallGuestTools": True,
                        "VMCustomizeType": "replicate",
                        "VMPriority": "High",
                        "VMReference": {
                            "UUID": vm_uuid
                        }
                    }
                ]
            }
        },
        "Type": "VM"
    }
    endpoint = f"/plans"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        migration_plan_create = response.json()
        migration_plan_uuid = migration_plan_create['MetaData']['UUID']
        migration_plan_name = migration_plan_create['Spec']['Name']
        #print(json.dumps(migration_plan_create, indent=4))
        print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Created migration plan {migration_plan_name} with uuid {migration_plan_uuid} on {api_server}.{PrintColors.RESET}")
    except requests.exceptions.HTTPError as e:
        error_message = response.json()
        #print(json.dumps(error_message, indent=4))
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}: {error_message['Message']}{PrintColors.RESET}")
        exit(1)
    except requests.exceptions.RequestException as e:
        error_message = response.json()
        print(json.dumps(payload, indent=4))
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}: {error_message['message']}{PrintColors.RESET}")
        exit(1)
    #endregion POST migration plan


    #* prepare plan
    #region prepare migration plan
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Preparing migration plan {migration_plan_name}...{PrintColors.RESET}")
    payload =  {
        "Spec": {
            "CommonCredentials": {
                "LinuxPassword": "",
                "LinuxUserName": "",
                "WindowsPassword": "",
                "WindowsUserName": "",
                "PemFile": ""
            },
            "Region": "",
            "VMs": [
                {
                    "UserName": os_username,
                    "Password": os_secret,
                    "UUID": vm_uuid,
                    "GuestPrepMode": "auto"
                }
            ]
        }
    }
    endpoint = f"/plans/{migration_plan_uuid}/prepare"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        migration_plan_prepare = response.json()
        #print(json.dumps(migration_plan_prepare, indent=4))
        if migration_plan_prepare['Status']['Result']['Failed']:
            for failed_status in migration_plan_prepare['Status']['Result']['Failed']:
                print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Failed to prepare migration plan {migration_plan_name}: {failed_status['Status']}: {failed_status['Message']}{PrintColors.RESET}")
            exit(1)
    except requests.exceptions.HTTPError as e:
        error_message = response.json()
        #print(json.dumps(error_message, indent=4))
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}: {error_message['Message']}{PrintColors.RESET}")
        exit(1)
    except requests.exceptions.RequestException as e:
        error_message = response.json()
        print(json.dumps(payload, indent=4))
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}: {error_message['message']}{PrintColors.RESET}")
        exit(1)
    #endregion prepare migration plan


    #* start migration plan
    #region start migration plan
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Starting migration plan {migration_plan_name}...{PrintColors.RESET}")
    payload =  {
        "Spec": {
            "Time": 120
        }
    }
    endpoint = f"/plans/{migration_plan_uuid}/start"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Migration plan start request was {response.reason} with status code {response.status_code}.{PrintColors.RESET}")
    except requests.exceptions.HTTPError as e:
        error_message = response.json()
        print(json.dumps(error_message, indent=4))
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}: {error_message['Message']}{PrintColors.RESET}")
        exit(1)
    except requests.exceptions.RequestException as e:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
        exit(1)
    #endregion start migration plan


    #* logout from Move instance
    #region logout
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Logging out from Move instance...{PrintColors.RESET}")
    payload = {
        "Spec": {
            "Token": token
        }
    }
    endpoint = "/token/revoke"
    url = f"{move_url}{endpoint}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
        response.raise_for_status()
        logout_response = response.json()
        #print(json.dumps(logout_response, indent=4))
    except requests.exceptions.RequestException as e:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
    #endregion logout


#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = ArgumentParser()
    parser.add_argument("-m", "--move", required=True, help="move server.")
    parser.add_argument("-u", "--username", default="nutanix", help="username for move server.")
    parser.add_argument("-s", "--source", required=True, help="name of the source environment.")
    parser.add_argument("-t", "--target", required=True, help="name of the target environment.")
    parser.add_argument("-v", "--vm", required=True, help="name of the vm you want to migrate.")
    parser.add_argument("-c", "--cluster", required=True, help="name of the cluster you want to migrate the vm to.")
    parser.add_argument("-n", "--network", required=True, help="name of the network you want to attach the vm to.")
    parser.add_argument("-sc", "--storage_container", default="default", help="name of the storage container you want to migrate the vm to.")
    parser.add_argument("-o", "--os_username", default="administrator", help="vm guest operating username (with privileged access for preparation).")
    args = parser.parse_args()

    # * check for password (we use keyring python module to access the workstation operating system 
    # * password store in an "ntnx" section)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for user {args.username} from the password store.{PrintColors.RESET}")
    pwd = keyring.get_password("ntnx",args.username)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for os user {args.os_username} from the password store.{PrintColors.RESET}")
    os_secret = keyring.get_password("ntnx",args.os_username)
    if not pwd:
        try:
            pwd = getpass.getpass()
            keyring.set_password("ntnx",args.username,pwd)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")
    if not os_secret:
        try:
            os_secret = getpass.getpass()
            keyring.set_password("ntnx",args.os_username,os_secret)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")

    main(api_server=args.move,username=args.username,secret=pwd,
         source=args.source, target=args.target, vm=args.vm, cluster=args.cluster, network=args.network, storage_container=args.storage_container,
         os_username=args.os_username, os_secret=os_secret,
         )
