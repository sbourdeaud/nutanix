""" creates a VM migration plan in Move and starts the migration process. Allows for cutover and reporting of migration plans.

    Args:
        move: The IP or FQDN of the Move instance.
        username: The Move user name.
        action: Can be either "plan", "cutover" or "report". Defaults to "plan".
        plan: The name of the migration plan to cutover (required when using action "cutover").
        source: The name of the source environment (required when using action "plan").
        target: The name of the target environment (required when using action "plan").
        vm: The name of the VM to migrate (required when using action "plan").
        cluster: The name of the target cluster (required when using action "plan").
        network: The name of the target network (required when using action "plan").
        storage_container: The name of the target storage container (required when using action "plan").
        os_username: The username of the VM guest operating system (required when using action "plan").

    Returns:
        stdout text and a migration plan created, prepared and started in the target Move appliance when using "plan".
        stdout text and a requested workload cutover when using "cutover".
        stdout text and a report of the migration plans in csv and html format when using "report".
"""


#region IMPORT
from argparse import ArgumentParser
import datetime

import getpass
import json
import requests
import keyring
import urllib3
import pandas
import datapane
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
def main(api_server,username,secret,source,target,vm,cluster,network,storage_container,os_username,os_secret,action,plan,secure=False):
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


    if action == "plan":
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
                print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Virtual machine {vm} does not appear to be connected to any network!{PrintColors.RESET}")
                exit (1)
        except StopIteration:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not find virtual machine {vm} in source inventory!{PrintColors.RESET}")
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
    else:
        #* get migration plans
        #region GET migration plans
        print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching migration plans...{PrintColors.RESET}")
        payload = {
            "spec": {
                "IncludeVMDetails": True
            }
        }
        params = {
            "IncludeEntityDetails": "True"
        }
        endpoint = "/plans/list"
        url = f"{move_url}{endpoint}"
        try:
            response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload, params=params)
            response.raise_for_status()
            migration_plans = response.json()
            #print(json.dumps(migration_plans, indent=4))
        except requests.exceptions.RequestException as e:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
            exit(1)
        #endregion GET migration plans
    
        if action == "cutover":
            #* find migration plan
            print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Searching for migration plan {plan}...{PrintColors.RESET}")
            try:
                migration_plan = next(iter([plan_details["MetaData"] for plan_details in migration_plans["Entities"] if plan_details["MetaData"]["Name"] == plan]))
                print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Found migration plan {migration_plan['Name']} with uuid {migration_plan['UUID']}.{PrintColors.RESET}")
                #* check workloads are ready to cutover
                if "ReadyToCutover" not in migration_plan["VMStateCounts"]:
                    print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Migration plan {migration_plan['Name']} is not ready to cutover!{PrintColors.RESET}")
                    exit (1)
                else:
                    print(f"{PrintColors.DATA}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [DATA] Migration plan {migration_plan['Name']} has {migration_plan['NumVMs']} virtual machine(s) and {migration_plan['VMStateCounts']['ReadyToCutover']} are ready to cutover.{PrintColors.RESET}")
                #* cutover workloads
                for workload in migration_plan["VMStatus"]:
                    if "CUTOVER" not in workload["Actions"]:
                        print(f"{PrintColors.WARNING}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Virtual Machine {workload['Name']} is not ready to cutover!{PrintColors.RESET}")
                        continue
                    else:
                        print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Requesting cutover to start for workload {workload['Name']} in plan {plan}...{PrintColors.RESET}")
                        payload = {
                            "spec": {
                                "Action": "cutover"
                            }
                        }
                        endpoint = f"/plans/{migration_plan['UUID']}/workloads/{workload['UUID']}/action"
                        url = f"{move_url}{endpoint}"
                        try:
                            response = requests.post(url, headers=headers, verify=False, timeout=timeout, json=payload)
                            response.raise_for_status()
                        except requests.exceptions.RequestException as e:
                            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e}{PrintColors.RESET}")
                            exit(1)
            except StopIteration:
                print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Could not find migration plan {plan} on {api_server}!{PrintColors.RESET}")
                exit (1)
        elif action == "report":
            #* getting details for each workload in each migration plan
            migration_plan_workloads_list_output = []
            for migration_plan in migration_plans["Entities"]:
                for workload in migration_plan["MetaData"]["VMStatus"]:
                    migration_plan_workload_output = {
                        'vm_name': workload['Name'],
                        'progress_percentage': workload['ProgressPercentage'],
                        'eta_seconds': None,
                        'state': workload['StateString'],
                        'plan': migration_plan['MetaData']['Name'],
                        'source': migration_plan['MetaData']['SourceInfo']['Name'],
                        'target': migration_plan['MetaData']['TargetInfo']['Name'],
                        'target_cluster': migration_plan['MetaData']['TargetInfo']['Cluster']['Name'],
                        'total_bytes': workload['TotalDataSizeInBytes'],
                        'copied_bytes': workload['CopiedDataSizeInBytes'],
                        'migrated_bytes': workload['MigratedDataSizeInBytes'],
                        'vm_console_link': None,
                        'vm_link': None,
                    }
                    if "VmConsoleLink" in workload:
                        migration_plan_workload_output['vm_console_link'] = workload['VmConsoleLink']
                        migration_plan_workload_output['vm_link'] = workload['VmLink']
                    if "ETAInSecs" in workload:
                        migration_plan_workload_output['eta_seconds'] = workload['ETAInSecs']
                    migration_plan_workloads_list_output.append(migration_plan_workload_output)
            df = pandas.DataFrame(migration_plan_workloads_list_output)
            
            #* exporting to html
            file_name = f"{api_server}_{(datetime.datetime.now()).strftime('%Y_%m_%d_%H_%M_%S')}_report"
            print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting {len(df)} results to file {file_name}.html.{PrintColors.RESET}")
            datapane_app = datapane.App(datapane.DataTable(df))
            datapane_app.save(f"{file_name}.html")
            
            #* exporting to csv
            print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting {len(df)} results to file {file_name}.csv.{PrintColors.RESET}")
            df.to_csv(f"{file_name}.csv", index=False)

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
    parser.add_argument("-a", "--action", default="plan", choices=["plan","cutover","report"],help="action you want the script to take [plan,cutover,report]. Defaults to plan.")
    
    # action 'plan'
    parser.add_argument("-s", "--source", help="name of the source environment.")
    parser.add_argument("-t", "--target", help="name of the target environment.")
    parser.add_argument("-v", "--vm", help="name of the vm you want to migrate.")
    parser.add_argument("-c", "--cluster", help="name of the cluster you want to migrate the vm to.")
    parser.add_argument("-n", "--network", help="name of the network you want to attach the vm to.")
    parser.add_argument("-sc", "--storage_container", default="default", help="name of the storage container you want to migrate the vm to.")
    parser.add_argument("-o", "--os_username", default="administrator", help="vm guest operating username (with privileged access for preparation).")
    
    # action 'cutover'
    parser.add_argument("-p", "--plan", help="name of the migration plan you want to cutover.")
    
    args = parser.parse_args()

    #* custom verification of arguments
    if args.action == "plan":
        if not args.source:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a source environment with --source!{PrintColors.RESET}")
            exit (1)
        if not args.target:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a target environment with --target!{PrintColors.RESET}")
            exit (1)
        if not args.vm:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a vm to migrate with --vm!{PrintColors.RESET}")
            exit (1)
        if not args.cluster:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a target cluster with --cluster!{PrintColors.RESET}")
            exit (1)
        if not args.network:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a target network with --network!{PrintColors.RESET}")
            exit (1)
    elif args.action == "cutover":
        if not args.plan:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a migration plan to cutover with --plan!{PrintColors.RESET}")
            exit (1)
    
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
         action=args.action,
         source=args.source, target=args.target, vm=args.vm, cluster=args.cluster, network=args.network, storage_container=args.storage_container,
         os_username=args.os_username, os_secret=os_secret,
         plan=args.plan,
         )
