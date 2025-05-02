""" creates security policies for Flow NextGen using basic NVD templates.
    Also creates required categories if they do not exist.

    Args:
        prism: The IP or FQDN of Prism Central.
        username: The Prism Central user name.
        secure: True or False to control SSL certs verification.
        type: application or isolation.
        scope: vlan or vpc
        vpc_name: name of the vpc to use when scope is vpc.
        qty: number of policies to create.
        threads: number of threads to use for parallel processing.

    Returns:
        FNS NG security policies created in Prism Central.
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
import pandas as pd
import keyring
import tqdm
import json

import ntnx_prism_py_client
import ntnx_microseg_py_client
import ntnx_networking_py_client
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


def main(api_server,username,secret,policy_type,scope,vpc_name,qty,max_workers=5,secure=False):
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
    if scope == "vpc":
        scope = "VPC_LIST"
    if scope == "vlan":
        scope = "ALL_VLAN"


    #region vpc
    #* check specified vpc_name exists if scope is vpc
    if scope == "VPC_LIST":
        api_client_configuration = ntnx_networking_py_client.Configuration()
        api_client_configuration.host = api_server
        api_client_configuration.username = username
        api_client_configuration.password = secret
        
        if secure is False:
            #! suppress warnings about insecure connections
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            #! suppress ssl certs verification
            api_client_configuration.verify_ssl = False
        
        client = ntnx_networking_py_client.ApiClient(configuration=api_client_configuration)
        entity_api = ntnx_networking_py_client.VpcsApi(api_client=client)
        print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching VPC {vpc_name}...{PrintColors.RESET}")
        entity_list=[]
        response = entity_api.list_vpcs(_page=0,_limit=1,_filter=f"name eq '{vpc_name}'")
        vpc_details = response.data
        if not vpc_details:
            print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] VPC {vpc_name} not found.{PrintColors.RESET}")
            exit(1)
        #print(vpc_details)
    #endregion vpc
    
    #region categories
    #* GET categories
    #region GET categories
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_prism_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    client = ntnx_prism_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_prism_py_client.CategoriesApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Categories...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_categories(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/limit)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_prism_py_client,
                    entity_api='CategoriesApi',
                    client=client,
                    function='list_categories',
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
    categories_list = entity_list
    #endregion GET categories


    #* ADD required category keys and values
    #region POST categories
    required_categories_list = ["AppTier:Web","AppTier:App","AppTier:DB"]
    #adding AppType category values based on the required quantity of policies
    for i in range(qty):
        required_categories_list.append(f"AppType:NVDMultiVmApp{i + 1:02}")
    #converting our list to a list of dictionaries for later
    required_categories_dict_list = []
    for category_key_value_pair in required_categories_list:
        category_key,category_value = category_key_value_pair.split(":")
        required_categories_dict_list.append({"category_key": category_key, "category_value": category_value})
    
    #figure out unique list of existing and required category keys
    unique_existing_category_keys = {getattr(c, 'key') for c in categories_list if hasattr(c, 'key')}
    unique_required_category_keys = {c["category_key"] for c in required_categories_dict_list}
    
    #check we have all categories and values we need otherwise create them
    for category_key in unique_required_category_keys:
        category_values = [c["category_value"] for c in required_categories_dict_list if c["category_key"] == category_key]
        if category_key not in unique_existing_category_keys:
            for category_value in category_values:
                #* create category value in this new category key
                print(f"{PrintColors.STEP}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [STEP] Creating category {category_key}:{category_value}{PrintColors.RESET}")
                new_category = ntnx_prism_py_client.Category()
                new_category.key = category_key
                new_category.value = category_value
                new_category.description = "Created by add_security_policy.py script"
                response = entity_api.create_category(new_category)
        else:
            for category_value in category_values:
                category_match = [c for c in categories_list if c.key == category_key and c.value == category_value]
                if not category_match:
                    #* create category value in this existing category key
                    print(f"{PrintColors.STEP}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [STEP] Creating category {category_key}:{category_value}{PrintColors.RESET}")
                    new_category = ntnx_prism_py_client.Category()
                    new_category.key = category_key
                    new_category.value = category_value
                    new_category.description = "Created by add_security_policy.py script"
                    response = entity_api.create_category(new_category)
    #endregion POST categories
    #endregion categories


    #region policies
    #* GET policies
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


    #* ADD required policies
    #region POST policies
    required_policies_list = []
    for i in range(qty):
        if policy_type == "application":
            required_policies_list.append(f"NVDMultiVmApp{i + 1:02}")
        elif policy_type == "isolation":
            required_policies_list.append(f"NVDIsolation{i + 1:02}")
    app_tier_list = [c["category_value"] for c in required_categories_dict_list if c["category_key"] == "AppTier"]

    for security_policy in required_policies_list:
        secured_group = []
        #figuring out the uuids of the AppTier category values and adding them to the secured group
        for app_tier in app_tier_list:
            app_tier_uuid = {c.ext_id for c in categories_list if (c.key == "AppTier" and c.value == app_tier)}
            secured_group.append(str(next(iter(app_tier_uuid))))
        #* check if policy already exists
        security_policy_match = [s for s in security_policies_list if s.name == security_policy]
        if not security_policy_match:
            #* create policy
            print(f"{PrintColors.STEP}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [STEP] Creating security policy {security_policy}{PrintColors.RESET}")
            new_policy = ntnx_microseg_py_client.NetworkSecurityPolicy()
            new_policy.name = security_policy
            new_policy.description = "Created by add_security_policy.py script"
            new_policy.type = policy_type.upper()
            new_policy.scope = scope
            new_policy.is_ipv6_traffic_allowed = False
            new_policy.is_hitlog_enabled = True
            #adding vpc reference if scope is vpc
            if scope == "VPC_LIST":
                new_policy.vpc_references = [vpc_details[0].ext_id]
            #figuring out the uuid of the AppType category value and adding it to the secured group
            app_type_uuid = {c.ext_id for c in categories_list if (c.key == "AppType" and c.value == security_policy)}
            secured_group.append(str(next(iter(app_type_uuid))))
            new_policy.secured_groups = secured_group
            new_policy.rules = []
            #* add outbount rules for each AppTier
            for app_tier in app_tier_list:
                application_security_policy_rule = ntnx_microseg_py_client.NetworkSecurityPolicyRule()
                application_security_policy_rule.description = f"Outbound rule for application {security_policy} for AppTier {app_tier}"
                application_security_policy_rule.type = "APPLICATION"

                security_policy_rule_spec = ntnx_microseg_py_client.ApplicationRuleSpec()
                security_policy_rule_spec.secured_group_category_references = [str(next(iter(app_type_uuid)))]
                app_tier_uuid = {c.ext_id for c in categories_list if (c.key == "AppTier" and c.value == app_tier)}
                security_policy_rule_spec.secured_group_category_references.append(str(next(iter(app_tier_uuid))))
                #security_policy_rule_spec.src_category_references = []
                security_policy_rule_spec.is_all_protocol_allowed = True
                security_policy_rule_spec.src_allow_spec = "NONE"
                application_security_policy_rule.spec = security_policy_rule_spec
                new_policy.rules.append(application_security_policy_rule)
            #* prevent entities witht he same tier from talking to each other
            for app_tier in app_tier_list:
                application_security_policy_rule = ntnx_microseg_py_client.NetworkSecurityPolicyRule()
                application_security_policy_rule.description = f"deny {app_tier} from talking to each other"
                application_security_policy_rule.type = "INTRA_GROUP"

                security_policy_rule_spec = ntnx_microseg_py_client.IntraEntityGroupRuleSpec()
                security_policy_rule_spec.secured_group_category_references = [str(next(iter(app_type_uuid)))]
                app_tier_uuid = {c.ext_id for c in categories_list if (c.key == "AppTier" and c.value == app_tier)}
                security_policy_rule_spec.secured_group_category_references.append(str(next(iter(app_tier_uuid))))
                security_policy_rule_spec.secured_group_action = "DENY"
                application_security_policy_rule.spec = security_policy_rule_spec
                new_policy.rules.append(application_security_policy_rule)
            #* inbound rules for each AppTier
            for app_tier in app_tier_list:
                application_security_policy_rule = ntnx_microseg_py_client.NetworkSecurityPolicyRule()
                application_security_policy_rule.description = f"Inbound rule for application {security_policy} for AppTier {app_tier}"
                application_security_policy_rule.type = "APPLICATION"

                security_policy_rule_spec = ntnx_microseg_py_client.ApplicationRuleSpec()
                security_policy_rule_spec.secured_group_category_references = [str(next(iter(app_type_uuid)))]
                app_tier_uuid = {c.ext_id for c in categories_list if (c.key == "AppTier" and c.value == app_tier)}
                security_policy_rule_spec.secured_group_category_references.append(str(next(iter(app_tier_uuid))))
                #security_policy_rule_spec.src_category_references = []
                security_policy_rule_spec.is_all_protocol_allowed = False
                security_policy_rule_spec.src_allow_spec = "ALL"
                security_policy_rule_spec.tcp_services = []
                security_policy_rule_spec.udp_services = []
                security_policy_rule_spec.icmp_services = []

                #common tcp services for all AppTiers
                for tcp_service in [22,2074,3389,5985]:
                    tcp_service_spec = ntnx_microseg_py_client.TcpPortRangeSpec()
                    tcp_service_spec.start_port = tcp_service
                    tcp_service_spec.end_port = tcp_service
                    security_policy_rule_spec.tcp_services.append(tcp_service_spec)

                #common icmp service for all AppTiers
                icmp_service_spec = ntnx_microseg_py_client.IcmpTypeCodeSpec()
                icmp_service_spec.type = 8
                icmp_service_spec.code = 0
                security_policy_rule_spec.icmp_services.append(icmp_service_spec)

                #tier specific tcp services
                if app_tier == "Web":
                    for tcp_service in [80,443]:
                        tcp_service_spec = ntnx_microseg_py_client.TcpPortRangeSpec()
                        tcp_service_spec.start_port = tcp_service
                        tcp_service_spec.end_port = tcp_service
                        security_policy_rule_spec.tcp_services.append(tcp_service_spec)
                elif app_tier == "App":
                    for tcp_service in [4066]:
                        tcp_service_spec = ntnx_microseg_py_client.TcpPortRangeSpec()
                        tcp_service_spec.start_port = tcp_service
                        tcp_service_spec.end_port = tcp_service
                        security_policy_rule_spec.tcp_services.append(tcp_service_spec)
                elif app_tier == "DB":
                    for tcp_service in [3386]:
                        tcp_service_spec = ntnx_microseg_py_client.TcpPortRangeSpec()
                        tcp_service_spec.start_port = tcp_service
                        tcp_service_spec.end_port = tcp_service
                        security_policy_rule_spec.tcp_services.append(tcp_service_spec)

                application_security_policy_rule.spec = security_policy_rule_spec
                new_policy.rules.append(application_security_policy_rule)
            #* create policy
            try:
                response = entity_api.create_network_security_policy(new_policy)
            except ntnx_microseg_py_client.rest.ApiException as e:
                print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {e.status} {e.reason}{PrintColors.RESET}")
                error_details = json.loads(e.body)
                for error_message in error_details["data"]["error"]["validationErrorMessages"]:
                    print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error_message['message']}{PrintColors.RESET}")
    #endregion POST policies
    #endregion policies

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
    parser.add_argument("--type","-t",
        choices=["application","isolation"],
        help="Specifies the type of policy to create. Defaults to application.",
        default="application"
    )
    parser.add_argument("--scope","-s",
        choices=["vlan","vpc"],
        help="Specifies the scope of the policies to be created."
    )
    parser.add_argument("--threads",
        type=int,
        default=5,
        help="Maximum number of threads for parallel processing (defaults to 5)."
    )
    parser.add_argument("--qty", "-q",
        type=int,
        default=1,
        help="Quantity of categories to create (defaults to 1)."
    )
    parser.add_argument("--vpc_name", "-v",
        type=str,
        help="Name of the vpc to use when scope is vpc."
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
    
    if args.scope == "vpc" and args.vpc_name is None:
        print(f"{PrintColors.FAIL}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] You must specify a vpc name when scope is vpc.{PrintColors.RESET}")
        exit(1)
    main(api_server=args.prism,username=args.username,secret=pwd,policy_type=args.type,max_workers=args.threads,scope=args.scope,vpc_name=args.vpc_name,qty=args.qty,secure=args.secure)
