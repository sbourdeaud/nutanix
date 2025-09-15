""" gets virtual machines list from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.

    Returns:
        html report file.
"""


#region IMPORT
from time import sleep
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from urllib.parse import parse_qs

import argparse
import getpass
import urllib3
import pandas
import datapane
import keyring

import ntnx_vmm_py_client
import ntnx_clustermgmt_py_client
import ntnx_networking_py_client
import ntnx_prism_py_client
import ntnx_iam_py_client
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
def ntnx_api_pagination_get_page_links(response):
    '''retrieves self, next and last page links from metadata section of a response.
        Args:
            response: response payload.
        Returns:
            response_self_page_link,response_next_page_link,response_last_page_link (python sets)
    '''
    response_self_page_link ={ link.href for link in response.metadata.links if link.rel == "self" }
    response_next_page_link ={ link.href for link in response.metadata.links if link.rel == "next" }
    response_last_page_link ={ link.href for link in response.metadata.links if link.rel == "last" }
    return response_self_page_link,response_next_page_link,response_last_page_link


def ntnx_api_pagination_get_next_page_number(response_next_page_link):
    '''extracts the $page parameter value from a url.
        Args:
            response_next_page_link: python set containing the url to parse.
        Returns:
            next_page_number (integer)
    '''
    next_page_link = next(iter(response_next_page_link))
    parsed_url_next_page_link = urlparse(next_page_link)
    next_page_number = parse_qs(parsed_url_next_page_link.query)['$page'][0]
    return next_page_number


def ntnx_api_pagination(api_instance,function):
    '''gets all available objects of a specific type.
        api_instance:
            api instance object
        function:
            name of function to run on the api instance (exp: list_clusters)
        Returns:
            entity_list (cumulated data section from all pages)
    ''' 
    
    #get the name of the list function for this specific api instance    
    list_function = getattr(api_instance, function)
    
    #* paginate thru all response pages
    entity_list=[]
    response_self_page_link = 'a'
    response_last_page_link = 'b'
    next_page_number = 0
    while response_self_page_link != response_last_page_link:
        response = list_function(_page=next_page_number)
        entity_list = entity_list + response.data
        response_self_page_link,response_next_page_link,response_last_page_link = ntnx_api_pagination_get_page_links(response)
        if response_next_page_link:
            next_page_number = ntnx_api_pagination_get_next_page_number(response_next_page_link)
    return entity_list


def main(api_server,username,secret,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''

    #region clusters
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_clustermgmt_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    api_client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    
    #* getting list of clusters
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all clusters from {api_server}.{PrintColors.RESET}")
    
    api_instance_cluster = ntnx_clustermgmt_py_client.api.ClustersApi(api_client=api_client)
    
    cluster_list = ntnx_api_pagination(api_instance=api_instance_cluster,function='list_clusters')
    
    #* format output
    cluster_list_output = []
    for entity in cluster_list:
        if 'PRISM_CENTRAL' in entity.config.cluster_function:
            continue
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'incarnation_id': entity.config.incarnation_id,
            'is_available': entity.config.is_available,
            'operation_mode': entity.config.operation_mode,
            'redundancy_factor': entity.config.redundancy_factor,
            'domain_awareness_level': entity.config.fault_tolerance_state.domain_awareness_level,
            'current_max_fault_tolerance': entity.config.fault_tolerance_state.current_max_fault_tolerance,
            'desired_max_fault_tolerance': entity.config.fault_tolerance_state.desired_max_fault_tolerance,
            'upgrade_status': entity.upgrade_status,
            'vm_count': entity.vm_count,
            'inefficient_vm_count': entity.inefficient_vm_count,
            'cluster_arch': entity.config.cluster_arch,
            'cluster_function': entity.config.cluster_function,
            'hypervisor_types': entity.config.hypervisor_types,
            'is_password_remote_login_enabled': entity.config.is_password_remote_login_enabled,
            'is_remote_support_enabled': entity.config.is_remote_support_enabled,
            'pulse_enabled': entity.config.pulse_status.is_enabled,
            'timezone': entity.config.timezone,
            'ncc_version': next(iter({ software.version for software in entity.config.cluster_software_map if software.software_type == "NCC" })),
            'aos_full_version': entity.config.build_info.full_version,
            'aos_commit_id': entity.config.build_info.short_commit_id,
            'aos_version': entity.config.build_info.version,
            'is_segmentation_enabled': entity.network.backplane.is_segmentation_enabled,
            'external_address_ipv4': entity.network.external_address.ipv4.value,
            'external_data_service_ipv4': entity.network.external_data_service_ip.ipv4.value,
            'external_subnet': entity.network.external_subnet,
            'name_server_ipv4_list': list({ name_server.ipv4.value for name_server in entity.network.name_server_ip_list}),
            'ntp_server_fqdn_list': list({ ntp_server.fqdn.value for ntp_server in entity.network.ntp_server_ip_list}),
            'number_of_nodes': entity.nodes.number_of_nodes,
        }
        
        cluster_list_output.append(entity_output)
    #endregion clusters
    
    #region hosts
    #* getting list of hosts
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all hosts from {api_server}.{PrintColors.RESET}")
    host_list = ntnx_api_pagination(api_instance=api_instance_cluster,function='list_hosts')
    
    #* format output
    host_list_output = []
    for entity in host_list:
        entity_output = {
            'name': entity.host_name,
            'ext_id': entity.ext_id,
        }
        
        host_list_output.append(entity_output)    
    #endregion hosts
    
    #region storage containers
    #* getting list of storage containers
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all storage containers from {api_server}.{PrintColors.RESET}")
    api_instance_storage_containers = ntnx_clustermgmt_py_client.api.StorageContainersApi(api_client=api_client)
    storage_container_list = ntnx_api_pagination(api_instance=api_instance_storage_containers,function='list_storage_containers')
    
    #* format output
    storage_container_list_output = []
    for entity in storage_container_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.container_ext_id,
        }
        
        storage_container_list_output.append(entity_output)
    #endregion storage containers
    
    #region networks
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_networking_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    api_client = ntnx_networking_py_client.ApiClient(configuration=api_client_configuration)
    
    #* getting list of subnets
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all subnets from {api_server}.{PrintColors.RESET}")
    
    api_instance_networking = ntnx_networking_py_client.api.SubnetsApi(api_client=api_client)
    
    subnet_list = ntnx_api_pagination(api_instance=api_instance_networking,function='list_subnets')
    
    #* format output
    subnet_list_output = []
    for entity in subnet_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
        }
        
        subnet_list_output.append(entity_output)
    #endregion networks
    
    #region categories
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_prism_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    api_client = ntnx_prism_py_client.ApiClient(configuration=api_client_configuration)
    
    #* getting list of categories
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all categories from {api_server}.{PrintColors.RESET}")
    
    api_instance_categories = ntnx_prism_py_client.api.CategoriesApi(api_client=api_client)
    
    category_list = ntnx_api_pagination(api_instance=api_instance_categories,function='list_categories')
    
    #* format output
    category_list_output = []
    for entity in category_list:
        entity_output = {
            'name': f"{entity.key}:{entity.value}",
            'ext_id': entity.ext_id,
        }
        
        category_list_output.append(entity_output)
    #endregion categories

    #region users
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_iam_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret
    
    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
    
    api_client = ntnx_iam_py_client.ApiClient(configuration=api_client_configuration)
    
    #* getting list of users
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all users from {api_server}.{PrintColors.RESET}")
    
    api_instance_users = ntnx_iam_py_client.api.UsersApi(api_client=api_client)
    
    user_list = ntnx_api_pagination(api_instance=api_instance_users,function='list_users')
    
    #* format output
    user_list_output = []
    for entity in user_list:
        entity_output = {
            'name': entity.username,
            'ext_id': entity.ext_id,
        }
        
        user_list_output.append(entity_output)
    #endregion users
    
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
    
    api_client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)
    
    #* getting list of virtual machines
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all virtual machines from {api_server}.{PrintColors.RESET}")
    api_instance_vm = ntnx_vmm_py_client.api.VmApi(api_client=api_client)
    vm_list = ntnx_api_pagination(api_instance=api_instance_vm,function='list_vms')

    #* format output
    vm_list_output = []
    boot_config = ''
    for entity in vm_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'cluster': next(iter({ cluster['name'] for cluster in cluster_list_output if cluster['ext_id'] == entity.cluster.ext_id })) if hasattr(entity.cluster, 'ext_id') else '',
            'host': next(iter({ host['name'] for host in host_list_output if host['ext_id'] == entity.host.ext_id })) if hasattr(entity.host, 'ext_id') else '',
            'num_cores_per_socket': entity.num_cores_per_socket,
            'num_numa_nodes': entity.num_numa_nodes,
            'num_sockets': entity.num_sockets,
            'num_threads_per_core': entity.num_threads_per_core,
            'memory_size_bytes': entity.memory_size_bytes,
            'power_state': entity.power_state,
            'protection_type': entity.protection_type,
            'machine_type': entity.machine_type,
            'guest_tools_version': '',
            'guest_tools_enabled': '',
            'guest_tools_capabilities': '',
            'is_agent_vm': entity.is_agent_vm,
            'is_cpu_hotplug_enabled': entity.is_cpu_hotplug_enabled,
            'is_memory_overcommit_enabled': entity.is_memory_overcommit_enabled,
            'power_state': entity.power_state,
            'is_vtpm_enabled': entity.vtpm_config.is_vtpm_enabled,
            'is_gpu_console_enabled': entity.is_gpu_console_enabled,
            'boot_type': '',
            'is_secure_boot_enabled': '',
            'boot_order': entity.boot_config.boot_order,
            'cdroms': list({ cdrom.disk_address.bus_type for cdrom in entity.cd_roms}) if entity.cd_roms else [],
            'disks': list({ disk.disk_address.bus_type for disk in entity.disks}) if entity.disks else [],
            'disks_bytes': list({ disk.backing_info.disk_size_bytes for disk in entity.disks}) if entity.disks else [],
            'disks_bytes_total': sum(list({ disk.backing_info.disk_size_bytes for disk in entity.disks})) if entity.disks else [],
            'storage_containers': [],
            'categories': [],
            'mac_addresses': list({ vnic.backing_info.mac_address for vnic in entity.nics}) if entity.nics else [],
            'vnic_connection_status': list({ vnic.backing_info.is_connected for vnic in entity.nics}) if entity.nics else [],
            'vnic_types': list({ vnic.network_info.nic_type for vnic in entity.nics}) if entity.nics else [],
            'vnic_vlan_mode': list({ vnic.network_info.vlan_mode for vnic in entity.nics}) if entity.nics else [],
            'learned_ip_addresses': [],
            'subnets': [],
            'owner': next(iter({ entry['name'] for entry in user_list_output if entry['ext_id'] == entity.ownership_info.owner.ext_id })),
        }
        
        #getting ngt information
        if entity.guest_tools:
            entity_output['guest_tools_version'] = entity.guest_tools.available_version
            entity_output['guest_tools_enabled'] = entity.guest_tools.is_enabled
            entity_output['guest_tools_capabilities'] = entity.guest_tools.capabilities
        
        #getting boot information
        boot_config=(entity.boot_config._object_type).split('.')
        entity_output['boot_type'] = boot_config[len(boot_config)-1]
        if entity_output['boot_type'] == 'UefiBoot':
            entity_output['is_secure_boot_enabled'] = entity.boot_config.is_secure_boot_enabled
        
        #getting categories
        if entity.categories:
            for category in entity.categories:
                entity_output['categories'].append(next(iter({ entry['name'] for entry in category_list_output if entry['ext_id'] == category.ext_id })))
            
        #getting storage containers
        if entity.disks:
            for disk in entity.disks:
                entity_output['storage_containers'].append(next(iter({ storage_container['name'] for storage_container in storage_container_list_output if storage_container['ext_id'] == disk.backing_info.storage_container.ext_id })))
        
        #getting ip_addresses and subnets
        if entity.nics:
            for vnic in entity.nics:
                if vnic.network_info.ipv4_info.learned_ip_addresses:
                    for ip_address in vnic.network_info.ipv4_info.learned_ip_addresses:
                        entity_output['learned_ip_addresses'].append(ip_address.value)
                entity_output['subnets'].append(next(iter({ subnet['name'] for subnet in subnet_list_output if subnet['ext_id'] == vnic.network_info.subnet.ext_id })))
        
        vm_list_output.append(entity_output)
    #endregion vms
    
    #region html report
    #* exporting to html
    html_file_name = "get_vm_report.html"
    df = pandas.DataFrame(vm_list_output)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting {len(df)} results to file {html_file_name}.{PrintColors.RESET}")
    """ html_content = df.to_html(index=False)
    html_file= open(html_file_name,"w")
    html_file.write(html_content)
    html_file.close() """
    datapane_app = datapane.App(datapane.DataTable(df))
    datapane_app.save(html_file_name)
    #endregion html report
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, help="True of False to control SSL certs verification.")
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
            
    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure)