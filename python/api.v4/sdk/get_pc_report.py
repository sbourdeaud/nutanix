""" gets misc entities list from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.

    Returns:
        html report file.
"""


#region IMPORT
from time import sleep
from humanfriendly import format_timespan
from urllib.parse import urlparse
from urllib.parse import parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import math
import datetime
import argparse
import getpass
import urllib3
import pandas
import datapane
import keyring
import tqdm

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
def fetch_entities(client,module,entity_api,function,page,limit):
    entity_api_module = getattr(module, entity_api)
    entity_api = entity_api_module(api_client=client)
    list_function = getattr(entity_api, function)
    response = list_function(_page=page,_limit=limit)
    return response

def main(api_server,username,secret,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''

    LENGTH=100
    
    #region clusters
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_clustermgmt_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
   
    #* getting list of clusters
    client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_clustermgmt_py_client.ClustersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Clusters...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_clusters(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_clustermgmt_py_client,
                    entity_api='ClustersApi',
                    client=client,
                    function='list_clusters',
                    page=page_number,
                    limit=LENGTH
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
    cluster_list = entity_list
    
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
            'ntp_server_list': "",
            'number_of_nodes': entity.nodes.number_of_nodes,
        }
        if "fqdn" in entity.network.ntp_server_ip_list:
            entity_output['ntp_server_list'] = list({ ntp_server.fqdn.value for ntp_server in entity.network.ntp_server_ip_list})
        elif "ipv4" in entity.network.ntp_server_ip_list:
            entity_output['ntp_server_list'] = list({ ntp_server.ipv4.value for ntp_server in entity.network.ntp_server_ip_list})
        
        cluster_list_output.append(entity_output)
    #endregion clusters
    
    #region hosts
    #* getting list of hosts
    client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_clustermgmt_py_client.ClustersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Hosts...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_hosts(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_clustermgmt_py_client,
                    entity_api='ClustersApi',
                    client=client,
                    function='list_hosts',
                    page=page_number,
                    limit=LENGTH
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
    host_list = entity_list
    
    #* format output
    host_list_output = []
    for entity in host_list:
        entity_output = {
            'cluster': entity.cluster.name,
            'name': entity.host_name,
            'ext_id': entity.ext_id,
            'type': entity.host_type,
            'connection_state': entity.hypervisor.acropolis_connection_state,
            'hypervisor_ip': entity.hypervisor.external_address.ipv4.value,
            'cvm_ip': entity.controller_vm.external_address.ipv4.value,
            'ipmi_ip': entity.ipmi.ip.ipv4.value,
            'hypervisor': entity.hypervisor.type,
            'hypervisor_full_name': entity.hypervisor.full_name,
            'vms_qty': entity.hypervisor.number_of_vms,
            'acropolis_state': entity.hypervisor.state,
            'maintenance_state': entity.maintenance_state,
            'is_secure_booted': entity.is_secure_booted,
            'cpu_model': entity.cpu_model,
            'cpu_frequency_hz': entity.cpu_frequency_hz,
            'number_of_cpu_cores': entity.number_of_cpu_cores,
            'number_of_cpu_sockets': entity.number_of_cpu_sockets,
            'number_of_cpu_threads': entity.number_of_cpu_threads,
            'cpu_capacity_hz': entity.cpu_capacity_hz,
            'memory_size_bytes': entity.memory_size_bytes,
            'block_model': entity.block_model,
            'block_serial': entity.block_serial,
            'uptime': format_timespan(entity.boot_time_usecs/1000000000),
            'disks_serials': list({ disk.serial_id for disk in entity.disk}) if entity.disk else [],
            'disks_storage_tier': list({ disk.storage_tier for disk in entity.disk}) if entity.disk else [],
            'disks_size_in_bytes': list({ disk.size_in_bytes for disk in entity.disk}) if entity.disk else [],
            'gpu_list': entity.gpu_list if hasattr(entity, 'gpu_list') else [],
            'gpu_driver_version': entity.gpu_driver_version if hasattr(entity, 'gpu_list') else '',
        }
        
        host_list_output.append(entity_output)    
    #endregion hosts
    
    #region storage containers
    #* getting list of storage containers
    client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_clustermgmt_py_client.StorageContainersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Hosts...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_storage_containers(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_clustermgmt_py_client,
                    entity_api='StorageContainersApi',
                    client=client,
                    function='list_storage_containers',
                    page=page_number,
                    limit=LENGTH
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
    storage_container_list = entity_list
    
    #* format output
    storage_container_list_output = []
    for entity in storage_container_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.container_ext_id,
            'cluster': entity.cluster_name,
            'replication_factor': entity.replication_factor,
            'cache_deduplication': entity.cache_deduplication,
            'on_disk_dedup': entity.on_disk_dedup,
            'erasure_code': entity.erasure_code,
            'is_compression_enabled': entity.is_compression_enabled,
            'compression_delay_secs': entity.compression_delay_secs,
            'is_inline_ec_enabled': entity.is_inline_ec_enabled,
            'is_software_encryption_enabled': entity.is_software_encryption_enabled,
            'max_capacity_bytes': entity.max_capacity_bytes,
            'logical_explicit_reserved_capacity_bytes': entity.logical_explicit_reserved_capacity_bytes,
        }
        
        storage_container_list_output.append(entity_output)
    #endregion storage containers
    
    #region subnets
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
    client = ntnx_networking_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_networking_py_client.SubnetsApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Subnets...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_subnets(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_networking_py_client,
                    entity_api='SubnetsApi',
                    client=client,
                    function='list_subnets',
                    page=page_number,
                    limit=LENGTH
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
    subnet_list = entity_list
    
    #* format output
    subnet_list_output = []
    #todo: add virtual switch reference (will require listing virtual switches as separate entities)
    for entity in subnet_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'cluster': next(iter({ cluster['name'] for cluster in cluster_list_output if cluster['ext_id'] == entity.cluster_reference })) if hasattr(entity, 'cluster_reference') else '',
            'network_id': entity.network_id,
            'subnet_type': entity.subnet_type,
            'bridge_name': entity.bridge_name,
            'hypervisor_type': entity.hypervisor_type,
            'is_advanced_networking': entity.is_advanced_networking,
            'owner': entity.metadata.owner_user_name,
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
    client = ntnx_prism_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_prism_py_client.CategoriesApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Categories...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_categories(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_prism_py_client,
                    entity_api='CategoriesApi',
                    client=client,
                    function='list_categories',
                    page=page_number,
                    limit=LENGTH
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
    category_list = entity_list
    
    #* format output
    category_list_output = []
    for entity in category_list:
        entity_output = {
            'name': f"{entity.key}:{entity.value}",
            'ext_id': entity.ext_id,
            'key': entity.key,
            'value': entity.value,
            'description': entity.description,
            'type': entity.type,
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
    client = ntnx_iam_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_iam_py_client.UsersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Users...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_users(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_iam_py_client,
                    entity_api='UsersApi',
                    client=client,
                    function='list_users',
                    page=page_number,
                    limit=LENGTH
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
    user_list = entity_list
    
    #* format output
    user_list_output = []
    for entity in user_list:
        entity_output = {
            'name': entity.username,
            'ext_id': entity.ext_id,
            'type': entity.user_type,
            'description': entity.description,
            'display_name': entity.display_name,
            'first_name': entity.first_name,
            'middle_initial': entity.middle_initial,
            'last_name': entity.last_name,
            'status': entity.status,
            'is_force_reset_password_enabled': entity.is_force_reset_password_enabled,
            'created_time': entity.created_time,
            'last_updated_time': entity.last_updated_time,
            'last_login_time': entity.last_login_time,
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
    client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_vmm_py_client.VmApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching VMs...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_vms(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_vmm_py_client,
                    entity_api='VmApi',
                    client=client,
                    function='list_vms',
                    page=page_number,
                    limit=LENGTH
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
    vm_list = entity_list
    
    
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
                if hasattr(vnic.network_info.ipv4_info, "learned_ip_addresses"):
                    for ip_address in vnic.network_info.ipv4_info.learned_ip_addresses:
                        entity_output['learned_ip_addresses'].append(ip_address.value)
                entity_output['subnets'].append(next(iter({ subnet['name'] for subnet in subnet_list_output if subnet['ext_id'] == vnic.network_info.subnet.ext_id })))
        
        vm_list_output.append(entity_output)
    #endregion vms
    
    #region html report
    #* exporting to html
    html_file_name = f"{api_server}_get_pc_report.html"
    
    vm_df = pandas.DataFrame(vm_list_output)
    cluster_df = pandas.DataFrame(cluster_list_output)
    host_df = pandas.DataFrame(host_list_output)
    storage_container_df = pandas.DataFrame(storage_container_list_output)
    subnet_df = pandas.DataFrame(subnet_list_output)
    category_df = pandas.DataFrame(category_list_output)
    user_df = pandas.DataFrame(user_list_output)
    
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting results to file {html_file_name}.{PrintColors.RESET}")
    
    """ df.style \
        .format(thousands=" ", decimal=",") \
        .format_index(str.upper, axis=1)
    
    html_content = df.to_html(index=False)
    html_file= open(html_file_name,"w")
    html_file.write(html_content)
    html_file.close() """
    
    #datapane_app = datapane.App(datapane.DataTable(df))
    datapane_app = datapane.App(
        datapane.Select(
        datapane.DataTable(vm_df,label="vms"),
        datapane.DataTable(cluster_df,label="clusters"),
        datapane.DataTable(host_df,label="hosts"),
        datapane.DataTable(storage_container_df,label="storage_containers"),
        datapane.DataTable(subnet_df,label="subnets"),
        datapane.DataTable(category_df,label="categories"),
        datapane.DataTable(user_df,label="users"),
        )
    )
    datapane_app.save(html_file_name)
    #endregion html report

    #region excel spreadsheet
    excel_file_name = f"{api_server}_get_pc_report.xlsx"
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting results to file {excel_file_name}.{PrintColors.RESET}")
    list_of_dicts = [vm_list_output, cluster_list_output, host_list_output, storage_container_list_output, subnet_list_output, category_list_output, user_list_output]
    data = {'vms': vm_list_output, 'clusters': cluster_list_output, 'hosts': host_list_output, 'storage_containers': storage_container_list_output, 'subnets': subnet_list_output, 'categories': category_list_output, 'users': user_list_output}
    writer = pandas.ExcelWriter(excel_file_name, engine='xlsxwriter')
    for sheet_name, df_data in data.items():
        df = pandas.DataFrame(df_data)  # Create a DataFrame for each dictionary
        if sheet_name == 'users':
            df['created_time'] = df['created_time'].dt.tz_localize(None)
            df['last_updated_time'] = df['last_updated_time'].dt.tz_localize(None)
            df['last_login_time'] = df['last_login_time'].dt.tz_localize(None)
        df.to_excel(writer, sheet_name=sheet_name, index=False)  # index=False to avoid row numbers
    writer.close()
    #end region excel spreadsheet
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, help="True of False to control SSL certs verification.")
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
            
    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure)