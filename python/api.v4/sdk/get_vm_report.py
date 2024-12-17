""" gets virtual machines list from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.

    Returns:
        html report file.
"""


#region IMPORT
from time import sleep
from datetime import datetime, timedelta
from urllib.parse import urlparse
from urllib.parse import parse_qs

import argparse
import getpass
import urllib3
import pandas
import datapane
import keyring
import ntnx_vmm_py_client
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

def main(api_server,username,secret,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''


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
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all virtual machines from {api_server}.{PrintColors.RESET}")
    
    api_instance_vm = ntnx_vmm_py_client.api.VmApi(api_client=api_client)
    
    vm_list = []
    response_self_page_link = 'a'
    response_last_page_link = 'b'
    next_page_number = 0
    
    while response_self_page_link != response_last_page_link:
        response = api_instance_vm.list_vms(_page=next_page_number)
        vm_list = vm_list + response.data
        response_self_page_link,response_next_page_link,response_last_page_link = ntnx_api_pagination_get_page_links(response)
        if response_next_page_link:
            next_page_number = ntnx_api_pagination_get_next_page_number(response_next_page_link)
        

    #* format output
    vm_list_output = []
    boot_config = ''
    for entity in vm_list:
        entity_output = {
            'name': entity.name,
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
        }
        
        if entity.guest_tools:
            entity_output['guest_tools_version'] = entity.guest_tools.available_version
            entity_output['guest_tools_enabled'] = entity.guest_tools.is_enabled
            entity_output['guest_tools_capabilities'] = entity.guest_tools.capabilities
        
        boot_config=(entity.boot_config._object_type).split('.')
        entity_output['boot_type'] = boot_config[len(boot_config)-1]
        if entity_output['boot_type'] == 'UefiBoot':
            entity_output['is_secure_boot_enabled'] = entity.boot_config.is_secure_boot_enabled
        
        vm_list_output.append(entity_output)
    
    #* exporting to html
    html_file_name = "get_vm_report.html"
    df = pandas.DataFrame(vm_list_output)
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting {len(df)} results to file {html_file_name}.{PrintColors.RESET}")
    """ html_content = df.to_html(index=False)
    html_file= open(html_file_name,"w")
    html_file.write(html_content)
    html_file.close() """
    datapane_app = datapane.App(datapane.DataTable(df))
    datapane_app.save(html_file_name)
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, help="True of False to control SSL certs verification.")
    args = parser.parse_args()
    
    # * check for password (we use keyring python module to access the workstation operating system password store in an "ntnx" section)
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for user {args.username} from the password store.{PrintColors.RESET}")
    pwd = keyring.get_password("ntnx",args.username)
    if not pwd:
        try:
            pwd = getpass.getpass()
            keyring.set_password("ntnx",args.username,pwd)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")
            
    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure)