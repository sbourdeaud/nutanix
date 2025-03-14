""" gets performance metrics from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.
        secure: True or False to control SSL certs verification.

    Returns:
        html and excel report files.
"""


#region #*IMPORT
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

import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import ntnx_aiops_py_client
import ntnx_vmm_py_client
#endregion #*IMPORT


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


#region #*FUNCTIONS


def fetch_entities(client,module,entity_api,function,page,limit=50):
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


def fetch_entity_descriptors(client,source_ext_id,page,limit=50):
    '''fetch_entity_descriptors function.
        Args:
            client: a v4 Python SDK client object.
            source_ext_id: uuid of a valid source.
            page: page number to fetch.
            limit: number of entities to fetch.
        Returns:
    '''
    entity_api = ntnx_aiops_py_client.StatsApi(api_client=client)
    response = entity_api.get_entity_descriptors_v4(sourceExtId=source_ext_id,_page=page,_limit=limit)
    return response


def get_vm_metrics(client,vm,minutes_ago,sampling_interval,stat_type,graph,csv_export):
    '''get_vm_metrics function.
       Fetches metrics for a specified vm and generates graphs for that entity.
        Args:
            client: a v4 Python SDK client object.
            vm: a virtual machine name
            minutes_ago: integer indicating the number of minutes to get metrics for (exp: 60 would mean get the metrics for the last hour).
            sampling_interval: integer used to specify in seconds the sampling interval.
            stat_type: The operator to use while performing down-sampling on stats data. Allowed values are SUM, MIN, MAX, AVG, COUNT and LAST.
        Returns:
    '''
    
    """ print(f"(get_vm_metrics) show graphs: {graph}")
    print(f"(get_vm_metrics) csv exports: {csv_export}") """
    
    #* fetch vm object to figure out extId
    entity_api = ntnx_vmm_py_client.VmApi(api_client=client)
    query_filter = f"name eq '{vm}'"
    response = entity_api.list_vms(_filter=query_filter)
    vm_uuid = response.data[0].ext_id
    #print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching metrics for VM {vm} with uuid {vm_uuid}...{PrintColors.RESET}")
    
    #* fetch metrics for vm
    entity_api = ntnx_vmm_py_client.StatsApi(api_client=client)
    start_time = (datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=minutes_ago)).isoformat()
    end_time = (datetime.datetime.now(datetime.timezone.utc)).isoformat()
    response = entity_api.get_vm_stats_by_id(vm_uuid, _startTime=start_time, _endTime=end_time, _samplingInterval=sampling_interval, _statType=stat_type, _select='*')
    vm_stats = [stat for stat in response.data.stats if stat.cluster is None]
    #print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Found {len(vm_stats)} data points for VM {vm} with uuid {vm_uuid}...{PrintColors.RESET}")
    
    #* building pandas dataframe from the retrieved data
    data_points = []
    for data_point in vm_stats:
        data_points.append(data_point.to_dict())
    df = pd.DataFrame(data_points)
    df = df.set_index('timestamp')
    df.drop('_reserved', axis=1, inplace=True)
    df.drop('_object_type', axis=1, inplace=True)
    df.drop('_unknown_fields', axis=1, inplace=True)
    df.drop('cluster', axis=1, inplace=True)
    df.drop('hypervisor_type', axis=1, inplace=True)
    df.drop('check_score', axis=1, inplace=True)

    #* building graphs
    if graph is True:
        df = df.dropna(subset=['disk_usage_ppm'])
        df['disk_usage'] = (df['disk_usage_ppm'] / 10000).round(2)
        df = df.dropna(subset=['memory_usage_ppm'])
        df['memory_usage'] = (df['memory_usage_ppm'] / 10000).round(2)
        df = df.dropna(subset=['hypervisor_cpu_usage_ppm'])
        df['hypervisor_cpu_usage'] = (df['hypervisor_cpu_usage_ppm'] / 10000).round(2)
        df = df.dropna(subset=['hypervisor_cpu_ready_time_ppm'])
        df['hypervisor_cpu_ready_time'] = (df['hypervisor_cpu_ready_time_ppm'] / 10000).round(2)

        fig = make_subplots(rows=2, cols=2,
                subplot_titles=(f"{vm} Overview", f"{vm} Storage IOPS", f"{vm} Storage Bandwidth", f"{vm} Storage Latency"),
                x_title="Time")  # Shared x-axis title
        # Subplot 1: Overview
        y_cols1 = ["hypervisor_cpu_usage", "hypervisor_cpu_ready_time", "memory_usage", "disk_usage"]
        for y_col in y_cols1:
            fig.add_trace(go.Scatter(x=df.index, y=df[y_col], hovertemplate="%{x}<br>%%{y}", name=y_col, mode='lines', legendgroup='group1'), row=1, col=1)
        fig.update_yaxes(title_text="% Utilized", range=[0, 100], row=1, col=1)
        # Subplot 2: Storage IOPS
        y_cols2 = ["controller_num_iops", "controller_num_read_iops", "controller_num_write_iops"]
        for y_col in y_cols2:
            fig.add_trace(go.Scatter(x=df.index, y=df[y_col], hovertemplate="%{x}<br>%{y} iops", name=y_col, mode='lines', legendgroup='group2'), row=1, col=2)
        fig.update_yaxes(title_text="IOPS", row=1, col=2)
        # Subplot 3: Storage Bandwidth
        y_cols3 = ["controller_io_bandwidth_kbps", "controller_read_io_bandwidth_kbps", "controller_write_io_bandwidth_kbps"]
        for y_col in y_cols3:
            fig.add_trace(go.Scatter(x=df.index, y=df[y_col], hovertemplate="%{x}<br>%{y} kbps", name=y_col, mode='lines', legendgroup='group3'), row=2, col=1)
        fig.update_yaxes(title_text="Kbps", row=2, col=1)
        # Subplot 4: Storage Latency
        y_cols4 = ["controller_avg_io_latency_micros", "controller_avg_read_io_latency_micros", "controller_avg_write_io_latency_micros"]
        for y_col in y_cols4:
            fig.add_trace(go.Scatter(x=df.index, y=df[y_col], hovertemplate="%{x}<br>%{y} usec", name=y_col, mode='lines', legendgroup='group4'), row=2, col=2)
        fig.update_yaxes(title_text="Microseconds", row=2, col=2)
        fig.update_layout(height=800, legend_title_text="Metric") # Shared legend title
        fig.show()

    #* exporting results to csv
    if csv_export is True:
        for column in df.columns:
            df[column].to_csv(f"{vm}_{column}.csv", index=True)


def main(api_server,username,secret,vms,graph,csv_export,minutes_ago=5,sampling_interval=30,stat_type="AVG",secure=False,show=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
            html and excel report files.
    '''

    processing_start_time = time.time()
    limit=100
    
    """ print(f"(main) show graphs: {graph}")
    print(f"(main) csv exports: {csv_export}") """


    if show is True:
        #* initialize variable for API client configuration
        api_client_configuration = ntnx_aiops_py_client.Configuration()
        api_client_configuration.host = api_server
        api_client_configuration.username = username
        api_client_configuration.password = secret

        if secure is False:
            #! suppress warnings about insecure connections
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            #! suppress ssl certs verification
            api_client_configuration.verify_ssl = False

        #* getting list of sources
        client = ntnx_aiops_py_client.ApiClient(configuration=api_client_configuration)
        entity_api = ntnx_aiops_py_client.StatsApi(api_client=client)
        print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching available sources...{PrintColors.RESET}")
        response = entity_api.get_sources_v4() 
        source_ext_id = next(iter([source.ext_id for source in response.data if source.source_name == 'nutanix']))
        
        #* getting entities and metrics descriptor for nutanix source
        print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching entities and descriptors for source nutanix...{PrintColors.RESET}")
        entity_list=[]
        response = entity_api.get_entity_descriptors_v4(sourceExtId=source_ext_id,_page=0,_limit=1)
        total_available_results=response.metadata.total_available_results
        page_count = math.ceil(total_available_results/limit)
        with tqdm.tqdm(total=page_count, desc="Fetching pages") as progress_bar:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(
                        fetch_entity_descriptors,
                        client=client,
                        source_ext_id=source_ext_id,
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
        entity_descriptors_list = entity_list
        descriptors={}
        for item in entity_descriptors_list:
            entity_type = item.entity_type
            descriptors[entity_type] = {}
            for metric in item.metrics:
                metric_name = metric.name
                descriptors[entity_type][metric_name] = {}
                descriptors[entity_type][metric_name]['name'] = metric.name
                descriptors[entity_type][metric_name]['value_type'] = metric.value_type
                if metric.additional_properties is not None:
                    descriptors[entity_type][metric_name]['description'] = next(iter([metric_property.value for metric_property in metric.additional_properties if metric_property.name == 'description']),None)
                else:
                    descriptors[entity_type][metric_name]['description'] = None
        for entity_type in descriptors.keys():
            print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Available metrics for {entity_type} are:{PrintColors.RESET}")
            for metric in sorted(descriptors[entity_type]):
                print(f"    {descriptors[entity_type][metric]['name']},{descriptors[entity_type][metric]['value_type']},{descriptors[entity_type][metric]['description']}")
    elif vms:
        #* initialize variable for API client configuration
        api_client_configuration = ntnx_vmm_py_client.Configuration()
        api_client_configuration.host = api_server
        api_client_configuration.username = username
        api_client_configuration.password = secret

        if secure is False:
            #! suppress warnings about insecure connections
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            #! suppress ssl certs verification
            api_client_configuration.verify_ssl = False

        client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)

        with tqdm.tqdm(total=len(vms), desc="Processing VMs") as progress_bar:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(
                        get_vm_metrics,
                        client=client,
                        vm=vm,
                        minutes_ago=minutes_ago,
                        sampling_interval=sampling_interval,
                        stat_type=stat_type,
                        graph=graph,
                        csv_export=csv_export,
                    ) for vm in vms]
                for future in as_completed(futures):
                    try:
                        entities = future.result()
                    except Exception as e:
                        print(f"{PrintColors.WARNING}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                    finally:
                        progress_bar.update(1)


            #! if you wanted to show 4 graphs on separate pages, use this instead:
            """ fig = make_subplots(rows=2, cols=2, subplot_titles=(f"{vm} Overview", f"{vm} Storage IOPS", f"{vm} Storage Bandwidth", f"{vm} Storage Latency"))
            fig.add_trace(go.Line(y=df["hypervisor_cpu_usage", "hypervisor_cpu_ready_time", "memory_usage", "disk_usage"]), row=1, col=1)
            fig.add_trace(go.Line(y=df["hypervisor_cpu_usage", "hypervisor_cpu_ready_time", "memory_usage", "disk_usage"]), row=1, col=2)
            fig.add_trace(go.Line(y=df["hypervisor_cpu_usage", "hypervisor_cpu_ready_time", "memory_usage", "disk_usage"]), row=2, col=1)
            fig.add_trace(go.Line(y=df["hypervisor_cpu_usage", "hypervisor_cpu_ready_time", "memory_usage", "disk_usage"]), row=2, col=2)
            fig.update_yaxes(range=[0, 100], row=1, col=1)
            fig.update_yaxes(range=[0, 100], row=1, col=2)
            fig.update_yaxes(range=[0, 100], row=2, col=1)
            fig.update_yaxes(range=[0, 100], row=2, col=2)
            fig.update_layout(xaxis_title="Time",  # For shared x-axis title
                  yaxis_title="% Utilized", # For the first subplot's y-axis
                  yaxis2_title="% Utilized", # For the first subplot's y-axis
                  yaxis3_title="% Utilized", # For the first subplot's y-axis
                  yaxis4_title="% Utilized",
                  legend_title_text="Metric")
            fig.show() """


    processing_end_time = time.time()
    elapsed_time = processing_end_time - processing_start_time
    print(f"{PrintColors.STEP}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUM] Process completed in {format_timespan(elapsed_time)}{PrintColors.RESET}")


#endregion #*FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, action=argparse.BooleanOptionalAction, help="Control SSL certs verification.")
    parser.add_argument("-sh", "--show", action=argparse.BooleanOptionalAction, help="Show available entity types and metrics.")
    parser.add_argument("-g", "--graph", action=argparse.BooleanOptionalAction, help="Indicate you want graphs to be generated. Defaults to True.")
    parser.add_argument("-e", "--export", action=argparse.BooleanOptionalAction, help="Indicate you want csv exports to be generated (1 csv file per metric for each vm). Defaults to False.")
    parser.add_argument("-v", "--vm", type=str, help="Comma separated list of VM names you want to process.")
    parser.add_argument("-c", "--csv", type=str, help="Path and name of csv file with vm names (header: vm_name and then one vm name per line).")
    parser.add_argument("-t", "--time", type=int, default=5, help="Integer used to specify how many minutes ago you want to collect metrics for (defaults to 5 minutes ago).")
    parser.add_argument("-i", "--interval", type=int, default=30, help="Integer used to specify in seconds the sampling interval (defaults to 30 seconds).")
    parser.add_argument("-st", "--stat_type", default="AVG", choices=["AVG","MIN","MAX","LAST","SUM","COUNT"], help="The operator to use while performing down-sampling on stats data. Allowed values are SUM, MIN, MAX, AVG, COUNT and LAST. Defaults to AVG")
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
            exit(1)

    if args.show is True:
        target_vms = None
    elif args.csv:
        data=pd.read_csv(args.csv)
        target_vms = data['vm_name'].tolist()
    elif args.vm:
        target_vms = args.vm.split(',')

    """ print(f"show graphs: {args.graph}")
    print(f"csv exports: {args.export}") """
    
    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure,show=args.show,vms=target_vms,minutes_ago=args.time,sampling_interval=args.interval,stat_type=args.stat_type,graph=args.graph,csv_export=args.export)
