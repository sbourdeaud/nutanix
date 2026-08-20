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
from datetime import datetime, timezone, timedelta
from pathlib import Path

import math
import time
import argparse
import getpass
import webbrowser

from humanfriendly import format_timespan

import urllib3
import pandas as pd
import keyring
import tqdm

import plotly.graph_objects as go
from plotly.subplots import make_subplots

import ntnx_aiops_py_client
import ntnx_clustermgmt_py_client
import ntnx_vmm_py_client
import ntnx_networking_py_client
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
    vm_entity = response.data[0]
    vm_uuid = vm_entity.ext_id

    def bytes_to_gib(bytes_value):
        try:
            return round(float(bytes_value) / (1024 ** 3), 2)
        except (TypeError, ValueError):
            return None

    # Build VM configuration summary for chart header.
    num_sockets = getattr(vm_entity, 'num_sockets', None)
    cores_per_socket = getattr(vm_entity, 'num_cores_per_socket', None)
    total_vcpu = None
    if num_sockets is not None and cores_per_socket is not None:
        total_vcpu = num_sockets * cores_per_socket
    memory_gib = bytes_to_gib(getattr(vm_entity, 'memory_size_bytes', None))
    disk_sizes = []
    for disk in (getattr(vm_entity, 'disks', None) or []):
        disk_size = getattr(getattr(disk, 'backing_info', None), 'disk_size_bytes', None)
        if disk_size is not None:
            disk_sizes.append(disk_size)
    storage_gib = bytes_to_gib(sum(disk_sizes)) if disk_sizes else None
    os_name = getattr(vm_entity, 'guest_os_name', None)
    if not os_name:
        guest_tools = getattr(vm_entity, 'guest_tools', None)
        os_name = getattr(guest_tools, 'guest_os_version', None) if guest_tools else None
    if not os_name:
        os_name = "unknown"
    cluster_ref = getattr(vm_entity, 'cluster', None)
    cluster_ext_id = getattr(cluster_ref, 'ext_id', None) if cluster_ref else None
    cluster_name = None
    if cluster_ext_id:
        try:
            cluster_cfg = ntnx_clustermgmt_py_client.Configuration()
            cluster_cfg.host = client.configuration.host
            cluster_cfg.username = client.configuration.username
            cluster_cfg.password = client.configuration.password
            cluster_cfg.verify_ssl = client.configuration.verify_ssl
            cluster_api = ntnx_clustermgmt_py_client.ClustersApi(
                api_client=ntnx_clustermgmt_py_client.ApiClient(configuration=cluster_cfg)
            )
            cluster_resp = cluster_api.get_cluster_by_id(cluster_ext_id)
            cluster_name = getattr(getattr(cluster_resp, 'data', None), 'name', None)
        except Exception as cluster_error:
            print(
                f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] "
                f"Could not resolve cluster name for VM {vm}: {cluster_error}{PrintColors.RESET}"
            )
    cluster_display = cluster_name or cluster_ext_id or "unknown"
    vm_nics = getattr(vm_entity, 'nics', None) or []
    nic_count = len(vm_nics)
    ip_addresses = []
    for nic in vm_nics:
        network_info = getattr(nic, 'network_info', None)
        ipv4_info = getattr(network_info, 'ipv4_info', None) if network_info else None
        learned_ips = getattr(ipv4_info, 'learned_ip_addresses', None) if ipv4_info else None
        if learned_ips:
            for ip in learned_ips:
                ip_value = getattr(ip, 'value', None)
                if ip_value:
                    ip_addresses.append(ip_value)
        # Fallback to configured NIC IPs when learned IPs are not populated.
        for info_obj in [network_info, getattr(nic, 'nic_network_info', None)]:
            ipv4_cfg = getattr(info_obj, 'ipv4_config', None) if info_obj else None
            primary_ip = getattr(getattr(ipv4_cfg, 'ip_address', None), 'value', None) if ipv4_cfg else None
            if primary_ip:
                ip_addresses.append(primary_ip)
            for sec_ip in (getattr(ipv4_cfg, 'secondary_ip_address_list', None) or []):
                sec_value = getattr(sec_ip, 'value', None)
                if sec_value:
                    ip_addresses.append(sec_value)
    unique_ips = sorted(set(ip_addresses))
    subnet_names = []
    subnet_ids = sorted({
        getattr(getattr(getattr(nic, 'network_info', None), 'subnet', None), 'ext_id', None)
        for nic in vm_nics
        if getattr(getattr(getattr(nic, 'network_info', None), 'subnet', None), 'ext_id', None)
    })
    if subnet_ids:
        try:
            networking_api = ntnx_networking_py_client.SubnetsApi(
                api_client=ntnx_networking_py_client.ApiClient(configuration=client.configuration)
            )
            for subnet_id in subnet_ids:
                subnet_response = networking_api.get_subnet_by_id(subnet_id)
                subnet_name = getattr(getattr(subnet_response, 'data', None), 'name', None)
                subnet_names.append(subnet_name or subnet_id)
        except Exception as subnet_error:
            print(
                f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] "
                f"Could not resolve subnet names for VM {vm}: {subnet_error}{PrintColors.RESET}"
            )
    unique_subnets = sorted(set(subnet_names))
    #print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching metrics for VM {vm} with uuid {vm_uuid}...{PrintColors.RESET}")
    
    #* fetch metrics for vm
    entity_api = ntnx_vmm_py_client.StatsApi(api_client=client)
    start_time = (datetime.now(timezone.utc)-timedelta(minutes=minutes_ago)).isoformat()
    end_time = (datetime.now(timezone.utc)).isoformat()
    response = entity_api.get_vm_stats_by_id(vm_uuid, _startTime=start_time, _endTime=end_time, _samplingInterval=sampling_interval, _statType=stat_type, _select='*')
    vm_stats = [stat for stat in response.data.stats if stat.cluster is None]
    #print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Found {len(vm_stats)} data points for VM {vm} with uuid {vm_uuid}...{PrintColors.RESET}")
    
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
        df_plot = df.copy()
        def ppm_to_pct(series):
            return (pd.to_numeric(series, errors='coerce') / 10000).round(2)

        if 'disk_usage_ppm' in df_plot.columns:
            df_plot['disk_usage'] = ppm_to_pct(df_plot['disk_usage_ppm'])
        if 'memory_usage_ppm' in df_plot.columns:
            df_plot['memory_usage'] = ppm_to_pct(df_plot['memory_usage_ppm'])
        if 'hypervisor_cpu_usage_ppm' in df_plot.columns:
            df_plot['hypervisor_cpu_usage'] = ppm_to_pct(df_plot['hypervisor_cpu_usage_ppm'])
        if 'hypervisor_cpu_ready_time_ppm' in df_plot.columns:
            df_plot['hypervisor_cpu_ready_time'] = ppm_to_pct(df_plot['hypervisor_cpu_ready_time_ppm'])
        if 'controller_avg_io_latency_micros' in df_plot.columns:
            df_plot['controller_avg_io_latency_ms'] = (pd.to_numeric(df_plot['controller_avg_io_latency_micros'], errors='coerce') / 1000).round(3)
        if 'controller_avg_read_io_latency_micros' in df_plot.columns:
            df_plot['controller_avg_read_io_latency_ms'] = (pd.to_numeric(df_plot['controller_avg_read_io_latency_micros'], errors='coerce') / 1000).round(3)
        if 'controller_avg_write_io_latency_micros' in df_plot.columns:
            df_plot['controller_avg_write_io_latency_ms'] = (pd.to_numeric(df_plot['controller_avg_write_io_latency_micros'], errors='coerce') / 1000).round(3)
        if 'hypervisor_num_received_bytes' in df_plot.columns:
            # Convert bytes/s to MiB/s for readability.
            df_plot['hypervisor_receive_mibps'] = (pd.to_numeric(df_plot['hypervisor_num_received_bytes'], errors='coerce') / (1024 * 1024)).round(3)
        if 'hypervisor_num_transmitted_bytes' in df_plot.columns:
            # Convert bytes/s to MiB/s for readability.
            df_plot['hypervisor_transmit_mibps'] = (pd.to_numeric(df_plot['hypervisor_num_transmitted_bytes'], errors='coerce') / (1024 * 1024)).round(3)

        def add_trace_if_data(fig, x_data, y_series, hovertemplate, trace_name, row, col, empty_metrics):
            if y_series is None:
                empty_metrics.append(trace_name)
                return
            valid_series = y_series.dropna()
            if valid_series.empty:
                empty_metrics.append(trace_name)
                return
            fig.add_trace(
                go.Scatter(
                    x=x_data.loc[valid_series.index] if hasattr(x_data, "loc") else valid_series.index,
                    y=valid_series,
                    hovertemplate=hovertemplate,
                    name=trace_name,
                    mode='lines'
                ),
                row=row,
                col=col
            )

        fig = make_subplots(rows=3, cols=2,
                subplot_titles=(
                    f"{vm} Overview",
                    f"{vm} Storage IOPS",
                    f"{vm} Storage Bandwidth",
                    f"{vm} Storage Latency",
                    f"{vm} Network Throughput",
                    f"{vm} Network Packet Drops"
                ),
                x_title="Time")  # Shared x-axis title
        empty_metrics = []
        # Subplot 1: Overview
        y_cols1 = ["hypervisor_cpu_usage", "hypervisor_cpu_ready_time", "memory_usage", "disk_usage"]
        for y_col in y_cols1:
            series = df_plot[y_col] if y_col in df_plot.columns else None
            add_trace_if_data(fig, df_plot.index, series, "%{x}<br>%%{y}", y_col, 1, 1, empty_metrics)
        fig.update_yaxes(title_text="% Utilized", range=[0, 100], row=1, col=1)
        # Subplot 2: Storage IOPS
        y_cols2 = ["controller_num_iops", "controller_num_read_iops", "controller_num_write_iops"]
        for y_col in y_cols2:
            series = df_plot[y_col] if y_col in df_plot.columns else None
            add_trace_if_data(fig, df_plot.index, series, "%{x}<br>%{y} iops", y_col, 1, 2, empty_metrics)
        fig.update_yaxes(title_text="IOPS", row=1, col=2)
        # Subplot 3: Storage Bandwidth
        y_cols3 = ["controller_io_bandwidth_kbps", "controller_read_io_bandwidth_kbps", "controller_write_io_bandwidth_kbps"]
        for y_col in y_cols3:
            series = df_plot[y_col] if y_col in df_plot.columns else None
            add_trace_if_data(fig, df_plot.index, series, "%{x}<br>%{y} kbps", y_col, 2, 1, empty_metrics)
        fig.update_yaxes(title_text="Kbps", row=2, col=1)
        # Subplot 4: Storage Latency
        y_cols4 = ["controller_avg_io_latency_ms", "controller_avg_read_io_latency_ms", "controller_avg_write_io_latency_ms"]
        for y_col in y_cols4:
            series = df_plot[y_col] if y_col in df_plot.columns else None
            add_trace_if_data(fig, df_plot.index, series, "%{x}<br>%{y} ms", y_col, 2, 2, empty_metrics)
        fig.update_yaxes(title_text="Milliseconds", row=2, col=2)
        # Subplot 5: Network Throughput
        y_cols5 = ["hypervisor_receive_mibps", "hypervisor_transmit_mibps"]
        for y_col in y_cols5:
            series = df_plot[y_col] if y_col in df_plot.columns else None
            add_trace_if_data(fig, df_plot.index, series, "%{x}<br>%{y} MiB/s", y_col, 3, 1, empty_metrics)
        fig.update_yaxes(title_text="MiB/s", row=3, col=1)
        # Subplot 6: Packet drops
        y_cols6 = [
            "hypervisor_num_receive_packets_dropped",
            "hypervisor_num_transmit_packets_dropped",
        ]
        for y_col in y_cols6:
            series = df_plot[y_col] if y_col in df_plot.columns else None
            add_trace_if_data(fig, df_plot.index, series, "%{x}<br>%{y}", y_col, 3, 2, empty_metrics)
        fig.update_yaxes(title_text="Dropped Packets", row=3, col=2)
        config_lines = [
            f"<b>vCPU:</b> {total_vcpu if total_vcpu is not None else 'n/a'}",
            f"<b>RAM:</b> {memory_gib} GiB" if memory_gib is not None else "<b>RAM:</b> n/a",
            f"<b>Storage:</b> {storage_gib} GiB" if storage_gib is not None else "<b>Storage:</b> n/a",
            f"<b>OS:</b> {os_name}",
            f"<b>Cluster:</b> {cluster_display}",
            f"<b>NICs:</b> {nic_count}",
            f"<b>IPs:</b> {', '.join(unique_ips)}" if unique_ips else "<b>IPs:</b> n/a",
            f"<b>Subnets:</b> {', '.join(unique_subnets)}" if unique_subnets else "<b>Subnets:</b> n/a",
        ]
        fig.add_annotation(
            x=0,
            y=1.12,
            xref="paper",
            yref="paper",
            xanchor="left",
            yanchor="bottom",
            showarrow=False,
            align="left",
            text=" | ".join(config_lines),
            font=dict(size=13),
        )
        fig.update_layout(height=1200, legend_title_text="Metric", margin=dict(t=170)) # Shared legend title
        if empty_metrics:
            print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] No data points for metrics: {', '.join(empty_metrics)}{PrintColors.RESET}")

        fig_html = fig.to_html(full_html=False, include_plotlyjs='cdn')
        output_path = Path(f"{vm}_metrics.html").resolve()
        html_content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{vm} Metrics</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; background: #fff; }}
    .topbar {{
      position: sticky; top: 0; z-index: 1000;
      display: flex; align-items: center; justify-content: flex-end;
      gap: 8px; padding: 10px 14px; border-bottom: 1px solid #e5e7eb; background: #fff;
    }}
    .btn {{
      border: 1px solid #2563eb; background: #2563eb; color: #fff;
      padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 13px;
    }}
    .btn:hover {{ background: #1d4ed8; border-color: #1d4ed8; }}
    .content {{ padding: 10px; }}
    @media print {{
      .topbar {{ display: none !important; }}
      .content {{ padding: 0; }}
    }}
  </style>
</head>
<body>
  <div class="topbar">
    <button class="btn" onclick="window.print()">Export to PDF</button>
  </div>
  <div class="content">
    {fig_html}
  </div>
</body>
</html>
"""
        output_path.write_text(html_content, encoding='utf-8')
        webbrowser.open(output_path.as_uri())
        print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Generated HTML report: {output_path}{PrintColors.RESET}")

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
        print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching available sources...{PrintColors.RESET}")
        response = entity_api.get_sources_v4() 
        source_ext_id = next(iter([source.ext_id for source in response.data if source.source_name == 'nutanix']))
        
        #* getting entities and metrics descriptor for nutanix source
        print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching entities and descriptors for source nutanix...{PrintColors.RESET}")
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
                        print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
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
            print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Available metrics for {entity_type} are:{PrintColors.RESET}")
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
                        print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
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
    print(f"{PrintColors.STEP}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUM] Process completed in {format_timespan(elapsed_time)}{PrintColors.RESET}")


#endregion #*FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, action=argparse.BooleanOptionalAction, help="Control SSL certs verification.")
    parser.add_argument("-sh", "--show", action=argparse.BooleanOptionalAction, help="Show available entity types and metrics.")
    parser.add_argument("-g", "--graph", action=argparse.BooleanOptionalAction, default=True, help="Indicate you want graphs to be generated. Defaults to True.")
    parser.add_argument("-e", "--export", action=argparse.BooleanOptionalAction, default=False, help="Indicate you want csv exports to be generated (1 csv file per metric for each vm). Defaults to False.")
    parser.add_argument("-v", "--vm", type=str, help="Comma separated list of VM names you want to process.")
    parser.add_argument("-c", "--csv", type=str, help="Path and name of csv file with vm names (header: vm_name and then one vm name per line).")
    parser.add_argument("-t", "--time", type=int, default=5, help="Integer used to specify how many minutes ago you want to collect metrics for (defaults to 5 minutes ago).")
    parser.add_argument("-i", "--interval", type=int, default=30, help="Integer used to specify in seconds the sampling interval (defaults to 30 seconds).")
    parser.add_argument("-st", "--stat_type", default="AVG", choices=["AVG","MIN","MAX","LAST","SUM","COUNT"], help="The operator to use while performing down-sampling on stats data. Allowed values are SUM, MIN, MAX, AVG, COUNT and LAST. Defaults to AVG")
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
            exit(1)

    target_vms = None
    if args.show is True:
        target_vms = None
    elif args.csv:
        data=pd.read_csv(args.csv)
        target_vms = data['vm_name'].tolist()
    elif args.vm:
        target_vms = args.vm.split(',')

    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure,show=args.show,vms=target_vms,minutes_ago=args.time,sampling_interval=args.interval,stat_type=args.stat_type,graph=args.graph,csv_export=args.export)
