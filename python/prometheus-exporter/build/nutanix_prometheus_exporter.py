""" extracts metrics from Nutanix API and published them in 
    prometheus format on a web service.

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.
        secure: boolean to indicate if certs should be verified.

    Returns:
        csv file.
"""


#region #*IMPORT
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import json
import time
import socket
import ipaddress
import urllib3
import requests
from prometheus_client import start_http_server, Gauge, Info
#endregion #*IMPORT


#region #*CLASS
class PrintColors:
    """ used in print statements for colored output
    """
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR   


class NutanixMetrics:
    """
    Representation of Prometheus metrics and loop to fetch and transform
    application metrics into Prometheus metrics.
    """
    def __init__(self,
                 ipmi_username='ADMIN', ipmi_secret=None,
                 app_port=9440, polling_interval_seconds=30, api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,
                 prism='127.0.0.1', user='admin', pwd='Nutanix/4u', prism_secure=False,
                 vm_list='',
                 cluster_metrics=True, storage_containers_metrics=True, ipmi_metrics=True, prism_central_metrics=False, ncm_ssp_metrics=False):
        self.ipmi_username = ipmi_username
        self.ipmi_secret = ipmi_secret
        self.app_port = app_port
        self.polling_interval_seconds = polling_interval_seconds
        self.api_requests_timeout_seconds = api_requests_timeout_seconds
        self.api_requests_retries = api_requests_retries
        self.api_sleep_seconds_between_retries = api_sleep_seconds_between_retries
        self.prism = prism
        self.user = user
        self.pwd = pwd
        self.prism_secure = prism_secure
        self.vm_list = vm_list
        self.cluster_metrics = cluster_metrics
        self.storage_containers_metrics = storage_containers_metrics
        self.ipmi_metrics = ipmi_metrics
        self.prism_central_metrics = prism_central_metrics
        self.ncm_ssp_metrics = ncm_ssp_metrics

        if self.cluster_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for clusters...{PrintColors.RESET}")

            cluster_uuid, cluster_details = prism_get_cluster(api_server=prism,username=user,secret=pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            hosts_details = prism_get_hosts(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)

            #creating host stats metrics
            for key,value in hosts_details[0]['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixHosts_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['host']))
            for key,value in hosts_details[0]['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixHosts_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['host']))

            #creating cluster stats metrics
            for key,value in cluster_details['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixClusters_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))
            for key,value in cluster_details['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixClusters_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))

            #creating cluster counts metrics
            key_strings = [
                "NutanixClusters_count_vm",
                "NutanixClusters_count_vm_on",
                "NutanixClusters_count_vm_off",
                "NutanixClusters_count_vcpu",
                "NutanixClusters_count_vram_mib",
                "NutanixClusters_count_vdisk",
                "NutanixClusters_count_vdisk_ide",
                "NutanixClusters_count_vdisk_sata",
                "NutanixClusters_count_vdisk_scsi",
                "NutanixClusters_count_vnic"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))

            #creating host counts metrics
            key_strings = [                
                "NutanixHosts_count_vm",
                "NutanixHosts_count_vcpu",
                "NutanixHosts_count_vram_mib",
                "NutanixHosts_count_vdisk",
                "NutanixHosts_count_vdisk_ide",
                "NutanixHosts_count_vdisk_sata",
                "NutanixHosts_count_vdisk_scsi",
                "NutanixHosts_count_vnic"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['host']))

            #other misc info based metrics
            #self.lts = Enum("is_lts", "AOS Long Term Support", ['cluster'], states=['True', 'False'])
            setattr(self, 'NutanixClusters_info', Info('is_lts', 'Long Term Support AOS true/false', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('num_nodes', 'Quantity of hardware nodes', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('model_name', 'Hardware model', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('storage_type', 'Mixed or full flash', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('aos_version', 'AOS version', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('is_nsenabled', 'Status of network segmentation', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('encrypted', 'Status of encryption', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('timezone', 'Timezone', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('operation_mode', 'Status of operations', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('enable_shadow_clones', 'Status of shadow clones', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('rf', 'Replication factor', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('enable_rebuild_reservation', 'Status of rebuild reservation', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('fault_tolerance_domain_type', 'Fault tolerance type', ['cluster']))
            setattr(self, 'NutanixClusters_info', Info('data_in_transit_encryption_dto', 'In transit encryption status', ['cluster']))

        if self.vm_list:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for virtual machines...{PrintColors.RESET}")
            vm_list_array = self.vm_list.split(',')
            vm_details = prism_get_vm(vm_name=vm_list_array[0],api_server=prism,username=user,secret=pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            if len(vm_details) > 0:
                for key,value in vm_details['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixVms_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    setattr(self, key_string, Gauge(key_string, key_string, ['vm']))
                for key,value in vm_details['usageStats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixVms_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    setattr(self, key_string, Gauge(key_string, key_string, ['vm']))
            else:
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] Specified VM {vm_list_array[0]} does not exist on Prism Element {prism}...{PrintColors.RESET}")
                exit(1)

        if self.storage_containers_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for storage containers...{PrintColors.RESET}")
            storage_containers_details = prism_get_storage_containers(api_server=prism,username=user,secret=pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            for key,value in storage_containers_details[0]['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixStorageContainers_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['storage_container']))
            for key,value in storage_containers_details[0]['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixStorageContainers_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['storage_container']))

        if self.ipmi_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for IPMI adapters...{PrintColors.RESET}")
            key_strings = [
                "Nutanix_power_consumption_power_consumed_watts",
                "Nutanix_power_consumption_min_consumed_watts",
                "Nutanix_power_consumption_max_consumed_watts",
                "Nutanix_power_consumption_average_consumed_watts"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['node']))

        if self.prism_central_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for Prism Central...{PrintColors.RESET}")
            key_strings = [
                "Nutanix_count_vm",
                "Nutanix_count_vm_on",
                "Nutanix_count_vm_off",
                "Nutanix_count_vcpu",
                "Nutanix_count_vram_mib",
                "Nutanix_count_vdisk",
                "Nutanix_count_vdisk_ide",
                "Nutanix_count_vdisk_sata",
                "Nutanix_count_vdisk_scsi",
                "Nutanix_count_vnic",
                "Nutanix_count_category",
                "Nutanix_count_vm_protected",
                "Nutanix_count_vm_protected_compliant",
                "Nutanix_count_vm_protected_synced",
                "Nutanix_count_ngt_installed",
                "Nutanix_count_ngt_enabled"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['prism_central']))

        if self.ncm_ssp_metrics:        
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for NCM SSP...{PrintColors.RESET}")
            key_strings = [
                "Nutanix_ncm_count_applications",
                "Nutanix_ncm_count_applications_provisioning",
                "Nutanix_ncm_count_applications_running",
                "Nutanix_ncm_count_applications_error",
                "Nutanix_ncm_count_applications_deleting",
                "Nutanix_ncm_count_blueprints",
                "Nutanix_ncm_count_runbooks",
                "Nutanix_ncm_count_projects",
                "Nutanix_ncm_count_marketplace_items"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['ncm_ssp']))

    def run_metrics_loop(self):
        """Metrics fetching loop"""
        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Starting metrics loop {PrintColors.RESET}")
        while True:
            self.fetch()
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Waiting for {self.polling_interval_seconds} seconds...{PrintColors.RESET}")
            time.sleep(self.polling_interval_seconds)


    def fetch(self):
        """
        Get metrics from application and refresh Prometheus metrics with
        new values.
        """

        if self.cluster_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting clusters metrics{PrintColors.RESET}")
            cluster_uuid, cluster_details = prism_get_cluster(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            vm_details = prism_get_vms(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            hosts_details = prism_get_hosts(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            
            vms_powered_on = [vm for vm in vm_details if vm['power_state'] == "on"]
            
            for host in hosts_details:
                #populating values for host stats metrics
                for key, value in host['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixHosts_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(host=host['name']).set(value)
                for key, value in host['usage_stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixHosts_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(host=host['name']).set(value)
                #populating values for host count metrics
                host_vms_list = [vm for vm in vms_powered_on if vm['host_uuid'] == host['uuid']]
                key_string = "NutanixHosts_count_vm"
                self.__dict__[key_string].labels(host=host['name']).set(len(host_vms_list))
                key_string = "NutanixHosts_count_vcpu"
                self.__dict__[key_string].labels(host=host['name']).set(sum([(vm['num_vcpus'] * vm['num_cores_per_vcpu']) for vm in host_vms_list]))
                key_string = "NutanixHosts_count_vram_mib"
                self.__dict__[key_string].labels(host=host['name']).set(sum([vm['memory_mb'] for vm in host_vms_list]))
                key_string = "NutanixHosts_count_vdisk"
                self.__dict__[key_string].labels(host=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if vdisk['is_cdrom'] is False]) for vm in host_vms_list]))
                key_string = "NutanixHosts_count_vdisk_ide"
                self.__dict__[key_string].labels(host=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'ide')]) for vm in host_vms_list]))
                key_string = "NutanixHosts_count_vdisk_sata"
                self.__dict__[key_string].labels(host=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'sata')]) for vm in host_vms_list]))
                key_string = "NutanixHosts_count_vdisk_scsi"
                self.__dict__[key_string].labels(host=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'scsi')]) for vm in host_vms_list]))
                key_string = "NutanixHosts_count_vnic"
                self.__dict__[key_string].labels(host=host['name']).set(sum([len(vm['vm_nics']) for vm in host_vms_list]))

            #populating values for cluster stats metrics
            for key, value in cluster_details['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixClusters_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                self.__dict__[key_string].labels(cluster=cluster_details['name']).set(value)
            for key, value in cluster_details['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"NutanixClusters_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                self.__dict__[key_string].labels(cluster=cluster_details['name']).set(value)

            #populating values for cluster count metrics
            key_string = "NutanixClusters_count_vm"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(len(vm_details))
            key_string = "NutanixClusters_count_vm_on"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(len([vm for vm in vm_details if vm['power_state'] == "on"]))
            key_string = "NutanixClusters_count_vm_off"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(len([vm for vm in vm_details if vm['power_state'] == "off"]))
            key_string = "NutanixClusters_count_vcpu"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([(vm['num_vcpus'] * vm['num_cores_per_vcpu']) for vm in vm_details]))
            key_string = "NutanixClusters_count_vram_mib"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([vm['memory_mb'] for vm in vm_details]))
            key_string = "NutanixClusters_count_vdisk"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if vdisk['is_cdrom'] is False]) for vm in vm_details]))
            key_string = "NutanixClusters_count_vdisk_ide"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'ide')]) for vm in vm_details]))
            key_string = "NutanixClusters_count_vdisk_sata"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'sata')]) for vm in vm_details]))
            key_string = "NutanixClusters_count_vdisk_scsi"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'scsi')]) for vm in vm_details]))
            key_string = "NutanixClusters_count_vnic"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).set(sum([len(vm['vm_nics']) for vm in vm_details]))

            #populating values for other misc info based metrics
            #self.lts.labels(cluster=cluster_details['name']).state(str(cluster_details['is_lts']))
            key_string = "NutanixClusters_info"
            self.__dict__[key_string].labels(cluster=cluster_details['name']).info({
                'is_lts': str(cluster_details['is_lts']),
                'num_nodes': str(cluster_details['num_nodes']),
                'model_name': str(cluster_details['rackable_units'][0]['model_name']),
                'storage_type': str(cluster_details['storage_type']),
                'aos_version': str(cluster_details['version']),
                'is_nsenabled': str(cluster_details['is_nsenabled']),
                'encrypted': str(cluster_details['encrypted']),
                'timezone': str(cluster_details['timezone']),
                'operation_mode': str(cluster_details['operation_mode']),
                'enable_shadow_clones': str(cluster_details['enable_shadow_clones']),
                'rf': str(cluster_details['cluster_redundancy_state']['desired_redundancy_factor']),
                'enable_rebuild_reservation': str(cluster_details['enable_rebuild_reservation']),
                'fault_tolerance_domain_type': str(cluster_details['fault_tolerance_domain_type']),
                'data_in_transit_encryption_dto': str(cluster_details['data_in_transit_encryption_dto']['enabled'])
            })

        if self.vm_list:
            vm_list_array = self.vm_list.split(',')
            for vm in vm_list_array:
                print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting vm metrics for {vm}{PrintColors.RESET}")
                vm_details = prism_get_vm(vm_name=vm,api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
                for key, value in vm_details['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixVms_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(vm=vm_details['vmName']).set(value)
                for key, value in vm_details['usageStats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixVms_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(vm=vm_details['vmName']).set(value)

        if self.storage_containers_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting storage containers metrics{PrintColors.RESET}")
            storage_containers_details = prism_get_storage_containers(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            for container in storage_containers_details:
                for key, value in container['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixStorageContainers_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(storage_container=container['name']).set(value)
                for key, value in container['usage_stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"NutanixStorageContainers_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(storage_container=container['name']).set(value)

        if self.ipmi_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting IPMI metrics{PrintColors.RESET}")
            if not self.cluster_metrics:
                hosts_details = prism_get_hosts(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            for node in hosts_details:
                if self.ipmi_username is not None:
                    ipmi_username = self.ipmi_username
                else:
                    ipmi_username = 'ADMIN'
                if self.ipmi_secret is not None:
                    ipmi_secret = self.ipmi_secret
                else:
                    ipmi_secret = node['serial']

                node_name = node['name']
                node_name = node_name.replace(".","_")
                node_name = node_name.replace("-","_")

                power_control = ipmi_get_powercontrol(node['ipmi_address'],secret=ipmi_secret,username=ipmi_username,secure=self.prism_secure)
                key_string = "Nutanix_power_consumption_power_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerConsumedWatts'])
                key_string = "Nutanix_power_consumption_min_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerMetrics']['MinConsumedWatts'])
                key_string = "Nutanix_power_consumption_max_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerMetrics']['MaxConsumedWatts'])
                key_string = "Nutanix_power_consumption_average_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerMetrics']['AverageConsumedWatts'])

        if self.prism_central_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting Prism Central metrics{PrintColors.RESET}")

            if ipaddress.ip_address(self.prism):
                try:
                    prism_central_hostname = socket.gethostbyaddr(self.prism)[0]
                except:
                    prism_central_hostname = self.prism
            else:
                prism_central_hostname = self.prism

            length=500
            vm_details=[]
            
            vm_count = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='vm',
                entity_api_root='vms',
                secure=self.prism_secure
            )

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(
                    get_entities_batch,
                    api_server=self.prism,
                    username=self.user,
                    password=self.pwd,
                    entity_type='vm',
                    entity_api_root='vms',
                    offset= offset,
                    length=length
                    ) for offset in range(0, vm_count, length)]
                for future in as_completed(futures):
                    vms = future.result()
                    vm_details.extend(vms)

            key_string = "Nutanix_count_vm"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len(vm_details))
            key_string = "Nutanix_count_vm_on"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([vm for vm in vm_details if vm['status']['resources']['power_state'] == "ON"]))
            key_string = "Nutanix_count_vm_off"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([vm for vm in vm_details if vm['status']['resources']['power_state'] == "OFF"]))
            key_string = "Nutanix_count_vcpu"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([(vm['status']['resources']['num_sockets'] * vm['status']['resources']['num_threads_per_core']) for vm in vm_details]))
            key_string = "Nutanix_count_vram_mib"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([vm['status']['resources']['memory_size_mib'] for vm in vm_details]))
            key_string = "Nutanix_count_vdisk"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if vdisk['device_properties']['device_type'] == 'DISK']) for vm in vm_details]))
            key_string = "Nutanix_count_vdisk_ide"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if (vdisk['device_properties']['device_type'] == 'DISK') and (vdisk['device_properties']['disk_address']['adapter_type'] == 'IDE')]) for vm in vm_details]))
            key_string = "Nutanix_count_vdisk_sata"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if (vdisk['device_properties']['device_type'] == 'DISK') and (vdisk['device_properties']['disk_address']['adapter_type'] == 'SATA')]) for vm in vm_details]))
            key_string = "Nutanix_count_vdisk_scsi"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if (vdisk['device_properties']['device_type'] == 'DISK') and (vdisk['device_properties']['disk_address']['adapter_type'] == 'SCSI')]) for vm in vm_details]))
            key_string = "Nutanix_count_vnic"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vnic for vnic in vm['status']['resources']['nic_list']]) for vm in vm_details]))

            key_string = "Nutanix_count_category"

            key_string = "Nutanix_count_vm_protected"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([vm for vm in vm_details if vm['status']['resources']['protection_type'] == "RULE_PROTECTED"]))
            key_string = "Nutanix_count_vm_protected_synced"
            protected_vms_list = [vm for vm in vm_details if vm.get('status', {}).get('resources', {}).get('protection_policy_state') is not None]
            protected_vms_with_status_list = [vm for vm in protected_vms_list if vm.get('status', {}).get('resources', {}).get('protection_policy_state').get('policy_info').get('replication_status') is not None]
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([protected_vm for protected_vm in protected_vms_with_status_list if protected_vm['status']['resources']['protection_policy_state']['policy_info']['replication_status'] == "SYNCED"]))
            key_string = "Nutanix_count_vm_protected_compliant"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([protected_vm for protected_vm in protected_vms_list if protected_vm['status']['resources']['protection_policy_state']['compliance_status'] == "COMPLIANT"]))

            ngt_vms_list = [vm for vm in vm_details if vm.get('status', {}).get('resources', {}).get('guest_tools') is not None]
            key_string = "Nutanix_count_ngt_installed"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([ngt_vm for ngt_vm in ngt_vms_list if ngt_vm['status']['resources']['guest_tools']['nutanix_guest_tools']['ngt_state'] == "INSTALLED"]))
            key_string = "Nutanix_count_ngt_enabled"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([ngt_vm for ngt_vm in ngt_vms_list if ngt_vm['status']['resources']['guest_tools']['nutanix_guest_tools']['is_reachable'] is True]))

        if self.ncm_ssp_metrics:
            #print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP metrics{PrintColors.RESET}")

            if ipaddress.ip_address(self.prism):
                try:
                    ncm_ssp_hostname = socket.gethostbyaddr(self.prism)[0]
                except:
                    ncm_ssp_hostname = self.prism
            else:
                ncm_ssp_hostname = self.prism

            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP apps metrics{PrintColors.RESET}")        
            ncm_applications = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='app',
                entity_api_root='apps',
                fiql_filter="_state==running,_state==deleting,_state==error,_state==provisioning;(name!=Infrastructure;name!=Self%20Service)",
                secure=self.prism_secure
            )

            ncm_applications_running = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='app',
                entity_api_root='apps',
                fiql_filter="_state==running;(name!=Infrastructure;name!=Self%20Service)",
                secure=self.prism_secure
            )
            
            ncm_applications_provisioning = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='app',
                entity_api_root='apps',
                fiql_filter="_state==provisioning;(name!=Infrastructure;name!=Self%20Service)",
                secure=self.prism_secure
            )
            
            ncm_applications_error = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='app',
                entity_api_root='apps',
                fiql_filter="_state==error;(name!=Infrastructure;name!=Self%20Service)",
                secure=self.prism_secure
            )
            
            ncm_applications_deleting = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='app',
                entity_api_root='apps',
                fiql_filter="_state==deleting;(name!=Infrastructure;name!=Self%20Service)",
                secure=self.prism_secure
            )
            
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP projects metrics{PrintColors.RESET}")
            ncm_projects_details = prism_get_entities(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,
                                                      entity_type="project",entity_api_root="projects",
                                                      api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP marketplace metrics{PrintColors.RESET}")
            ncm_marketplace_items_details = prism_get_entities(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,
                                                      entity_type="marketplace_item",entity_api_root="marketplace_items",
                                                      api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP blueprints metrics{PrintColors.RESET}")
            ncm_blueprints_details = prism_get_entities(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,
                                                      entity_type="blueprint",entity_api_root="blueprints",
                                                      api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP runbooks metrics{PrintColors.RESET}")
            ncm_runbooks_details = prism_get_entities(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,
                                                      entity_type="runbook",entity_api_root="runbooks",
                                                      api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)

            key_string = "Nutanix_ncm_count_applications"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications)
            key_string = "Nutanix_ncm_count_applications_provisioning"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_provisioning)
            key_string = "Nutanix_ncm_count_applications_running"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_running)
            key_string = "Nutanix_ncm_count_applications_error"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_error)
            key_string = "Nutanix_ncm_count_applications_deleting"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_deleting)
            key_string = "Nutanix_ncm_count_blueprints"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(len(ncm_blueprints_details))
            key_string = "Nutanix_ncm_count_runbooks"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(len(ncm_runbooks_details))
            key_string = "Nutanix_ncm_count_marketplace_items"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(len(ncm_marketplace_items_details))
            key_string = "Nutanix_ncm_count_projects"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(len(ncm_projects_details))
#endregion #*CLASS


#region #*FUNCTIONS
def process_request(url, method, user, password, headers, api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15, payload=None, secure=False):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    #configuring web request behavior
    timeout = api_requests_timeout_seconds
    retries = api_requests_retries
    sleep_between_retries = api_sleep_seconds_between_retries

    while retries > 0:
        try:

            if method == 'GET':
                #print("secure is {}".format(secure))
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.HTTPError as error_code:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Http Error! Status code: {response.status_code}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {response.reason}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {response.text}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {response.elapsed}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {response.headers}{PrintColors.RESET}")
            if payload is not None:
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            if retries == 1:
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                exit(1)
            else:
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                time.sleep(sleep_between_retries)
                retries -= 1
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Retries left: {retries}{PrintColors.RESET}")
                continue
        except requests.exceptions.Timeout as error_code:
            if retries == 1:
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                exit(1)
            else:
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                time.sleep(sleep_between_retries)
                retries -= 1
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Retries left: {retries}{PrintColors.RESET}")
                continue
        except requests.exceptions.RequestException as error_code:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.status_code} {PrintColors.RESET}")
            exit(response.status_code)
        break

    if response.ok:
        return response
    if response.status_code == 401:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.status_code} {response.reason} {PrintColors.RESET}")
        exit(response.status_code)
    elif response.status_code == 500:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.status_code} {response.reason} {response.text} {PrintColors.RESET}")
        exit(response.status_code)
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] Request failed! Status code: {response.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] reason: {response.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] text: {response.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] raise_for_status: {response.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] elapsed: {response.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] headers: {response.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)


def prism_get_cluster(api_server,username,secret,api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /clusters.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Cluster uuid as cluster_uuid. Cluster details as cluster_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/clusters/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion

    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
    resp = process_request(url,method,username,secret,headers,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        cluster_uuid = json_resp['entities'][0]['uuid']
        cluster_details = json_resp['entities'][0]
        return cluster_uuid, cluster_details
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        raise


def prism_get_vm(vm_name,api_server,username,secret,api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /vms using a vm name as a filter criteria.

    Args:
        vm_name: The VM name to search for.
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        VM details as vm_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = f"/PrismGateway/services/rest/v1/vms/?filterCriteria=vm_name%3D%3D{vm_name}"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
    resp = process_request(url,method,username,secret,headers,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        vm_details = json_resp['entities']
        if len(vm_details) > 0:
            return vm_details[0]
        else:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] Specified VM {vm_name} does not exist on Prism Element {api_server}...{PrintColors.RESET}")
            exit(1)
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        raise


def prism_get_storage_containers(api_server,username,secret,api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /storage_containers.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Storage containers details as storage_containers_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/storage_containers/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
    resp = process_request(url,method,username,secret,headers,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        storage_containers_details = json_resp['entities']
        return storage_containers_details
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        raise


def prism_get_hosts(api_server,username,secret,api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /hosts.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Hosts details as hosts_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/hosts/"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
    resp = process_request(url,method,username,secret,headers,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        hosts_details = json_resp['entities']
        return hosts_details
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        raise
    

def prism_get_vms(api_server,username,secret,api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /hosts.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Hosts details as vms_details
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true&include_vm_nic_config=true"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
    resp = process_request(url,method,username,secret,headers,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        vms_details = json_resp['entities']
        return vms_details
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        raise


def ipmi_get_powercontrol(api_server,secret,username='ADMIN',api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the IPMI RedFisk REST API endpoint /PowerControl.

    Args:
        api_server: The IP or FQDN of the IPMI.
        username: The IPMI user name (defaults to ADMIN).
        secret: The IPMI user name password.
        
    Returns:
        PowerControl metrics object as power_control
    """
    
    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_endpoint = "/redfish/v1/Chassis/1/Power"
    url = "https://{}{}".format(
        api_server,
        api_server_endpoint
    )
    method = "GET"
    #endregion
    
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
    resp = process_request(url,method,username,secret,headers,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        power_control = json_resp['PowerControl'][0]
        return power_control
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        raise


def prism_get_entities(api_server,secret,
                       entity_type,entity_api_root,length = 250,
                       username='ADMIN',secure=False,
                       print_f=True,filter=None,
                       api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15):

    """Retrieve the list of entities from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object (exp: project)
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        An array of entities (entities part of the json response).
    """

    entities = []
    #region prepare the api call
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/{}/list".format(entity_api_root)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"

    # Compose the json payload
    payload = {
        "kind": entity_type,
        "offset": 0,
        "length": length
    }
    if filter:
        payload["filter"] = filter
    #endregion
    
    while True:
        if print_f:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure}{PrintColors.RESET}")
        resp = process_request(url,method,user=username,password=secret,headers=headers,payload=payload,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)
        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            #json_resp = resp
            entities.extend(json_resp['entities'])
            key = 'length'
            if key in json_resp['metadata']:
                if json_resp['metadata']['length'] == length:
                    if print_f:
                        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Processing results from {json_resp['metadata']['offset']} to {json_resp['metadata']['length']+json_resp['metadata']['offset']} out of {json_resp['metadata']['total_matches']}{PrintColors.RESET}")
                    payload = {
                        "kind": entity_type,
                        "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'],
                        "length": length
                    }
                else:
                    if print_f:
                        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Processing results from {json_resp['metadata']['offset']} to {json_resp['metadata']['length']+json_resp['metadata']['offset']} out of {json_resp['metadata']['total_matches']}{PrintColors.RESET}")
                    return entities
            else:
                return entities
        else:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
            if payload is not None:
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise


def prism_get_apps(api_server,secret,
                       username='ADMIN',secure=False,
                       print_f=True,filter=None,
                       api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15):

    """Retrieve the list of apps from Prism Central/NCM.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        json response from groups endpoint.
    """

    #region prepare the api call
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/dm/v3/groups"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"

    # Compose the json payload
    payload = {
        "fields":[
            "app_name","project_name","state","created_on","updated_on"
        ]
    }
    if filter:
        payload["filter"] = filter
    #endregion
    
    
    if print_f:
        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Making a {method} API call to {url} with secure set to {secure} to retrieve NCM Apps with the following filter: {filter}{PrintColors.RESET}")
    resp = process_request(url,method,user=username,password=secret,headers=headers,payload=payload,secure=secure,api_requests_timeout_seconds=api_requests_timeout_seconds, api_requests_retries=api_requests_retries, api_sleep_seconds_between_retries=api_sleep_seconds_between_retries)
    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        return json_resp
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        if payload is not None:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def get_total_entities(api_server, username, password, entity_type, entity_api_root, fiql_filter=None, secure=False):

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
    if fiql_filter:
        payload["filter"] = fiql_filter

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


def get_entities_batch(api_server, username, password, offset, entity_type, entity_api_root, length=100, fiql_filter=None, secure=False):

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
    if fiql_filter:
        payload["filter"] = fiql_filter
    
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


def main():
    """Main entry point"""

    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Getting environment variables...{PrintColors.RESET}")
    polling_interval_seconds = int(os.getenv("POLLING_INTERVAL_SECONDS", "30"))
    api_requests_timeout_seconds = int(os.getenv("API_REQUESTS_TIMEOUT_SECONDS", "30"))
    api_requests_retries = int(os.getenv("API_REQUESTS_RETRIES", "5"))
    api_sleep_seconds_between_retries = int(os.getenv("API_SLEEP_SECONDS_BETWEEN_RETRIES", "15"))
    app_port = int(os.getenv("APP_PORT", "9440"))
    exporter_port = int(os.getenv("EXPORTER_PORT", "8000"))
    
    cluster_metrics_env = os.getenv('CLUSTER_METRICS',default='True')
    if cluster_metrics_env is not None:
        cluster_metrics = cluster_metrics_env.lower() in ("true", "1", "t", "y", "yes")
    else:
        cluster_metrics = False
    
    storage_containers_metrics_env = os.getenv('STORAGE_CONTAINERS_METRICS',default='True')
    if storage_containers_metrics_env is not None:
        storage_containers_metrics = storage_containers_metrics_env.lower() in ("true", "1", "t", "y", "yes")
    else:
        storage_containers_metrics = False
    
    ipmi_metrics_env = os.getenv('IPMI_METRICS',default='True')
    if ipmi_metrics_env is not None:
        ipmi_metrics = ipmi_metrics_env.lower() in ("true", "1", "t", "y", "yes")
    else:
        ipmi_metrics = False
    
    prism_central_metrics_env = os.getenv('PRISM_CENTRAL_METRICS',default='False')
    if prism_central_metrics_env is not None:
        prism_central_metrics = prism_central_metrics_env.lower() in ("true", "1", "t", "y", "yes")
    else:
        prism_central_metrics = False
    
    ncm_ssp_metrics_env = os.getenv('NCM_SSP_METRICS',default='False')
    if ncm_ssp_metrics_env is not None:
        ncm_ssp_metrics = ncm_ssp_metrics_env.lower() in ("true", "1", "t", "y", "yes")
    else:
        ncm_ssp_metrics = False
        
    prism_secure_env = os.getenv('PRISM_SECURE',default='False')
    if prism_secure_env is not None:
        prism_secure = prism_secure_env.lower() in ("true", "1", "t", "y", "yes")
        if prism_secure is False:
            #! suppress warnings about insecure connections
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        prism_secure = False
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Initializing metrics class...{PrintColors.RESET}")
    nutanix_metrics = NutanixMetrics(
        app_port=app_port,
        polling_interval_seconds=polling_interval_seconds,
        api_requests_timeout_seconds=api_requests_timeout_seconds,
        api_requests_retries=api_requests_retries,
        api_sleep_seconds_between_retries=api_sleep_seconds_between_retries,
        prism=os.getenv('PRISM'),
        user = os.getenv('PRISM_USERNAME'),
        pwd = os.getenv('PRISM_SECRET'),
        prism_secure=prism_secure,
        ipmi_username = os.getenv('IPMI_USERNAME', default='ADMIN'),
        ipmi_secret = os.getenv('IPMI_SECRET', default=None),
        vm_list=os.getenv('VM_LIST'),
        cluster_metrics=cluster_metrics,
        storage_containers_metrics=storage_containers_metrics,
        ipmi_metrics=ipmi_metrics,
        prism_central_metrics=prism_central_metrics,
        ncm_ssp_metrics=ncm_ssp_metrics
    )
    
    print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Starting http server on port {exporter_port}{PrintColors.RESET}")
    start_http_server(exporter_port)
    nutanix_metrics.run_metrics_loop()
#endregion #*FUNCTIONS


if __name__ == "__main__":
    main()