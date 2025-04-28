""" extracts metrics from Nutanix API and publishes them in 
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
import traceback
import json
import time
import re
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
        pass


class NutanixMetricsLegacy:
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
                key_string = f"nutanix_host_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['host']))
            for key,value in hosts_details[0]['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_host_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['host']))

            #creating cluster stats metrics
            for key,value in cluster_details['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_cluster_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))
            for key,value in cluster_details['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_cluster_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['cluster']))

            #creating cluster counts metrics
            key_strings = [
                "nutanix_count_vg",
                "nutanix_count_vm",
                "nutanix_count_vm_on",
                "nutanix_count_vm_off",
                "nutanix_count_vcpu",
                "nutanix_count_vram_mib",
                "nutanix_count_vdisk",
                "nutanix_count_vdisk_ide",
                "nutanix_count_vdisk_sata",
                "nutanix_count_vdisk_scsi",
                "nutanix_count_vnic"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['entity']))

            #other misc info based metrics
            setattr(self, 'nutanix_cluster', Info('nutanix_cluster', 'Misc cluster information'))

        if self.vm_list:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for virtual machines...{PrintColors.RESET}")
            vm_list_array = self.vm_list.split(',')
            vm_details = prism_get_vm(vm_name=vm_list_array[0],api_server=prism,username=user,secret=pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            if len(vm_details) > 0:
                for key,value in vm_details['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_vms_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    setattr(self, key_string, Gauge(key_string, key_string, ['vm']))
                for key,value in vm_details['usageStats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_vms_usage_stats_{key}"
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
                key_string = f"nutanix_storage_container_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['storage_container']))
            for key,value in storage_containers_details[0]['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_storage_container_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                setattr(self, key_string, Gauge(key_string, key_string, ['storage_container']))

        if self.ipmi_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for IPMI adapters...{PrintColors.RESET}")
            key_strings = [
                "nutanix_power_consumption_power_consumed_watts",
                "nutanix_power_consumption_min_consumed_watts",
                "nutanix_power_consumption_max_consumed_watts",
                "nutanix_power_consumption_average_consumed_watts",
                "nutanix_thermal_cpu_temp_celsius",
                "nutanix_thermal_pch_temp_celcius",
                "nutanix_thermal_system_temp_celcius",
                "nutanix_thermal_peripheral_temp_celcius",
                "nutanix_thermal_inlet_temp_celcius",
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['node']))

        if self.prism_central_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for Prism Central...{PrintColors.RESET}")
            key_strings = [
                "nutanix_count_vg",
                "nutanix_count_vm",
                "nutanix_count_vm_on",
                "nutanix_count_vm_off",
                "nutanix_count_vcpu",
                "nutanix_count_vram_mib",
                "nutanix_count_vdisk",
                "nutanix_count_vdisk_ide",
                "nutanix_count_vdisk_sata",
                "nutanix_count_vdisk_scsi",
                "nutanix_count_vnic",
                "nutanix_count_category",
                "nutanix_count_vm_protected",
                "nutanix_count_vm_protected_compliant",
                "nutanix_count_vm_protected_synced",
                "nutanix_count_ngt_installed",
                "nutanix_count_ngt_enabled"
            ]
            for key_string in key_strings:
                setattr(self, key_string, Gauge(key_string, key_string, ['prism_central']))

        if self.ncm_ssp_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for NCM SSP...{PrintColors.RESET}")
            key_strings = [
                "nutanix_ncm_count_applications",
                "nutanix_ncm_count_applications_provisioning",
                "nutanix_ncm_count_applications_running",
                "nutanix_ncm_count_applications_error",
                "nutanix_ncm_count_applications_deleting",
                "nutanix_ncm_count_blueprints",
                "nutanix_ncm_count_runbooks",
                "nutanix_ncm_count_projects",
                "nutanix_ncm_count_marketplace_items"
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
            vg_details = prism_get_volume_groups(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            
            vms_powered_on = [vm for vm in vm_details if vm['power_state'] == "on"]

            for host in hosts_details:
                #populating values for host stats metrics
                for key, value in host['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_host_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(host=host['name']).set(value)
                for key, value in host['usage_stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_host_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(host=host['name']).set(value)
                #populating values for host count metrics
                host_vms_list = [vm for vm in vms_powered_on if vm['host_uuid'] == host['uuid']]
                key_string = "nutanix_count_vm"
                self.__dict__[key_string].labels(entity=host['name']).set(len(host_vms_list))
                key_string = "nutanix_count_vcpu"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([(vm['num_vcpus'] * vm['num_cores_per_vcpu']) for vm in host_vms_list]))
                key_string = "nutanix_count_vram_mib"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([vm['memory_mb'] for vm in host_vms_list]))
                key_string = "nutanix_count_vdisk"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if vdisk['is_cdrom'] is False]) for vm in host_vms_list]))
                key_string = "nutanix_count_vdisk_ide"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'ide')]) for vm in host_vms_list]))
                key_string = "nutanix_count_vdisk_sata"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'sata')]) for vm in host_vms_list]))
                key_string = "nutanix_count_vdisk_scsi"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'scsi')]) for vm in host_vms_list]))
                key_string = "nutanix_count_vnic"
                self.__dict__[key_string].labels(entity=host['name']).set(sum([len(vm['vm_nics']) for vm in host_vms_list]))

            #populating values for cluster stats metrics
            for key, value in cluster_details['stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_cluster_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                self.__dict__[key_string].labels(cluster=cluster_details['name']).set(value)
            for key, value in cluster_details['usage_stats'].items():
                #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                key_string = f"nutanix_cluster_usage_stats_{key}"
                key_string = key_string.replace(".","_")
                key_string = key_string.replace("-","_")
                self.__dict__[key_string].labels(cluster=cluster_details['name']).set(value)

            #populating values for cluster count metrics
            key_string = "nutanix_count_vg"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(len(vg_details))
            key_string = "nutanix_count_vm"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(len(vm_details))
            key_string = "nutanix_count_vm_on"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(len([vm for vm in vm_details if vm['power_state'] == "on"]))
            key_string = "nutanix_count_vm_off"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(len([vm for vm in vm_details if vm['power_state'] == "off"]))
            key_string = "nutanix_count_vcpu"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([(vm['num_vcpus'] * vm['num_cores_per_vcpu']) for vm in vm_details]))
            key_string = "nutanix_count_vram_mib"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([vm['memory_mb'] for vm in vm_details]))
            key_string = "nutanix_count_vdisk"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if vdisk['is_cdrom'] is False]) for vm in vm_details]))
            key_string = "nutanix_count_vdisk_ide"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'ide')]) for vm in vm_details]))
            key_string = "nutanix_count_vdisk_sata"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'sata')]) for vm in vm_details]))
            key_string = "nutanix_count_vdisk_scsi"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([len([vdisk for vdisk in vm['vm_disk_info'] if (vdisk['is_cdrom'] is False) and (vdisk['disk_address']['device_bus'] == 'scsi')]) for vm in vm_details]))
            key_string = "nutanix_count_vnic"
            self.__dict__[key_string].labels(entity=cluster_details['name']).set(sum([len(vm['vm_nics']) for vm in vm_details]))

            #populating values for other misc info based metrics
            #self.lts.labels(cluster=cluster_details['name']).state(str(cluster_details['is_lts']))
            key_string = "nutanix_cluster"
            labels = {
                'entity': cluster_details['name'],
                'is_lts': str(cluster_details['is_lts']),
                'num_nodes': str(cluster_details['num_nodes']),
                'model_name': str(cluster_details['rackable_units'][0]['model_name']),
                'storage_type': str(cluster_details['storage_type']),
                'version': str(cluster_details['version']),
                'is_nsenabled': str(cluster_details['is_nsenabled']),
                'encrypted': str(cluster_details['encrypted']),
                'timezone': str(cluster_details['timezone']),
                'operation_mode': str(cluster_details['operation_mode']),
                'enable_shadow_clones': str(cluster_details['enable_shadow_clones']),
                'desired_redundancy_factor': str(cluster_details['cluster_redundancy_state']['desired_redundancy_factor']),
                'enable_rebuild_reservation': str(cluster_details['enable_rebuild_reservation']),
                'fault_tolerance_domain_type': str(cluster_details['fault_tolerance_domain_type']),
                'data_in_transit_encryption_dto': str(cluster_details['data_in_transit_encryption_dto']['enabled'])
            }
            self.__dict__[key_string].info(labels)

        if self.vm_list:
            vm_list_array = self.vm_list.split(',')
            for vm in vm_list_array:
                print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting vm metrics for {vm}{PrintColors.RESET}")
                vm_details = prism_get_vm(vm_name=vm,api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
                for key, value in vm_details['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_vms_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(vm=vm_details['vmName']).set(value)
                for key, value in vm_details['usageStats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_vms_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(vm=vm_details['vmName']).set(value)

        if self.storage_containers_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting storage containers metrics{PrintColors.RESET}")
            storage_containers_details = prism_get_storage_containers(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            for container in storage_containers_details:
                for key, value in container['stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_storage_container_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(storage_container=container['name']).set(value)
                for key, value in container['usage_stats'].items():
                    #making sure we are compliant with the data model (https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
                    key_string = f"nutanix_storage_container_usage_stats_{key}"
                    key_string = key_string.replace(".","_")
                    key_string = key_string.replace("-","_")
                    self.__dict__[key_string].labels(storage_container=container['name']).set(value)

        if self.ipmi_metrics:
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting IPMI metrics{PrintColors.RESET}")
            if not self.cluster_metrics:
                hosts_details = prism_get_hosts(api_server=self.prism,username=self.user,secret=self.pwd,secure=self.prism_secure,api_requests_timeout_seconds=self.api_requests_timeout_seconds, api_requests_retries=self.api_requests_retries, api_sleep_seconds_between_retries=self.api_sleep_seconds_between_retries)
            for node in hosts_details:
                #* figuring out management module creds
                if self.ipmi_username is not None:
                    ipmi_username = self.ipmi_username
                else:
                    ipmi_username = 'ADMIN'
                if self.ipmi_secret is not None and self.ipmi_secret != 'null':
                    ipmi_secret = self.ipmi_secret
                else:
                    ipmi_secret = node['serial']

                #* getting node name for labels
                node_name = node['name']
                node_name = node_name.replace(".","_")
                node_name = node_name.replace("-","_")

                #* collection power consumption metrics
                power_control = ipmi_get_powercontrol(node['ipmi_address'],secret=ipmi_secret,username=ipmi_username,secure=self.prism_secure)
                key_string = "nutanix_power_consumption_power_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerConsumedWatts'])
                key_string = "nutanix_power_consumption_min_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerMetrics']['MinConsumedWatts'])
                key_string = "nutanix_power_consumption_max_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerMetrics']['MaxConsumedWatts'])
                key_string = "nutanix_power_consumption_average_consumed_watts"
                self.__dict__[key_string].labels(node=node_name).set(power_control['PowerMetrics']['AverageConsumedWatts'])

                #* collection thermal metrics
                thermal = ipmi_get_thermal(node['ipmi_address'],secret=ipmi_secret,username=ipmi_username,secure=self.prism_secure)
                cpu_temps = []
                for temperature in thermal:
                    if re.match(r"CPU\d+ Temp", temperature['Name']) and temperature['ReadingCelsius']:
                        #key_string = "nutanix_thermal_cpu_temp_celsius"
                        #self.__dict__[key_string].labels(node=node_name).set(temperature['ReadingCelsius'])
                        cpu_temps.append(float(temperature['ReadingCelsius']))
                    elif temperature['Name'] == 'PCH Temp' and temperature['ReadingCelsius']:
                        key_string = "nutanix_thermal_pch_temp_celcius"
                        self.__dict__[key_string].labels(node=node_name).set(temperature['ReadingCelsius'])
                    elif temperature['Name'] == 'System Temp' and temperature['ReadingCelsius']:
                        key_string = "nutanix_thermal_system_temp_celcius"
                        self.__dict__[key_string].labels(node=node_name).set(temperature['ReadingCelsius'])
                    elif temperature['Name'] == 'Peripheral Temp' and temperature['ReadingCelsius']:
                        key_string = "nutanix_thermal_peripheral_temp_celcius"
                        self.__dict__[key_string].labels(node=node_name).set(temperature['ReadingCelsius'])
                    elif temperature['Name'] == 'Inlet Temp' and temperature['ReadingCelsius']:
                        key_string = "nutanix_thermal_inlet_temp_celcius"
                        self.__dict__[key_string].labels(node=node_name).set(temperature['ReadingCelsius'])
                if cpu_temps:
                    cpu_temp = sum(cpu_temps) / len(cpu_temps)
                    key_string = "nutanix_thermal_cpu_temp_celsius"
                    self.__dict__[key_string].labels(node=node_name).set(cpu_temp)

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
            
            vg_count = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='volume_group',
                entity_api_root='volume_groups',
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

            #* volume groups metrics
            key_string = "nutanix_count_vg"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(vg_count)
            
            #* general vm count metrics
            key_string = "nutanix_count_vm"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len(vm_details))
            key_string = "nutanix_count_vm_on"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([vm for vm in vm_details if vm['status']['resources']['power_state'] == "ON"]))
            key_string = "nutanix_count_vm_off"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([vm for vm in vm_details if vm['status']['resources']['power_state'] == "OFF"]))
            key_string = "nutanix_count_vcpu"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([(vm['status']['resources']['num_sockets'] * vm['status']['resources']['num_threads_per_core']) for vm in vm_details]))
            key_string = "nutanix_count_vram_mib"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([vm['status']['resources']['memory_size_mib'] for vm in vm_details]))
            key_string = "nutanix_count_vdisk"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if vdisk['device_properties']['device_type'] == 'DISK']) for vm in vm_details]))
            key_string = "nutanix_count_vdisk_ide"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if (vdisk['device_properties']['device_type'] == 'DISK') and (vdisk['device_properties']['disk_address']['adapter_type'] == 'IDE')]) for vm in vm_details]))
            key_string = "nutanix_count_vdisk_sata"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if (vdisk['device_properties']['device_type'] == 'DISK') and (vdisk['device_properties']['disk_address']['adapter_type'] == 'SATA')]) for vm in vm_details]))
            key_string = "nutanix_count_vdisk_scsi"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vdisk for vdisk in vm['status']['resources']['disk_list'] if (vdisk['device_properties']['device_type'] == 'DISK') and (vdisk['device_properties']['disk_address']['adapter_type'] == 'SCSI')]) for vm in vm_details]))
            key_string = "nutanix_count_vnic"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(sum([len([vnic for vnic in vm['status']['resources']['nic_list']]) for vm in vm_details]))

            #* categories count metrics
            #todo: keep count of entities for each category
            key_string = "nutanix_count_category"

            #* DR protected vm count metrics
            key_string = "nutanix_count_vm_protected"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([vm for vm in vm_details if vm['status']['resources']['protection_type'] == "RULE_PROTECTED"]))
            key_string = "nutanix_count_vm_protected_synced"
            protected_vms_list = [vm for vm in vm_details if vm.get('status', {}).get('resources', {}).get('protection_policy_state') is not None]
            protected_vms_with_status_list = [vm for vm in protected_vms_list if vm.get('status', {}).get('resources', {}).get('protection_policy_state').get('policy_info').get('replication_status') is not None]
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([protected_vm for protected_vm in protected_vms_with_status_list if protected_vm['status']['resources']['protection_policy_state']['policy_info']['replication_status'] == "SYNCED"]))
            key_string = "nutanix_count_vm_protected_compliant"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([protected_vm for protected_vm in protected_vms_list if protected_vm['status']['resources']['protection_policy_state']['compliance_status'] == "COMPLIANT"]))

            #* NGT vm count metrics
            ngt_vms_list = [vm for vm in vm_details if vm.get('status', {}).get('resources', {}).get('guest_tools') is not None]
            key_string = "nutanix_count_ngt_installed"
            self.__dict__[key_string].labels(prism_central=prism_central_hostname).set(len([ngt_vm for ngt_vm in ngt_vms_list if ngt_vm['status']['resources']['guest_tools']['nutanix_guest_tools']['ngt_state'] == "INSTALLED"]))
            key_string = "nutanix_count_ngt_enabled"
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
                fiql_filter="(name!=Infrastructure;name!=Self%20Service);_state==running,_state==deleting,_state==error,_state==provisioning",
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
            ncm_projects_count = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='project',
                entity_api_root='projects',
                secure=self.prism_secure
            )
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP marketplace metrics{PrintColors.RESET}")
            ncm_marketplace_items_count = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='marketplace_item',
                entity_api_root='marketplace_items',
                secure=self.prism_secure
            )
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP blueprints metrics{PrintColors.RESET}")
            ncm_blueprints_count = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='blueprint',
                entity_api_root='blueprints',
                secure=self.prism_secure
            )
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting NCM SSP runbooks metrics{PrintColors.RESET}")
            ncm_runbooks_count = get_total_entities(
                api_server=self.prism,
                username=self.user,
                password=self.pwd,
                entity_type='runbook',
                entity_api_root='runbooks',
                secure=self.prism_secure
            )

            key_string = "nutanix_ncm_count_applications"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications)
            key_string = "nutanix_ncm_count_applications_provisioning"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_provisioning)
            key_string = "nutanix_ncm_count_applications_running"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_running)
            key_string = "nutanix_ncm_count_applications_error"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_error)
            key_string = "nutanix_ncm_count_applications_deleting"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_applications_deleting)
            key_string = "nutanix_ncm_count_blueprints"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_blueprints_count)
            key_string = "nutanix_ncm_count_runbooks"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_runbooks_count)
            key_string = "nutanix_ncm_count_marketplace_items"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_marketplace_items_count)
            key_string = "nutanix_ncm_count_projects"
            self.__dict__[key_string].labels(ncm_ssp=ncm_ssp_hostname).set(ncm_projects_count)


class NutanixMetricsRedfish:
    """
    Representation of Prometheus metrics and loop to fetch and transform
    application metrics into Prometheus metrics.
    """
    def __init__(self,
                 ipmi_config,
                 polling_interval_seconds=30, api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,
                 ipmi_secure=False,
                 ):
        self.ipmi_config = ipmi_config
        self.polling_interval_seconds = polling_interval_seconds
        self.api_requests_timeout_seconds = api_requests_timeout_seconds
        self.api_requests_retries = api_requests_retries
        self.api_sleep_seconds_between_retries = api_sleep_seconds_between_retries
        self.ipmi_secure = ipmi_secure

        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [INFO] Initializing metrics for IPMI adapters...{PrintColors.RESET}")
        key_strings = [
            "nutanix_power_consumption_power_consumed_watts",
            "nutanix_power_consumption_min_consumed_watts",
            "nutanix_power_consumption_max_consumed_watts",
            "nutanix_power_consumption_average_consumed_watts",
            "nutanix_thermal_cpu_temp_celsius",
            "nutanix_thermal_pch_temp_celcius",
            "nutanix_thermal_system_temp_celcius",
            "nutanix_thermal_peripheral_temp_celcius",
            "nutanix_thermal_inlet_temp_celcius",
        ]
        for key_string in key_strings:
            setattr(self, key_string, Gauge(key_string, key_string, ['ipmi']))


    def run_metrics_loop(self):
        """Metrics fetching loop"""
        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Starting metrics loop {PrintColors.RESET}")
        while True:
            self.fetch()
            print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Waiting for {self.polling_interval_seconds} seconds...{PrintColors.RESET}")
            time.sleep(self.polling_interval_seconds)


    def process_redfish_entity(self,ipmi_entity):
        """Retrieves metrics from a single IPMI entity and updates Prometheus metrics."""
        ipmi = ipmi_entity['ip']
        ipmi_name = ipmi_entity['name']
        ipmi_username = ipmi_entity['username']
        ipmi_secret = ipmi_entity['password']


        #* collection power consumption metrics
        power_control = ipmi_get_powercontrol(ipmi,secret=ipmi_secret,username=ipmi_username,secure=self.ipmi_secure)
        key_string = "nutanix_power_consumption_power_consumed_watts"
        power = float(power_control.get('PowerConsumedWatts', 0))
        self.__dict__[key_string].labels(ipmi=ipmi_name).set(power)
        
        key_string = "nutanix_power_consumption_min_consumed_watts"
        power = float(power_control.get('PowerMetrics', {}).get('MinConsumedWatts', 0))
        self.__dict__[key_string].labels(ipmi=ipmi_name).set(power_control['PowerMetrics']['MinConsumedWatts'])
        
        key_string = "nutanix_power_consumption_max_consumed_watts"
        power = float(power_control.get('PowerMetrics', {}).get('MaxConsumedWatts', 0))
        self.__dict__[key_string].labels(ipmi=ipmi_name).set(power_control['PowerMetrics']['MaxConsumedWatts'])
        
        key_string = "nutanix_power_consumption_average_consumed_watts"
        power = float(power_control.get('PowerMetrics', {}).get('AverageConsumedWatts', 0))
        self.__dict__[key_string].labels(ipmi=ipmi_name).set(power_control['PowerMetrics']['AverageConsumedWatts'])


        #* collection thermal metrics
        thermal = ipmi_get_thermal(ipmi,secret=ipmi_secret,username=ipmi_username,secure=self.ipmi_secure)
        cpu_temps = []
        for temperature in thermal:
            #print(f"{ipmi_entity['name']}: {type(temperature['Name'])}: {type(temperature['ReadingCelsius'])}")
            if temperature['ReadingCelsius'] is None:
                temp = 0
            else:
                try:
                    temp = float(temperature.get('ReadingCelsius', 0))
                except TypeError as e:
                    print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] TypeError: {e} for {ipmi_entity['name']} when retrieving {temperature['ReadingCelsius']} for {temperature['Name']}. Setting value to 0. {PrintColors.RESET}")
                    temp = 0
            if re.match(r"CPU\d+ Temp", temperature['Name']):
                cpu_temps.append(temp)
            elif temperature['Name'] == 'PCH Temp':
                key_string = "nutanix_thermal_pch_temp_celcius"
                self.__dict__[key_string].labels(ipmi=ipmi_name).set(temp)
            elif temperature['Name'] == 'System Temp':
                key_string = "nutanix_thermal_system_temp_celcius"
                self.__dict__[key_string].labels(ipmi=ipmi_name).set(temp)
            elif temperature['Name'] == 'Peripheral Temp':
                key_string = "nutanix_thermal_peripheral_temp_celcius"
                self.__dict__[key_string].labels(ipmi=ipmi_name).set(temp)
            elif temperature['Name'] == 'Inlet Temp':
                key_string = "nutanix_thermal_inlet_temp_celcius"
                self.__dict__[key_string].labels(ipmi=ipmi_name).set(temp)
        if cpu_temps:
            cpu_temp = sum(cpu_temps) / len(cpu_temps)
            key_string = "nutanix_thermal_cpu_temp_celsius"
            self.__dict__[key_string].labels(ipmi=ipmi_name).set(cpu_temp)


    def fetch(self):
        """
        Get metrics from application and refresh Prometheus metrics with
        new values.
        """

        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Collecting IPMI metrics{PrintColors.RESET}")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.process_redfish_entity,ipmi_entity=ipmi_entity) for ipmi_entity in self.ipmi_config]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] A task failed with error: {e} {type(e)} {PrintColors.RESET}")
                traceback.print_exc()
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

        except requests.exceptions.HTTPError:
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
            error_message = f"HTTPError {url} {response.status_code} {response.reason} {response.text}"
            raise Exception(error_message)
        except requests.exceptions.ConnectionError as error_code:
            if retries == 1:
                error_message = f"ConnectionError {url} {type(error_code).__name__} {str(error_code)}"
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] ConnectionError {url} {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                raise Exception(error_message)
            else:
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {url} {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                time.sleep(sleep_between_retries)
                retries -= 1
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {url} Retries left: {retries}{PrintColors.RESET}")
                continue
        except requests.exceptions.Timeout as error_code:
            if retries == 1:
                error_message = f"Timeout {url} {type(error_code).__name__} {str(error_code)}"
                print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Timeout {url} {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                raise Exception(error_message)
            else:
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {url} {type(error_code).__name__} {str(error_code)} {PrintColors.RESET}")
                time.sleep(sleep_between_retries)
                retries -= 1
                print(f"{PrintColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {url} Retries left: {retries}{PrintColors.RESET}")
                continue
        except requests.exceptions.RequestException as error_code:
            print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {url} {response.status_code} {PrintColors.RESET}")
            error_message = f"{url} {response.status_code}"
            raise Exception(error_message)
        break

    if response.ok:
        return response
    if response.status_code == 401:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {url} {response.status_code} {response.reason} {PrintColors.RESET}")
        error_message = f"{url} {response.status_code} {response.reason}"
        raise Exception(error_message)
    elif response.status_code == 500:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {url} {response.status_code} {response.reason} {response.text} {PrintColors.RESET}")
        error_message = f"{url} {response.status_code} {response.reason} {response.text}"
        raise Exception(error_message)
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
        error_message = f"{url} {response.status_code} {response.reason} {response.text}"
        raise Exception(error_message)


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
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        error_message = f"{url} {resp.status_code} {resp.reason} {resp.text}"
        raise Exception(error_message)


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
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        error_message = f"{url} {resp.status_code} {resp.reason} {resp.text}"
        raise Exception(error_message)


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
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        error_message = f"{url} {resp.status_code} {resp.reason} {resp.text}"
        raise Exception(error_message)


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
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        error_message = f"{url} {resp.status_code} {resp.reason} {resp.text}"
        raise Exception(error_message)


def prism_get_volume_groups(api_server,username,secret,api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the Prism Element v2 REST API endpoint /volume_groups.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        VG details as vg_details
    """

    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = int(os.getenv("APP_PORT", "9440"))
    api_server_endpoint = "/PrismGateway/services/rest/v2.0/volume_groups/"
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
        vg_details = json_resp['entities']
        return vg_details
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        error_message = f"{url} {resp.status_code} {resp.reason} {resp.text}"
        raise Exception(error_message)


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
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        error_message = f"{url} {resp.status_code} {resp.reason} {resp.text}"
        raise Exception(error_message)


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
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise


def ipmi_get_thermal(api_server,secret,username='ADMIN',api_requests_timeout_seconds=30, api_requests_retries=5, api_sleep_seconds_between_retries=15,secure=False):
    """Retrieves data from the IPMI RedFisk REST API endpoint /Thermal.

    Args:
        api_server: The IP or FQDN of the IPMI.
        username: The IPMI user name (defaults to ADMIN).
        secret: The IPMI user name password.
        
    Returns:
        Thermal metrics object as thermal
    """

    #region prepare the api call
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_endpoint = "/redfish/v1/Chassis/1/Thermal"
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
        thermal = json_resp['Temperatures']
        return thermal
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Request failed! Status code: {resp.status_code}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {resp.reason}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {resp.text}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] raise_for_status: {resp.raise_for_status()}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {resp.elapsed}{PrintColors.RESET}")
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {resp.headers}{PrintColors.RESET}")
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise
#todo: add get cpu and memory metrics from redfish

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


def v4_get_entities():
    pass


def v4_get_entity_stats():
    pass


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

    ipmi_secure_env = os.getenv('IPMI_SECURE',default='False')
    if ipmi_secure_env is not None:
        ipmi_secure = ipmi_secure_env.lower() in ("true", "1", "t", "y", "yes")
        if ipmi_secure is False:
            #! suppress warnings about insecure connections
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        ipmi_secure = False
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ipmi_config = json.loads(os.getenv('IPMI_CONFIG', '[]'))

    operations_mode_env = os.getenv('OPERATIONS_MODE',default='v4')

    if operations_mode_env == 'legacy':
        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Initializing metrics class...{PrintColors.RESET}")
        nutanix_metrics = NutanixMetricsLegacy(
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
    elif operations_mode_env == 'v4':
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
    elif operations_mode_env == 'redfish':
        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Initializing metrics class...{PrintColors.RESET}")
        nutanix_metrics = NutanixMetricsRedfish(
            polling_interval_seconds=polling_interval_seconds,
            api_requests_timeout_seconds=api_requests_timeout_seconds,
            api_requests_retries=api_requests_retries,
            api_sleep_seconds_between_retries=api_sleep_seconds_between_retries,
            ipmi_secure=ipmi_secure,
            ipmi_config=ipmi_config,
        )
        print(f"{PrintColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Starting http server on port {exporter_port}{PrintColors.RESET}")
        start_http_server(exporter_port)
        nutanix_metrics.run_metrics_loop()
    else:
        print(f"{PrintColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Invalid operations mode (v4, legacy, redfish): {operations_mode_env}{PrintColors.RESET}")
#endregion #*FUNCTIONS


if __name__ == "__main__":
    main()
