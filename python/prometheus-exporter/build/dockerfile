FROM python:3.14.0a7-alpine

WORKDIR /~

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "-u", "./nutanix_prometheus_exporter.py" ]

#to make sure stdout shows up in the logs
ENV PYTHONUNBUFFERED=1
#used to specify Prism Element IP address or FQDN (assuming FQDN can be resolved inside the container)
ENV PRISM='127.0.0.1'
#used to specify the username to access Prism (viewer is the least privilege required) 
ENV PRISM_USERNAME='admin'
#used to specify the password for username
ENV PRISM_SECRET='secret'
#used to specify the OOBM module (IPMI) username.  Will default to ADMIN is nothing is specified.
#ENV IPMI_USERNAME='ADMIN'
#used to specify the password for the IPMI user. Will default to using the node serial number if this is left blank.
#ENV IPMI_SECRET='secret'
#leave this value to null if you don't want to verify SSL certificates. Set it to anything but null to check SSL certificates.
#ENV PRISM_SECURE=''
#used to specify the port used by Prism API
ENV APP_PORT='9440'

#defines the time to wait between each poll
ENV POLLING_INTERVAL_SECONDS='30'
#used to control timeout setting when making API calls
ENV API_REQUESTS_TIMEOUT_SECONDS=30
#used to control retry setting when making API calls
ENV API_REQUESTS_RETRIES=5
#used to control retry sleep setting when making API calls
ENV API_SLEEP_SECONDS_BETWEEN_RETRIES=15
#used to specify the container port where the node exporter will publish metrics
ENV EXPORTER_PORT='8000'

#use a comma separated string with virtual machine names for which you want to collect metrics. If this is null, then no VM metrics will be collected.
#it is strongly recommended not to get crazy with vm list as this would considerably lengthen the metric collection time.
ENV VM_LIST=''

#used to determine operations mode (v4,legacy,redfish).
ENV OPERATIONS_MODE='legacy'

#*used when operations mode is legacy
#used to determine if clusters metrics will be generated; set it to False value if you don't want to collect cluster metrics.
ENV CLUSTER_METRICS='True'
#used to determine if storage containers metrics will be generated; set it to False value if you don't want to collect storage containers metrics.
ENV STORAGE_CONTAINERS_METRICS='True'
#used to determine if IPMI metrics will be generated; set it to False value if you don't want to collect IPMI metrics.
ENV IPMI_METRICS='True'
#used to determine if Prism Central metrics will be generated; set it to False value if you don't want to collect Prism Central metrics.
ENV PRISM_CENTRAL_METRICS='False'
#used to determine if NCM SSP metrics will be generated; set it to False value if you don't want to collect NCM SSP metrics.
ENV NCM_SSP_METRICS='False'

#*used when operations mode is redfish
#leave this value to null if you don't want to verify SSL certificates when using redfish operations mode. Set it to anything but null to check SSL certificates.
#ENV IPMI_SECURE=''
#When using redfish operations mode, configure list of ipmi entities as follows.
#ENV IPMI_CONFIG='[
#    {"ip":"1.1.1.1","name":"myhost1","username":"ADMIN","password":"my_pwd"},
#    {"ip":"2.2.2.2","name":"myhost2","username":"ADMIN","password":"my_other_pwd"},
#]


