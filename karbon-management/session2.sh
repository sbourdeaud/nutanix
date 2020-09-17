#* title: Managing Kubernetes Clusters at Scale with Karbon
#* version/date: Sept-15-2020
#* author: Stephane Bourdeaud (stephane.bourdeaud@nutanix.com)
#* url: https://github.com/sbourdeaud/nutanix/blob/master/karbon-management/

#* note: meant to be used in vscode with the "Better Comments" extension
#*       this extension will color code the comments and make this file
#*       a lot easier to navigate.

#! prometheus federation (system)
#? objective: (1/3)Consolidate Prometheus metrics and alerts from multiple Karbon K8s clusters 
#?  into a central Prometheus server instance and central Prometheus alert manager.
#?  (2/3)Configure Prometheus alert-manager to forward alerts to an email address.
#?  (3/3)Setup a simple Grafana dashboard using this centralized data.
#region prometheus-federation

    #* on all source K8s clusters: create a prometheus-federation service account, bind it a a ClusterRole and grab the token
    kubectl create serviceaccount prometheus-federation

    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
 name: prometheus-federation-CRB #* name of ClusterRoleBinding or RoleBinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole #* could be Role or ClusterRole
  name: prometheus-operator #* name of the ClusterRole
subjects:
- kind: ServiceAccount
  name: prometheus-federation #* name of service account
  namespace: default #* namespace to create this binding in
EOF

    #* on all source K8s clusters: list the Prometheus URL available from kube-proxy
    kubectl cluster-info --namespace ntnx-system #exp: prometheus-k8s is running at https://1.1.1.1:443/api/v1/namespaces/ntnx-system/services/prometheus-k8s:web/proxy

    #* on the central K8s cluster: use Helm (https://github.com/prometheus-community/helm-charts/) to provision a dedicated Prometheus server and alert-manager instance
    #? repo files used: prometheus-values.yaml
    #* step1: install helm using: https://helm.sh/docs/intro/install/
    #* step2: customize prometheus-values.yaml:
    #*      a/ customize ingress/nodeport/laodbalancer for prometheus service
    #*      b/ change persistent storage size based on metrics & sample & number of targets collected (needed_disk_space = retention_time_seconds * ingested_samples_per_second * bytes_per_sample) ref: https://prometheus.io/docs/prometheus/latest/storage/
    #*      c/ customize the "alertmanagerFiles:" section with your SMTP configuration
    #*      d/ customize the "scrape_configs:" section to define your targets (using the service account token and kube-proxy url)
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts #add prometheus community repo to helm
    kubectl create namespace prometheus-federation #create namespace
    helm install prometheus-federation prometheus-community/prometheus -f prometheus-values.yaml -n prometheus-federation #deploy central prometheus instance
    kubectl --namespace ntnx-system get PrometheusRule prometheus-k8s-rules -o yaml >prometheus-rules.yaml #grab default ntnx rules
    kubectl create -f prometheus-rules.yaml -n prometheus-federation #import default ntnx rules

    export POD_NAME=$(kubectl get pods --namespace prometheus-federation -l "app=prometheus,component=server" -o jsonpath="{.items[0].metadata.name}") #grabs pod name where prometheus is running
    kubectl port-forward $POD_NAME 9090:9090 #then access prometheus ui using localhost:9090 and check that targets are being scraped from

    #* additional targets can be added by editing the ConfigMap:
    kubectl --namespace prometheus-federation edit ConfigMap prometheus-federation-server
    curl -X POST http://localhost:9090/-/reload #force Prometheus to reload the configuration

    #* on the central K8s cluster: use Helm to deploy Grafana
    #? repo files used: grafana-values.yaml
    #* customize the grafana service type in grafana-values.yaml as well as the persistent storage size
    #* customize the plugins you want/need in grafana-values.yaml
    kubectl create ns grafana #create a namespace for grafana
    helm repo add grafana https://grafana.github.io/helm-charts #add the helm repo
    helm install grafana grafana/grafana -f grafana-values.yaml -n grafana #deploy grafana

    kubectl get secret --namespace grafana grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo #grab the grafana admin user password
    export NODE_PORT=$(kubectl get --namespace grafana -o jsonpath="{.spec.ports[0].nodePort}" services grafana) #get the node_port where grafana is running (assuming the service is using NODE_PORT)
    export NODE_IP=$(kubectl get nodes --namespace grafana -o jsonpath="{.items[0].status.addresses[0].address}") #get the worker node IP where grafana is running
    echo http://$NODE_IP:$NODE_PORT #display the URL to use to connect to grafana

    #* import dashboard id 315 to create a sample dashboard using the defined prometheus source instance

#endregion


#! prometheus (apps)
#? objective: Create a separate prometheus instance on source servers to monitor pods in addition to system
#region prometheus-pods
    #* ref: https://medium.com/@christophe_99995/applications-metrics-monitoring-on-nutanix-karbon-c1d1158ebcfc
#endregion


#! prometheus with thanos (system)
#? objective: configure alert/metrics centralization using thanos sidecar instead of prometheus federation
#?  this may be required if long term retention of data is required or if there are high availability requirements
#region prometheus-thanos
    #* work in progress
#endregion


#! logging aggregation with fluentbit/fluentd
#? objective: have system logs from multiple K8s clusters aggregated into a central EFK stack
#region fluentd

    #* deploy the central EFK stack:
    kubectl create ns logging #create a namespace
    kubectl apply -f https://download.elastic.co/downloads/eck/1.0.0-beta1/all-in-one.yaml #install the elastic search operator
    #deploy elastic search:
    cat <<EOF | kubectl apply -f -
apiVersion: elasticsearch.k8s.elastic.co/v1beta1
kind: Elasticsearch
metadata:
  name: quickstart
spec:
  version: 7.5.0
  http:
    service:
      spec:
        type: NodePort
  nodeSets:
  - name: default
    count: 1
    config:
      node.master: true
      node.data: true
      node.ingest: true
      node.store.allow_mmap: false
EOF
    kubectl -n logging get secret quickstart-es-elastic-user -o=jsonpath='{.data.elastic}' | base64 --decode #to grab the elastic user password
    #deploy kibana:
    cat <<EOF | kubectl apply -f -
apiVersion: kibana.k8s.elastic.co/v1beta1
kind: Kibana
metadata:
  name: quickstart
spec:
  version: 7.5.0
  http:
    service:
      spec:
        type: NodePort
  count: 1
  elasticsearchRef:
    name: quickstart
EOF
    #* deploy fluentd daemonset on the central K8s cluster (where es and kibana were deployed):
    #? repo files used: prometheus-values.yaml
    kubectl -n logging apply -f fluentd-daemonset.yaml

    #* configure fluentbit on distributed K8s clusters
    kubectl create ns logging #create namespace
    #create service account:
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluent-bit
  namespace: logging
EOF
    #create ClusterRole:
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: fluent-bit-read
rules:
- apiGroups: [""]
  resources:
  - namespaces
  - pods
  verbs: ["get", "list", "watch"]
EOF
    #create ClusterRoleBinding:
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: fluent-bit-read
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: fluent-bit-read
subjects:
- kind: ServiceAccount
  name: fluent-bit
  namespace: logging
EOF
    #create ConfigMap:
    #? repo files used: fluent-bit-configmap.yaml
    kubectl apply -n logging -f fluent-bit-configmap.yaml
    #* customize the fluent-bit-daemonset.yaml file
    #create fluentbit DaemonSet:
    #? repo files used: fluent-bit-daemonset.yaml
    kubectl apply -n logging -f fluent-bit-daemonset.yaml

    #* back on the central cluster, connect to Kibana to validate it is collecting logs:
    kubectl -n logging port-forward svc/quickstart-kb-http 5601 #and connect to localhost:5601 in your browser

#endregion