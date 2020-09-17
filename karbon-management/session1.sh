#* title: Managing Kubernetes Clusters at Scale with Karbon
#* version/date: Sept-15-2020
#* author: Stephane Bourdeaud (stephane.bourdeaud@nutanix.com)
#* url: 

#* note: meant to be used in vscode with the "Better Comments" extension
#*       this extension will color code the comments and make this file
#*       a lot easier to navigate.


#! kubeconfig
#? objective: understand how to get the kubeconfig file from the cmdline
#?   and how to use it to access multiple K8s clusters.
#region kubeconfig

    #* ref: Nutanix kb7457 (https://portal.nutanix.com/page/documents/kbs/details?targetId=kA00e0000009D3cCAE)

    #* karbonctl is a binary available on Prism Central in /home/nutanix/karbon
    #* it does not have to be used from Prism Central and should work on any Linux
    #* distribution.
    
    #* assuming a user has been given read access to Prism Central (RBAC to K8s is documented in the next section):
    ./karbonctl login --pc-ip 1.1.1.1 --pc-username user@domain #to login Prism Central
    ./karbonctl cluster list #to list available K8s clusters
    ./karbonctl cluster kubeconfig --cluster-name myK8s > kubeconfig #to grab the required configuration
    export KUBECONFIG=./kubeconfig #at this point, user is ready to start using kubectl

    #* the content of multiple KUBECONFIG files can also be aggregated into a single file
    #* the user can then switch the kubectl context like so:
    kubectl config get-contexts #to list available contexts (determined by kubeconfig content)
    kubectl config use-context myK8s-context #to use a particular context
    kubectl config set-context myK8s-context --namespace mynamespace #to change the default namespace for a given context

#endregion


#!rbac
#? objective: understand how to delegate access to Active Directory users
#?   and groups to K8s clusters.
#region rbac

    #* ref: https://next.nutanix.com/architectural-best-practices-74/providing-rbac-for-your-karbon-kubernetes-clusters-33132

    #* Karbon deployed K8s clusters have RBAC enabled
    #* process is:
    #*      (1)determine if role will be cluster wide or specific to a namespace
    #*      (2)create or identify existing ClusterRole or Role
    #*      (3)create ClusterRoleBinding or RoleBinding
    #*      (4)add users as viewers to Prism Central
    #*      (5)user grabs kubeconfig from Prism Central UI or using karbonctl (see previous section)

    #* exp: cluster wide admin (apply ClusterRoleBinding)
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: steph-karbon-admins-CRB #* name of ClusterRoleBinding
subjects:
- kind: Group
  name: steph-karbon-admins #* AD user group
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin #* must match the name of a Role or ClusterRole to bind to
  apiGroup: rbac.authorization.k8s.io
EOF

    #* exp: dev role for specific namespace (create namespace, create custom role, apply rolebinding)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: app-group1 #* creates the namespace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app-group1 #* namespace name
  name: steph-karbon-devs-R #* Role name
rules:
- apiGroups: ["", "apps", "batch", "extensions"]
  resources: ["services", "endpoints", "pods", "secrets", "configmaps", "deployments", "jobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: app-group1 #* namespace name
  name: steph-karbon-devs-RB #* RoleBinding name
subjects:
- kind: Group
  name: steph-karbon-devs #* AD user group
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: steph-karbon-devs-R #* must match the name of the Role to bind to
  apiGroup: rbac.authorization.k8s.io
EOF

#endregion


#!serviceaccounts
#? objective: 
#region serviceaccounts

    #* ref: Nutanix kb7357 (https://portal.nutanix.com/page/documents/kbs/details?targetId=kA00e0000009CegCAE)

    #* K8s service accounts have non-expiring tokens and can be used for things like CI/CD pipelines
    kubectl create serviceaccount prometheus-federation #example
    #* once the serviceaccount has been created, you must bind it to a Role or ClusterRole
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
 name: prometheus-federation-CRB #* name of ClusterRoleBinding or RoleBinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole #* could be Role or ClusterRole
  name: prometheus-k8s #* name of the ClusterRole
subjects:
- kind: ServiceAccount
  name: prometheus-federation #* name of service account
  namespace: default #* namespace to create this binding in
EOF
    #* to then retrieve the token (to add to kubeconfig or Jenkins, etc...)
    kubectl get secrets $(kubectl get serviceaccounts prometheus-federation -o jsonpath='{.secrets[].name}') -o jsonpath={.data.token} | base64 -d #replace with your serviceaccount name

#endregion


#! upgrades
#? objective: 
#region upgrades

    #* upgrading Prism Central: Settings > Prism Central
    #*      note that Prism Central has a unique release (no LTS/STS distinction)

    #* upgrading Karbon (from Prism Central): Administration > LCM > Inventory > Perform Inventory
    #*      then: Administration > LCM > Updates > Software > Select Karbon > Update
    #*      this will update the container images for karbon-core and karbon-ui on Prism Central

    #* upgrading nodes host image (from Prism Central): Services > Karbon > Select K8s cluster > Actions > Upgrade Node Image
    #*      this is a rolling upgrade of master/etcd/worker nodes CentOS Nutanix/Karbon approved image
    #*      assuming the K8s cluster has multiple master/etcd/worker nodes and sufficient capacity, it runs with no service outage for pods/applications

    #* upgrading K8s: documented in https://portal.nutanix.com/page/documents/details?targetId=Karbon-v2_1:kar-karbon-kubernetes-upgrade-t.html
    ./karbonctl login --pc-ip 1.1.1.1 --pc-username user@domain #to login Prism Central
    ./karbonctl k8s get-from-portal #to grab latest compatible K8s versions with Karbon
    ./karbonctl cluster list #to list available K8s clusters
    ./karbonctl cluster k8s get-compatible-versions --cluster-name myK8s #to show available upgrades
    ./karbonctl cluster k8s upgrade --cluster-name myK8s --package-version 1.16.13-0 #to upgrade to specified version
    ./karbonctl cluster k8s upgrade status --cluster-name myK8s #to monitor progress of upgrade (also visible from Prism Central Karbon UI)

#endregion