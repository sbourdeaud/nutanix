#* title: Managing Kubernetes Clusters at Scale with Karbon
#* version/date: Sept-15-2020
#* author: Stephane Bourdeaud (stephane.bourdeaud@nutanix.com)
#* url: https://github.com/sbourdeaud/nutanix/blob/master/karbon-management/

#* note: meant to be used in vscode with the "Better Comments" extension
#*       this extension will color code the comments and make this file
#*       a lot easier to navigate.

#! using the built-in Nutanix Volumes CSI
#? objective: understand how to create pv and pvc then use it in a manifest to assign
#?  persistent storage to a container
#region csi
#endregion


#! snapshot & DR of stateful containers (native)
#? objective: understand how to snapshot and replicate Nutanix Volumes volumes used as pv
#?  in Karbon deployed K8s clusters and recover them on a different cluster.
#region csi-dr
#endregion