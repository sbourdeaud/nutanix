Collection of scripts used for Nutanix Services:

- set-ipconfig.ps1: used for IP reconfiguration on Windows for cross-hypervisor DR. Can aslo be used for AHV migrations to save/restore ip configuration on multiple NICs.

- set-cvms.ps1: used after Foundation during installation services to configure CVMs and HA/DRS cluster in a vSphere environment according to best practices.

- set-hostconfig.ps1: used after Foundation during installation services to configure NTP and DNS on vSphere hosts in a Nutanix cluster.

- add-DRSAffinityRulesForMA.ps1: used to confnigure DRS affinity rules when setting up MA on Nutanix clusters running vSphere.

- add-VmToPd.ps1: used to add one or more virtual machines to an async protection domain in a Nutanix cluster.

- get-NutanixStatus.ps1: used to retrieve a csv with containers status for one or more Nutanix clusters.

- ahv-migration.ps1: used to import Scale Computing exported vms (as xml and qcow2) in a given container and create corresponding AHV virtual machines.  Can also be used to export an AHV virtual machine's disks to qcow2.

- get-NTNXAlertPolicy.ps1: retrieves all healthchecks and alerts with full information and export to csv.


When setting up a new Nutanix cluster, use:
- set-cvms.ps1 after having created the HA/DRS cluster in vCenter to apply Nutanix best practices on the vSphere cluster,
- set-hostconfig.ps1 to configure redundant dns and ntp on esxi servers,
- add-DRSAffinityRulesForMA.ps1 after having configured Metro Availability (if applicable) to create the relevant DRS groups and rules for MA.

Please report any bugs here.  Not that scripts were recently modified to deal with PowerCLI 6.5 (dropped snapins) and updated Nutanix cmdlets (errors should now be more verbose when those aren't installed properly).
