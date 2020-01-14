NOTE: Some older scripts require PowerCLI (https://my.vmware.com/web/vmware/details?downloadGroup=PCLI650R1&productId=614) and/or Nutanix CmdLets (which can be downloaded from the user menu in Prism).

All scripts are documented and can be queried with get-help.

When setting up a new Nutanix cluster, use:
- set-cvms.ps1 after having created the HA/DRS cluster in vCenter to apply Nutanix best practices on the vSphere cluster,
- set-hostconfig.ps1 to configure redundant dns and ntp on esxi servers,
- add-DRSAffinityRulesForMA.ps1 after having configured Metro Availability (if applicable) to create the relevant DRS groups and rules for MA.

Please report any bugs here.
