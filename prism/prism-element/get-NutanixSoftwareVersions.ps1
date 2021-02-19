<#
.SYNOPSIS
  Use this script to collect software versions from a Nutanix cluster.
.DESCRIPTION
  Th script will collect information about the following components: AOS, NCC, Foundation, Hypervisor, LCM.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER prismcentral
  Nutanix Prism Central FQDN or IP. You can target a Prism Central instance instead of an individual cluster/Prism Element, in which case the script will process each Nutanix cluster managed by that Prism Central instance.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER nolcm
  Specifies you don't want to retrieve lcm version information.
.PARAMETER csv
  Specifies you want to export results to a csv file in the current directory.
.PARAMETER startinventory
  Triggers an lcm inventory on the specified Nutanix cluster.
.PARAMETER nowait
  Don't wait for the inventory task triggered to complete.
.EXAMPLE
.\get-NutanixSoftwareVersions.ps1 -cluster ntnxc1.local
Connect to a Nutanix cluster of your choice and collect software information:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
#>

#region parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$log,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$cluster,
      [parameter(mandatory = $false)] [string]$prismcentral,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [switch]$nolcm,
      [parameter(mandatory = $false)] [switch]$csv,
      [parameter(mandatory = $false)] [switch]$startinventory,
      [parameter(mandatory = $false)] [switch]$nowait
  )
#endregion

#region functions
  Function Get-PrismTaskStatus
  {
      <#
  .SYNOPSIS
  Retrieves the status of a given task uuid from Prism and loops until it is completed.

  .DESCRIPTION
  Retrieves the status of a given task uuid from Prism and loops until it is completed.

  .PARAMETER Task
  Prism task uuid.

  .NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

  .EXAMPLE
  .\Get-PrismTaskStatus -Task $task
  Prints progress on task $task until successfull completion. If the task fails, print the status and error code and details and exits.

  .LINK
  https://github.com/sbourdeaud
  #>
  [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

      param
      (
          [Parameter(Mandatory)]
          $task,
          
          [parameter(mandatory = $true)]
          [System.Management.Automation.PSCredential]
          $credential,

          [parameter(mandatory = $true)]
          [String]
          $cluster
      )

      begin
      {}
      process 
      {
          #region get initial task details
              Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
              $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
              $method = "GET"
              $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
              Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
          #endregion

          if ($taskDetails.percentage_complete -ne "100") 
          {
              Do 
              {
                  New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                  Sleep 5
                  $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                  $method = "GET"
                  $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                  
                  if ($taskDetails.status -ine "running") 
                  {
                      if ($taskDetails.status -ine "succeeded") 
                      {
                          Throw "$(Get-Date) [INFO] Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                      }
                  }
              }
              While ($taskDetails.percentage_complete -ne "100")
              
              New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
              Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
          } 
          else 
          {
              New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
              Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
          }
      }
      end
      {}
  }
#endregion

#region prepwork
  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/16/2020 sb   Initial release.
06/25/2020 sb   Added the -startinventory and -nowait parameters.
################################################################################
'@
  $myvarScriptName = ".\get-NutanixSoftwareVersions.ps1"

  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

  #check PoSH version
  if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

  #check if we have all the required PoSH modules
  Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

  #region module sbourdeaud is used for facilitating Prism REST calls
  $required_version = "3.0.8"
  if (!(Get-Module -Name sbourdeaud)) {
      Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
      try
      {
          Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
          Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
      }#end try
      catch #we couldn't import the module, so let's install it
      {
          Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
          try {Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop}
          catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

          try
          {
              Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
              Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
          }#end try
          catch #we couldn't import the module
          {
              Write-Host "$(get-date) [ERROR] Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)" -ForegroundColor Red
              Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/sbourdeaud/1.1" -ForegroundColor Yellow
              Exit
          }#end catch
      }#end catch
  }#endif module sbourdeaud
  $MyVarModuleVersion = Get-Module -Name sbourdeaud | Select-Object -Property Version
  if (($MyVarModuleVersion.Version.Major -lt $($required_version.split('.')[0])) -or (($MyVarModuleVersion.Version.Major -eq $($required_version.split('.')[0])) -and ($MyVarModuleVersion.Version.Minor -eq $($required_version.split('.')[1])) -and ($MyVarModuleVersion.Version.Build -lt $($required_version.split('.')[2])))) {
      Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
      Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
      Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
      try {
          Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
          Import-Module -Name sbourdeaud -ErrorAction Stop
      }
      catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
  }
  #endregion
  Set-PoSHSSLCerts
  Set-PoshTls
#endregion

#region variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
  [System.Collections.ArrayList]$myvar_generic_results = New-Object System.Collections.ArrayList($null)
  [System.Collections.ArrayList]$myvar_nodes_reference = New-Object System.Collections.ArrayList($null)
#endregion

#region parameters validation
  if (!$cluster -and !$prismcentral)
  {
    Throw "$(Get-Date) [ERROR] You must specify either a Nutanix cluster with -cluster or a Nutanix Prism Central instance with -prismcentral!"
  }
  if (!$prismCreds) 
  {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
      $prismCredentials = Get-Credential -Message "Please enter Prism credentials"
  } 
  else 
  { #we are using custom credentials, so let's grab the username and password from that
      try 
      {
          $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
          $username = $prismCredentials.UserName
          $PrismSecurePassword = $prismCredentials.Password
      }
      catch 
      {
          Set-CustomCredentials -credname $prismCreds
          $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
          $username = $prismCredentials.UserName
          $PrismSecurePassword = $prismCredentials.Password
      }
      $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
  }
#endregion

#todo: deal with lcm inventory tasks already running (status will be 409: CONFLICT)
#todo: deal with no lcm API
#todo: deal with errors when posting to v3/groups while trying to retrieve lcm updates
#region processing

    if ($prismcentral)
    {#prismcentral was targeted, let's retrieve information about each cluster

    }
    else 
    {#we are only targeting a single cluster
      $myvar_cluster_list = $cluster  
    }

    ForEach ($myvar_cluster in $myvar_cluster_list)
    {#process each cluster
      if ($startinventory) 
      {#we are doing an lcm inventory
        Write-Host "$(get-date) [INFO] Triggering LCM inventory on Nutanix cluster $($cluster)..." -ForegroundColor Green
        $url = "https://$($cluster):9440/lcm/v1.r0.b1/operations/inventory"
        $method = "POST"
        $myvar_inventory_task = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully triggered LCM inventory on Nutanix cluster $($cluster): task $($myvar_inventory_task.data.task_uuid)!" -ForegroundColor Cyan
  
        if (!$nowait) 
        {#we are waiting for the lcm inventory to complete
          Get-PrismTaskStatus -task $myvar_inventory_task.data.task_uuid -cluster $cluster -credential $prismCredentials
        }
      } 
      else 
      {#we are not doing an lcm inventory
  
        #region get cluster information
            Write-Host "$(get-date) [INFO] Retrieving cluster information..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
            $method = "GET"
            $myvar_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information!" -ForegroundColor Cyan
        #endregion
  
        #region get nodes information
            #building the list of nodes
            $myvar_cluster_nodes_uuids = @()
            Foreach ($myvar_block in $myvar_cluster_info.rackable_units) 
            {#process each node
                $myvar_cluster_nodes_uuids += $myvar_block.node_uuids
            }
  
            #querying each node
            $myvar_cluster_hypervisors = @()
            $myvar_cluster_node_types = @()
            $myvar_cluster_bios_versions = @()
            $myvar_cluster_bmc_versions = @()
            $myvar_cluster_disk_types = @()
            $myvar_cluster_disk_firmwares = @()
            Foreach ($myvar_node in $myvar_cluster_nodes_uuids) 
            {#process each host
                Write-Host "$(get-date) [INFO] Retrieving information for node uuid $($myvar_node)..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/hosts/$($myvar_node)"
                $method = "GET"
                $myvar_node_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved information for node uuid $($myvar_node)!" -ForegroundColor Cyan
  
                #capturing node reference for lcm data cross-check
                if (!$nolcm) {
                    $myvar_node_reference = [ordered]@{
                        "node_name" = $myvar_node_info.name;
                        "node_uuid" = $myvar_node_info.uuid;
                        "node_hypervisor_ip_address" = $myvar_node_info.hypervisor_address
                    }
                    $myvar_nodes_reference.Add((New-Object PSObject -Property $myvar_node_reference)) | Out-Null
                }
  
                #capturing relevant data for generic report
                if ($myvar_cluster_hypervisors -notcontains $myvar_node_info.hypervisor_full_name) {
                    $myvar_cluster_hypervisors += $myvar_node_info.hypervisor_full_name
                }
                if ($myvar_cluster_node_types -notcontains $myvar_node_info.block_model_name) {
                    $myvar_cluster_node_types += $myvar_node_info.block_model_name
                }
                if ($myvar_cluster_bios_versions -notcontains $myvar_node_info.bios_version) {
                    $myvar_cluster_bios_versions += $myvar_node_info.bios_version
                }
                if ($myvar_cluster_bmc_versions -notcontains $myvar_node_info.bmc_version) {
                    $myvar_cluster_bmc_versions += $myvar_node_info.bmc_version
                }
  
                #processsing disks information
                ($myvar_node_info.disk_hardware_configs | Get-Member -MemberType NoteProperty).Name | ForEach-Object {
                    if ($myvar_cluster_disk_types -notcontains $myvar_node_info.disk_hardware_configs.$_.model) {
                        $myvar_cluster_disk_types += $myvar_node_info.disk_hardware_configs.$_.model
                    }
                    if ($myvar_cluster_disk_firmwares -notcontains $myvar_node_info.disk_hardware_configs.$_.current_firmware_version) {
                        $myvar_cluster_disk_firmwares += $myvar_node_info.disk_hardware_configs.$_.current_firmware_version
                    }
                }
            }
        #endregion
  
        #region get lcm version
            if (!$nolcm) 
            {#we are getting lcm information
                Write-Host "$(get-date) [INFO] Retrieving lcm information..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/genesis"
                $method = "POST"
                $payload = @"
{
    "value": "{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"get_config\"}}"
}
"@      
                $myvar_lcm_info = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved lcm information!" -ForegroundColor Cyan
            }
        #endregion
  
        #region get lcm updates
            if (!$nolcm) 
            {#we are getting lcm updates
                Write-Host "$(get-date) [INFO] Retrieving lcm updates..." -ForegroundColor Green
                $url = "https://$($cluster):9440/api/nutanix/v3/groups"
                $method = "POST"
                $payload= @"
{
  "entity_type": "lcm_available_version_v2",
  "group_member_count": 500,
  "group_member_attributes": [{
    "attribute": "uuid"
  }, {
    "attribute": "entity_uuid"
  }, {
    "attribute": "entity_class"
  }, {
    "attribute": "status"
  }, {
    "attribute": "version"
  }, {
    "attribute": "dependencies"
  }, {
    "attribute": "single_group_uuid"
  }, {
    "attribute": "_master_cluster_uuid_"
  }, {
    "attribute": "order"
  }],
  "query_name": "lcm:VersionModel",
  "filter_criteria": "_master_cluster_uuid_==[no_val]"
}
"@ 
                $myvar_lcm_updates = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved lcm updates!" -ForegroundColor Cyan
            }
        #endregion
  
        #region get lcm entities
            if (!$nolcm) 
            {#we are getting lcm entities
                Write-Host "$(get-date) [INFO] Retrieving lcm entities..." -ForegroundColor Green
                $url = "https://$($cluster):9440/api/nutanix/v3/groups"
                $method = "POST"
                $payload= @"
{
  "entity_type": "lcm_entity_v2",
  "group_member_count": 500,
  "group_member_attributes": [{
    "attribute": "id"
  }, {
    "attribute": "uuid"
  }, {
    "attribute": "entity_model"
  }, {
    "attribute": "version"
  }, {
    "attribute": "location_id"
  }, {
    "attribute": "entity_class"
  }, {
    "attribute": "description"
  }, {
    "attribute": "last_updated_time_usecs"
  }, {
    "attribute": "request_version"
  }, {
    "attribute": "_master_cluster_uuid_"
  }, {
    "attribute": "entity_type"
  }, {
    "attribute": "single_group_uuid"
  }],
  "query_name": "lcm:EntityGroupModel",
  "grouping_attribute": "location_id",
  "filter_criteria": ""
}
"@ 
                $myvar_lcm_entities = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved lcm entities!" -ForegroundColor Cyan
            }
        #endregion
  
        #region process generic results
            $myvar_software_versions = [ordered]@{
                #from cluster information
                "cluster_name" = $myvar_cluster_info.name;
                "cluster_id" = $myvar_cluster_info.id;
                "aos_version" = $myvar_cluster_info.version;
                "ncc_version" = $myvar_cluster_info.ncc_version;
                "num_nodes" = $myvar_cluster_info.num_nodes
                #from node information
                "hypervisor(s)" = $myvar_cluster_hypervisors -join ',';
                "node_type(s)" = $myvar_cluster_node_types -join ',';
                "bios_version(s)" = $myvar_cluster_bios_versions -join ',';
                "bmc_version(s)" = $myvar_cluster_bmc_versions -join ',';
                "disk_types" = $myvar_cluster_disk_types -join ',';
                "disk_firmwares" = $myvar_cluster_disk_firmwares -join ',';
            }
            if (!$nolcm) 
            {#we are using lcm information
                $myvar_software_versions.lcm_version = ($myvar_lcm_info.value | ConvertFrom-Json).".return".version
            }
            $myvar_generic_results.Add((New-Object PSObject -Property $myvar_software_versions)) | Out-Null
            $myvar_software_versions | ft
            Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($myvar_cluster_info.name)_sw_versions.csv" -ForegroundColor Green
            $myvar_generic_results | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($myvar_cluster_info.name)+"_sw_versions.csv")
        #endregion
  
        #region process lcm detailed results
            if (!$nolcm) 
            {#we are using lcm information
                [System.Collections.ArrayList]$myvar_entity_results = New-Object System.Collections.ArrayList($null)
                [System.Collections.ArrayList]$myvar_update_results = New-Object System.Collections.ArrayList($null)
  
                Foreach ($group_result in $myvar_lcm_updates.group_results) 
                {#process each group result from lcm info
                    Foreach ($entity_id in $group_result.entity_results) 
                    {#process each entity from lcm group results
                        $myvar_software_versions = [ordered]@{
                            "entity_class" = ($entity_id.data | Where-Object {$_.name -eq "entity_class"} | Select-Object -Property values).values.values;
                            "status" = ($entity_id.data | Where-Object {$_.name -eq "status"} | Select-Object -Property values).values.values;
                            "version" = ($entity_id.data | Where-Object {$_.name -eq "version"} | Select-Object -Property values).values.values;
                            "dependencies" = (($entity_id.data | Where-Object {$_.name -eq "dependencies"} | Select-Object -Property values).values.values) -join ',';
                            "order" = ($entity_id.data | Where-Object {$_.name -eq "order"} | Select-Object -Property values).values.values;
                            "entity_uuid" = ($entity_id.data | Where-Object {$_.name -eq "entity_uuid"} | Select-Object -Property values).values.values;
                            "lcm_uuid" = ($entity_id.data | Where-Object {$_.name -eq "uuid"} | Select-Object -Property values).values.values;
                        }
                        $myvar_update_results.Add((New-Object PSObject -Property $myvar_software_versions)) | Out-Null
                    }
                }
                
                Foreach ($group_result in $myvar_lcm_entities.group_results) 
                {#process each group result for each entity
                    Foreach ($entity_id in $group_result.entity_results) 
                    {#process each entity id in each entity result
                        $myvar_software_versions = [ordered]@{
                            #from cluster information
                            "component" = $group_result.group_by_column_value;
                            "software" = ($entity_id.data | Where-Object {$_.name -eq "entity_model"} | Select-Object -Property values).values.values;
                            "version" = $(($entity_id.data | Where-Object {$_.name -eq "version"} | Select-Object -Property values).values.values);
                            #"description" = ($entity_id.data | Where-Object {$_.name -eq "description"} | Select-Object -Property values).values.values;
                            "entity_class" = ($entity_id.data | Where-Object {$_.name -eq "entity_class"} | Select-Object -Property values).values.values;
                            "entity_type" = ($entity_id.data | Where-Object {$_.name -eq "entity_type"} | Select-Object -Property values).values.values;
                            #"request_version" = ($entity_id.data | Where-Object {$_.name -eq "request_version"} | Select-Object -Property values).values.values;
                            "id" = ($entity_id.data | Where-Object {$_.name -eq "id"} | Select-Object -Property values).values.values;
                            "lcm_entity_uuid" = ($entity_id.data | Where-Object {$_.name -eq "uuid"} | Select-Object -Property values).values.values
                        }
                        $myvar_software_versions.update_version = (($myvar_update_results | Where-Object {$_.entity_uuid -eq $myvar_software_versions.lcm_entity_uuid}).version) | Select-Object -Last 1
                        $myvar_software_versions.update_status = (($myvar_update_results | Where-Object {$_.entity_uuid -eq $myvar_software_versions.lcm_entity_uuid}).status) | Select-Object -Last 1
                        #$myvar_software_versions.update_dependencies = (($myvar_update_results | Where-Object {$_.entity_uuid -eq $myvar_software_versions.lcm_entity_uuid}).dependencies) -join ','
  
                        if ($group_result.group_by_column_value -like "cluster:*") {
                            $myvar_software_versions.component_name = $myvar_cluster_info.name;
                            $myvar_software_versions.component_ip = $myvar_cluster_info.cluster_external_ipaddress
                        } else {
                            $myvar_software_versions.component_name = ($myvar_nodes_reference | Where-Object {$_.node_uuid -eq $group_result.group_by_column_value.split(':')[1]}).node_name
                            $myvar_software_versions.component_ip = ($myvar_nodes_reference | Where-Object {$_.node_uuid -eq $group_result.group_by_column_value.split(':')[1]}).node_hypervisor_ip_address
                        }
                        
                        $myvar_entity_results.Add((New-Object PSObject -Property $myvar_software_versions)) | Out-Null
                    }
                }
                
                $myvar_entity_results | ft
                Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($myvar_cluster_info.name)_lcm_report.csv" -ForegroundColor Green
                $myvar_entity_results | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($myvar_cluster_info.name)+"_lcm_report.csv")
            }
        #endregion
    
      }
    }

#endregion

#region cleanup
  #let's figure out how much time this all took
  Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

  #cleanup after ourselves and delete all custom variables
  Remove-Variable myvar* -ErrorAction SilentlyContinue
  Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
  Remove-Variable help -ErrorAction SilentlyContinue
  Remove-Variable history -ErrorAction SilentlyContinue
  Remove-Variable log -ErrorAction SilentlyContinue
  Remove-Variable cluster -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion