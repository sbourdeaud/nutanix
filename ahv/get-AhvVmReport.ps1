<#
.SYNOPSIS
  This script retrieves the complete list of virtual machines from Prism Central.
.DESCRIPTION
  This script retrieves the complete list of virtual machines from Prism Central, including each VM specs and exports the results to csv in the current directory.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER ngt
  Retrieves additional information about Nutanix Guest Tools (including guest OS).  This requires that the credentials to access Prism Element are the same as the ones used for Prism Central.
.EXAMPLE
.\get-AhvVmReport.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix Prism Central VM of your choice and retrieve the list of VMs.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 21st 2019
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $true)] [string]$prismcentral,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [switch]$ngt
)
#endregion

#region prepwork

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
06/21/2019 sb   Initial release.
04/02/2020 sb   Do over to include sbourdeaud module.
################################################################################
'@
$myvarScriptName = ".\get-AhvVmReport.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

#region module sbourdeaud is used for facilitating Prism REST calls
if (!(Get-Module -Name sbourdeaud)) {
  Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
  try
  {
      Import-Module -Name sbourdeaud -ErrorAction Stop
      Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
  }#end try
  catch #we couldn't import the module, so let's install it
  {
      Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
      try {Install-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
      catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

      try
      {
          Import-Module -Name sbourdeaud -ErrorAction Stop
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
if (($MyVarModuleVersion.Version.Major -lt 3) -or (($MyVarModuleVersion.Version.Major -eq 3) -and ($MyVarModuleVersion.Version.Minor -eq 0) -and ($MyVarModuleVersion.Version.Build -lt 1))) {
  Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
  try {Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
  catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
}
#endregion
Set-PoSHSSLCerts
Set-PoshTls

#endregion

#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
#prepare our overall results variable
[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
$length=100 #this specifies how many entities we want in the results of each API query
$api_server_port = "9440"
#endregion

#region parameters validation
if (!$prismCreds) 
{#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
    if (!$username) 
    {#if Prism username has not been specified ask for it
        $username = Read-Host "Enter the Prism username"
    } 

    if (!$password) 
    {#if password was not passed as an argument, let's prompt for it
        $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
    }
    else 
    {#if password was passed as an argument, let's convert the string to a secure string and flush the memory
        $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
        Remove-Variable password
    }
    $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
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
        $credname = Read-Host "Enter the credentials name"
        Set-CustomCredentials -credname $credname
        $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
        $username = $prismCredentials.UserName
        $PrismSecurePassword = $prismCredentials.Password
    }
    $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
}
#endregion

#region main processing

#region make v3 api call for clusters (if -ngt)
if ($ngt) {
  [System.Collections.ArrayList]$myvarClusterResults = New-Object System.Collections.ArrayList($null)
  $api_server_endpoint = "/api/nutanix/v3/clusters/list"
  $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
  $method = "POST"
  
  # this is used to capture the content of the payload
  $content = @{
      kind="cluster";
      offset=0;
      length=$length
  }
  $payload = (ConvertTo-Json $content -Depth 4)
  Write-Host "$(Get-Date) [INFO] Retrieving clusters information from Prism Central $($prismcentral)" -ForegroundColor Green
  Do {
      try {
          $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
          $listLength = 0
          if ($resp.metadata.offset) {
              $firstItem = $resp.metadata.offset
          } else {
              $firstItem = 0
          }
          if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
              $listLength = $resp.metadata.length
          } else {
              $listLength = $resp.metadata.total_matches
          }
          Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
          if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
  
          #grab the information we need in each entity
          ForEach ($entity in $resp.entities) {
              $myvarClusterInfo = [ordered]@{
                  "name" = $entity.spec.name;
                  "uuid" = $entity.metadata.uuid;
                  "external_ip" = $entity.spec.resources.network.external_ip;
                  "AOS" = $entity.spec.resources.config.software_map.NOS.version
              }
              #store the results for this entity in our overall result variable
              $myvarClusterResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
          }
  
          #prepare the json payload for the next batch of entities/response
          $content = @{
              kind="cluster";
              offset=($resp.metadata.length + $resp.metadata.offset);
              length=$length
          }
          $payload = (ConvertTo-Json $content -Depth 4)
      }
      catch {
          $saved_error = $_.Exception.Message
          # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
          Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
          Throw "$(get-date) [ERROR] $saved_error"
      }
      finally {
          #add any last words here; this gets processed no matter what
      }
  }
  While ($resp.metadata.length -eq $length)
  
  if ($debugme) {
      Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
      $myvarClusterResults
  }
}
#endregion

#region make v3 api call for vms
# this is used to capture the content of the payload
$content = @{
    kind="vm";
    offset=0;
    length=$length
}
$payload = (ConvertTo-Json $content -Depth 4)
Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral)" -ForegroundColor Green
Do {
    try {
        $api_server_endpoint = "/api/nutanix/v3/vms/list"
        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
        $method = "POST"
        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
        $listLength = 0
        if ($resp.metadata.offset) {
            $firstItem = $resp.metadata.offset
        } else {
            $firstItem = 0
        }
        if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
            $listLength = $resp.metadata.length
        } else {
            $listLength = $resp.metadata.total_matches
        }
        Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

        #grab the information we need in each entity
        ForEach ($entity in $resp.entities) {
          if ($ngt) {
            $myvarClusterIp = ($myvarClusterResults | Where-Object {$_.uuid -eq $entity.spec.cluster_reference.uuid}).external_ip
            if (!$myvarClusterIp) {throw "$(get-date) [ERROR] COuld not find external ip address of cluster $($entity.spec.cluster_reference.name)"}
            $api_server_endpoint = "/PrismGateway/services/rest/v1/vms/?filterCriteria=vm_uuid%3D%3D{0}" -f $entity.metadata.uuid
            $url = "https://{0}:{1}{2}" -f $myvarClusterIp,$api_server_port, $api_server_endpoint
            $method = "GET"
            try {
              Write-Host "$(Get-Date) [INFO] Retrieving detailed VM information for $($entity.spec.name) from cluster $($entity.spec.cluster_reference.name)" -ForegroundColor Green
              $myvarVmDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
              Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved detailed VM information for $($entity.spec.name) from cluster $($entity.spec.cluster_reference.name)" -ForegroundColor Cyan
            }
            catch {
              $saved_error = $_.Exception.Message
              # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
              #Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
              Throw "$(get-date) [ERROR] $saved_error"
            }
            $myvarVmInfo = [ordered]@{
              "name" = $entity.spec.name;
              "os" = $myvarVmDetails.entities.guestOperatingSystem;
              "ip_addresses" = $myvarVmDetails.entities.ipAddresses -join ',';
              "virtual_disks" = $myvarVmDetails.entities.nutanixVirtualDisks -join ',';
              "flash_mode" = $myvarVmDetails.entities.vmFeatures.FLASH_MODE;
              "description" = $myvarVmDetails.entities.description;
              "ngt_status" = $myvarVmDetails.entities.nutanixGuestTools.enabled;
              "ngt_version" = $myvarVmDetails.entities.nutanixGuestTools.installedVersion;
              "ngt_vss_snapshot" = $myvarVmDetails.entities.nutanixGuestTools.applications.vss_snapshot;
              "ngt_vss_file_level_restore" = $myvarVmDetails.entities.nutanixGuestTools.applications.file_level_restore;
              "ngt_iso_mounted" = $myvarVmDetails.entities.nutanixGuestTools.toolsMounted;
              "ngt_communication_alive" = $myvarVmDetails.entities.nutanixGuestTools.communicationLinkActive;
              "num_sockets" = $entity.spec.resources.num_sockets;
              "memory_size_mib" = $entity.spec.resources.memory_size_mib;
              "power_state" = $entity.spec.resources.power_state;
              "cluster" = $entity.spec.cluster_reference.name;
              "hypervisor" = $entity.status.resources.hypervisor_type;
              "creation_time" = $entity.metadata.creation_time;
              "owner" = $entity.metadata.owner_reference.name;
              "protection_type" = $entity.status.resources.protection_type;
              "vdisk_count" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"}).Count;
              "vdisk_total_mib" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"} | Measure-Object disk_size_mib -Sum).Sum;
              "vnic_count" = ($entity.spec.resources.nic_list).Count;
              "vnic_vlans" = (($entity.spec.resources.nic_list | Select-Object -Property subnet_reference).name) -join ',';
              "vnic_macs" = (($entity.spec.resources.nic_list | Select-Object -Property mac_address).mac_address) -join ',';
              "gpu" = $entity.status.resources.gpu_list | Select-Object -First 1;
              "uuid" = $entity.metadata.uuid
            }
          } else {
            $myvarVmInfo = [ordered]@{
                "name" = $entity.spec.name;
                "num_sockets" = $entity.spec.resources.num_sockets;
                "memory_size_mib" = $entity.spec.resources.memory_size_mib;
                "power_state" = $entity.spec.resources.power_state;
                "cluster" = $entity.spec.cluster_reference.name;
                "hypervisor" = $entity.status.resources.hypervisor_type;
                "creation_time" = $entity.metadata.creation_time;
                "owner" = $entity.metadata.owner_reference.name;
                "protection_type" = $entity.status.resources.protection_type;
                "vdisk_count" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"}).Count;
                "vdisk_total_mib" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"} | Measure-Object disk_size_mib -Sum).Sum;
                "vnic_count" = ($entity.spec.resources.nic_list).Count;
                "vnic0_vlan" = $entity.spec.resources.nic_list[0].subnet_reference.name;
                "vnic0_mac" = $entity.spec.resources.nic_list[0].mac_address;
                "vnic1_vlan" = $entity.spec.resources.nic_list[1].subnet_reference.name;
                "vnic1_mac" = $entity.spec.resources.nic_list[1].mac_address;
                "gpu" = $entity.status.resources.gpu_list | Select-Object -First 1;
                "uuid" = $entity.metadata.uuid
            }
          }
          #store the results for this entity in our overall result variable
          $myvarResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="vm";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
        #add any last words here; this gets processed no matter what
    }
}
While ($resp.metadata.length -eq $length)

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $myvarResults
}
Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")VmList.csv" -ForegroundColor Green
$myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"VmList.csv")
#endregion

#endregion

#region Cleanup	
#let's figure out how much time this all took
Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable help -ErrorAction SilentlyContinue
Remove-Variable history -ErrorAction SilentlyContinue
Remove-Variable log -ErrorAction SilentlyContinue
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable cluster -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
