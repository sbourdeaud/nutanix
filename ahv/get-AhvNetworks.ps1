<#
.SYNOPSIS
  This script retrieves the complete list of AHV networks from Prism Central.
.DESCRIPTION
  This script retrieves the complete list of AHV networks from Prism Central, including IP pool information and exports the results to csv in the current directory.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.EXAMPLE
.\get-AhvNetworks.ps1 -cluster ntnxc1.local
Connect to a Nutanix Prism Central of your choice and retrieve the list of networks.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: November 13th 2020
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
      [parameter(mandatory = $false)] $prismCreds
  )
#endregion

#region prepwork
  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
11/13/2020 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
  $myvarScriptName = ".\get-AhvNetworks.ps1"

  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

  #check PoSH version
  if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

  #region module sbourdeaud is used for facilitating Prism REST calls
    $required_version = "3.0.8"
    if (!(Get-Module -Name sbourdeaud)) 
    {
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
    if (($MyVarModuleVersion.Version.Major -lt $($required_version.split('.')[0])) -or (($MyVarModuleVersion.Version.Major -eq $($required_version.split('.')[0])) -and ($MyVarModuleVersion.Version.Minor -eq $($required_version.split('.')[1])) -and ($MyVarModuleVersion.Version.Build -lt $($required_version.split('.')[2])))) 
    {
      Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
      Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
      Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
      try 
      {
        Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
        Import-Module -Name sbourdeaud -ErrorAction Stop
      }
      catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
    }
  #endregion
  Set-PoSHSSLCerts
  Set-PoshTls

  if (!(Get-Module -Name Indented.net.IP))
  {
    Write-Host "$(get-date) [INFO] Importing module 'Indented.net.IP'..." -ForegroundColor Green
    try
    {
        Import-Module -Name Indented.net.IP -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Imported module 'Indented.net.IP'!" -ForegroundColor Cyan
    }#end try
    catch #we couldn't import the module, so let's install it
    {
        Write-Host "$(get-date) [INFO] Installing module 'Indented.net.IP' from the Powershell Gallery..." -ForegroundColor Green
        try {Install-Module -Name Indented.net.IP -Scope CurrentUser -Force -ErrorAction Stop}
        catch {throw "$(get-date) [ERROR] Could not install module 'Indented.net.IP': $($_.Exception.Message)"}

        try
        {
            Import-Module -Name Indented.net.IP -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Imported module 'Indented.net.IP'!" -ForegroundColor Cyan
        }#end try
        catch #we couldn't import the module
        {
            Write-Host "$(get-date) [ERROR] Unable to import the module Indented.net.IP : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/Indented.Net.IP/6.1.0" -ForegroundColor Yellow
            Exit
        }#end catch
    }#end catch
  }
#endregion

#region variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
  $length=100 #this specifies how many entities we want in the results of each API query
  $api_server_port = "9440"
#endregion

#region parameters validation
  if (!$prismCreds) 
  {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
      $prismCredentials = Get-Credential -Message "Please enter Prism credentials"
  } 
  else 
  { #we are using custom credentials, so let's grab the username and password from that
      try 
      {
          $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
      }
      catch 
      {
          Set-CustomCredentials -credname $prismCreds
          $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
      }
  }
  $username = $prismCredentials.UserName
  $PrismSecurePassword = $prismCredentials.Password
  $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
#endregion

#region main processing
  #region make v3 api call for vms
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving VM information from Prism Central $($prismcentral)" -ForegroundColor Magenta
    # this is used to capture the content of the payload
    $content = @{
      kind="vm";
      offset=0;
      length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
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
          ForEach ($entity in $resp.entities) 
          {
            $myvarVmInfo = [ordered]@{
                "name" = $entity.spec.name;
                "num_sockets" = $entity.spec.resources.num_sockets;
                "memory_size_mib" = $entity.spec.resources.memory_size_mib;
                "power_state" = $entity.spec.resources.power_state;
                "cluster" = $entity.spec.cluster_reference.name;
                "hypervisor" = $entity.status.resources.hypervisor_type;
                "creation_time" = $entity.metadata.creation_time;
                "owner" = $entity.metadata.owner_reference.name;
                "vdisk_count" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"}).Count;
                "vdisk_total_mib" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"} | Measure-Object disk_size_mib -Sum).Sum;
                "vnic_count" = ($entity.spec.resources.nic_list).Count;
                "vnic_vlans" = (($entity.spec.resources.nic_list | Select-Object -Property subnet_reference).subnet_reference.name) -join ',';
                "vnic_macs" = (($entity.spec.resources.nic_list | Select-Object -Property mac_address).mac_address) -join ',';
                "gpu" = $entity.status.resources.gpu_list | Select-Object -First 1;
                "uuid" = $entity.metadata.uuid
            }
            #store the results for this entity in our overall result variable
            $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
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
      $myvarVmResults
    }
  #endregion

  #region make v3 api call for networks
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving networks information from Prism Central $($prismcentral)" -ForegroundColor Magenta

    [System.Collections.ArrayList]$myvarNetworksResults = New-Object System.Collections.ArrayList($null)
    $api_server_endpoint = "/api/nutanix/v3/subnets/list"
    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
    $method = "POST"
    
    # this is used to capture the content of the payload
    $content = @{
        kind="subnet";
        offset=0;
        length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
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
              if ($entity.spec.resources.ip_config)
              {
                #* count here how many ips are available in total by looking at each ip pool: available ips
                [int]$ip_count=0
                ForEach ($range in $entity.spec.resources.ip_config.pool_list.range)
                {
                  $range_list = $range -split " "
                  $start_ip = ConvertTo-DecimalIP $range_list[0]
                  $end_ip = ConvertTo-DecimalIP $range_list[1]
                  $ip_count += $end_ip - $start_ip +1
                }
                #* count here how many vms are connected to that network: used ips
                [int]$vm_count=0
                [int]$vm_count = ($myvarVmResults | Where-Object {$_.vnic_vlans -contains $entity.spec.name}).count
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Nb of VMs connected to network $($entity.spec.name): $($vm_count)" -ForegroundColor White}
                
                #todo figure out number of remaining ips for the network (available ips - used ips)
                $myvarNetworkInfo = [ordered]@{
                  "network_name" = $entity.spec.name;
                  "network_uuid" = $entity.metadata.uuid;
                  "cluster_name" = $entity.spec.cluster_reference.name;
                  "cluster_uuid" = $entity.spec.cluster_reference.uuid;
                  "vswitch_name" = $entity.spec.resources.vswitch_name;
                  "vlan_id" = $entity.spec.resources.vlan_id;
                  "ipam" = "yes";
                  "default_gw" = $entity.spec.resources.ip_config.default_gateway_ip;
                  "ip_pools" = ($entity.spec.resources.ip_config.pool_list.range) -join ',';
                  "total_available_ips" = $ip_count;
                  "nb_connected_vms" = $vm_count;
                  "remaining_ips" = $ip_count - $vm_count;
                  "subnet_mask_length" = $entity.spec.resources.ip_config.prefix_length;
                  "subnet_mask" = (ConvertTo-Mask $entity.spec.resources.ip_config.prefix_length).IPAddressToString;
                  "network" = $entity.spec.resources.ip_config.subnet_ip;
                  "dns" = ($entity.spec.resources.ip_config.dhcp_options.domain_name_server_list) -join ',';
                  "dns_search_list" = ($entity.spec.resources.ip_config.dhcp_options.domain_search_list) -join ',';
                  "dns_domain" = $entity.spec.resources.ip_config.dhcp_options.domain_name
                }
              }
              else 
              {
                $myvarNetworkInfo = [ordered]@{
                  "network_name" = $entity.spec.name;
                  "network_uuid" = $entity.metadata.uuid;
                  "cluster_name" = $entity.spec.cluster_reference.name;
                  "cluster_uuid" = $entity.spec.cluster_reference.uuid;
                  "vswitch_name" = $entity.spec.resources.vswitch_name;
                  "vlan_id" = $entity.spec.resources.vlan_id;
                  "ipam" = "no";
                  "default_gw" = "";
                  "ip_pools" = "";
                  "total_available_ips" = "";
                  "nb_connected_vms" = "";
                  "remaining_ips" = "";
                  "subnet_mask_length" = "";
                  "subnet_mask" = "";
                  "network" = "";
                  "dns" = "";
                  "dns_search_list" = "";
                  "dns_domain" = ""
                }
              }
                
              #store the results for this entity in our overall result variable
              $myvarNetworksResults.Add((New-Object PSObject -Property $myvarNetworkInfo)) | Out-Null
            }
    
            #prepare the json payload for the next batch of entities/response
            $content = @{
                kind="subnet";
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
        $myvarNetworksResults
    }
  #endregion

  Write-Host "$(Get-Date) [DATA] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")NetworksList.csv" -ForegroundColor White
  $myvarNetworksResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"NetworksList.csv")
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
  Remove-Variable cluster -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
