<#
.SYNOPSIS
  This script retrieves the complete list of virtual machines from Prism Central.
.DESCRIPTION
  This script retrieves the complete list of virtual machines from Prism Central, including each VM specs and exports the results to csv in the current directory.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER ngt
  Retrieves additional VM information, including Nutanix Guest Tools status and version.  This requires that the credentials to access Prism Element are the same as the ones used for Prism Central.
.EXAMPLE
.\get-AhvVmReport.ps1 -prismcentral ntnxc1.local
Connect to a Nutanix Prism Central VM of your choice and retrieve the list of VMs.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $true)] [string]$prismcentral,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [switch]$ngt
  )
#endregion


#region prepwork

  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
10/20/2026 sb   Fix Set-PoSHSSLCerts/Set-PoshTls for PowerShell 7 (avoid SYSLIB0014 Add-Type errors).
06/21/2019 sb   Initial release.
04/02/2020 sb   Do over to include sbourdeaud module.
02/06/2021 sb   Replaced username with get-credential
04/15/2022 sb   Added functions and removed dependency to sbourdeaud module.
################################################################################
'
  $myvarScriptName = ".\get-AhvVmReport.ps1"

  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

  #check PoSH version
  if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

  #region helper functions (previously from sbourdeaud module)
  function Invoke-PrismAPICall {
      param (
          [parameter(mandatory = $true)]
          [ValidateSet("POST","GET","DELETE","PUT")]
          [string]$method,

          [parameter(mandatory = $true)]
          [string]$url,

          [parameter(mandatory = $false)]
          [string]$payload,

          [parameter(mandatory = $true)]
          [System.Management.Automation.PSCredential]$credential
      )

      Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
      try {
          if ($PSVersionTable.PSVersion.Major -gt 5) {
              $headers = @{
                  "Content-Type" = "application/json"
                  "Accept"       = "application/json"
              }
              if ($payload) {
                  $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
              } else {
                  $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
              }
          } else {
              $username = $credential.UserName
              $password = $credential.Password
              $headers = @{
                  "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))))
                  "Content-Type"  = "application/json"
                  "Accept"        = "application/json"
              }
              if ($payload) {
                  $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
              } else {
                  $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
              }
          }
          Write-Host "$(Get-Date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan
          if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White }
      }
      catch {
          Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
          throw "$(Get-Date) [ERROR] $($_.Exception.Message)"
      }
      return $resp
  }

  function Set-CustomCredentials {
      param (
          [parameter(mandatory = $false)]
          [string]$path,

          [parameter(mandatory = $true)]
          [string]$credname
      )

      if (!$path) {
          if ($IsLinux -or $IsMacOS) {
              $path = $home
          } else {
              $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
          }
          Write-Host "$(Get-Date) [INFO] Set path to $path" -ForegroundColor Green
      }

      $credentialsFilePath = "$path\$credname.txt"
      $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
      $user = $credentials.UserName
      $securePassword = $credentials.Password

      try {
          $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
      }
      catch {
          throw "$(Get-Date) [ERROR] Could not convert password : $($_.Exception.Message)"
      }

      if (!(Test-Path $path)) {
          try {
              New-Item -Type Directory $path -ErrorAction Stop | Out-Null
          }
          catch {
              throw "$(Get-Date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
          }
      }

      try {
          Set-Content $credentialsFilePath $user -ErrorAction Stop
      }
      catch {
          throw "$(Get-Date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
      }
      try {
          Add-Content $credentialsFilePath $password -ErrorAction Stop
      }
      catch {
          throw "$(Get-Date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
      }

      Write-Host "$(Get-Date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan
  }

  function Get-CustomCredentials {
      param (
          [parameter(mandatory = $false)]
          [string]$path,

          [parameter(mandatory = $true)]
          [string]$credname
      )

      if (!$path) {
          if ($IsLinux -or $IsMacOS) {
              $path = $home
          } else {
              $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
          }
          Write-Host "$(Get-Date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
      }

      $credentialsFilePath = "$path\$credname.txt"
      if (!(Test-Path $credentialsFilePath)) {
          throw "$(Get-Date) [ERROR] Could not access file $credentialsFilePath"
      }

      $credFile = Get-Content $credentialsFilePath
      $user = $credFile[0]
      $securePassword = $credFile[1] | ConvertTo-SecureString
      $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

      Write-Host "$(Get-Date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan
      return $customCredentials
  }

  function Set-PoshTls {
      if ($PSVersionTable.PSVersion.Major -gt 5) {
          # PowerShell 7+ already defaults to TLS 1.2+; Invoke-PrismAPICall also sets -SslProtocol Tls12
          return
      }
      Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
      [Net.ServicePointManager]::SecurityProtocol = (
          [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      )
  }

  function Set-PoSHSSLCerts {
      # PowerShell 6+ uses -SkipCertificateCheck on Invoke-RestMethod (see Invoke-PrismAPICall).
      # The old ServicePointManager Add-Type path is obsolete on modern .NET and fails to compile (SYSLIB0014).
      if ($PSVersionTable.PSVersion.Major -gt 5) {
          Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates (SkipCertificateCheck)" -ForegroundColor Green
          return
      }

      Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates" -ForegroundColor Green
      if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
          $certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{
    public static void Ignore()
    {
        if (ServicePointManager.ServerCertificateValidationCallback == null)
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                delegate (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                {
                    return true;
                };
        }
    }
}
"@
          Add-Type $certCallback
      }
      [ServerCertificateValidationCallback]::Ignore()
  }
  #endregion

  Set-PoSHSSLCerts
  Set-PoshTls
#endregion


#region variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
  [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
  $length = 100
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

  #region make v3 api call for clusters (if -ngt)
    if ($ngt) 
    {
      [System.Collections.ArrayList]$myvarClusterResults = New-Object System.Collections.ArrayList($null)
      $url = "https://{0}:{1}/api/nutanix/v3/clusters/list" -f $prismcentral,$api_server_port
      $method = "POST"
      $content = @{
          kind="cluster";
          offset=0;
          length=$length
      }
      $payload = (ConvertTo-Json $content -Depth 4)
      
      Write-Host "$(Get-Date) [INFO] Retrieving clusters information from Prism Central $($prismcentral)" -ForegroundColor Green
      Do 
      {
          try 
          {
              $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
              if ($resp.entities) {
                  ForEach ($entity in $resp.entities) 
                  {
                      $myvarClusterInfo = [ordered]@{
                          "name" = $entity.spec.name;
                          "uuid" = $entity.metadata.uuid;
                          "external_ip" = $entity.spec.resources.network.external_ip;
                          "AOS" = $entity.spec.resources.config.software_map.NOS.version
                      }
                      $myvarClusterResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
                  }
              }
              $content.offset = $content.offset + $content.length
              $payload = (ConvertTo-Json $content -Depth 4)
          }
          catch 
          {
              Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
              Throw "$(get-date) [ERROR] $($_.Exception.Message)"
          }
      }
      While ($resp.metadata.length -eq $length)
      
      if ($debugme) 
      {
          Write-Host "$(Get-Date) [DEBUG] Showing cluster results:" -ForegroundColor White
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
  Do 
  {
      try 
      {
          $api_server_endpoint = "/api/nutanix/v3/vms/list"
          $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
          $method = "POST"
          $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
          
          if ($resp.entities) {
              ForEach ($entity in $resp.entities) 
              {
                if ($ngt) 
                {
                  $myvarClusterIp = ($myvarClusterResults | Where-Object {$_.uuid -eq $entity.spec.cluster_reference.uuid}).external_ip
                  if (!$myvarClusterIp) {throw "$(get-date) [ERROR] Could not find external ip address of cluster $($entity.spec.cluster_reference.name)"}
                  $api_server_endpoint = "/PrismGateway/services/rest/v1/vms/?filterCriteria=vm_uuid%3D%3D{0}" -f $entity.metadata.uuid
                  $url = "https://{0}:{1}{2}" -f $myvarClusterIp,$api_server_port, $api_server_endpoint
                  $method = "GET"
                  try 
                  {
                    Write-Host "$(Get-Date) [INFO] Retrieving detailed VM information for $($entity.spec.name) from cluster $($entity.spec.cluster_reference.name)" -ForegroundColor Green
                    $myvarVmDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved detailed VM information for $($entity.spec.name) from cluster $($entity.spec.cluster_reference.name)" -ForegroundColor Cyan
                  }
                  catch 
                  {
                    Throw "$(get-date) [ERROR] $($_.Exception.Message)"
                  }
                  $myvarVmInfo = [ordered]@{
                    "name" = $entity.spec.name;
                    #"os" = $myvarVmDetails.entities.guestOperatingSystem;
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
                    "vnic_vlans" = (($entity.spec.resources.nic_list | Select-Object -Property subnet_reference).subnet_reference.name) -join ',';
                    "vnic_macs" = (($entity.spec.resources.nic_list | Select-Object -Property mac_address).mac_address) -join ',';
                    "gpu" = $entity.status.resources.gpu_list | Select-Object -First 1;
                    "uuid" = $entity.metadata.uuid
                  }
                } 
                else 
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
          }
          
          $content.offset = $content.offset + $content.length
          $payload = (ConvertTo-Json $content -Depth 4)
      }
      catch 
      {
          Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
          Throw "$(get-date) [ERROR] $($_.Exception.Message)"
      }
  }
  While ($resp.metadata.length -eq $length)

  if ($debugme) 
  {
      Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
      $myvarResults
  }
  Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")VmList.csv" -ForegroundColor Green
  $myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"VmList.csv")
  #endregion

#endregion


#region Cleanup	
  #let's figure out how much time this all took
  Write-Host ""
  Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

  #cleanup after ourselves and delete all custom variables
  Remove-Variable myvar* -ErrorAction SilentlyContinue
  Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
  Remove-Variable help -ErrorAction SilentlyContinue
  Remove-Variable history -ErrorAction SilentlyContinue
  Remove-Variable log -ErrorAction SilentlyContinue
  Remove-Variable cluster -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
  Remove-Variable prismcentral -ErrorAction SilentlyContinue
  Remove-Variable prismCreds -ErrorAction SilentlyContinue
  Remove-Variable ngt -ErrorAction SilentlyContinue
  Remove-Variable length -ErrorAction SilentlyContinue
  Remove-Variable api_server_port -ErrorAction SilentlyContinue
#endregion