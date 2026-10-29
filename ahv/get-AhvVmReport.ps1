<#
.SYNOPSIS
  This script retrieves the complete list of virtual machines from Prism Central using v4 API.
.DESCRIPTION
  This script retrieves the complete list of virtual machines from Prism Central, including each VM specs and exports the results to csv in the current directory.
  Uses Nutanix Prism Central v4 API (VMM for VMs) and v3 API (for clusters, since v4 doesn't have clusters endpoint).
.PARAMETER help
  Displays a help message.
.PARAMETER history
  Displays a release history for this script.
.PARAMETER debugme
  Turns on debug output.
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
  Revision: October 29th 2026 - Migrated to v4 API (VMs) with v3 fallback for clusters
#>

#region parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$prismcentral,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [switch]$ngt
  )
#endregion


#region prepwork

  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Migrated to Prism Central v4 API (VMM for VMs), v3 for clusters; inline helpers; fixed SSL for PS7+
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
10/20/2026 sb   Fix Set-PoSHSSLCerts/Set-PoshTls for PowerShell 7 (avoid SYSLIB0014 Add-Type errors).
06/21/2019 sb   Initial release.
04/02/2020 sb   Do over to include sbourdeaud module.
02/06/2021 sb   Replaced username with get-credential
04/15/2022 sb   Added functions and removed dependency to sbourdeaud module.
################################################################################
'@
  $myvarScriptName = ".\get-AhvVmReport.ps1"

    if ($help) {
        $helpContent = Get-Content $PSCommandPath -Raw
        $inHelp = $false
        $helpLines = @()
        foreach ($line in $helpContent -split "`n") {
            if ($line -match '^<#') { $inHelp = $true; continue }
            if ($line -match '^#>') { break }
            if ($inHelp) { $helpLines += $line }
        }
        $helpLines -join "`n" | Write-Host
        exit
    }
  if ($History) {$HistoryText; exit}

  #check PoSH version
  if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

  #region helper functions (previously from sbourdeaud module)
  function Invoke-PrismAPICall {
      param (
          [parameter(mandatory = $false)]
          [ValidateSet("POST","GET","DELETE","PUT")]
          [string]$method,

          [parameter(mandatory = $false)]
          [string]$url,

          [parameter(mandatory = $false)]
          [string]$payload,

          [parameter(mandatory = $false)]
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

  function Invoke-PrismAPICallWithRetry {
      param (
          [parameter(mandatory = $true)]
          [hashtable]$InvokeParams,

          [parameter(mandatory = $false)]
          [int]$MaxRetries = 3,

          [parameter(mandatory = $false)]
          [string]$RequestId = (New-Guid).ToString()
      )
      $attempt = 0
      $delayMs = 1000
      # For PS7+, add SSL certificate bypass parameters
      $sslParams = @{}
      if ($PSVersionTable.PSVersion.Major -gt 5) {
          $sslParams = @{
              SkipCertificateCheck = $true
              SslProtocol          = 'Tls12'
          }
      }
      while ($true) {
          try {
              $response = Invoke-RestMethod @InvokeParams @sslParams
              return $response
          }
          catch {
              $statusCode = $null
              if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                  try { $statusCode = [int][System.Net.HttpStatusCode]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
              }
              if (($statusCode -in 429, 503) -and ($attempt -lt $MaxRetries)) {
                  $attempt++
                  Write-Host "$(Get-Date) [WARN] Transient error (HTTP $statusCode), retry $attempt/$MaxRetries in ${delayMs}ms" -ForegroundColor Yellow
                  Start-Sleep -Milliseconds $delayMs
                  $delayMs = [Math]::Min($delayMs * 2, 30000)
                  continue
              }
              Write-Host "$(Get-Date) [ERROR] API call failed: $($_.Exception.Message)" -ForegroundColor Red
              throw
          }
      }
  }

  function Set-CustomCredentials {
      param (
          [parameter(mandatory = $false)]
          [string]$path,

          [parameter(mandatory = $false)]
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

          [parameter(mandatory = $false)]
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
  $pageLimit = 100
  $api_server_port = "9440"
#endregion


#region parameters validation
    if (!$prismcentral) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral!"
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
  
  # Build auth header for v4 API calls
  $pair = "$($prismCredentials.UserName):$($prismCredentials.GetNetworkCredential().Password)"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
  $base64 = [Convert]::ToBase64String($bytes)
  $v4Headers = @{
      'Content-Type' = 'application/json'
      'Accept'       = 'application/json'
      'Authorization' = "Basic $base64"
  }
  $baseUri = "https://${prismcentral}:${api_server_port}/api"
  
  # v3 clusters endpoint (v4 doesn't have clusters list)
  $v3ClustersUrl = "https://${prismcentral}:${api_server_port}/api/nutanix/v3/clusters/list"
  $v3Payload = '{"kind":"cluster","offset":0,"length":100}'
#endregion


#region main processing

  #region Build cluster lookup table (using v3 API since v4 doesn't have clusters endpoint)
  [System.Collections.Hashtable]$clusterLookup = @{}
  [System.Collections.Hashtable]$clusterNameLookup = @{}
  
  Write-Host "$(Get-Date) [INFO] Retrieving clusters information from Prism Central $($prismcentral) (v3 API)" -ForegroundColor Green
  try 
  {
      $resp = Invoke-PrismAPICall -method "POST" -url $v3ClustersUrl -payload $v3Payload -credential $prismCredentials
      if ($resp.entities) {
          ForEach ($entity in $resp.entities) 
          {
              $clusterUuid = $entity.metadata.uuid
              $clusterLookup[$clusterUuid] = $entity.spec.resources.network.external_ip
              $clusterNameLookup[$clusterUuid] = $entity.spec.name
              if ($debugme) {
                  Write-Host "$(Get-Date) [DEBUG] Cluster: $($entity.spec.name) UUID=$clusterUuid IP=$($entity.spec.resources.network.external_ip)" -ForegroundColor White
              }
          }
      }
  }
  catch 
  {
      Write-Host "$(Get-Date) [ERROR] Failed to retrieve clusters: $($_.Exception.Message)" -ForegroundColor Red
      Throw "$(get-date) [ERROR] $($_.Exception.Message)"
  }
  
  if ($debugme) 
  {
      Write-Host "$(Get-Date) [DEBUG] Cluster lookup table has $($clusterLookup.Count) entries" -ForegroundColor White
  }
  #endregion

  #region make v4 api call for vms
  # v4 VMM API uses GET with $page, $limit (no $select needed - we get full objects)
  $page = 0
  
  Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)" -ForegroundColor Green
  Do 
  {
      try 
      {
          $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$pageLimit"
          Write-Host "$(Get-Date) [INFO] Fetching VMs page $page" -ForegroundColor Green
          if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $vmsUri" -ForegroundColor White }
          
          $invokeParams = @{
              Uri        = $vmsUri
              Method     = 'GET'
              Headers    = $v4Headers
              TimeoutSec = 60
          }
          $resp = Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
          
          if ($resp.data) {
              ForEach ($entity in $resp.data) 
              {
                # Map v4 VM fields
                $vmExtId = $entity.extId
                $vmName = $entity.name
                $numSockets = $entity.numSockets
                $numCoresPerSocket = $entity.numCoresPerSocket
                $numVcpus = $numSockets * $numCoresPerSocket
                $memorySizeBytes = $entity.memorySizeBytes
                $memorySizeMiB = [math]::Round($memorySizeBytes / 1MB)
                $powerState = $entity.powerState
                $clusterExtId = $entity.cluster.extId
                $clusterName = $clusterNameLookup[$clusterExtId] ?? "Unknown"
                $hostExtId = $entity.host.extId
                $description = $entity.description
                $createTime = $entity.createTime
                $ownerExtId = $entity.ownershipInfo.owner.extId
                $disks = $entity.disks
                $nics = $entity.nics
                
                # Count disks and calculate total size
                $vdiskCount = 0
                $vdiskTotalMiB = 0
                if ($disks) {
                    foreach ($disk in $disks) {
                        # v4 disk structure: diskAddress.busType (SCSI/IDE/VIRTIO), backingInfo.diskSizeBytes
                        # All disks in this array are virtual disks (no CDROM differentiation)
                        $vdiskCount++
                        if ($disk.backingInfo.diskSizeBytes) {
                            $vdiskTotalMiB += [math]::Round($disk.backingInfo.diskSizeBytes / 1MB)
                        }
                    }
                }
                
                # NIC info
                $vnicCount = 0
                $vnicVlans = @()
                $vnicMacs = @()
                $vnic0Vlan = ""
                $vnic0Mac = ""
                $vnic1Vlan = ""
                $vnic1Mac = ""
                if ($nics) {
                    $vnicCount = $nics.Count
                    $i = 0
                    foreach ($nic in $nics) {
                        # v4 NIC structure: nicNetworkInfo.subnet.extId, nicBackingInfo.macAddress
                        $subnetExtId = $nic.nicNetworkInfo.subnet.extId
                        $macAddr = $nic.nicBackingInfo.macAddress
                        $vnicVlans += $subnetExtId  # Using extId since name not in response
                        $vnicMacs += $macAddr
                        if ($i -eq 0) { $vnic0Vlan = $subnetExtId; $vnic0Mac = $macAddr }
                        if ($i -eq 1) { $vnic1Vlan = $subnetExtId; $vnic1Mac = $macAddr }
                        $i++
                    }
                }
                $vnicVlansStr = $vnicVlans -join ','
                $vnicMacsStr = $vnicMacs -join ','
                $vnicVlansStr = $vnicVlans -join ','
                $vnicMacsStr = $vnicMacs -join ','
                
                if ($ngt) 
                {
                  # Get cluster IP for NGT
                  $myvarClusterIp = $clusterLookup[$clusterExtId]
                  if (!$myvarClusterIp) {throw "$(get-date) [ERROR] Could not find external ip address of cluster $clusterName (extId=$clusterExtId)"}
                  
                  # NGT still uses Prism Element REST API (unchanged)
                  $api_server_endpoint = "/PrismGateway/services/rest/v1/vms/?filterCriteria=vm_uuid%3D%3D{0}" -f $vmExtId
                  $url = "https://{0}:{1}{2}" -f $myvarClusterIp,$api_server_port, $api_server_endpoint
                  $method = "GET"
                  try 
                  {
                    Write-Host "$(Get-Date) [INFO] Retrieving detailed VM information for $vmName from cluster $clusterName" -ForegroundColor Green
                    $myvarVmDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved detailed VM information for $vmName from cluster $clusterName" -ForegroundColor Cyan
                  }
                  catch 
                  {
                    Throw "$(get-date) [ERROR] $($_.Exception.Message)"
                  }
                  $myvarVmInfo = [ordered]@{
                    "name" = $vmName;
                    #"os" = $myvarVmDetails.entities.guestOperatingSystem;
                    "ip_addresses" = $myvarVmDetails.entities.ipAddresses -join ',';
                    "virtual_disks" = $myvarVmDetails.entities.nutanixVirtualDisks -join ',';
                    "flash_mode" = $myvarVmDetails.entities.vmFeatures.FLASH_MODE;
                    "description" = $description;
                    "ngt_status" = $myvarVmDetails.entities.nutanixGuestTools.enabled;
                    "ngt_version" = $myvarVmDetails.entities.nutanixGuestTools.installedVersion;
                    "ngt_vss_snapshot" = $myvarVmDetails.entities.nutanixGuestTools.applications.vss_snapshot;
                    "ngt_vss_file_level_restore" = $myvarVmDetails.entities.nutanixGuestTools.applications.file_level_restore;
                    "ngt_iso_mounted" = $myvarVmDetails.entities.nutanixGuestTools.toolsMounted;
                    "ngt_communication_alive" = $myvarVmDetails.entities.nutanixGuestTools.communicationLinkActive;
                    "num_sockets" = $numSockets;
                    "num_cores_per_socket" = $numCoresPerSocket;
                    "num_vcpus" = $numVcpus;
                    "memory_size_mib" = $memorySizeMiB;
                    "power_state" = $powerState;
                    "cluster" = $clusterName;
                    "cluster_extId" = $clusterExtId;
                    "host_extId" = $hostExtId;
                    "creation_time" = $createTime;
                    "owner_extId" = $ownerExtId;
                    "protection_type" = "N/A";  # Not available in v4 VM response
                    "vdisk_count" = $vdiskCount;
                    "vdisk_total_mib" = $vdiskTotalMiB;
                    "vnic_count" = $vnicCount;
                    "vnic_vlans" = $vnicVlansStr;
                    "vnic_macs" = $vnicMacsStr;
                    "vnic0_vlan" = $vnic0Vlan;
                    "vnic0_mac" = $vnic0Mac;
                    "vnic1_vlan" = $vnic1Vlan;
                    "vnic1_mac" = $vnic1Mac;
                    "gpu" = "N/A";  # Not available in v4 VM response
                    "extId" = $vmExtId
                  }
                } 
                else 
                {
                  $myvarVmInfo = [ordered]@{
                      "name" = $vmName;
                      "num_sockets" = $numSockets;
                      "num_cores_per_socket" = $numCoresPerSocket;
                      "num_vcpus" = $numVcpus;
                      "memory_size_mib" = $memorySizeMiB;
                      "power_state" = $powerState;
                      "cluster" = $clusterName;
                      "cluster_extId" = $clusterExtId;
                      "host_extId" = $hostExtId;
                      "creation_time" = $createTime;
                      "owner_extId" = $ownerExtId;
                      "protection_type" = "N/A";  # Not available in v4 VM response
                      "vdisk_count" = $vdiskCount;
                      "vdisk_total_mib" = $vdiskTotalMiB;
                      "vnic_count" = $vnicCount;
                      "vnic_vlans" = $vnicVlansStr;
                      "vnic0_vlan" = $vnic0Vlan;
                      "vnic0_mac" = $vnic0Mac;
                      "vnic1_vlan" = $vnic1Vlan;
                      "vnic1_mac" = $vnic1Mac;
                      "gpu" = "N/A";  # Not available in v4 VM response
                      "extId" = $vmExtId
                  }
                }
                #store the results for this entity in our overall result variable
                $myvarResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
              }
          }
          
          if (-not $resp.data -or (@($resp.data)).Count -eq 0) { break }
          $page++
      }
      catch 
      {
          Write-Host "$(Get-Date) [ERROR] $($_.Exception.Message)" -ForegroundColor Red
          Throw "$(get-date) [ERROR] $($_.Exception.Message)"
      }
  }
  While ($resp.data -and $resp.data.Count -eq $pageLimit)

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
  Remove-Variable pageLimit -ErrorAction SilentlyContinue
  Remove-Variable api_server_port -ErrorAction SilentlyContinue
  Remove-Variable v4Headers -ErrorAction SilentlyContinue
  Remove-Variable baseUri -ErrorAction SilentlyContinue
  Remove-Variable v3ClustersUrl -ErrorAction SilentlyContinue
  Remove-Variable v3Payload -ErrorAction SilentlyContinue
  Remove-Variable clusterLookup -ErrorAction SilentlyContinue
  Remove-Variable clusterNameLookup -ErrorAction SilentlyContinue
#endregion