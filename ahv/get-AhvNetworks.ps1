<#
.SYNOPSIS
  This script retrieves the complete list of AHV networks from Prism Central using v4 API.
.DESCRIPTION
  This script retrieves the complete list of AHV networks from Prism Central, including IP pool information and exports the results to csv in the current directory.
  Uses Nutanix Prism Central v4 APIs (VMM for VMs, Networking for subnets).
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
.EXAMPLE
.\get-AhvNetworks.ps1 -prismcentral ntnxc1.local
Connect to a Nutanix Prism Central VM of your choice and retrieve the list of networks.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026 - Migrated to v4 API
#>

#region parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$prismcentral,
      [parameter(mandatory = $false)] $prismCreds
  )
#endregion


#region prepwork

  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Migrated to Prism Central v4 API (VMM for VMs, Networking for subnets)
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
11/13/2020 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
04/15/2022 sb   Added functions and removed dependency to sbourdeaud module.
################################################################################
'@
  $myvarScriptName = ".\get-AhvNetworks.ps1"

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
#endregion


#region main processing

  #region Build cluster lookup table (using v3 API since v4 doesn't have clusters endpoint)
  [System.Collections.Hashtable]$clusterLookup = @{}  # uuid -> {name, extId}
  
  Write-Host "$(Get-Date) [INFO] Retrieving clusters information from Prism Central $($prismcentral) (v3 API)" -ForegroundColor Green
  $v3ClustersUrl = "https://${prismcentral}:${api_server_port}/api/nutanix/v3/clusters/list"
  $v3Payload = '{"kind":"cluster","offset":0,"length":100}'
  try 
  {
      $resp = Invoke-PrismAPICall -method "POST" -url $v3ClustersUrl -payload $v3Payload -credential $prismCredentials
      if ($resp.entities) {
          ForEach ($entity in $resp.entities) 
          {
              $clusterUuid = $entity.metadata.uuid
              $clusterLookup[$clusterUuid] = @{
                  name = $entity.spec.name
                  extId = $clusterUuid  # v3 UUID == v4 extId
              }
              if ($debugme) {
                  Write-Host "$(Get-Date) [DEBUG] Cluster: $($entity.spec.name) UUID=$clusterUuid" -ForegroundColor White
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

  #region Build VM NIC lookup (v4 API)
  # Used to count VMs connected to each network
  [System.Collections.Hashtable]$networkVmCount = @{}  # network extId -> VM count
  
  Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)" -ForegroundColor Green
  $page = 0
  Do 
  {
      try 
      {
          $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$pageLimit"
          Write-Host "$(Get-Date) [INFO] Fetching VMs page $($page + 1)" -ForegroundColor Green
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
                # v4 NIC structure: nicNetworkInfo.subnet.extId
                if ($entity.nics) {
                    foreach ($nic in $entity.nics) {
                        $subnetExtId = $nic.nicNetworkInfo.subnet.extId
                        if ($subnetExtId) {
                            $networkVmCount[$subnetExtId] = ($networkVmCount[$subnetExtId] + 1)
                        }
                    }
                }
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
      Write-Host "$(Get-Date) [DEBUG] Network VM count table has $($networkVmCount.Count) entries" -ForegroundColor White
  }
  #endregion

  #region make v4 api call for subnets
  # v4 Networking API uses GET with $page, $limit
  $page = 0
  [System.Collections.ArrayList]$myvarNetworksResults = New-Object System.Collections.ArrayList($null)
  
  Write-Host "$(Get-Date) [INFO] Retrieving networks information from Prism Central $($prismcentral) (v4 API)" -ForegroundColor Magenta
  Do 
  {
      try 
      {
          $subnetsUri = "${baseUri}/networking/v4.0/config/subnets?`$page=$page&`$limit=$pageLimit"
          Write-Host "$(Get-Date) [INFO] Fetching subnets page $($page + 1)" -ForegroundColor Green
          if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $subnetsUri" -ForegroundColor White }
          
          $invokeParams = @{
              Uri        = $subnetsUri
              Method     = 'GET'
              Headers    = $v4Headers
              TimeoutSec = 60
          }
          $resp = Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
          
          if ($resp.data) {
              ForEach ($entity in $resp.data) {

                
                $networkName = $entity.name
                $networkExtId = $entity.extId
                $networkType = $entity.subnetType
                $vlanId = $entity.networkId
                $vswitchRef = $entity.virtualSwitchReference
                $clusterExtId = $entity.clusterReference
                $vpcRef = $entity.vpcReference
                $isExternal = $entity.isExternal
                $isNatEnabled = $entity.isNatEnabled
                $isAdvanced = $entity.isAdvancedNetworking
                
                # Determine cluster name from lookup
                $clusterName = "Unknown"
                $clusterUuid = $clusterExtId
                if ($clusterExtId -and $clusterLookup[$clusterExtId]) {
                    $clusterName = $clusterLookup[$clusterExtId].name
                    $clusterUuid = $clusterExtId
                }
                
                # IP configuration
                $hasIpam = $false
                $defaultGw = ""
                $ipPools = @()
                $totalAvailableIps = 0
                $subnetMaskLength = ""
                $subnetMask = ""
                $networkIp = ""
                $dnsServers = ""
                $dnsSearchList = ""
                $dnsDomain = ""
                
                if ($entity.ipConfig -and $entity.ipConfig.Count -gt 0 -and $entity.ipConfig[0].ipv4) {
                    $hasIpam = $true
                    $ipv4 = $entity.ipConfig[0].ipv4
                    
                    # Subnet IP and prefix
                    $networkIp = $ipv4.ipSubnet.ip.value
                    $subnetMaskLength = $ipv4.ipSubnet.prefixLength
                    
                    # Calculate subnet mask from prefix length
                    $prefix = $subnetMaskLength
                    $mask = 0
                    for ($i = 0; $i -lt $prefix; $i++) { $mask = ($mask * 2) + 1 }
                    $mask = $mask -shl (32 - $prefix)
                    $bytes = @(
                        ($mask -shr 24) -band 0xFF
                        ($mask -shr 16) -band 0xFF
                        ($mask -shr 8) -band 0xFF
                        $mask -band 0xFF
                    )
                    $subnetMask = [System.Net.IPAddress]::New($bytes).IPAddressToString
                    
                    # Default gateway
                    $defaultGw = $ipv4.defaultGatewayIp.value
                    
                    # IP pools
                    if ($ipv4.poolList) {
                        foreach ($pool in $ipv4.poolList) {
                            $startIp = $pool.startIp.value
                            $endIp = $pool.endIp.value
                            $ipPools += "$startIp $endIp"
                            
                            # Count IPs in pool
                            $startBytes = [System.Net.IPAddress]::Parse($startIp).GetAddressBytes()
                            $endBytes = [System.Net.IPAddress]::Parse($endIp).GetAddressBytes()
                            $startInt = 0; $endInt = 0
                            foreach ($b in $startBytes) { $startInt = ($startInt * 256) + $b }
                            foreach ($b in $endBytes) { $endInt = ($endInt * 256) + $b }
                            $totalAvailableIps += $endInt - $startInt + 1
                        }
                    }
                    
                    # DHCP options (if present)
                    if ($ipv4.psobject.Properties['dhcpOptions'] -and $ipv4.dhcpOptions) {
                        $dnsServers = ($ipv4.dhcpOptions.domainNameServerList) -join ','
                        $dnsSearchList = ($ipv4.dhcpOptions.domainSearchList) -join ','
                        $dnsDomain = $ipv4.dhcpOptions.domainName
                    }
                }
                
                # VM count from NIC lookup
                $vmCount = $networkVmCount[$networkExtId] ?? 0
                $remainingIps = if ($hasIpam) { $totalAvailableIps - $vmCount } else { "" }
                
                $myvarNetworkInfo = [ordered]@{
                  "network_name" = $networkName;
                  "network_extId" = $networkExtId;
                  "cluster_name" = $clusterName;
                  "cluster_extId" = $clusterUuid;
                  "vswitch_reference" = $vswitchRef;
                  "vlan_id" = $vlanId;
                  "ipam" = if ($hasIpam) { "yes" } else { "no" };
                  "default_gw" = $defaultGw;
                  "ip_pools" = $ipPools -join ',';
                  "total_available_ips" = if ($hasIpam) { $totalAvailableIps } else { "" };
                  "nb_connected_vms" = $vmCount;
                  "remaining_ips" = $remainingIps;
                  "subnet_mask_length" = $subnetMaskLength;
                  "subnet_mask" = $subnetMask;
                  "network" = $networkIp;
                  "dns" = $dnsServers;
                  "dns_search_list" = $dnsSearchList;
                  "dns_domain" = $dnsDomain;
                  "subnet_type" = $networkType;
                  "is_external" = $isExternal;
                  "is_nat_enabled" = $isNatEnabled;
                  "is_advanced_networking" = $isAdvanced;
                  "vpc_reference" = $vpcRef
                }
                
                #store the results for this entity in our overall result variable
                $myvarNetworksResults.Add((New-Object PSObject -Property $myvarNetworkInfo)) | Out-Null
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
      Write-Host "$(Get-Date) [DEBUG] Network results count: $($myvarNetworksResults.Count)" -ForegroundColor White
  }
  #endregion
  
  $myvar_csv_out_file = $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($prismcentral)+"_NetworksList.csv"
  Write-Host "$(Get-Date) [DATA] Writing results to $($myvar_csv_out_file)" -ForegroundColor White
  $myvarNetworksResults | export-csv -NoTypeInformation $($myvar_csv_out_file)
#endregion


#region Cleanup	
  #let's figure out how much time this all took
  Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

  #cleanup after ourselves and delete all custom variables
  Remove-Variable myvar* -ErrorAction SilentlyContinue
  Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
  Remove-Variable help -ErrorAction SilentlyContinue
  Remove-Variable history -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
  Remove-Variable prismcentral -ErrorAction SilentlyContinue
  Remove-Variable prismCreds -ErrorAction SilentlyContinue
  Remove-Variable pageLimit -ErrorAction SilentlyContinue
  Remove-Variable api_server_port -ErrorAction SilentlyContinue
  Remove-Variable v4Headers -ErrorAction SilentlyContinue
  Remove-Variable baseUri -ErrorAction SilentlyContinue
  Remove-Variable clusterLookup -ErrorAction SilentlyContinue
  Remove-Variable networkVmCount -ErrorAction SilentlyContinue
#endregion