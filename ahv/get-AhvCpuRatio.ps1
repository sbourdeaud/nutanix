<#
.SYNOPSIS
  This script connects to Prism Central and for each managed cluster, returns
  the CPU oversubscription ratio using v4 API.
.DESCRIPTION
  This script connects to Prism Central and for each managed cluster, returns
  the CPU oversubscription ratio (total number of allocated vCPUs / number of 
  logical cores). Uses Nutanix Prism Central v4 APIs (VMM for VMs, clustermgmt for hosts) 
  and v3 API for clusters (v4 doesn't have clusters endpoint).
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
.PARAMETER ignorePoweredOff
  Ignores VMs which are powered off.
.EXAMPLE
.\get-AhvCpuRatio.ps1 -prismcentral ntnxc1.local
Connect to a Nutanix Prism Central VM of your choice and compute the CPU 
oversubscription ratio for each managed AHV cluster.
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
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $false)] [string]$prismcentral,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [switch]$ignorePoweredOff
    )
#endregion

#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Migrated to Prism Central v4 API (VMM for VMs, clustermgmt for hosts), v3 for clusters
10/20/2026 sb   Remove sbourdeaud module dependency; inline helpers; fix SSL for PS7
09/23/2019 sb   Initial release.
04/06/2020 sb   Do over with sbourdeaud module
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\get-AhvCpuRatio.ps1"

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
    #prepare our overall results variable
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarHostResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarClusterResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarReport = New-Object System.Collections.ArrayList($null)
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
  [System.Collections.Hashtable]$clusterLookup = @{}  # uuid -> cluster object
  
  Write-Host "$(Get-Date) [INFO] Retrieving clusters information from Prism Central $($prismcentral) (v3 API)" -ForegroundColor Green
  try 
  {
      $resp = Invoke-PrismAPICall -method "POST" -url $v3ClustersUrl -payload $v3Payload -credential $prismCredentials
      if ($resp.entities) {
          ForEach ($entity in $resp.entities) 
          {
              $clusterUuid = $entity.metadata.uuid
              # Safe access to hypervisor type
              $hypervisor = "AHV"
              if ($entity.status.resources.nodes.hypervisor_server_list) {
                  $hypervisor = $entity.status.resources.nodes.hypervisor_server_list[0].type
              }
              $clusterLookup[$clusterUuid] = @{
                  name = $entity.spec.name
                  hypervisor = $hypervisor
              }
              if ($debugme) {
                  Write-Host "$(Get-Date) [DEBUG] Cluster: $($entity.spec.name) UUID=$clusterUuid Hypervisor=$hypervisor" -ForegroundColor White
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
  # v4 VMM API uses GET with $page, $limit
  $page = 0
  
  Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)" -ForegroundColor Green
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
                # Map v4 VM fields
                $vmClusterExtId = $entity.cluster.extId
                if ($entity.numSockets -and $entity.numCoresPerSocket) {
                    $myvarVmInfo = [ordered]@{
                        "num_sockets" = $entity.numSockets;
                        "num_vcpus_per_socket" = $entity.numCoresPerSocket;
                        "num_vcpus" = $entity.numSockets * $entity.numCoresPerSocket;
                        "power_state" = $entity.powerState;
                        "cluster_extId" = $vmClusterExtId;
                    }
                    #store the results for this entity in our overall result variable
                    $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
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
      Write-Host "$(Get-Date) [DEBUG] VM results count: $($myvarVmResults.Count)" -ForegroundColor White
  }
  #endregion

  #region make v4 api call for hosts
  # v4 clustermgmt API for hosts
  $page = 0
  
  Write-Host "$(Get-Date) [INFO] Retrieving host information from Prism Central $($prismcentral) (v4 API)" -ForegroundColor Green
  Do 
  {
      try 
      {
          $hostsUri = "${baseUri}/clustermgmt/v4.0/config/hosts?`$page=$page&`$limit=$pageLimit"
          Write-Host "$(Get-Date) [INFO] Fetching hosts page $($page + 1)" -ForegroundColor Green
          if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $hostsUri" -ForegroundColor White }
          
          $invokeParams = @{
              Uri        = $hostsUri
              Method     = 'GET'
              Headers    = $v4Headers
              TimeoutSec = 60
          }
          $resp = Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
          
          if ($resp.data) {
              ForEach ($entity in $resp.data) 
              {
                # Map v4 host fields
                # v4 host structure: numberOfCpuSockets, numberOfCpuCores, cluster.uuid
                if ($entity.numberOfCpuSockets) {
                    $hostClusterExtId = $entity.cluster.uuid
                    $myvarHostInfo = [ordered]@{
                        "num_cpu_sockets" = $entity.numberOfCpuSockets;
                        "num_cpu_cores" = $entity.numberOfCpuCores;
                        "cluster_extId" = $hostClusterExtId;
                    }
                    #store the results for this entity in our overall result variable
                    $myvarHostResults.Add((New-Object PSObject -Property $myvarHostInfo)) | Out-Null
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
      Write-Host "$(Get-Date) [DEBUG] Host results count: $($myvarHostResults.Count)" -ForegroundColor White
  }
  #endregion

  #region Build cluster results from v3 lookup + v4 data
  # We need to match v4 cluster.extId with v3 cluster UUID
  # v4 uses extId, v3 uses metadata.uuid - they should be the same format
  foreach ($clusterUuid in $clusterLookup.Keys) {
      $clusterInfo = $clusterLookup[$clusterUuid]
      $myvarClusterInfo = [ordered]@{
          "cluster_name" = $clusterInfo.name;
          "hypervisor" = $clusterInfo.hypervisor;
          "cluster_extId" = $clusterUuid;  # v3 UUID == v4 extId
      }
      $myvarClusterResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
  }

  if ($debugme) 
  {
      Write-Host "$(Get-Date) [DEBUG] Cluster results count: $($myvarClusterResults.Count)" -ForegroundColor White
  }
  #endregion

#region process and print overall results
    ForEach ($cluster in $myvarClusterResults) {
        # Get VMs for this cluster
        $clusterVms = $myvarVmResults | where {$_.cluster_extId -eq $cluster.cluster_extId}
        $clusterHosts = $myvarHostResults | where {$_.cluster_extId -eq $cluster.cluster_extId}
        
        if ($ignorePoweredOff) {
            $clusterVms = $clusterVms | where {$_.power_state -eq "ON"}
        }
        
        $sumResult = $clusterVms | measure num_vcpus -sum
        $myvarAllocatedvCpus = if ($sumResult.Sum) { $sumResult.Sum } else { 0 }
        
        $avgResult = $clusterVms | measure num_vcpus -average
        $myvarAveragevCpuAllocation = if ($avgResult.Average -and $avgResult.Average -ne 'NaN') { [math]::Round($avgResult.Average) } else { 0 }
        
        $coreSumResult = $clusterHosts | measure num_cpu_cores -sum
        $myvarTotalCores = if ($coreSumResult.Sum) { $coreSumResult.Sum } else { 0 }
        
        # Debug output
        if ($debugme) {
            Write-Host "$(Get-Date) [DEBUG] Cluster $($cluster.cluster_name): vCpus=$myvarAllocatedvCpus, TotalCores=$myvarTotalCores, Hosts=$($clusterHosts.Count)" -ForegroundColor White
        }
        
        # Skip clusters with no hosts (e.g., PC management cluster)
        if ($myvarTotalCores -eq 0) {
            Write-Host "$(Get-Date) [DEBUG] Skipping cluster $($cluster.cluster_name) - no hosts found (total_cores=0)" -ForegroundColor Yellow
            continue
        }
        
        $myvarCpuRatio = [math]::Round($myvarAllocatedvCpus / $myvarTotalCores,2)
        $myvarClusterReport = [ordered]@{
            "cluster_name" = $cluster.cluster_name;
            "hypervisor" = $cluster.hypervisor;
            "cluster_extId" = $cluster.cluster_extId;
            "allocated_vcpus" = $myvarAllocatedvCpus;
            "average_vcpu_allocation" = $myvarAveragevCpuAllocation;
            "total_cores" = $myvarTotalCores;
            "cpu_ratio" = $myvarCpuRatio;
        }
        #store the results for this entity in our overall result variable
        $myvarReport.Add((New-Object PSObject -Property $myvarClusterReport)) | Out-Null
    }
    if ($myvarReport.Count -gt 0) {
        $myvarReport | ft -AutoSize
    } else {
        Write-Host "$(Get-Date) [WARN] No clusters with hosts found to calculate CPU ratio" -ForegroundColor Yellow
    }
#endregion


#region cleanup	
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
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable ignorePoweredOff -ErrorAction SilentlyContinue
    Remove-Variable pageLimit -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
    Remove-Variable v4Headers -ErrorAction SilentlyContinue
    Remove-Variable baseUri -ErrorAction SilentlyContinue
    Remove-Variable v3ClustersUrl -ErrorAction SilentlyContinue
    Remove-Variable v3Payload -ErrorAction SilentlyContinue
    Remove-Variable clusterLookup -ErrorAction SilentlyContinue
#endregion