<#
.SYNOPSIS
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
.DESCRIPTION
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
  Uses Nutanix Prism Central v4 APIs for read operations (VMM for VMs, Networking for subnets, Prism for tasks)
  and v3 API for write operations (v4 VM PUT with ETag has known 412 PRECONDITION_FAILED issue - VMM-30301).
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
.PARAMETER vms
  One or more vm name(s) (comma separated).
.PARAMETER ahv_network
  AHV network name you want to connect the specified vm(s) to. Can't be used with -vpc_subnet.
.PARAMETER vpc_subnet
  VPC subnet name you want to connect the specified vm(s) to. Can't be used with -ahv_network.
.PARAMETER skiptaskstatuscheck
  Do not check each vm update task status.
.PARAMETER dontkeepip
  When attaching to a vpc subnet, don't try to preserve the ip configuration.
.EXAMPLE
.\set-AhvVmNetwork.ps1 -prismcentral ntnxc1.local -vms myvm -ahv_network mynetwork
Connect myvm to the mynetwork AHV network:
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 30th 2026 - Hybrid v4 reads + v3 writes (v4 VM PUT ETag defect VMM-30301)
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
        [parameter(mandatory = $false)] $vms,
        [parameter(mandatory = $false)] [string]$ahv_network,
        [parameter(mandatory = $false)] [string]$vpc_subnet,
        [parameter(mandatory = $false)] [switch]$skiptaskstatuscheck,
        [parameter(mandatory = $false)] [switch]$dontkeepip
    )
#endregion


#region prepwork

    $myvar_history_text = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/30/2026 sb   Hybrid v4 reads (VMM, Networking, Prism) + v3 writes (v4 VM PUT ETag 412 VMM-30301)
10/30/2026 sb   Full v4 ETag testing: composite ETag, version-only, wildcard, no header - all fail PLAT-10005
10/30/2026 sb   Attempted full v4 but hit v4 VM PUT ETag PRECONDITION_FAILED (PLAT-10005/VMM-30301)
10/30/2026 sb   Migrated reads to Prism Central v4 API (VMM for VMs, Networking for subnets); writes use v3 API
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
04/27/2021 sb   Initial release.
06/24/2022 sb   Adding vpc_subnet option.  Replacing external module dependency with local functions.
################################################################################
'@
    $myvar_script_name = ".\set-AhvVmNetwork.ps1"

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
    if ($History) {$myvar_history_text; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $false)]
            [ValidateSet("POST","GET","DELETE","PUT","PATCH")]
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
        # For PS7+, add SSL certificate bypass parameters and capture headers
        $sslParams = @{
            SkipCertificateCheck = $true
            SslProtocol          = 'Tls12'
        }
        while ($true) {
            try {
                $respHeaders = $null
                # Add ResponseHeadersVariable to capture headers
                $invokeParamsWithHeaders = $InvokeParams.Clone()
                $invokeParamsWithHeaders.ResponseHeadersVariable = 'respHeaders'
                $response = Invoke-RestMethod @invokeParamsWithHeaders @sslParams
                # Add headers to response object (ETag is array, get first element)
                $etagValue = $respHeaders.ETag
                if ($etagValue -is [array]) { $etagValue = $etagValue[0] }
                $response | Add-Member -MemberType NoteProperty -Name 'ResponseHeaders' -Value $respHeaders -Force
                $response | Add-Member -MemberType NoteProperty -Name 'ResponseETag' -Value $etagValue -Force
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
                if ($statusCode -eq 412) {
                    Write-Host "$(Get-Date) [ERROR] Precondition failed (ETag mismatch). The resource was modified by another process." -ForegroundColor Red
                    throw "ETag mismatch - resource was modified by another process. Please retry."
                }
                if ($statusCode -eq 428) {
                    Write-Host "$(Get-Date) [ERROR] Precondition required. If-Match header is mandatory for mutations." -ForegroundColor Red
                    throw "If-Match header required for this mutation."
                }
                Write-Host "$(Get-Date) [ERROR] API call failed: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }
        }
    }

    function Invoke-PrismV4Get {
        param (
            [parameter(mandatory = $true)]
            [string]$Url,

            [parameter(mandatory = $true)]
            [hashtable]$Headers,

            [parameter(mandatory = $false)]
            [int]$TimeoutSec = 60
        )
        $invokeParams = @{
            Uri        = $Url
            Method     = 'GET'
            Headers    = $Headers
            TimeoutSec = $TimeoutSec
        }
        return Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
    }

    function Invoke-PrismV3Post {
        param (
            [parameter(mandatory = $true)]
            [string]$Url,

            [parameter(mandatory = $true)]
            [hashtable]$Headers,

            [parameter(mandatory = $true)]
            [string]$Body,

            [parameter(mandatory = $false)]
            [int]$TimeoutSec = 120
        )
        $postHeaders = $Headers.Clone()
        $postHeaders["NTNX-Request-Id"] = (New-Guid).ToString()
        $invokeParams = @{
            Uri        = $Url
            Method     = 'POST'
            Headers    = $postHeaders
            Body       = $Body
            TimeoutSec = $TimeoutSec
        }
        return Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
    }

    function Invoke-PrismV3Put {
        param (
            [parameter(mandatory = $true)]
            [string]$Url,

            [parameter(mandatory = $true)]
            [hashtable]$Headers,

            [parameter(mandatory = $true)]
            [string]$Body,

            [parameter(mandatory = $false)]
            [int]$TimeoutSec = 120
        )
        $putHeaders = $Headers.Clone()
        $putHeaders["NTNX-Request-Id"] = (New-Guid).ToString()
        $invokeParams = @{
            Uri        = $Url
            Method     = 'PUT'
            Headers    = $putHeaders
            Body       = $Body
            TimeoutSec = $TimeoutSec
        }
        return Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
    }

    function Get-V4TaskStatus {
        param (
            [Parameter(Mandatory)]
            [string]$TaskExtId,
            
            [parameter(mandatory = $true)]
            [hashtable]$Headers,
            
            [parameter(mandatory = $true)]
            [string]$BaseUri
        )

        $taskUrl = "$BaseUri/prism/v4.0/config/tasks/$TaskExtId"
        Write-Host "$(Get-Date) [INFO] Retrieving details of task $TaskExtId..." -ForegroundColor Green
        $taskDetails = Invoke-PrismV4Get -Url $taskUrl -Headers $Headers
        Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $TaskExtId" -ForegroundColor Cyan

        if ($taskDetails.data.percentage_complete -ne "100") 
        {
            Do 
            {
                Write-Host "$(Get-Date) [INFO] Task progress: $($taskDetails.data.percentage_complete)%" -ForegroundColor Green
                Sleep 5
                $taskDetails = Invoke-PrismV4Get -Url $taskUrl -Headers $Headers
                
                if ($taskDetails.data.status -ne "running") 
                {
                    if ($taskDetails.data.status -ne "succeeded") 
                    {
                        Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.data.operation_type) failed with status: $($taskDetails.data.status) : $($taskDetails.data.progress_message)" -ForegroundColor Yellow
                    }
                }
            }
            While ($taskDetails.data.percentage_complete -ne "100")
            
            Write-Host ""
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.data.operation_type) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            if ($taskDetails.data.status -ine "succeeded") {
                Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.data.operation_type) status is $($taskDetails.data.status): $($taskDetails.data.progress_message)" -ForegroundColor Yellow
            } else {
                Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.data.operation_type) completed successfully!" -ForegroundColor Cyan
            }
        }
    }

    function Get-V3TaskStatus {
        param (
            [Parameter(Mandatory)]
            [string]$TaskUUID,
            
            [parameter(mandatory = $true)]
            [hashtable]$Headers,
            
            [parameter(mandatory = $true)]
            [string]$BaseUri
        )

        $taskUrl = "$BaseUri/nutanix/v3/tasks/$TaskUUID"
        Write-Host "$(Get-Date) [INFO] Retrieving details of task $TaskUUID..." -ForegroundColor Green
        $taskDetails = Invoke-PrismAPICallWithRetry -InvokeParams @{Uri=$taskUrl; Method='GET'; Headers=$Headers; TimeoutSec=60}
        Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $TaskUUID" -ForegroundColor Cyan

        if ($taskDetails.status -eq "SUCCEEDED") {
            Write-Host "$(Get-Date) [SUCCESS] Task completed successfully!" -ForegroundColor Cyan
            return
        }
        if ($taskDetails.status -eq "FAILED") {
            $errMsg = $taskDetails.progress_message
            if ($taskDetails.error_detail) { $errMsg += " - $($taskDetails.error_detail)" }
            if ($taskDetails.error_message) { $errMsg += " - $($taskDetails.error_message)" }
            Write-Host "$(Get-Date) [ERROR] Task failed: $errMsg" -ForegroundColor Red
            throw "Task $TaskUUID failed: $errMsg"
        }

        # Task is running, poll until completion
        Do 
        {
            Write-Host "$(Get-Date) [INFO] Task progress: $($taskDetails.progress_message)" -ForegroundColor Green
            Sleep 5
            $taskDetails = Invoke-PrismAPICallWithRetry -InvokeParams @{Uri=$taskUrl; Method='GET'; Headers=$Headers; TimeoutSec=60}
            
            if ($taskDetails.status -eq "SUCCEEDED") {
                Write-Host ""
                Write-Host "$(Get-Date) [SUCCESS] Task completed successfully!" -ForegroundColor Cyan
                return
            }
            if ($taskDetails.status -eq "FAILED") {
                $errMsg = $taskDetails.progress_message
                if ($taskDetails.error_detail) { $errMsg += " - $($taskDetails.error_detail)" }
                if ($taskDetails.error_message) { $errMsg += " - $($taskDetails.error_message)" }
                Write-Host "$(Get-Date) [ERROR] Task failed: $errMsg" -ForegroundColor Red
                throw "Task $TaskUUID failed: $errMsg"
            }
        }
        While ($taskDetails.status -eq "RUNNING")
        
        # Unexpected status
        Write-Host "$(Get-Date) [ERROR] Task ended with unexpected status: $($taskDetails.status)" -ForegroundColor Red
        throw "Task $TaskUUID ended with unexpected status: $($taskDetails.status)"
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
    $myvar_elapsed_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_api_server_port = "9440"
    $myvar_length = 100
#endregion


#region parameters validation
    if (!$prismcentral -or !$vms -or (!$ahv_network -and !$vpc_subnet)) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral, -vms, and either -ahv_network or -vpc_subnet!"
    }
    if ($ahv_network -and $vpc_subnet) {Throw "$(get-date) [ERROR] You can only specify an ahv_network OR a vpc_subnet but not both! Exiting."}

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
    $baseUri = "https://${prismcentral}:${myvar_api_server_port}/api"

    #assume vms is a list
    $myvar_vms = $vms.Split(",")
#endregion


#region processing

    if ($ahv_network)
    {#we're updating an ahv network (VLAN)

        Write-Host "$(Get-Date) [INFO] Mode: AHV Network (VLAN) - $ahv_network" -ForegroundColor Green

        #region get subnet details from v4 Networking API
            Write-Host "$(Get-Date) [INFO] Retrieving subnet information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $subnetFilter = [uri]::EscapeDataString("name eq '$ahv_network'")
            $subnetsUri = "${baseUri}/networking/v4.0/config/subnets?`$filter=$subnetFilter"
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $subnetsUri" -ForegroundColor White }
            
            $resp = Invoke-PrismV4Get -Url $subnetsUri -Headers $v4Headers
            
            if (-not $resp.data -or $resp.data.Count -eq 0) {
                Write-Host "$(Get-Date) [ERROR] Network '$ahv_network' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                exit 1
            }
            $subnet = $resp.data[0]
            $subnetExtId = $subnet.extId
            $subnetName = $subnet.name
            $subnetType = $subnet.subnetType
            Write-Host "$(Get-Date) [SUCCESS] Found subnet '$subnetName' (extId: $subnetExtId, type: $subnetType)" -ForegroundColor Cyan
        #endregion

        #region get vms from v4 VMM API
            Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $page = 0
            $allVms = @()
            
            Do 
            {
                try 
                {
                    $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$myvar_length"
                    if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $vmsUri" -ForegroundColor White }
                    
                    $resp = Invoke-PrismV4Get -Url $vmsUri -Headers $v4Headers
                    
                    if ($resp.data) {
                        $allVms += $resp.data
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
            While ($resp.data -and $resp.data.Count -eq $myvar_length)

            Write-Host "$(Get-Date) [SUCCESS] Retrieved $($allVms.Count) VMs from Prism Central" -ForegroundColor Cyan

            # Find specified VMs
            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($vmName in $myvar_vms) {
                $vm = $allVms | Where-Object { $_.name -eq $vmName }
                if (-not $vm) {
                    Write-Host "$(Get-Date) [ERROR] VM '$vmName' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                    exit 1
                }
                $myvar_vms_details.Add($vm) | Out-Null
                Write-Host "$(Get-Date) [DATA] Found VM '$vmName' (extId: $($vm.extId))" -ForegroundColor White
            }
        #endregion

        #region process each vm - update NIC using v3 API (v4 VM PUT has ETag defect VMM-30301)
            ForEach ($vm in $myvar_vms_details)
            {
                Write-Host "$(Get-Date) [INFO] Connecting VM '$($vm.name)' to network '$subnetName'..." -ForegroundColor Green
                
                $vmExtId = $vm.extId
                $vmUri = "${baseUri}/vmm/v4.0/ahv/config/vms/$vmExtId"
                
                # Step 1: Fresh GET from v4 to capture current state (no ETag needed for v3 write)
                Write-Host "$(Get-Date) [INFO] Retrieving VM $vmExtId from v4 API..." -ForegroundColor Green
                $vmResp = Invoke-PrismV4Get -Url $vmUri -Headers $v4Headers
                $vmData = $vmResp.data
                
                # Check if VM has at least one NIC
                if (-not $vmData.nics -or $vmData.nics.Count -eq 0) {
                    Write-Host "$(Get-Date) [WARNING] VM '$($vm.name)' has no NICs to update!" -ForegroundColor Yellow
                    Continue
                }
                
                # Update first NIC (nic0) to point to the new subnet
                $nic0 = $vmData.nics[0]
                $oldSubnetExtId = $nic0.nicNetworkInfo.subnet.extId
                $nicMac = $nic0.nicBackingInfo.macAddress
                
                if ($oldSubnetExtId -eq $subnetExtId) {
                    Write-Host "$(Get-Date) [WARNING] NIC 0 on VM '$($vm.name)' is already connected to subnet '$subnetName'! Skipping..." -ForegroundColor Yellow
                    Continue
                }
                
                Write-Host "$(Get-Date) [INFO] Updating NIC 0 (MAC: $nicMac) from subnet $oldSubnetExtId to $subnetExtId" -ForegroundColor Green
                
                # Modify only the requested field in the complete data object
                $nic0.nicNetworkInfo.subnet.extId = $subnetExtId
                
                # Step 2: Update using v3 API (bypasses v4 ETag defect)
                Write-Host "$(Get-Date) [INFO] Updating VM with new NIC configuration via v3 API..." -ForegroundColor Green
                
                # First, GET the complete VM spec from v3 API to preserve all fields
                $v3VmUrl = "${baseUri}/nutanix/v3/vms/$vmExtId"
                $v3GetResp = Invoke-PrismAPICallWithRetry -InvokeParams @{Uri=$v3VmUrl; Method='GET'; Headers=$v4Headers; TimeoutSec=60}
                # Extract only the VM spec (metadata + spec), excluding status and our added properties
                $v3VmSpec = @{
                    "metadata" = $v3GetResp.metadata
                    "spec" = $v3GetResp.spec
                    "api_version" = $v3GetResp.api_version
                }
                
                # Modify only the NIC list in the v3 spec
                $nicList = @()
                foreach ($nic in $vmData.nics) {
                    $nicList += @{
                        "nic_type" = "NORMAL_NIC"
                        "uuid" = $nic.extId
                        "mac_address" = $nic.nicBackingInfo.macAddress
                        "is_connected" = $nic.nicBackingInfo.isConnected
                        "subnet_reference" = @{
                            "kind" = "subnet"
                            "uuid" = $nic.nicNetworkInfo.subnet.extId
                        }
                        "vlan_mode" = $nic.nicNetworkInfo.vlanMode
                        "ip_endpoint_list" = @()
                    }
                }
                $v3VmSpec.spec.resources.nic_list = $nicList
                
                $v3Payload = $v3VmSpec | ConvertTo-Json -Depth 10
                
                $putResp = Invoke-PrismV3Put -Url $v3VmUrl -Headers $v4Headers -Body $v3Payload
                
                # Extract task UUID from response
                $taskUUID = $putResp.status.execution_context.task_uuid
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested connection of VM '$($vm.name)' to network '$subnetName'!" -ForegroundColor Cyan
                Write-Host "$(Get-Date) [INFO] Task UUID: $taskUUID" -ForegroundColor Green
                
                # Task status check using v3 API
                if (-not $skiptaskstatuscheck -and $taskUUID) {
                    Get-V3TaskStatus -TaskUUID $taskUUID -Headers $v4Headers -BaseUri $baseUri
                }
                
                # Step 3: Final GET from v4 for authoritative final state
                if ($taskUUID) {
                    Write-Host "$(Get-Date) [INFO] Retrieving final VM state from v4 API..." -ForegroundColor Green
                    $finalResp = Invoke-PrismV4Get -Url $vmUri -Headers $v4Headers
                    Write-Host "$(Get-Date) [DEBUG] Final VM state retrieved" -ForegroundColor White
                }
            }
        #endregion
    }

    if ($vpc_subnet)
    {#we're attaching a vnic to a subnet in a vpc (OVERLAY)

        Write-Host "$(Get-Date) [INFO] Mode: VPC Subnet (OVERLAY) - $vpc_subnet" -ForegroundColor Green

        #region get subnet details from v4 Networking API
            Write-Host "$(Get-Date) [INFO] Retrieving VPC subnet information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $subnetFilter = [uri]::EscapeDataString("name eq '$vpc_subnet'")
            $subnetsUri = "${baseUri}/networking/v4.0/config/subnets?`$filter=$subnetFilter"
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $subnetsUri" -ForegroundColor White }
            
            $resp = Invoke-PrismV4Get -Url $subnetsUri -Headers $v4Headers
            
            if (-not $resp.data -or $resp.data.Count -eq 0) {
                Write-Host "$(Get-Date) [ERROR] VPC subnet '$vpc_subnet' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                exit 1
            }
            $subnet = $resp.data[0]
            $subnetExtId = $subnet.extId
            $subnetName = $subnet.name
            $subnetType = $subnet.subnetType
            $vpcRef = $subnet.vpcReference
            Write-Host "$(Get-Date) [SUCCESS] Found VPC subnet '$subnetName' (extId: $subnetExtId, type: $subnetType, VPC: $vpcRef)" -ForegroundColor Cyan
            
            if ($subnetType -ne "OVERLAY") {
                Write-Host "$(Get-Date) [WARNING] Subnet '$subnetName' is not an OVERLAY (VPC) subnet (type: $subnetType)" -ForegroundColor Yellow
            }
        #endregion

        #region get vms from v4 VMM API
            Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $page = 0
            $allVms = @()
            
            Do 
            {
                try 
                {
                    $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$myvar_length"
                    if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $vmsUri" -ForegroundColor White }
                    
                    $resp = Invoke-PrismV4Get -Url $vmsUri -Headers $v4Headers
                    
                    if ($resp.data) {
                        $allVms += $resp.data
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
            While ($resp.data -and $resp.data.Count -eq $myvar_length)

            Write-Host "$(Get-Date) [SUCCESS] Retrieved $($allVms.Count) VMs from Prism Central" -ForegroundColor Cyan

            # Find specified VMs
            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($vmName in $myvar_vms) {
                $vm = $allVms | Where-Object { $_.name -eq $vmName }
                if (-not $vm) {
                    Write-Host "$(Get-Date) [ERROR] VM '$vmName' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                    exit 1
                }
                $myvar_vms_details.Add($vm) | Out-Null
                Write-Host "$(Get-Date) [DATA] Found VM '$vmName' (extId: $($vm.extId))" -ForegroundColor White
            }
        #endregion

        #region process each vm - use v4 VMM API reads, v3 writes for VPC subnet attachment
            ForEach ($vm in $myvar_vms_details)
            {
                Write-Host "$(Get-Date) [INFO] Processing VM '$($vm.name)' for VPC subnet '$subnetName'..." -ForegroundColor Green
                
                $vmExtId = $vm.extId
                $vmUri = "${baseUri}/vmm/v4.0/ahv/config/vms/$vmExtId"
                
                # ============================================================
                # PHASE 1: Remove NIC 0 (v4 read -> v3 write)
                # ============================================================
                
                # Step 1: Fresh GET from v4 to capture current state
                Write-Host "$(Get-Date) [INFO] Retrieving VM $vmExtId from v4 API (phase 1: remove NIC 0)..." -ForegroundColor Green
                $vmResp = Invoke-PrismV4Get -Url $vmUri -Headers $v4Headers
                $vmData = $vmResp.data
                
                # Check if VM has NICs
                if (-not $vmData.nics -or $vmData.nics.Count -eq 0) {
                    Write-Host "$(Get-Date) [WARNING] VM '$($vm.name)' has no NICs to update!" -ForegroundColor Yellow
                    Continue
                }
                
                # Check if NIC 0 is already connected to this subnet
                $nic0 = $vmData.nics[0]
                $currentSubnetExtId = $nic0.nicNetworkInfo.subnet.extId
                
                if ($currentSubnetExtId -eq $subnetExtId) {
                    Write-Host "$(Get-Date) [WARNING] NIC 0 on VM '$($vm.name)' is already connected to subnet '$subnetName'! Skipping..." -ForegroundColor Yellow
                    Continue
                }
                
                # Save NIC 0 configuration for new NIC (after removal)
                $nic0Config = $nic0 | Select-Object -Property extId, nicBackingInfo, nicNetworkInfo
                
                # Remove NIC 0 from the list
                if ($vmData.nics.Count -gt 1) {
                    $vmData.nics = $vmData.nics[1..($vmData.nics.Count - 1)]
                } else {
                    $vmData.nics = @()
                }
                
                # Step 2: PUT without NIC 0 using v3 API
                Write-Host "$(Get-Date) [INFO] Removing NIC 0 from VM '$($vm.name)' via v3 API..." -ForegroundColor Green
                
                # First, GET the complete VM spec from v3 API to preserve all fields
                $v3VmUrl = "${baseUri}/nutanix/v3/vms/$vmExtId"
                $v3GetResp = Invoke-PrismAPICallWithRetry -InvokeParams @{Uri=$v3VmUrl; Method='GET'; Headers=$v4Headers; TimeoutSec=60}
                # Extract only the VM spec (metadata + spec), excluding status and our added properties
                $v3VmSpec = @{
                    "metadata" = $v3GetResp.metadata
                    "spec" = $v3GetResp.spec
                    "api_version" = $v3GetResp.api_version
                }
                
                # Modify only the NIC list in the v3 spec
                $nicList = @()
                foreach ($nic in $vmData.nics) {
                    $nicList += @{
                        "nic_type" = "NORMAL_NIC"
                        "uuid" = $nic.extId
                        "mac_address" = $nic.nicBackingInfo.macAddress
                        "is_connected" = $nic.nicBackingInfo.isConnected
                        "subnet_reference" = @{
                            "kind" = "subnet"
                            "uuid" = $nic.nicNetworkInfo.subnet.extId
                        }
                        "vlan_mode" = $nic.nicNetworkInfo.vlanMode
                        "ip_endpoint_list" = @()
                    }
                }
                $v3VmSpec.spec.resources.nic_list = $nicList
                
                $v3Payload = $v3VmSpec | ConvertTo-Json -Depth 10
                
                $putResp = Invoke-PrismV3Put -Url $v3VmUrl -Headers $v4Headers -Body $v3Payload
                
                $taskUUID = $putResp.status.execution_context.task_uuid
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested removal of NIC 0 from VM '$($vm.name)'!" -ForegroundColor Cyan
                Write-Host "$(Get-Date) [INFO] Task UUID: $taskUUID" -ForegroundColor Green
                
                if (-not $skiptaskstatuscheck -and $taskUUID) {
                    Get-V3TaskStatus -TaskUUID $taskUUID -Headers $v4Headers -BaseUri $baseUri
                }
                
                # Step 3: Final GET from v4 after NIC removal (authoritative state)
                Write-Host "$(Get-Date) [INFO] Retrieving VM state after NIC removal from v4 API..." -ForegroundColor Green
                $vmResp2 = Invoke-PrismV4Get -Url $vmUri -Headers $v4Headers
                $vmData2 = $vmResp2.data
                
                # ============================================================
                # PHASE 2: Add new NIC connected to VPC subnet (v4 read -> v3 write)
                # ============================================================
                
                # Create new NIC configuration for VPC subnet
                $newNic = @{
                    "extId" = [guid]::NewGuid().ToString()
                    "nicBackingInfo" = @{
                        "\$objectType" = "vmm.v4.ahv.config.VirtualEthernetNic"
                        "macAddress" = $nic0Config.nicBackingInfo.macAddress
                        "isConnected" = $true
                        "numQueues" = 1
                    }
                    "nicNetworkInfo" = @{
                        "\$objectType" = "vmm.v4.ahv.config.VirtualEthernetNicNetworkInfo"
                        "nicType" = "NORMAL_NIC"
                        "subnet" = @{
                            "\$objectType" = "vmm.v4.ahv.config.SubnetReference"
                            "extId" = $subnetExtId
                        }
                        "vlanMode" = "ACCESS"
                        "ipv4Info" = @{
                            "\$objectType" = "vmm.v4.ahv.config.Ipv4Info"
                            "learnedIpAddresses" = " "
                        }
                    }
                }
                
                if ($dontkeepip) {
                    # Remove IP configuration for new NIC
                    $newNic.nicNetworkInfo.ipv4Info = @{
                        "\$objectType" = "vmm.v4.ahv.config.Ipv4Info"
                        "learnedIpAddresses" = " "
                    }
                }
                
                # Add new NIC to the list
                $vmData2.nics += $newNic
                
                # Step 4: PUT with new NIC using v3 API
                Write-Host "$(Get-Date) [INFO] Connecting VM '$($vm.name)' to VPC subnet '$subnetName' via v3 API..." -ForegroundColor Green
                
                # First, GET the complete VM spec from v3 API to preserve all fields
                $v3GetResp2 = Invoke-PrismAPICallWithRetry -InvokeParams @{Uri=$v3VmUrl; Method='GET'; Headers=$v4Headers; TimeoutSec=60}
                # Extract only the VM spec (metadata + spec), excluding status and our added properties
                $v3VmSpec2 = @{
                    "metadata" = $v3GetResp2.metadata
                    "spec" = $v3GetResp2.spec
                    "api_version" = $v3GetResp2.api_version
                }
                
                # Modify only the NIC list in the v3 spec
                $nicList2 = @()
                foreach ($nic in $vmData2.nics) {
                    $nicList2 += @{
                        "nic_type" = "NORMAL_NIC"
                        "uuid" = $nic.extId
                        "mac_address" = $nic.nicBackingInfo.macAddress
                        "is_connected" = $nic.nicBackingInfo.isConnected
                        "subnet_reference" = @{
                            "kind" = "subnet"
                            "uuid" = $nic.nicNetworkInfo.subnet.extId
                        }
                        "vlan_mode" = $nic.nicNetworkInfo.vlanMode
                        "ip_endpoint_list" = @()
                    }
                }
                $v3VmSpec2.spec.resources.nic_list = $nicList2
                
                $v3Payload2 = $v3VmSpec2 | ConvertTo-Json -Depth 10
                
                $putResp2 = Invoke-PrismV3Put -Url $v3VmUrl -Headers $v4Headers -Body $v3Payload2
                
                $taskUUID2 = $putResp2.status.execution_context.task_uuid
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested connection of VM '$($vm.name)' to VPC subnet '$subnetName'!" -ForegroundColor Cyan
                Write-Host "$(Get-Date) [INFO] Task UUID: $taskUUID2" -ForegroundColor Green
                
                if (-not $skiptaskstatuscheck -and $taskUUID2) {
                    Get-V3TaskStatus -TaskUUID $taskUUID2 -Headers $v4Headers -BaseUri $baseUri
                }
                
                # Step 5: Final GET from v4 for authoritative final state
                if ($taskUUID2) {
                    Write-Host "$(Get-Date) [INFO] Retrieving final VM state from v4 API..." -ForegroundColor Green
                    $finalResp = Invoke-PrismV4Get -Url $vmUri -Headers $v4Headers
                    Write-Host "$(Get-Date) [DEBUG] Final VM state retrieved" -ForegroundColor White
                }
            }
        #endregion
    }
#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvar_elapsed_time.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vms -ErrorAction SilentlyContinue
    Remove-Variable ahv_network -ErrorAction SilentlyContinue
    Remove-Variable vpc_subnet -ErrorAction SilentlyContinue
    Remove-Variable skiptaskstatuscheck -ErrorAction SilentlyContinue
    Remove-Variable dontkeepip -ErrorAction SilentlyContinue
    Remove-Variable myvar_api_server_port -ErrorAction SilentlyContinue
    Remove-Variable myvar_length -ErrorAction SilentlyContinue
    Remove-Variable v4Headers -ErrorAction SilentlyContinue
    Remove-Variable baseUri -ErrorAction SilentlyContinue
#endregion