<#
.SYNOPSIS
  This script connects to Prism Central and for each managed cluster, returns
  the CPU oversubscription ratio.
.DESCRIPTION
  This script connects to Prism Central and for each managed cluster, returns
  the CPU oversubscription ratio (total number of allocated vCPUs / number of 
  logical cores).
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
.PARAMETER ignorePoweredOff
  Ignores VMs which are powered off.
.EXAMPLE
.\get-AhvCpuRatio.ps1 -cluster ntnxc1.local
Connect to a Nutanix Prism Central VM of your choice and compute the CPU 
oversubscription ratio for each managed AHV cluster.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 20th 2026
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
    $length=100 #this specifies how many entities we want in the results of each API query
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
#endregion

#region prepare api call (get vms)
    $api_server_port = "9440"
    $api_server_endpoint = "/api/nutanix/v3/vms/list"
    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
    $method = "POST"

    # this is used to capture the content of the payload
    $content = @{
        kind="vm";
        offset=0;
        length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call and process results (get vms)
    Do {
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

        #grab the information we need in each entity
        ForEach ($entity in $resp.entities) {
            if ($entity.spec.resources.num_sockets) {
                $myvarVmInfo = [ordered]@{
                    "num_sockets" = $entity.spec.resources.num_sockets;
                    "num_vcpus_per_socket" = $entity.spec.resources.num_vcpus_per_socket;
                    "num_vcpus" = $entity.spec.resources.num_sockets * $entity.spec.resources.num_vcpus_per_socket;
                    "power_state" = $entity.spec.resources.power_state;
                    "cluster" = $entity.spec.cluster_reference.name;
                    "hypervisor" = $entity.status.resources.hypervisor_type;
                    "cluster_uuid" = $entity.status.cluster_reference.uuid;
                }
                #store the results for this entity in our overall result variable
                $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
            }
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="vm";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    While ($content.offset -lt $resp.metadata.total_matches)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $resp
    }
#endregion

#region prepare api call (get hosts)
    $api_server_port = "9440"
    $api_server_endpoint = "/api/nutanix/v3/hosts/list"
    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
    $method = "POST"

    # this is used to capture the content of the payload
    $content = @{
        kind="host";
        offset=0;
        length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call and process results (get hosts)
    Do {
        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
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
            if ($entity.status.resources.num_cpu_sockets) {
                $myvarHostInfo = [ordered]@{
                    "num_cpu_sockets" = $entity.status.resources.num_cpu_sockets;
                    "num_cpu_cores" = $entity.status.resources.num_cpu_cores;
                    #"num_cpu_total_cores" = ($entity.status.resources.num_cpu_sockets * $entity.status.resources.num_cpu_cores);
                    "cluster_uuid" = $entity.status.cluster_reference.uuid;
                }
                #store the results for this entity in our overall result variable
                $myvarHostResults.Add((New-Object PSObject -Property $myvarHostInfo)) | Out-Null
            }
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="host";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    While ($content.offset -lt $resp.metadata.total_matches)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarHostResults
    }
#endregion

#region prepare api call (get clusters)
    $api_server_port = "9440"
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
#endregion

#region make api call and process results (get clusters)
    Do {
        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
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
        
        #grab the information we need in each entity
        ForEach ($entity in $resp.entities) {
            if ($entity.status.resources.nodes.hypervisor_server_list) {
                $myvarClusterInfo = [ordered]@{
                    "cluster_name" = $entity.spec.name;
                    "hypervisor" = $entity.status.resources.nodes.hypervisor_server_list[0].type;
                    "cluster_uuid" = $entity.metadata.uuid;
                }
                #store the results for this entity in our overall result variable
                $myvarClusterResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
            }
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="host";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    While ($content.offset -lt $resp.metadata.total_matches)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarClusterResults
    }
#endregion

#region process and print overall results
    ForEach ($cluster in $myvarClusterResults) {
        if ($ignorePoweredOff) {
            $myvarAllocatedvCpus = ($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | where {$_.power_state -eq "ON"} | measure num_vcpus -sum).Sum
            $myvarAveragevCpuAllocation = [math]::Round(($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | where {$_.power_state -eq "ON"} | measure num_vcpus -average).Average)
        }
        else {
            $myvarAllocatedvCpus = ($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | measure num_vcpus -sum).Sum
            $myvarAveragevCpuAllocation = [math]::Round(($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | measure num_vcpus -average).Average)
        }
        $myvarTotalCores = ($myvarHostResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | measure num_cpu_cores -sum).Sum
        $myvarCpuRatio = [math]::Round($myvarAllocatedvCpus / $myvarTotalCores,2)
        $myvarClusterReport = [ordered]@{
            "cluster_name" = $cluster.cluster_name;
            "hypervisor" = $cluster.hypervisor;
            "cluster_uuid" = $cluster.cluster_uuid;
            "allocated_vcpus" = $myvarAllocatedvCpus;
            "average_vcpu_allocation" = $myvarAveragevCpuAllocation;
            "total_cores" = $myvarTotalCores;
            "cpu_ratio" = $myvarCpuRatio;
        }
        #store the results for this entity in our overall result variable
        $myvarReport.Add((New-Object PSObject -Property $myvarClusterReport)) | Out-Null
    }
    $myvarReport | ft
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
#endregion
