<#
.SYNOPSIS
  This script can be used to remove recovery points for a specified vm or remove orphaned recovery points (where the vm no longer exists).
.DESCRIPTION
  This script can be used to remove recovery points for a specified vm or remove orphaned recovery points (where the vm no longer exists).
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vm
  Name of the virtual machine for which you want to remove recovery points. By default, you will be prompted to remove each matching recovery point, unless you use -all.
.PARAMETER all
  Switch to specify you do not want to be prompted for each recovery point to be removed.
.PARAMETER orphans
  Switch to indicate you want to remove all recovery points which do not belong to any existing virtual machine.
.EXAMPLE
.\remove-VmRecoveryPoints.ps1 -prismcentral mypc.local -prismcreds mycreds -orphans
Remove all recovery points which don't belong to any vms.
.EXAMPLE
.\remove-VmRecoveryPoints.ps1 -prismcentral mypc.local -prismcreds mycreds -vm myvm
Remove all recovery points which belong to myvm.
.LINK
  http://www.nutanix.com/services
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
    [parameter(mandatory = $false)] [string]$vm,
    [parameter(mandatory = $false)] [switch]$all,
    [parameter(mandatory = $false)] [switch]$orphans,
    [parameter(mandatory = $false)] $prismCreds
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
08/23/2022 sb   Initial release.
################################################################################
'
    $myvarScriptName = ".\remove-VmRecoveryPoints.ps1"

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
    $myvar_ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $length = 100
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

if (!$vm -and !$orphans) {Throw "$(get-date) [ERROR] You must specify either a vm name or use the orphans parameter!"}
#endregion


#region processing	
#region retrieve VM recovery points using inline pagination
    Write-Host "$(get-date) [INFO] Retrieving list of VM recovery points from Prism Central $($prismcentral)..." -ForegroundColor Green
    
    $content = @{
        kind = "vm_recovery_point";
        offset = 0;
        length = $length
    }
    $url = "https://$($prismcentral):9440/api/nutanix/v3/vm_recovery_points/list"
    $method = "POST"
    $payload = (ConvertTo-Json $content -Depth 4)
    $myvar_vm_recovery_points = @()
    $total = 0
    $cumulated = 0
    $page_offset = 0

    Do {
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            
            if ($total -eq 0) {$total = $resp.metadata.total_matches}
            $cumulated += $resp.entities.count
            
            Write-Host "$(Get-Date) [INFO] Processing results from $($page_offset) to $($cumulated) out of $($total)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    
            #grab the information we need in each entity
            ForEach ($entity in $resp.entities) {                
                $myvar_vm_recovery_points += $entity
            }
            
            $page_offset += $length
            $content.offset = $page_offset
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        catch {
            $saved_error = $_.Exception.Message
            if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
            Throw "$(get-date) [ERROR] $saved_error"
        }
    }
    While ($cumulated -lt $total)

    Write-Host "$(get-date) [SUCCESS] Successfully retrieved $($myvar_vm_recovery_points.Count) VM recovery points from Prism Central $($prismcentral)!" -ForegroundColor Cyan
#endregion retrieve VM recovery points

#region retrieve VMs using inline pagination
    Write-Host "$(get-date) [INFO] Retrieving list of VMs from Prism Central $($prismcentral)..." -ForegroundColor Green
    
    $content = @{
        kind = "vm";
        offset = 0;
        length = $length
    }
    $url = "https://$($prismcentral):9440/api/nutanix/v3/vms/list"
    $method = "POST"
    $payload = (ConvertTo-Json $content -Depth 4)
    $myvar_vms = @()
    $total = 0
    $cumulated = 0
    $page_offset = 0

    Do {
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            
            if ($total -eq 0) {$total = $resp.metadata.total_matches}
            $cumulated += $resp.entities.count
            
            Write-Host "$(Get-Date) [INFO] Processing results from $($page_offset) to $($cumulated) out of $($total)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    
            ForEach ($entity in $resp.entities) {                
                $myvar_vms += $entity
            }
            
            $page_offset += $length
            $content.offset = $page_offset
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        catch {
            $saved_error = $_.Exception.Message
            if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
            Throw "$(get-date) [ERROR] $saved_error"
        }
    }
    While ($cumulated -lt $total)

    Write-Host "$(get-date) [SUCCESS] Successfully retrieved $($myvar_vms.Count) VMs from Prism Central $($prismcentral)!" -ForegroundColor Cyan
#endregion retrieve VMs

    $vm_uuids = @($myvar_vms | Select-Object -ExpandProperty metadata.uuid)

    if ($vm)
    {#figure out the uuid of the user specified vm
        if ($myvar_vm_uuid = ($myvar_vms | ?{$_.status.name -eq $vm}).metadata.uuid)
        {#the user specified vm exists: let's grab its uuid
            Write-Host "$(get-date) [DATA] VM $($vm) has uuid $($myvar_vm_uuid)" -ForegroundColor White
        }
        else 
        {#the user specified vm does not exist: error out
            Write-Host "$(get-date) [ERROR] Could not find VM $($vm) on Prism Central $($prismcentral)!" -ForegroundColor Red
            Exit 1
        }
    }

#region process vm recovery points
    foreach ($myvar_recovery_point in $myvar_vm_recovery_points)
    {
        if ($vm)
        {#user specified a vm
            if ($myvar_recovery_point.spec.resources.parent_vm_reference.uuid -eq $myvar_vm_uuid) 
            {#this recovery point belongs to the vm specified by the user
                if (!$all)
                {#let's prompt for each recovery point
                    Write-Host "$(Get-Date) [WARNING] Do you want to delete VM recovery point $($myvar_recovery_point.spec.name) which belongs to vm $($vm) with owner $($myvar_recovery_point.metadata.owner_reference.name) created on $($myvar_recovery_point.status.resources.creation_time) with an expiration date of $($myvar_recovery_point.status.resources.expiration_time)?" -ForegroundColor Yellow
                    do {$myvar_user_choice = Read-Host -Prompt "Continue? (y/n)"}
                    while ($myvar_user_choice -notmatch '[ynYN]')
                    $myvar_user_choice = $myvar_user_choice.ToLower()
                }
                else             
                {#no need to prompt
                    $myvar_user_choice = "y" 
                }
                if ($myvar_user_choice -ieq "y")
                {
                    Write-Host "$(get-date) [INFO] Deleting VM recovery point $($myvar_recovery_point.metadata.uuid)..." -ForegroundColor Green
                    $url = "https://$($prismcentral):9440/api/nutanix/v3/vm_recovery_points/{0}" -f $myvar_recovery_point.metadata.uuid
                    $method = "DELETE"
                    $myvar_vm_recovery_point_delete = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(get-date) [SUCCESS] Successfully deleted VM recovery point $($myvar_recovery_point.metadata.uuid) from $($prismcentral)!" -ForegroundColor Cyan
                }
            }
        }
        elseif ($orphans)
        {#user wants to delete all recovery points that don't belong to any vm
            if ($myvar_recovery_point.spec.resources.parent_vm_reference.uuid -notin $vm_uuids) 
            {#this recovery point belongs to no vm
                if (!$all)
                {#let's prompt for each recovery point
                    Write-Host "$(Get-Date) [WARNING] Do you want to delete VM recovery point $($myvar_recovery_point.spec.name) which does not belong to any vm with owner $($myvar_recovery_point.metadata.owner_reference.name) created on $($myvar_recovery_point.status.resources.creation_time) with an expiration date of $($myvar_recovery_point.status.resources.expiration_time)?" -ForegroundColor Yellow
                    do {$myvar_user_choice = Read-Host -Prompt "Continue? (y/n)"}
                    while ($myvar_user_choice -notmatch '[ynYN]')
                    $myvar_user_choice = $myvar_user_choice.ToLower()
                }
                else             
                {#no need to prompt
                    $myvar_user_choice = "y" 
                }
                if ($myvar_user_choice -ieq "y")
                {
                    Write-Host "$(get-date) [INFO] Deleting VM recovery point $($myvar_recovery_point.metadata.uuid)..." -ForegroundColor Green
                    $url = "https://$($prismcentral):9440/api/nutanix/v3/vm_recovery_points/{0}" -f $myvar_recovery_point.metadata.uuid
                    $method = "DELETE"
                    $myvar_vm_recovery_point_delete = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(get-date) [SUCCESS] Successfully deleted VM recovery point $($myvar_recovery_point.metadata.uuid) from $($prismcentral)!" -ForegroundColor Cyan
                }
            }
        }
    }
#endregion process vm recovery points

#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvar_ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable vm -ErrorAction SilentlyContinue
    Remove-Variable all -ErrorAction SilentlyContinue
    Remove-Variable orphans -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion