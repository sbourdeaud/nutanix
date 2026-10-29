<#
.SYNOPSIS
  This script retrieves the list of unprotected (not in any protection domain) virtual machines from a given Nutanix cluster.
.DESCRIPTION
  The script uses v2 REST API in Prism to GET the list of unprotected VMs from /protection_domains/unprotected_vms/.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER email
  Specifies that you want to email the output. This requires that you set up variables inside the script for smtp gateway and recipients.
.PARAMETER details
  Specifies that you want additional information about each unprotected virtual machine (includes agent vm status, description, number of vdisks and total vdisk size).
.EXAMPLE
.\get-UnprotectedVms.ps1 -cluster ntnxc1.local
Retrieve the list of unprotected VMs from cluster ntnxc1.local
.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
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
    [parameter(mandatory = $false)] [string]$cluster,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [switch]$email,
    [parameter(mandatory = $false)] [switch]$details
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
02/06/2021 sb   Replaced username with get-credential
03/25/2020 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-UnprotectedVms.ps1"
    
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
    #! Constants (for -email)
    $smtp_gateway = "" #add your smtp gateway address here
    $smtp_port = 25 #customize the smtp port here if necessary
    $recipients = "" #add a comma separated value of valid email addresses here
    $from = "" #add the from email address here
    $subject = "WARNING: Unprotected VMs in Nutanix cluster $cluster" #customize the subject here
    $body = "Please open the attached csv file and make sure the VMs listed are in protection domains on cluster $cluster" #customize the body here

    #initialize variables
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
#endregion


#region parameters validation
    if (!$cluster) {
        Throw "$(Get-Date) [ERROR] You must specify -cluster!"
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


#region processing	

    #region retrieving all AHV vm information
        Write-Host "$(get-date) [INFO] Retrieving list of unprotected VMs..." -ForegroundColor Green
        $url = "https://$($cluster):9440/api/nutanix/v2.0/protection_domains/unprotected_vms/"
        $method = "GET"
        $vmList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved unprotected VMs list from $cluster!" -ForegroundColor Cyan

        if ($details) 
        {
            Write-Host "$(get-date) [INFO] Retrieving details for VMs on cluster $cluster..." -ForegroundColor Green
            $url = "https://$($cluster):9440/api/nutanix/v2.0/vms?include_vm_disk_config=true&include_vm_nic_config=true"
            $method = "GET"
            $vmsDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details for VMs on cluster $cluster!" -ForegroundColor Cyan

            Write-Host "$(get-date) [INFO] Retrieving details for virtual disks on cluster $cluster..." -ForegroundColor Green
            $url = "https://$($cluster):9440/api/nutanix/v2.0/virtual_disks/"
            $method = "GET"
            $disksDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details for virtual disks on cluster $cluster!" -ForegroundColor Cyan

            Write-Host "$(get-date) [INFO] Retrieving details for volume groups on cluster $cluster..." -ForegroundColor Green
            $url = "https://$($cluster):9440/api/nutanix/v2.0/volume_groups/"
            $method = "GET"
            $vgsDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details for volume groups on cluster $cluster!" -ForegroundColor Cyan
        }

        ForEach ($vm in $vmList.entities) 
        {
            if ($debugme) {Write-Host "$(get-date) [DEBUG] - - - - - - - - - - VM: $($vm.vm_name) ) - - - - - - - - - -" -ForegroundColor White}
            
            if ($details) 
            {
                $vmDetail = $vmsDetails.entities | Where-Object {$_.name -eq $vm.vm_name}
                $vmDisks = $vmDetail.vm_disk_info | Where-Object {$_.is_cdrom -eq $false}
                $total_vdisk_size_bytes_used = 0
                $total_vdisk_size_bytes_allocated = 0
                
                ForEach ($disk in $vmDisks) 
                {
                    if ($disk.disk_address.vmdisk_uuid) 
                    {
                        if ($debugme) {Write-Host "$(get-date) [DEBUG] (vm: $($vm.vm_name)) Found a virtual disk." -ForegroundColor White}
                        $diskStats = $disksDetails.entities | Where-Object {$_.uuid -eq $disk.disk_address.vmdisk_uuid}
                        if ($diskStats) 
                        {
                            if ($debugme) {Write-Host "$(get-date) [DEBUG] (vm: $($vm.vm_name)) Bytes used for this disk: $($diskStats.stats.controller_user_bytes)" -ForegroundColor White}
                            $total_vdisk_size_bytes_used += $diskStats.stats.controller_user_bytes
                            $total_vdisk_size_bytes_allocated += $diskStats.stats.controller_bytes
                        }
                    }
                }
                
                $myvarResult = [ordered]@{
                    "vm_name" = $vm.vm_name
                    "vm_uuid" = $vm.vm_uuid
                    "description" = $vmDetail.description
                    "num_vdisks" = $vmDisks.Count
                    "total_vdisk_size_gb_used" = [math]::Round($total_vdisk_size_bytes_used / 1GB, 2)
                    "total_vdisk_size_gb_allocated" = [math]::Round($total_vdisk_size_bytes_allocated / 1GB, 2)
                }
            }
            else 
            {
                $myvarResult = [ordered]@{
                    "vm_name" = $vm.vm_name
                    "vm_uuid" = $vm.vm_uuid
                }
            }
            #store the results for this entity in our overall result variable
            $myvarResults.Add((New-Object PSObject -Property $myvarResult)) | Out-Null
        }

        Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")unprotected_vms.csv" -ForegroundColor Green
        $myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"unprotected_vms.csv")

    #endregion

    #region email results
        if ($email) 
        {
            Write-Host "$(Get-Date) [INFO] Sending email with results..." -ForegroundColor Green
            Send-MailMessage -SmtpServer $smtp_gateway -Port $smtp_port -From $from -To $recipients -Subject $subject -Body $body -Attachments $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"unprotected_vms.csv")
            Write-Host "$(Get-Date) [SUCCESS] Email sent successfully!" -ForegroundColor Cyan
        }
    #endregion

#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    
    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable email -ErrorAction SilentlyContinue
    Remove-Variable details -ErrorAction SilentlyContinue
    Remove-Variable ElapsedTime -ErrorAction SilentlyContinue
#endregion