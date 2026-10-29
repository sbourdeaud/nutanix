<#
.SYNOPSIS
  This script will show the VM count, NFS file count, total files count and total file size bytes for all the consistency group of the designated protection domain.
.DESCRIPTION
  This is a detailed description of what the script does and how it is used.
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
.PARAMETER pd
  Name of the protection domain.
.PARAMETER html
  Produces an html output in addition to console output.
.PARAMETER viewnow
  Means you want the script to open the html report in your default browser immediately after creation.
.PARAMETER dir
  Directory/path where to save the html report.  By default, it will be created in the current directory. Note that the name of the report is always cg_stats_report.html and that you can change this in the script variables section.

.EXAMPLE
.\get-ntnxCgStats.ps1 -cluster ntnxc1.local -prismCreds myCreds -pd myPdName
Shows consistency groups stats for protection domain called myPdName on cluster ntnxc1.local:
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
        [parameter(mandatory = $false)] [string]$cluster,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [switch]$html,
        [parameter(mandatory = $false)] [switch]$viewnow,
        [parameter(mandatory = $false)] [string]$pd,
        [parameter(mandatory = $false)] [string]$dir
    )
#endregion

#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
03/10/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-ntnxCgStats.ps1"

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

    if (!$dir)
    {#no report directory was specified, so we'll use the current directory
        $dir = Get-Location | Select-Object -ExpandProperty Path
    }

    if (!$dir.EndsWith("\")) 
    {#make sure given log path has a trailing \
        if ($IsMacOS -or $IsLinux)
        {#we are on Mac or Linux
            $dir += "/"
        }
        else 
        {#we are on Windows
            $dir += "\"
        }
    }
    if (Test-Path -path $dir)
    {#specified path exists
        $myvar_html_report_name = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvar_html_report_name += "$($cluster)_$($pd)_cg_stats_report.html"
        $myvar_html_report_name = $dir + $myvar_html_report_name
    }
    else 
    {#specified path does not exist
        Write-Host "$(Get-Date) [ERROR] Specified log path $($dir) does not exist! Exiting." -ForegroundColor Red
        Exit 1
    }

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
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
#endregion

#region parameters validation
    if (!$cluster -or !$pd) {
        Throw "$(Get-Date) [ERROR] You must specify -cluster -pd!"
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
#endregion

#region processing	
    Write-Host "$(get-date) [INFO] Retrieving list of Consistency Groups from $($cluster)..." -ForegroundColor Green
    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/consistency_groups/"
    $method = "GET"
    $myvar_cg_list = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved Consistency Groups list from $($cluster)!" -ForegroundColor Cyan
    
    [System.Collections.ArrayList]$myvar_cg_stats = New-Object System.Collections.ArrayList($null)
    ForEach ($myvar_cg in $myvar_cg_list.entities)
    {
        if ($myvar_cg.protection_domain_name -eq $pd)
        {
            $myvar_cg_info = [ordered]@{
                "name" = $myvar_cg.consistency_group_name;
                "vm_count" = $myvar_cg.vm_count;
                "nfs_file_count" = $myvar_cg.nfs_file_count;
                "total_file_count" = $myvar_cg.total_file_count;
                "total_file_size_bytes" = $myvar_cg.total_file_size_bytes;
            }
            #store the results for this entity in our overall result variable
            $myvar_cg_stats.Add((New-Object PSObject -Property $myvar_cg_info)) | Out-Null
        }
    }

    if ($html) 
    {#we need html output
        #* html report creation/formatting starts here
        $myvar_html_report = New-HTML -TitleText "Consistency Group Stats Report" -Online {
            New-HTMLTableStyle -BackgroundColor Black -TextColor White -Type Button
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#4C4C4E" -TextColor White -TextAlign center -Type Header
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#4C4C4E" -TextColor White -TextAlign center -Type Footer
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor White -TextColor Black -TextAlign center -Type RowOdd
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor WhiteSmoke -TextColor Black -TextAlign center -Type RowEven
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowSelected
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowHoverSelected
            New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowHover
            New-HTMLTableStyle -Type Header -BorderLeftStyle dashed -BorderLeftColor "#4C4C4E" -BorderLeftWidthSize 1px
            New-HTMLTableStyle -Type Footer -BorderLeftStyle dotted -BorderLeftColor "#4C4C4E" -BorderleftWidthSize 1px
            New-HTMLTableStyle -Type Footer -BorderTopStyle none -BorderTopColor Black -BorderTopWidthSize 5px -BorderBottomColor "#4C4C4E" -BorderBottomStyle solid

            New-HTMLSection -HeaderText "Consistency Groups List" -Wrap wrap -CanCollapse  -HeaderBackGroundColor "#168CF5" -HeaderTextColor White -Direction Row {
                New-HTMLTable -DataTable ($myvar_cg_stats) -HideFooter
            }
        }
        $myvar_html_report | Out-File -FilePath $($myvar_html_report_name)

        if ($viewnow)
        {#open the html report now in the default browser
            Invoke-Item $myvar_html_report_name
        }
    }
    else 
    {
        $myvar_cg_stats
    }
#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable pd -ErrorAction SilentlyContinue
    Remove-Variable html -ErrorAction SilentlyContinue
    Remove-Variable viewnow -ErrorAction SilentlyContinue
    Remove-Variable dir -ErrorAction SilentlyContinue
#endregion