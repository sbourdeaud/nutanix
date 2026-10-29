<#
.SYNOPSIS
  This script can be used to add unprotected vm(s) to an existing protection domain on Nutanix.
.DESCRIPTION
  This script adds existing virtual machines to an existing protection domain if they are not already protected.
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
  Name of the protection domain you want to add vms to.
.PARAMETER vm
  Name of the virtual machine(s) you want to add.  You can specify multiple vm names by use a comma separated list enclosed in double quotes or using the * wildcard. Note that when you use the * wildcard, it will try to match that string (exp: *mystring or mystring* or my*string will always behave as *mystring*)
.PARAMETER replicateNow
  This is an optional parameter. If you use -replicateNow, a snapshot will be taken immediately for each created consistency group.
.EXAMPLE
  Add all VMs that start with myvm* to protection domain "mypd" and replicate immediately:
  PS> .\add-VmToPd.ps1 -cluster ntnxc1.local -prismCreds mycreds -pd mypd -vm myvm* -replicateNow
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
		[parameter(mandatory = $false)] [string]$pd,
		[parameter(mandatory = $false)] [string]$vm,
		[parameter(mandatory = $false)] [switch]$replicateNow
	)
#endregion

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

#region prepwork
	$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter; converted from NutanixCmdlets to REST API; converted from UTF-16 to UTF-8
 08/18/2016 sb   Initial release.
 09/15/2016 sb   Added interactive prompting for mandatory parameters.
################################################################################
'@
	$myvarScriptName = ".\add-VmToPd.ps1"
	
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
#endregion

#region variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarVMsToAddToPd = @()
#endregion

#region parameters validation
	$myvarVMs = $vm.Split(",")
	if (!$cluster) {$cluster = read-host "Enter the hostname or IP address of the Nutanix cluster"}#prompt for the Nutanix cluster name
	if (!$pd) {$pd = read-host "Enter the name of the protection domain"}#prompt for the Nutanix protection domain
	if (!$vm) {$vm = read-host "Enter the name of the vm(s) you want to add to the protection domain. Use comma separated values for multiple instances."}#prompt for the vm name

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
	
    Write-Host "$(get-date) [INFO] Connecting to the Nutanix cluster $cluster..." -ForegroundColor Green
    
    #start by making sure the protection domain exists
    Write-Host "$(get-date) [INFO] Getting protection domain $pd..." -ForegroundColor Green
    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/?names=$pd"
    $method = "GET"
    $pdResult = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    
    if ($pdResult.entities) {
        $myvarPdObject = $pdResult.entities[0]
        #take the array of vm names specified by the user and process each entry
        foreach ($myvarVM in $myvarVMs)
        {
            if ($myvarVM -match '\*')
            {
                #strip wildcard
                $myvarSearchString = $myvarVM -replace '\*'
                #retrieve vms using search
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/vms/"
                $method = "GET"
                $vmResult = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                $myvarSearchedVMs = $vmResult.entities | Where-Object {$_.vmName -like "*$myvarSearchString*"}
                
                if ($myvarSearchedVMs) {
                    #process each retrieved entry
                    foreach ($myvarSearchedVM in $myvarSearchedVMs)
                    {
                        #check protection status
                        if ($myvarSearchedVM.protectionDomainName)
                        {
                            #warn that vm is already protected and move on
                            Write-Host "$(get-date) [WARNING] VM $($myvarSearchedVM.vmName) is already in protection domain $($myvarSearchedVM.protectionDomainName)..." -ForegroundColor Yellow
                            continue
                        }
                        else #the vm is not in a protection domain
                        {
                            #add vm to the list
                            Write-Host "$(get-date) [INFO] Adding VM $($myvarSearchedVM.vmName) to the list of VMs to add to protection domain $pd..." -ForegroundColor Green
                            $myvarVMsToAddToPd += $myvarSearchedVM.vmName
                        }
                    }#end foreach searched vm
                }
                else #we did not find any matching VM
                {
                    Write-Host "$(get-date) [WARNING] Could not find any VM matching string $myvarSearchString..." -ForegroundColor Yellow
                }
            }
            else #the vm name did not contain a wildcard
            {
                #retrieve the vm object
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/vms/"
                $method = "GET"
                $vmResult = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                $myvarExactVM = $vmResult.entities | Where-Object {$_.vmName -eq $myvarVM}
                
                if ($myvarExactVM)
                {
                    #check that vm protection status
                    if ($myvarExactVM.protectionDomainName)
                    {
                        #warn that vm is already protected and move on
                        Write-Host "$(get-date) [WARNING] VM $($myvarExactVM.vmName) is already in protection domain $($myvarExactVM.protectionDomainName)..." -ForegroundColor Yellow
                        continue
                    }
                    else #the vm is not in a protection domain
                    {
                        #add vm to the list
                        Write-Host "$(get-date) [INFO] Adding VM $($myvarExactVM.vmName) to the list of VMs to add to protection domain $pd..." -ForegroundColor Green
                        $myvarVMsToAddToPd += $myvarExactVM.vmName
                    }
                }
                else
                {
                    Write-Host "$(get-date) [WARNING] Could not find VM $myvarVM..." -ForegroundColor Yellow
                }
            }#endif contains wildcard
        }#end foreach vm
        
        #add vms to the pd
        if ($myvarVMsToAddToPd)
        {
            Write-Host "$(get-date) [INFO] Adding VMs to protection domain $pd..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd/protect_vms"
            $method = "POST"
            $body = (ConvertTo-Json $myvarVMsToAddToPd)
            $result = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
            Write-Host "$(get-date) [SUCCESS] Successfully added VMs to protection domain $pd!" -ForegroundColor Cyan
        }#endif vms to add to pd?
    }
    else
    {
        Write-Host "$(get-date) [ERROR] Could not find protection domain $pd on cluster $cluster!" -ForegroundColor Red
        exit 1
    }
    
    if ($replicateNow)
    {
        #replicate now
        Write-Host "$(get-date) [INFO] Starting an immediate replication for the protection domain $pd..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd/snapshots"
        $method = "POST"
        $result = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully triggered immediate snapshot for protection domain $pd!" -ForegroundColor Cyan
    }

#endregion
	
#########################
##       cleanup       ##
#########################

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
	Remove-Variable vm -ErrorAction SilentlyContinue
	Remove-Variable replicateNow -ErrorAction SilentlyContinue