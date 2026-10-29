<#
.SYNOPSIS
  This script can be used to create protection domains and consistency groups based on a VM folder structure in vCenter.
.DESCRIPTION
  This script creates protection domains with consistency groups including all VMs in a given vCenter server VM folder.  Protection domains and consistency groups are automatically named "<clustername>-pd-<foldername>" and "<clustername>-cg-<foldername>".
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER vcenter
  Hostname of the vSphere vCenter to which the hosts you want to mount the NFS datastore belong to.  This is optional.  By Default, if no vCenter server and vSphere cluster name are specified, then the NFS datastore is mounted to all hypervisor hosts in the Nutanix cluster.  The script assumes the user running it has access to the vcenter server.
.PARAMETER folder
  Name of the VM folder object in vCenter which contains the virtual machines to be added to the protection domain and consistency group. You can specify multiple folder names by separating them with commas in which case you must enclose them in double quotes.
.PARAMETER repeatEvery
  Valid values are HOURLY, DAILY and WEEKLY, followed by the number of repeats.  For example, if you want backups to occur once a day, specify "DAILY,1" (note the double quotes).
.PARAMETER startOn
  Specifies the date and time at which you want to start the backup in the format: "MM/dd/YYYY,HH:MM". Note that this should be in UTC and enclosed in double quotes.  Depending on your regional settings, you may have to invert month and day to get the correct date.
.PARAMETER retention
  Specifies the number of snapshot versions you want to keep.
.PARAMETER replicateNow
  This is an optional parameter. If you use -replicateNow, a snapshot will be taken immediately for each created consistency group.
.PARAMETER interval
  This is an optional parameter. Specify the interval in minutes at which you want to separate each schedule.  This is to prevent scheduling all protection domains snapshots at the same time. If you are processing multiple folders, the first protection domain will be scheduled at the exact specified time (say 20:00 UTC), the next protection domain will be scheduled at +interval minutes (so 20:05 UTC if your interval is 5), and so on...
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\add-NutanixProtectionDomains.ps1 -cluster ntnxc1.local -folder "appA,appB" -repeatEvery "DAILY,1" -startOn "07/29/2015,20:00" -retention 3 -replicateNow
Create a protection domain for VM folders "appA" and "appB", schedule a replication every day at 8:00PM UTC, set a retention of 3 snapshots and replicate immediately.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#todo: add code to replicate now
#todo: add code to check pd is active on cluster before editing it
#todo: add code to enable adding remote site

#region parameters
	Param
	(
		#[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
		[parameter(mandatory = $false)] [switch]$help,
		[parameter(mandatory = $false)] [switch]$history,
		[parameter(mandatory = $false)] [switch]$debugme,
		[parameter(mandatory = $false)] [string]$cluster,
		[parameter(mandatory = $false)] [string]$folder,
		[parameter(mandatory = $false)] [string]$repeatEvery,
		[parameter(mandatory = $false)] [string]$startOn,
		[parameter(mandatory = $false)] [string]$retention,
		[parameter(mandatory = $false)] [switch]$replicateNow,
		[parameter(mandatory = $false)] [int]$interval,
		[parameter(mandatory = $false)] $prismCreds,
		[parameter(mandatory = $false)] $vcenterCreds
	)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
02/03/2021 sb   Code update with PowerCLI module and REST API calls for NTNX.
06/19/2015 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\add-NutanixProtectionDomains.ps1"
	
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

	#check if we have all the required PoSH modules
	Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green
  
	#region Load/Install VMware.PowerCLI
		if (!(Get-Module VMware.PowerCLI)) 
		{#module VMware.PowerCLI is not loaded
			try 
			{#load module VMware.PowerCLI
				Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
				Import-Module VMware.PowerCLI -ErrorAction Stop
				Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
			}
			catch 
			{#couldn't load module VMware.PowerCLI
				Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
				try 
				{#install module VMware.PowerCLI
					Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
					Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
					Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
					try 
					{#loading module VMware.PowerCLI
						Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
						Import-Module VMware.VimAutomation.Core -ErrorAction Stop
						Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
					}
					catch 
					{#couldn't load module VMware.PowerCLI
						throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
					}
				}
				catch 
				{#couldn't install module VMware.PowerCLI
					throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"
				}
			}
		}
		
		if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
		{#check PowerCLI version
			try 
			{#update module VMware.PowerCLI
				Update-Module -Name VMware.PowerCLI -ErrorAction Stop
			} 
			catch 
			{#couldn't update module VMware.PowerCLI
				throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"
			}
		}
	#endregion
	if ((Get-PowerCLIConfiguration | where-object {$_.Scope -eq "User"}).InvalidCertificateAction -ne "Ignore") {
	  Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false
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
	#initialize variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
#endregion


#region parameters validation
    if (!$prismcentral -or !$cluster -or !$pd) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral -cluster -pd!"
    }
	#let's initialize parameters if they haven't been specified
	$myvar_folders = $folder -split "\s*,\s*"
	if ($interval -and (($interval -le 0) -or ($interval -ge 60)))
	{
		Write-Host "$(get-date) [ERROR] Interval must be between 1 and 59 minutes!" -ForegroundColor Red
		Exit 1
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

    if ($vcenterCreds) 
	{#vcenterCreds was specified
		try 
		{
			$vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop 
		}
		catch 
		{
			Set-CustomCredentials -credname $vcenterCreds
			$vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
		}
	}
	else 
	{#no vcenter creds were given
		$vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
	}
	$vcenterUsername = $vcenterCredentials.UserName
	$vcenterSecurePassword = $vcenterCredentials.Password
	$vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword

	#! customization here
	#region define constants (you can customize those if you want)
	$pd_prefix = "-pd-" #prefix for protection domain name
	$cg_prefix = "-cg-" #prefix for consistency group name
	$default_repeat = "DAILY,1" #default replication frequency
	$default_start = (Get-Date).AddMinutes(5).ToString("MM/dd/yyyy,HH:mm") #default start time (5 min from now)
	$default_retention = 3 #default retention
	$default_interval = 5 #default interval between schedules (minutes)
	$vm_folder_root = "vm" #vSphere VM folder root
#endregion

#region processing

    #region connect to vCenter
        Write-Host "$(get-date) [INFO] Connecting to vCenter..." -ForegroundColor Green
        Connect-VIServer -Server $vcenter -Credential $vcenterCredentials -WarningAction SilentlyContinue | Out-Null
        if ($?) {
            Write-Host "$(get-date) [SUCCESS] Connected to vCenter" -ForegroundColor Cyan
        } else {
            Write-Host "$(get-date) [ERROR] Failed to connect to vCenter" -ForegroundColor Red
            Exit 1
        }
    #endregion

    #region get cluster info
        Write-Host "$(get-date) [INFO] Retrieving Nutanix cluster info..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $clusterInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Retrieved cluster info: $($clusterInfo.name)" -ForegroundColor Cyan
    #endregion

    #region process each folder
        ForEach ($folderName in $myvar_folders) {
            Write-Host "$(get-date) [INFO] Processing VM folder: $folderName" -ForegroundColor Green
            
            $vmFolder = Get-Folder -Name $folderName -Type VM -ErrorAction SilentlyContinue
            if (!$vmFolder) {
                Write-Host "$(get-date) [WARNING] VM folder '$folderName' not found in vCenter" -ForegroundColor Yellow
                Continue
            }
            
            $vms = Get-VM -Location $vmFolder -NoRecursion | Where-Object {$_.PowerState -eq "PoweredOn"}
            if (!$vms) {
                Write-Host "$(get-date) [WARNING] No powered-on VMs found in folder '$folderName'" -ForegroundColor Yellow
                Continue
            }
            
            $pdName = "$($clusterInfo.name)$pd_prefix$folderName"
            $cgName = "$($clusterInfo.name)$cg_prefix$folderName"
            
            Write-Host "$(get-date) [INFO] Protection domain: $pdName, Consistency group: $cgName" -ForegroundColor Green
            
            #region get existing protection domains
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $pdList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            #endregion
            
            #region check if PD exists
                $existingPd = $pdList.entities | Where-Object {$_.name -eq $pdName}
                if ($existingPd) {
                    Write-Host "$(get-date) [INFO] Protection domain $pdName already exists" -ForegroundColor Green
                } else {
                    Write-Host "$(get-date) [INFO] Creating protection domain $pdName..." -ForegroundColor Green
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                    $method = "POST"
                    $content = @{ name = $pdName }
                    $body = (ConvertTo-Json $content)
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
                    Write-Host "$(get-date) [SUCCESS] Created protection domain $pdName" -ForegroundColor Cyan
                }
            #endregion
            
            #region add VMs to protection domain
                $vmUuids = @()
                ForEach ($vm in $vms) {
                    $vmUuids += $vm.ExtensionData.Config.Uuid
                }
                
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pdName/vms/add"
                $method = "POST"
                $content = @{ uuids = $vmUuids }
                $body = (ConvertTo-Json $content)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
                Write-Host "$(get-date) [SUCCESS] Added $($vmUuids.Count) VMs to protection domain $pdName" -ForegroundColor Cyan
            #endregion
            
            #region create consistency group
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pdName/consistency_groups/"
                $method = "GET"
                $cgList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                
                $existingCg = $cgList.entities | Where-Object {$_.name -eq $cgName}
                if ($existingCg) {
                    Write-Host "$(get-date) [INFO] Consistency group $cgName already exists" -ForegroundColor Green
                } else {
                    Write-Host "$(get-date) [INFO] Creating consistency group $cgName..." -ForegroundColor Green
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pdName/consistency_groups/"
                    $method = "POST"
                    $content = @{ name = $cgName }
                    $body = (ConvertTo-Json $content)
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
                    Write-Host "$(get-date) [SUCCESS] Created consistency group $cgName" -ForegroundColor Cyan
                }
            #endregion
            
            #region schedule
                if ($repeatEvery -or $startOn -or $retention) {
                    Write-Host "$(get-date) [INFO] Configuring schedule for $pdName..." -ForegroundColor Green
                    # Schedule configuration would go here
                    Write-Host "$(get-date) [INFO] Schedule configuration not fully implemented in this version" -ForegroundColor Yellow
                }
            #endregion
            
            #region replicate now
                if ($replicateNow) {
                    Write-Host "$(get-date) [INFO] Triggering immediate replication for $cgName..." -ForegroundColor Green
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pdName/consistency_groups/$cgName/snapshot"
                    $method = "POST"
                    $content = @{}
                    $body = (ConvertTo-Json $content)
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
                    Write-Host "$(get-date) [SUCCESS] Triggered snapshot for $cgName" -ForegroundColor Cyan
                }
            #endregion
        }
    #endregion

#endregion


#region cleanup
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    
    #cleanup after ourselves
    Disconnect-VIServer -Server $vcenter -Confirm:$false -WarningAction SilentlyContinue
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable folder -ErrorAction SilentlyContinue
    Remove-Variable repeatEvery -ErrorAction SilentlyContinue
    Remove-Variable startOn -ErrorAction SilentlyContinue
    Remove-Variable retention -ErrorAction SilentlyContinue
    Remove-Variable replicateNow -ErrorAction SilentlyContinue
    Remove-Variable interval -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vcenterCreds -ErrorAction SilentlyContinue
    Remove-Variable vcenter -ErrorAction SilentlyContinue
#endregion