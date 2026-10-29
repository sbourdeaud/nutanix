<#
.SYNOPSIS
  Copy portgroups and security policy on a specified vSwitch from one host to other hosts.
.DESCRIPTION
  This script is meant to be used when you are setting up standard vSwitches as part of a vSphere installation. Provided that you have set up all your portgroups and vSwitch security policy on one host manually, the script will let you specifiy that vSwitch and host as a source and a cluster name or list of host hostnames as a target and will copy all portgroups and the security policy over. 
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER vcenter
  VMware vCenter server hostname. If you don't specify one, the script will prompt you.
.PARAMETER sourceHost
  Name of the source host which contains the desired vSwitch configuration.
.PARAMETER sourcevSwitch
  Name of the vSwitch you want to copy.
.PARAMETER targetHost
  Name of the target host where you want to copy the vSwitch configuration. Multiple hostnames can be specified using a comma separated list.
.PARAMETER targetCluster
  Instead of specifying a target host, you can specify a target cluster.  If the source host is in that cluster, it will be automatically excluded to avoid errors.
.EXAMPLE
  Copy vSwitch0 configuration to all hosts in cluster01 from host hostA:
  PS> .\set-portgroups.ps1 -vcenter myvcenter.local -sourceHost hostA -sourcevSwitch vSwitch0 -targetCluster cluster01
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region parameters
######################################
##   parameters and initial setup   ##
######################################
#let's start with some command line parsing
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$vcenter,
	[parameter(mandatory = $false)] [string]$sourceHost,
	[parameter(mandatory = $false)] [string]$sourcevSwitch,
	[parameter(mandatory = $false)] [string]$targetHost,
	[parameter(mandatory = $false)] [string]$targetCluster
)
#endregion

#region prepwork
# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
if ($debugme) {$VerbosePreference = "Continue"}

#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed -log parameter and OutputLogData function; updated PowerCLI handling
06/19/2015 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\set-portgroups.ps1"
 
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
#endregion

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	if (!$vcenter) {$vcenter = read-host "Enter vCenter server name or IP address"}#prompt for vcenter server name
	$myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
    if (!$sourceHost) {$sourceHost = read-host "Enter name of the source host"}#prompt for source host name
	if (!$sourcevSwitch) {$sourcevSwitch = read-host "Enter name of the source vSwitch"}#prompt for source vSwitch name
	if (!$targetCluster -and !$targetHost)
	{
		$myvarTargetType = read-host "Do you want to target host(s) or a cluster? [H/c] "
		if ($myvarTargetType -eq "c")
		{
			$targetCluster = read-host "Enter the name of the target cluster" #prompt for target cluster name
		}
		else 
		{
			$targetHost = read-host "Enter target Host(s) name (use comma to separate multiple entries)" #prompt for target host(s) name(s)
		}
	}
	if ($targetHost) {$myvarHosts = $targetHost.Split(",")}
#endregion

#region main processing
#########################
##   main processing   ##
#########################
	
################################
##  foreach vCenter loop      ##
################################
foreach ($myvarvCenter in $myvarvCenterServers)	
{
	Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
	if (!($myvarvCenterObject = Connect-VIServer $myvarvCenter))#make sure we connect to the vcenter server OK...
	{#make sure we can connect to the vCenter server
		$myvarerror = $error[0].Exception.Message
		Write-Host "$(get-date) [ERROR] $myvarerror" -ForegroundColor Red
		return
	}
	else #...otherwise show the error message
	{
		Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter." -ForegroundColor Cyan
	}#endelse
	
	if ($myvarvCenterObject)
	{
	
		######################
		#main processing here#
		######################
		
		#get hosts in the cluster
		if ($targetCluster) {$myvarHosts = Get-Cluster -Name $targetCluster | Get-VMHost | where {$_.Name -ne $sourceHost}}
		
		#connect to source host
		Write-Host "$(get-date) [INFO] Connecting to source host $sourceHost..." -ForegroundColor Green
		if ($myvarSourceHostObject = Get-VMHost -Name $sourceHost*)
		{
			Write-Host "$(get-date) [SUCCESS] Connected to source host server $myvarSourceHostObject." -ForegroundColor Cyan
			Write-Host "$(get-date) [INFO] Getting configuration for $sourcevSwitch..." -ForegroundColor Green
			$myvarvSwitch = $myvarSourceHostObject |Get-VirtualSwitch -Name $sourcevSwitch
			Write-Host "$(get-date) [INFO] Enumerating portgroups on $sourcevSwitch..." -ForegroundColor Green
			$myvarPortgroups = $myvarSourceHostObject | Get-VirtualPortGroup -Standard -VirtualSwitch $myvarvSwitch.Name | where {$_.VirtualSwitchName -eq $myvarvSwitch.Name}
			Write-Host "$(get-date) [INFO] Getting vSwitch security policy for $sourcevSwitch..." -ForegroundColor Green
			$myvarSourcevSwitchSecurityPolicy = Get-SecurityPolicy -virtualswitch $myvarvSwitch
		} else {
			$myerror = $error[0].Exception.Message
			Write-Host "$(get-date) [ERROR] $myerror" -ForegroundColor Red
			return
		}#endifelse
		
		
		foreach ($myvarHost in $myvarHosts)	
		{
			Write-Host "$(get-date) [INFO] Processing host $myvarHost..." -ForegroundColor Green
			if ($myvarTargetHostObject = Get-VMHost -Name $myvarHost*)
			{
				Write-Host "$(get-date) [SUCCESS] Connected to target host server $myvarTargetHostObject." -ForegroundColor Cyan
				
				#let's check to see if the vswitch already exists
				If (($myvarTargetHostObject |Get-VirtualSwitch -Name $myvarvSwitch.Name -ErrorAction SilentlyContinue)-eq $null)
				{
					Write-Host "$(get-date) [INFO] Creating Virtual Switch $myvarvSwitch on $myvarHost" -ForegroundColor Green
					$myvarNewSwitch = $myvarTargetHostObject |New-VirtualSwitch -Name $myvarvSwitch.Name -NumPorts $myvarvSwitch.NumPorts -Mtu $myvarvSwitch.Mtu
					Write-Host "$(get-date) [INFO] Copying security policy on Virtual Switch $myvarvSwitch on $myvarHost" -ForegroundColor Green
					Set-SecurityPolicy -VirtualSwitchPolicy (Get-SecurityPolicy -VirtualSwitch $myvarNewSwitch) -AllowPromiscuous $myvarSourcevSwitchSecurityPolicy.AllowPromiscuous -ForgedTransmits $myvarSourcevSwitchSecurityPolicy.ForgedTransmits -MacChanges $myvarSourcevSwitchSecurityPolicy.MacChanges | Out-Null
				}
				else
				{
					Write-Host "$(get-date) [INFO] Copying security policy on Virtual Switch $myvarvSwitch on $myvarHost" -ForegroundColor Green
					Set-SecurityPolicy -VirtualSwitchPolicy (Get-SecurityPolicy -VirtualSwitch ($myvarTargetHostObject |Get-VirtualSwitch -Name $myvarvSwitch.Name)) -AllowPromiscuous $myvarSourcevSwitchSecurityPolicy.AllowPromiscuous -ForgedTransmits $myvarSourcevSwitchSecurityPolicy.ForgedTransmits -MacChanges $myvarSourcevSwitchSecurityPolicy.MacChanges  | Out-Null
				}#endifelse
				
				#process port groups
				foreach ($myvarPortgroup in $myvarPortgroups)
				{
					$myvarPG = $myvarPortgroup.name
					#create the port group on the target host if it does not exist
					If (($myvarTargetHostObject |Get-VirtualPortGroup -Name $myvarPG -ErrorAction SilentlyContinue)-eq $null)
					{
						Write-Host "$(get-date) [INFO] Creating Portgroup $($myvarPortgroup.Name) on $myvarvSwitch on $myvarHost" -ForegroundColor Green
						$myvarNewPortGroup = $myvarTargetHostObject |Get-VirtualSwitch -Name $myvarvSwitch.Name |New-VirtualPortGroup -Name $myvarPortgroup.Name-VLanId $myvarPortgroup.VLanID
						Write-Host "$(get-date) [INFO] Copying Portgroup security policy for $($myvarPortgroup.Name) on $myvarvSwitch on $myvarHost" -ForegroundColor Green
						$myvarPortgroupSecurityPolicy = Get-SecurityPolicy -VirtualPortGroup $myvarPortgroup
						Set-SecurityPolicy -VirtualPortGroupPolicy (Get-SecurityPolicy -VirtualPortGroup $myvarNewPortGroup) -AllowPromiscuous $myvarPortgroupSecurityPolicy.AllowPromiscuous -ForgedTransmits $myvarPortgroupSecurityPolicy.ForgedTransmits -MacChanges $myvarPortgroupSecurityPolicy.MacChanges  | Out-Null
						Set-SecurityPolicy -VirtualPortGroupPolicy (Get-SecurityPolicy -VirtualPortGroup $myvarNewPortGroup) -AllowPromiscuousInherited $myvarPortgroupSecurityPolicy.AllowPromiscuousInherited -ForgedTransmitsInherited $myvarPortgroupSecurityPolicy.ForgedTransmitsInherited -MacChangesInherited $myvarPortgroupSecurityPolicy.MacChangesInherited  | Out-Null
					}
					else
					{
						Write-Host "$(get-date) [INFO] Copying Portgroup security policy for $($myvarPortgroup.Name) on $myvarvSwitch on $myvarHost" -ForegroundColor Green
						$myvarPortgroupSecurityPolicy = Get-SecurityPolicy -VirtualPortGroup $myvarPortgroup
						Set-SecurityPolicy -VirtualPortGroupPolicy (Get-SecurityPolicy -VirtualPortGroup ($myvarTargetHostObject |Get-VirtualPortGroup -Name $myvarPG)) -AllowPromiscuous $myvarPortgroupSecurityPolicy.AllowPromiscuous -ForgedTransmits $myvarPortgroupSecurityPolicy.ForgedTransmits -MacChanges $myvarPortgroupSecurityPolicy.MacChanges  | Out-Null
						Set-SecurityPolicy -VirtualPortGroupPolicy (Get-SecurityPolicy -VirtualPortGroup ($myvarTargetHostObject |Get-VirtualPortGroup -Name $myvarPG)) -AllowPromiscuousInherited $myvarPortgroupSecurityPolicy.AllowPromiscuousInherited -ForgedTransmitsInherited $myvarPortgroupSecurityPolicy.ForgedTransmitsInherited -MacChangesInherited $myvarPortgroupSecurityPolicy.MacChangesInherited  | Out-Null
					}#endifelse
				}#end foreach port group loop
			}
			else
			{
				$myerror = $error[0].Exception.Message
				Write-Host "$(get-date) [ERROR] $myerror" -ForegroundColor Red
				return
			}#endifelse
		}#end foreach host loop
	}#endif
	Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
	Disconnect-viserver -Confirm:$False #cleanup after ourselves and disconnect from vcenter
}#end foreach vCenter

#endregion

#region cleanup
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
	Remove-Variable vcenter -ErrorAction SilentlyContinue
	Remove-Variable sourceHost -ErrorAction SilentlyContinue
	Remove-Variable sourcevSwitch -ErrorAction SilentlyContinue
	Remove-Variable targetHost -ErrorAction SilentlyContinue
	Remove-Variable targetCluster -ErrorAction SilentlyContinue
#endregion