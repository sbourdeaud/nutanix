<#
.SYNOPSIS
  This script can be used to configure a vsphere virtual machine ip address using the invoke-vmscript.
.DESCRIPTION
  The script uses the invoke-vmscript and vmware tools to run a command inside a vm. The command uses netsh to configure the default network card with a static IP.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER vcenter
  VMware vCenter server hostname. Default is localhost. You can specify several hostnames by separating entries with commas.
.PARAMETER vm
  Name of the virtual machine you want to configure.
.PARAMETER user
  Username with admin credentials inside the guest VM.
.PARAMETER password
  Password for the user with admin credentials inside the guest vm.
.PARAMETER ip
  Static ip address you want to configure on the guest vm.
.PARAMETER mask
  Subnet mask (exp: 255.255.255.0)
.PARAMETER gw
  Default gateway
.PARAMETER dns
  IP address of the primary DNS server.
.EXAMPLE
  Cononfiigure VM1:
  PS> .\set-guestVMip.ps1 -vcenter myvcenter.local -vm VM1 -ip 192.168.0.10 -mask 255.255.255.0 -gw 192.168.0.1 -dns 192.168.0.100
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

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
    [parameter(mandatory = $false)] [string]$vm,
    [parameter(mandatory = $false)] [string]$ip,
    [parameter(mandatory = $false)] [string]$mask,
    [parameter(mandatory = $false)] [string]$gw,
    [parameter(mandatory = $false)] [string]$dns
)

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

########################
##   main functions   ##
########################

Function Set-WinVMIP ($VM, $HC, $GC, $IP, $SNM, $GW, $DNS){
 $myvarInterfaces = "Get-NetAdapter"
 Write-Host "$(get-date) [INFO] Getting the list of available network adapters..." -ForegroundColor Green
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptText $myvarInterfaces
 $myvarNetAdapter = Read-Host "Enter the name of the adapter you want to configure"
 
 $netsh = "c:\windows\system32\netsh.exe interface ip set address ""$myvarNetAdapter"" static $IP $SNM $GW 1"
 Write-Host "$(get-date) [INFO] Setting IP address for $VM..." -ForegroundColor Green
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptType bat -ScriptText $netsh
 Write-Host "$(get-date) [SUCCESS] Setting IP address $IP for $VM completed." -ForegroundColor Cyan

 $netsh = "c:\windows\system32\netsh.exe interface ip set dns ""$myvarNetAdapter"" static $DNS"
 Write-Host "$(get-date) [INFO] Setting DNS for $VM..." -ForegroundColor Green
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptType bat -ScriptText $netsh
 Write-Host "$(get-date) [SUCCESS] Setting DNS address $DNS for $VM completed." -ForegroundColor Cyan
}

#########################
##   main processing   ##
#########################

#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed -log parameter and OutputLogData function; updated for modern PowerCLI
04/05/2016 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\set-guestVMip.ps1"
 
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

#check if we have all the required PoSH modules
Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

#region Load/Install VMware.PowerCLI
if (!(Get-Module VMware.PowerCLI)) {
    try {
        Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
        Import-Module VMware.VimAutomation.Core -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
    }
    catch { 
        Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
        try {
            Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
            Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
            try {
                Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"}
        }
        catch {throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"} 
    }
}

#check PowerCLI version
if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) {
    try {Update-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"}
    throw "$(get-date) [ERROR] Please upgrade PowerCLI to version 10 or above by running the command 'Update-Module VMware.PowerCLI' as an admin user"
}
#endregion


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
    if (!$vm) {$vm = read-host "Enter the VM name"}
    if (!$ip) {$ip = read-host "Enter the IP address for $vm"}
    if (!$mask) {$mask = read-host "Enter the subnet mask for $vm (exp:255.255.255.0)"}
    if (!$gw) {$gw = read-host "Enter the default gateway IP for $vm"}
    if (!$dns) {$dns = read-host "Enter the DNS server IP for $vm"}
	
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
            $myvarVM = Get-VM $vm
            $myvarHost = $myvarVM | Get-VMHost
            $myvarHostCred = $Host.UI.PromptForCredential("Please enter credentials", "Enter ESX host credentials for $ESXHost", "root", "")
		    $myvarGuestCred = $Host.UI.PromptForCredential("Please enter credentials", "Enter Guest credentials for $vm", "", "")
            Set-WinVMIP $myvarVM $myvarHostCred $myvarGuestCred $ip $mask $gw $dns

		}#endif
        Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
		Disconnect-viserver -Confirm:$False #cleanup after ourselves and disconnect from vcenter
	}#end foreach vCenter
	
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
    Remove-Variable vm -ErrorAction SilentlyContinue
    Remove-Variable ip -ErrorAction SilentlyContinue
    Remove-Variable mask -ErrorAction SilentlyContinue
    Remove-Variable gw -ErrorAction SilentlyContinue
    Remove-Variable dns -ErrorAction SilentlyContinue