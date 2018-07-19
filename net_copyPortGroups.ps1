################################################################################
# Author: Stephane Bourdeaud (stephaneb@fr.ibm.com)
# Description:  This script enables you to copy port groups from a given vswitch
#				on a given host to another host or set of hosts.
# Revision history:
#	02/26/2010 - Initial tested version.
################################################################################

######################################
##   parameters and initial setup   ##
######################################
#let's start with some command line parsing
#this param line MUST BE FIRST in the script
param
(
	[switch] $help ,
	[string] $vcenter ,
	[string] $sourceHost ,
	[string] $sourcevSwitch ,
	[string] $targetHost ,
	[string] $targetvSwitch
)

# get rid of annoying error messages
$ErrorActionPreference = "SilentlyContinue"

#this function is used to show script usage guidelines
function Usage {
	""
	"Version: 1.0 (02/26/2010), Author: stephaneb@fr.ibm.com"
	""
	"Usage: net_copyPortGroups [-vcenter] <hostname> [-help] -sourceHost <hostname>"
	"			-sourcevSwitch <vSwitch name/all> -targetHost <hostname>"
	""
	"Parameters:"
	"  -vcenter      : VMware vCenter hostname. Default is localhost."
	"                  You can specify several hostnames by separating entries"
	"                  with commas."
	" -sourceHost	 : ESX hostname that you want to use as the source."
	" -sourcevSwitch : vSwitch name on the source host that you want to"
	"                  copy port groups from. You can specify 'all' if"
	"                  you want to copy all port groups from all vSwitches."
	" -targetHost	 : ESX hostname that you want to copy port groups to."
	"                  You can specify several hostnames by separating entries"
	"                  with commas."
	"  -help         : Displays this help message."
	""
	exit
}#end function Usage

#let's make sure the VIToolkit is being used
$myvarPowerCLI = Get-PSSnapin VMware.VimAutomation.Core -Registered
try {
    switch ($myvarPowerCLI.Version.Major) {
        {$_ -ge 6}
            {
            Import-Module VMware.VimAutomation.Vds -ErrorAction Stop
            OutputLogData -category "INFO" -message "PowerCLI 6+ module imported"
            }
        5   {
            Add-PSSnapin VMware.VimAutomation.Vds -ErrorAction Stop
            OutputLogData -category "WARNING" -message "PowerCLI 5 snapin added; recommend upgrading your PowerCLI version"
            }
        default {throw "This script requires PowerCLI version 5 or later"}
        }
    }
catch {throw "Could not load the required VMware.VimAutomation.Vds cmdlets"}

########################
##   main functions   ##
########################

#this function is used to output log data
function OutputLogData {
	#input: log category, log message
	#output: text to standard output
	param
	(
		[string] $category,
		[string] $message
	)
	$mydate = get-date
	Write-Host "$mydate [$category] $message"
	Write-Output "$mydate [$category] $message" >>$OutputLogFile
}#end function OutputLogData

#########################
##   main processing   ##
#########################

#initialize variables
	#misc variables
	$begint = "" #used to store script begin timestamp
	$vCenterServers = @() #used to store the list of all the vCenter servers we must connect to

#do some prep stuff
	#let's document when we start processing in order to determine how long it took in the end
	$begint = get-date
	
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	if (($args -eq '-?') -or $help) {#check if help was called
		Usage
	}#endif
	if (!$vcenter) {#assign localhost if no vCenter has been specified
		$vCenterServers += $env:computername
	} else {#otherwise make sure we parse the argument in case it contains several entries
		$vCenterServers = $vcenter.Split()
	}#endelse
	if (!$sourceHost) {
		OutputLogData -category "ERROR" -message "You must specify a source host."
		Usage
	}#endif
	if (!$sourcevSwitch) {
		OutputLogData -category "ERROR" -message "You must specify a source vSwitch."
		Usage
	}#endif
	if (!$targetHost) {
		OutputLogData -category "ERROR" -message "You must specify a target host."
		Usage
	} else {#otherwise make sure we parse the argument in case it contains several entries
		$targetHosts = $targetHost.Split()
	}#endelse
	
	$OutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$OutputLogFile += "OutputLog.log"
	
	################################
	##  foreach vCenter loop      ##
	################################
	foreach ($myvCenter in $vCenterServers)	{
		OutputLogData -category "INFO" -message "Connecting to vCenter server $myvCenter..."
		if (!($vCenterObject = Connect-VIServer $myvCenter))	{
			$myerror = $error[0].Exception.Message
			OutputLogData -category "ERROR" -message "$myerror"
			return 0
		} else {
			OutputLogData -category "INFO" -message "Connected to vCenter server $myvCenter."
		}#endelse
	}#end foreach vCenter
	
	#we are connected to all vCenter servers, now let's connect to our source host
	if ($sourceHostObject = Get-VMHost -Name $sourceHost*) {
		OutputLogData -category "INFO" -message "Connected to source host server $sourceHostObject."
	} else {
		$myerror = $error[0].Exception.Message
		OutputLogData -category "ERROR" -message "$myerror"
		return
	}#endelse
	
	if ($sourcevSwitch -eq "all") {#if we want to copy all port groups on all virtual switches
		#enumerate virtual switches on the source host
		$sourceHostObject |Get-VirtualSwitch |Foreach-Object {
			$switch = $_.Name
			#process all target hosts
			foreach ($mytargetHost in $targetHosts) {
				if ($mytargetHostObject = Get-VMHost -Name $mytargetHost*) {
					OutputLogData -category "INFO" -message "Connected to target host server $mytargetHostObject."
				} else {
					$myerror = $error[0].Exception.Message
					OutputLogData -category "ERROR" -message "$myerror"
					return
				}#endelse
				#let's check to see if the vswitch already exists
				If (($mytargetHostObject |Get-VirtualSwitch -Name $switch -ErrorAction SilentlyContinue)-eq $null){
					OutputLogData -category "INFO" -message "Creating Virtual Switch $($_.Name) on $mytargetHost”
					$NewSwitch = $mytargetHostObject |New-VirtualSwitch -Name $_.Name-NumPorts $_.NumPorts-Mtu $_.Mtu
					#$vSwitch = $_
				}#endif
				#enumerate port groups on the source host
				$sourceHostObject | Get-VirtualPortGroup -VirtualSwitch $switch | Where-Object {$_.VirtualSwitchName -eq $switch}| Foreach-Object {
					$myPG = $_.name
					#create the port group on the target host if it does not exist
					If (($mytargetHostObject |Get-VirtualPortGroup -Name $myPG -ErrorAction SilentlyContinue)-eq $null){
						OutputLogData -category "INFO" -message "Creating Portgroup $($_.Name) on $switch on $mytargetHost”
						$NewPortGroup = $mytargetHostObject |Get-VirtualSwitch -Name $switch |New-VirtualPortGroup -Name $_.Name-VLanId $_.VLanID
					}#endif
				}#end foreach port group loop
			}#end for each target host loop
		}#end foreach vSwitch loop
	} else {#we haven't specified all vswitches, so let's process only the one vswitch we want
		$myvSwitch = $sourceHostObject |Get-VirtualSwitch -Name $sourcevSwitch
		#process all target hosts
		foreach ($mytargetHost in $targetHosts) {
			$mytargetHostObject = Get-VMHost -Name $mytargetHost
			#let's check to see if the vswitch already exists
			If (($mytargetHostObject |Get-VirtualSwitch -Name $myvSwitch.Name -ErrorAction SilentlyContinue) -eq $null){
				OutputLogData -category "INFO" -message "Creating Virtual Switch $myvSwitch on $mytargetHost”
				$NewSwitch = $mytargetHostObject |New-VirtualSwitch -Name $myvSwitch.Name -NumPorts $myvSwitch.NumPorts -Mtu $myvSwitch.Mtu
			}#endif
			#enumerate port groups on the source host
			$sourceHostObject | Get-VirtualPortGroup -VirtualSwitch $myvSwitch.Name |where {$_.VirtualSwitchName -eq $myvSwitch.Name} | Foreach {
				$myPG = $_.name
				#create the port group on the target host if it does not exist
				If (($mytargetHostObject |Get-VirtualPortGroup -Name $myPG -ErrorAction SilentlyContinue)-eq $null){
					OutputLogData -category "INFO" -message "Creating Portgroup $($_.Name) on $myvSwitch on $mytargetHost”
					$NewPortGroup = $mytargetHostObject |Get-VirtualSwitch -Name $myvSwitch.Name |New-VirtualPortGroup -Name $_.Name-VLanId $_.VLanID
				}#endif
			}#end foreach port group loop
		}#end for each target host loop
	}#endelse
	
	Disconnect-viserver -Confirm:$False
	
	#let's figure out how much time this all took
	$endt = get-date
	$elapsed = (($endt - $begint).TotalSeconds)
	OutputLogData -category "SUM" -message "total processing time in seconds: $elapsed"