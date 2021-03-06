<#
.SYNOPSIS
  This script can be used to configure a vsphere virtual machine ip address using the invoke-vmscript.
.DESCRIPTION
  The script uses the invoke-vmscript and vmware tools to run a command inside a vm. The command uses netsh to configure the default network card with a static IP.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
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
  Revision: April 5th 2016
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
    [parameter(mandatory = $false)] [switch]$log,
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

#this function is used to output log data
Function OutputLogData 
{
	#input: log category, log message
	#output: text to standard output
<#
.SYNOPSIS
  Outputs messages to the screen and/or log file.
.DESCRIPTION
  This function is used to produce screen and log output which is categorized, time stamped and color coded.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER myCategory
  This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".
.PARAMETER myMessage
  This is the actual message you want to display.
.EXAMPLE
  PS> OutputLogData -mycategory "ERROR" -mymessage "You must specify a cluster name!"
#>
	param
	(
		[string] $category,
		[string] $message
	)

    begin
    {
	    $myvarDate = get-date
	    $myvarFgColor = "Gray"
	    switch ($category)
	    {
		    "INFO" {$myvarFgColor = "Green"}
		    "WARNING" {$myvarFgColor = "Yellow"}
		    "ERROR" {$myvarFgColor = "Red"}
		    "SUM" {$myvarFgColor = "Magenta"}
	    }
    }

    process
    {
	    Write-Host -ForegroundColor $myvarFgColor "$myvarDate [$category] $message"
	    if ($log) {Write-Output "$myvarDate [$category] $message" >>$myvarOutputLogFile}
    }

    end
    {
        Remove-variable category
        Remove-variable message
        Remove-variable myvarDate
        Remove-variable myvarFgColor
    }
}#end function OutputLogData

Function Set-WinVMIP ($VM, $HC, $GC, $IP, $SNM, $GW, $DNS){
 $myvarInterfaces = "Get-NetAdapter"
 OutputLogData -category "INFO" -message "Getting the list of available network adapters..."
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptText $myvarInterfaces
 $myvarNetAdapter = Read-Host "Enter the name of the adapter you want to configure"
 
 $netsh = "c:\windows\system32\netsh.exe interface ip set address ""$myvarNetAdapter"" static $IP $SNM $GW 1"
 OutputLogData -category "INFO" -message "Setting IP address for $VM..."
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptType bat -ScriptText $netsh
 OutputLogData -category "INFO" -message "Setting IP address $IP for $VM completed."

 $netsh = "c:\windows\system32\netsh.exe interface ip set dns ""$myvarNetAdapter"" static $DNS"
 OutputLogData -category "INFO" -message "Setting DNS for $VM..."
 Invoke-VMScript -VM $VM -GuestCredential $GC -ScriptType bat -ScriptText $netsh
 OutputLogData -category "INFO" -message "Setting DNS address $DNS for $VM completed."
}

#########################
##   main processing   ##
#########################

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 04/05/2016 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\set-guestVMip.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}



#let's make sure the VIToolkit is being used
if ((Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null)#is it already there?
{
	Add-PSSnapin VMware.VimAutomation.Core #no? let's add it
	if (!$?) #have we been able to add it successfully?
	{
		OutputLogData -category "ERROR" -message "Unable to load the PowerCLI snapin.  Please make sure PowerCLI is installed on this server."
		return
	}
} 
#Initialize-VIToolkitEnvironment.ps1 | Out-Null


#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
	
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
		OutputLogData -category "INFO" -message "Connecting to vCenter server $myvarvCenter..."
		if (!($myvarvCenterObject = Connect-VIServer $myvarvCenter))#make sure we connect to the vcenter server OK...
		{#make sure we can connect to the vCenter server
			$myvarerror = $error[0].Exception.Message
			OutputLogData -category "ERROR" -message "$myvarerror"
			return
		}
		else #...otherwise show the error message
		{
			OutputLogData -category "INFO" -message "Connected to vCenter server $myvarvCenter."
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
        OutputLogData -category "INFO" -message "Disconnecting from vCenter server $vcenter..."
		Disconnect-viserver -Confirm:$False #cleanup after ourselves and disconnect from vcenter
	}#end foreach vCenter
	
#########################
##       cleanup       ##
#########################

	#let's figure out how much time this all took
	OutputLogData -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar*
	Remove-Variable ErrorActionPreference
	Remove-Variable help
    Remove-Variable history
	Remove-Variable log
	Remove-Variable vcenter
    Remove-Variable debugme
    Remove-Variable vm
    Remove-Variable ip
    Remove-Variable mask
    Remove-Variable gw
    Remove-Variable dns