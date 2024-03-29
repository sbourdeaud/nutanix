<#
.SYNOPSIS
  This script can be used to add unprotected vm(s) to an existing protection domain on Nutanix.
.DESCRIPTION
  This script adds existing virtual machines to an existing protection domain if they are not already protected.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER pd
  Name of the protection domain you want to add vms to.
.PARAMETER vm
  Name of the virtual machine(s) you want to add.  You can specify multiple vm names by use a comma separated list enclosed in double quotes or using the * wildcard. Note that when you use the * wildcard, it will try to match that string (exp: *mystring or mystring* or my*string will always behave as *mystring*)
.PARAMETER replicateNow
  This is an optional parameter. If you use -replicateNow, a snapshot will be taken immediately for each created consistency group.
.EXAMPLE
  Add all VMs that start with myvm* to protection domain "mypd" and replicate immediately:
  PS> .\add-NutanixProtectionDomains.ps1 -cluster ntnxc1.local -username admin -password admin -pd mypd -vm myvm* -replicateNow
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: September 15th 2016
#>

#region parameters
	Param
	(
		#[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
		[parameter(mandatory = $false)] [switch]$help,
		[parameter(mandatory = $false)] [switch]$history,
		[parameter(mandatory = $false)] [switch]$log,
		[parameter(mandatory = $false)] [switch]$debugme,
		[parameter(mandatory = $false)] [string]$cluster,
		[parameter(mandatory = $false)] [string]$username,
		[parameter(mandatory = $false)] [string]$password,
		[parameter(mandatory = $false)] [string]$pd,
		[parameter(mandatory = $false)] [string]$vm,
		[parameter(mandatory = $false)] [switch]$replicateNow,
		[parameter(mandatory = $false)] [int]$interval
	)
#endregion

#region functions
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
#endregion

#region prepwork
	# get rid of annoying error messages
	if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

	#check if we need to display help and/or history
	$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 08/18/2016 sb   Initial release.
 09/15/2016 sb   Added interactive prompting for mandatory parameters.
################################################################################
'@
	$myvarScriptName = ".\add-VmToPd.ps1"
	
	if ($help) {get-help $myvarScriptName; exit}
	if ($History) {$HistoryText; exit}


	#let's load the Nutanix cmdlets
	if ((Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue) -eq $null)#is it already there?
	{
		try {
			Add-PSSnapin NutanixCmdletsPSSnapin -ErrorAction Stop #no? let's add it
		}
		catch {
			Write-Warning $($_.Exception.Message)
			OutputLogData -category "ERROR" -message "Unable to load the Nutanix snapin.  Please make sure the Nutanix Cmdlets are installed on this server."
			return
		}
	}
#endregion

#region variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
	#initialize the array variable we are going to use to store vm objects to add to the protection domain
	#[System.Collections.ArrayList]$myvarVMsToAddToPd = New-Object System.Collections.ArrayList($null)
	$myvarVMsToAddToPd = @()
#endregion

#region parameters validation
	$myvarVMs = $vm.Split("{,}")
	if (!$cluster) {$cluster = read-host "Enter the hostname or IP address of the Nutanix cluster"}#prompt for the Nutanix cluster name
	if (!$username) {$username = read-host "Enter the Nutanix cluster username"}#prompt for the Nutanix cluster username
	if ($password) {
		$spassword = $password | ConvertTo-SecureString -AsPlainText -Force
		Remove-Variable password #clear the password variable so we don't leak it
	}
	else 
	{
		$password = read-host "Enter the Nutanix cluster password" -AsSecureString #prompt for the Nutanix cluster password
		$spassword = $password #we already have a secrue string
		Remove-Variable password #clear the password variable so we don't leak it
	}
	if (!$pd) {$pd = read-host "Enter the name of the protection domain"}#prompt for the Nutanix protection domain
	if (!$vm) {$vm = read-host "Enter the name of the vm(s) you want to add to the protection domain. Use comma separated values WITHOUT double quotes for multiple instances."}#prompt for the vm name
#endregion

	################################
	##  Main execution here       ##
	################################
	OutputLogData -category "INFO" -message "Connecting to the Nutanix cluster $myvarNutanixCluster..."
		try
		{
			$myvarNutanixCluster = Connect-NutanixCluster -Server $cluster -UserName $username -Password $spassword –acceptinvalidsslcerts -ForcedConnection -ErrorAction Stop
		}
		catch
		{#error handling
			Write-Warning $($_.Exception.Message)
			OutputLogData -category "ERROR" -message "Could not connect to $cluster"
			Exit
		}
	OutputLogData -category "INFO" -message "Connected to Nutanix cluster $cluster."
	
	if ($myvarNutanixCluster)
	{		
		######################
		#main processing here#
		######################
		
		#start by making sure the protection domain exists
		OutputLogData -category "INFO" -message "Getting protection domain $pd..."
		if (Get-NTNXProtectionDomain -Name $pd)
		{
			$myvarPdObject = Get-NTNXProtectionDomain -Name $pd
			#take the array of vm names specified by the user and process each entry
			foreach ($myvarVM in $myvarVMs)
			{
				if ($myvarVM -match '\*')
				{
					#strip wildcard
					$myvarVM = $myvarVM -replace '\*'
					#retrieve vms using search
					if ($myvarSearchedVMs = Get-NTNXVM -SearchString $myvarVM)
					{
						#process each retrieved entry
						foreach ($myvarSearchedVM in $myvarSearchedVMs)
						{
							#check protection status
							if ($myvarSearchedVM.protectionDomainName)
							{
								#warn that vm is already protected and move on
								OutputLogData -category "WARN" -message "VM $($myvarSearchedVM.vmName) is already in protection domain $($myvarSearchedVM.protectionDomainName)..."
								continue
							}
							else #the vm is not in a protection domain
							{
								#add vm to the list
								OutputLogData -category "INFO" -message "Adding VM $($myvarSearchedVM.vmName) to the list of VMs to add to protection domain $pd..."
								$myvarVMsToAddToPd += $myvarSearchedVM.vmName
							}
						}#end foreach searched vm
					}
					else #we did not find any matching VM
					{
						OutputLogData -category "WARN" -message "Could not find any VM matching string $myvarVM..."
					}
				}
				else #the vm name did not contain a wildcard
				{
					#retrieve the vm object
					if ($myvarExactVM = Get-NTNXVM | Where-Object {$_.vmName -eq $myvarVM})
					{
						#check that vm protection status
						if ($myvarExactVM.protectionDomainName)
						{
							#warn that vm is already protected and move on
							OutputLogData -category "WARN" -message "VM $($myvarExactVM.vmName) is already in protection domain $($myvarExactVM.protectionDomainName)..."
							continue
						}
						else #the vm is not in a protection domain
						{
							#add vm to the list
							OutputLogData -category "INFO" -message "Adding VM $($myvarExactVM.vmName) to the list of VMs to add to protection domain $pd..."
							$myvarVMsToAddToPd += $myvarExactVM.vmName
						}
					}
					else
					{
						OutputLogData -category "WARN" -message "Could not find VM $($myvarExactVM.vmName)..."
					}
				}#endif contains wildcard
			}#end foreach vm
				#add vms to the pd
				if ($myvarVMsToAddToPd)
				{
					OutputLogData -category "INFO" -message "Adding VMs to protection domain $pd..."
					Add-NTNXProtectionDomainVM -Name $pd -Names $myvarVMsToAddToPd | Out-Null
				}#endif vms to add to pd?
		}
		else
		{
			$myvarerror = $error[0].Exception.Message
			OutputLogData -category "ERROR" -message "$myvarerror"
			break
		}
		
		if ($replicateNow)
		{
			#replicate now
			OutputLogData -category "INFO" -message "Starting an immediate replication for the protection domain $pd..."
			Add-NTNXOutOfBandSchedule -Name $pd | Out-Null
		}

	}			
	
    OutputLogData -category "INFO" -message "Disconnecting from Nutanix cluster $cluster..."
	Disconnect-NutanixCluster -Servers $cluster #cleanup after ourselves and disconnect from the Nutanix cluster
	
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
	Remove-Variable cluster
	Remove-Variable username
	Remove-Variable password
	Remove-Variable pd
	Remove-Variable vm
	Remove-Variable replicateNow
    Remove-Variable debugme