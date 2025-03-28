<#
.SYNOPSIS
  This script can be used to create protection domains and consistency groups based on a VM folder structure in vCenter.
.DESCRIPTION
  This script creates protection domains with consistency groups including all VMs in a given vCenter server VM folder.  Protection domains and consistency groups are automatically named "<clustername>-pd-<foldername>" and "<clustername>-cg-<foldername>".
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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\add-NutanixProtectionDomains.ps1 -cluster ntnxc1.local -folder "appA,appB" -repeatEvery "DAILY,1" -startOn "07/29/2015,20:00" -retention 3 -replicateNow
Create a protection domain for VM folders "appA" and "appB", schedule a replication every day at 8:00PM UTC, set a retention of 3 snapshots and replicate immediately.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
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
		[parameter(mandatory = $false)] [switch]$log,
		[parameter(mandatory = $false)] [switch]$debugme,
		[parameter(mandatory = $true)] [string]$cluster,
		[parameter(mandatory = $true)] [string]$folder,
		[parameter(mandatory = $false)] [string]$repeatEvery,
		[parameter(mandatory = $false)] [string]$startOn,
		[parameter(mandatory = $false)] [string]$retention,
		[parameter(mandatory = $false)] [switch]$replicateNow,
		[parameter(mandatory = $false)] [int]$interval,
		[parameter(mandatory = $false)] $prismCreds,
		[parameter(mandatory = $false)] $vcenterCreds
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
	#check if we need to display help and/or history
	$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
06/19/2015 sb   Initial release.
02/03/2021 sb   Code update with PowerCLI module and REST API calls for NTNX.
################################################################################
'@
	$myvarScriptName = ".\add-NutanixProtectionDomains.ps1"
	
	if ($help) {get-help $myvarScriptName; exit}
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

	#region module sbourdeaud is used for facilitating Prism REST calls
	$required_version = "3.0.8"
	if (!(Get-Module -Name sbourdeaud)) {
		Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
		try
		{
			Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
			Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
		}#end try
		catch #we couldn't import the module, so let's install it
		{
			Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
			try {Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop}
			catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

			try
			{
				Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
				Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
			}#end try
			catch #we couldn't import the module
			{
				Write-Host "$(get-date) [ERROR] Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)" -ForegroundColor Red
				Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/sbourdeaud/1.1" -ForegroundColor Yellow
				Exit
			}#end catch
		}#end catch
	}#endif module sbourdeaud
	$MyVarModuleVersion = Get-Module -Name sbourdeaud | Select-Object -Property Version
	if (($MyVarModuleVersion.Version.Major -lt $($required_version.split('.')[0])) -or (($MyVarModuleVersion.Version.Major -eq $($required_version.split('.')[0])) -and ($MyVarModuleVersion.Version.Minor -eq $($required_version.split('.')[1])) -and ($MyVarModuleVersion.Version.Build -lt $($required_version.split('.')[2])))) {
		Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
		Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
		Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
		try {
			Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
			Import-Module -Name sbourdeaud -ErrorAction Stop
		}
		catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
	}
	#endregion
	Set-PoSHSSLCerts
	Set-PoshTls
	
#endregion

#region variables
	#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
#endregion

#region parameters validation
	#let's initialize parameters if they haven't been specified
	$myvar_folders = $folder.Split("{,}")
	if ($interval -and (($interval -le 0) -or ($interval -ge 60)))
	{
		OutputLogData -category "ERROR" -message "Interval must be between 1 and 59 minutes!"
		break
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
		if (!$repeatEvery) 
		{#repeatEvery was not specified, let's figure it out ourselves
			$type = "HOURLY"
			$every_nth = 1
		}
		else 
		{#repeatEvery was specified
			$type = (($repeatEvery).Split(","))[0]
			$every_nth = (($repeatEvery).Split(","))[1]
		}

		if (!$startOn) 
		{#startOn was not specified, let's figure it out ourselves
			$myvar_start_time = (get-date).AddMinutes(5)
			$user_start_time_in_usecs = ([int][double]::Parse((Get-Date -Date $myvar_start_time -UFormat %s))).ToString() + "000000"
		} 
		else 
		{#startOn was specified, let's convert to usecs
			$user_start_time_in_usecs = ([int][double]::Parse((Get-Date -Date $startOn -UFormat %s))).ToString() + "000000"
		}

		if (!$retention) 
		{#retention was not specified, let's assign a value
			$local_max_snapshots = 2
		}
		else 
		{
			$local_max_snapshots = $retention	
		}

		if (!$interval) 
		{#interval was not specified, let's assign a value in minutes
			$interval = 5
		}

		$app_consistent = $true
	#endregion
#endregion

#region processing	
	#* testing connection to prism
	#region GET cluster
		Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $($cluster) ..." -ForegroundColor Green
		$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
		$method = "GET"
		try 
		{
			$myvar_ntnx_cluster_info = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
		}
		catch
		{
			throw "$(get-date) [ERROR] Could not retrieve cluster information from Nutanix cluster $($cluster) : $($_.Exception.Message)"
		}
		Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $($cluster)" -ForegroundColor Cyan
	#endregion
	
	#* figuring out vcenter ip
	#region assign cluster name and vcenter ip
		$myvar_ntnx_cluster_name = $myvar_ntnx_cluster_info.name
		Write-Host "$(get-date) [DATA] Nutanix cluster name is $($myvar_ntnx_cluster_name)" -ForegroundColor White
		$myvar_management_server = $myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
		if ($myvar_management_server -is [array]) 
		{#houston, we have a problem, there is more than one registered vcenter
			Throw "$(get-date) [ERROR] There is more than 1 registered management server for cluster $($cluster). Exiting."
		} 
		else 
		{
			$myvar_vcenter_ip = ($myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
			Write-Host "$(get-date) [DATA] vCenter IP address for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_vcenter_ip)" -ForegroundColor White
		}
		if (!$myvar_vcenter_ip) {Write-Host "$(get-date) [ERROR] vCenter registration is not done in Prism for cluster $cluster!" -ForegroundColor Red;exit}
	#endregion

	#* connecting to vcenter
	#region connect to vCenter
		Write-Host "$(get-date) [INFO] Connecting to vCenter server $($myvar_vcenter_ip) ..." -ForegroundColor Green
		if ($vcenterCreds) 
		{#vcenter credentials were specified already
			try 
			{#connect to vcenter
				$myvar_vcenter_connection = Connect-VIServer -Server $myvar_vcenter_ip -Credential $vcenterCredentials -ErrorAction Stop
			}
			catch 
			{#could not connect to vcenter
				throw "$(get-date) [ERROR] Could not connect to vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
			}
			Write-Host "$(get-date) [SUCCESS] Successfully connected to vCenter server $($myvar_vcenter_ip)" -ForegroundColor Cyan
		} 
		else 
		{#no vcenter credentials were specified, so script will prompt for them
			try 
			{#connect to vcenter
				$myvar_vcenter_connection = Connect-VIServer -Server $myvar_vcenter_ip -ErrorAction Stop
			}
			catch 
			{#could not connect to vcenter
				throw "$(get-date) [ERROR] Could not connect to vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
			}
			Write-Host "$(get-date) [SUCCESS] Successfully connected to vCenter server $($myvar_vcenter_ip)" -ForegroundColor Cyan
		}
	#endregion
		
	#* getting protection domains
	#region GET protection_domains
		Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $($cluster) ..." -ForegroundColor Green
		$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $cluster
		$method = "GET"
		try 
		{#GET v2.0/protection_domains/ in $myvar_pds
			$myvar_pds = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
		}
		catch
		{#could not GET v2.0/protection_domains/
			throw "$(get-date) [ERROR] Could not retrieve protection domains from Nutanix cluster $($cluster) : $($_.Exception.Message)"
		}
		Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $($cluster)" -ForegroundColor Cyan
	#endregion

	#* get list of unprotected vms
	#region GET unprotected vms
		Write-Host "$(get-date) [INFO] Retrieving unprotected vms from Nutanix cluster $($cluster) ..." -ForegroundColor Green
		$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/unprotected_vms/" -f $cluster
		$method = "GET"
		try 
		{#GET v2.0/protection_domains/unprotected_vms/ in $myvar_unprotected_vms
			$myvar_unprotected_vms = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
		}
		catch
		{#could not GET v2.0/protection_domains/unprotected_vms/
			throw "$(get-date) [ERROR] Could not unprotected vms from Nutanix cluster $($cluster) : $($_.Exception.Message)"
		}
		Write-Host "$(get-date) [SUCCESS] Successfully retrieved unprotected vms from Nutanix cluster $($cluster)" -ForegroundColor Cyan
	#endregion
	
	$myvarLoopCount = 0
	foreach ($myvar_folder in $myvar_folders)
	{#process each folder
		#region get VMs in folder from vCenter
			OutputLogData -category "INFO" -message "Retrieving the names of the VMs in $myvar_folder..."
			$myvar_vms = Get-Folder -Name $myvar_folder | get-vm | select -ExpandProperty Name
			if (!$myvar_vms)
			{#no VM in that folder...
				Write-Host "$(get-date) [WARNING] No VM object was found in $($myvar_folder) or that folder was not found!" -ForegroundColor Yellow
			}
		#endregion
		
		#* 1: see if the pd already exists ($myvar_folder is in $myvar_pds.entities.name)
		if ($myvar_pds.entities.name -contains $myvar_folder)
		{#the protection domain already exists
			Write-Host "$(get-date) [INFO] Protection domain $($myvar_folder) already exists. Determining if it needs to be udpated..." -ForegroundColor Green

			#todo: check pd is active on this end

			#* add counting vms in pd and warn if >200
			if ((($myvar_pds.entities | Where-Object {$_.name -eq $myvar_folder}).vms).count -ge 200)
			{#there are more than 200 vms in the protection domain already: print a warning
				Write-Host "$(get-date) [WARNING] Protection domain $($myvar_folder) already contains 200 virtual machines which may yield to issues during snapshots!" -ForegroundColor Yellow
			}
			
			#* 2: if it exists, see if it needs updating by comparing the list of vms in it ($myvar_pds.entities.vms.vm_name) with the list of vms in the folder ($myvar_vms)
			$myvar_pd_vm_list = ($myvar_pds.entities | Where-Object {$_.name -eq $myvar_folder}).vms.vm_name
			if ($myvar_pd_vm_list)
			{#there are already vms in the protection domain
				if (!$myvar_vms)
				{#there are no vms in the folder, but there are some in the protection domain: we need to remove them
					$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/{1}/unprotect_vms" -f $cluster,$myvar_folder
					$method = "POST"
					ForEach ($myvar_vm_name in $myvar_pd_vm_list)
					{#process each vm in the protection domain
						Write-Host "$(get-date) [WARNING] Removing VM $($myvar_vm_name) from protection domain $($myvar_folder)..." -ForegroundColor Yellow
						$content = @(
							"$myvar_vm_name"
						)
						$payload = (ConvertTo-Json $content)
						$resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
						Write-Host "$(get-date) [SUCCESS] Successfully removed VM $($myvar_vm_name) from protection domain $($myvar_folder)" -ForegroundColor Cyan
					}
				}
				else 
				{#there are vms in both the folder and the protection domain
					ForEach ($myvar_object in (Compare-Object -ReferenceObject $myvar_vms -DifferenceObject $myvar_pd_vm_list))
					{#process each different object between vms in folder and vms in protection domain
						#* 3: if it needs updating, process additions and removals
						if ($myvar_object.SideIndicator -eq "=>")
						{#vm is in pd but no longer in folder: it needs to be removed from the pd
							Write-Host "$(get-date) [WARNING] Removing orphaned VM $($myvar_object.InputObject) from protection domain $($myvar_folder)..." -ForegroundColor Yellow
							$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/{1}/unprotect_vms" -f $cluster,$myvar_folder
							$method = "POST"
							$content = @(
								"$($myvar_object.InputObject)"
							)
							$payload = (ConvertTo-Json $content)
							$resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
							Write-Host "$(get-date) [SUCCESS] Successfully removed orphaned VM $($myvar_object.InputObject) from protection domain $($myvar_folder)" -ForegroundColor Cyan
						}
						elseif ($myvar_object.SideIndicator -eq "<=")
						{#vm is in the folder, but not in the pd: it needs to be added to the pd
							if ($myvar_object.InputObject -notin $myvar_unprotected_vms.entities.vm_name)
							{#vm is already protected
								Write-Host "$(get-date) [WARNING] VM $($myvar_object.InputObject) is already protected so it cannot be added to protection domain $($myvar_folder) on cluster $($myvar_ntnx_cluster_name)!" -ForegroundColor Yellow
								continue
							}
							else 
							{#vm is not already protected, we can add it
								Write-Host "$(get-date) [WARNING] Adding VM $($myvar_object.InputObject) to protection domain $($myvar_folder) on cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Yellow
								$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/{1}/protect_vms" -f $cluster,$myvar_folder
								$method = "POST"
								$content = @{
									app_consistent_snapshots= $true;
									ignore_dup_or_missing_vms = $true;
									names = @(
										"$($myvar_object.InputObject)"
									)
								}
								$payload = (ConvertTo-Json $content -Depth 9)
								$result = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $payload
								Write-Host "$(get-date) [SUCCESS] VM $($myvar_object.InputObject) was added to protection domain $($myvar_folder) on cluster $($myvar_cluster_name)" -ForegroundColor Cyan
							}

						}
					}	
				}
			}
			else 
			{#there are currently no vms in the protection domain
				ForEach ($myvar_vm in $myvar_vms)
				{#make sure vms to add are not already protected
					if ($myvar_vm -notin $myvar_unprotected_vms.entities.vm_name)
					{#vm is already protected
						Write-Host "$(get-date) [WARNING] VM $($myvar_vm) is already protected so it cannot be added to protection domain $($myvar_folder)!" -ForegroundColor Yellow
						continue
					}
					else 
					{#vm is not already protected, we can add it
						Write-Host "$(get-date) [WARNING] Adding VM $($myvar_vm) to protection domain $($myvar_folder)..." -ForegroundColor Yellow
						$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/{1}/protect_vms" -f $cluster,$myvar_folder
						$method = "POST"
						$content = @{
							app_consistent_snapshots= $true;
							ignore_dup_or_missing_vms = $true;
							names = @(
								"$myvar_vm"
							)
						}
						$payload = (ConvertTo-Json $content -Depth 9)
						$result = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $payload
						Write-Host "$(get-date) [SUCCESS] VM $($myvar_vm) was added to protection domain $($myvar_folder) on cluster $($myvar_cluster_name)" -ForegroundColor Cyan
					}
				}
			}
			
		}
		else 
		{#the protection domain does not exist, let's create it
			#* 4: if the pd does not exist, create it
			Write-Host "$(get-date) [WARNING] Protection domain $($myvar_folder) does not exist and needs to be created." -ForegroundColor Yellow
			$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $cluster
			$method = "POST"
			$content = @{
				value= "$myvar_folder"
			}
			$payload = (ConvertTo-Json $content)
			try 
			{#POST v2.0/protection_domains/
				$result = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $payload
				Write-Host "$(get-date) [SUCCESS] Successfully created protection domain $($myvar_folder) on Nutanix cluster $($myvar_ntnx_cluster_name)." -ForegroundColor Cyan
			}
			catch
			{#could not POST v2.0/protection_domains/
				throw "$(get-date) [ERROR] Could not create protection domain $($myvar_folder) on Nutanix cluster $($myvar_ntnx_cluster_name) : $($_.Exception.Message)"
			}

			#* 5: pd was just created, add vms to it
			Write-Host "$(get-date) [WARNING] Adding VMs to Protection domain $($myvar_folder)..." -ForegroundColor Yellow
			ForEach ($myvar_vm in $myvar_vms)
			{#make sure vms to add are not already protected
				if ($myvar_vm -notin $myvar_unprotected_vms.entities.vm_name)
				{#vm is already protected
					Write-Host "$(get-date) [WARNING] VM $($myvar_vm) is already protected so it cannot be added to protection domain $($myvar_folder)!" -ForegroundColor Yellow
					continue
				}
				else 
				{#vm is not already protected, we can add it
					Write-Host "$(get-date) [WARNING] Adding VM $($myvar_vm) to protection domain $($myvar_folder)..." -ForegroundColor Yellow
					$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/{1}/protect_vms" -f $cluster,$myvar_folder
					$method = "POST"
					$content = @{
						app_consistent_snapshots= $true;
						ignore_dup_or_missing_vms = $true;
						names = @(
							"$myvar_vm"
						)
					}
					$payload = (ConvertTo-Json $content -Depth 9)
					$result = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $payload
					Write-Host "$(get-date) [SUCCESS] VM $($myvar_vm) was added to protection domain $($myvar_folder) on cluster $($myvar_cluster_name)" -ForegroundColor Cyan
				}
			}

			#* 6: add schedule to newly created pd
			#region add schedule
				Write-Host "$(get-date) [INFO] Adding schedule to protection domain $($myvar_folder)" -ForegroundColor Green
				$url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/{1}/schedules" -f $cluster,$myvar_folder
				$method = "POST"
				$content = @{
					suspended = $false;
					pd_name = "$myvar_folder";
					type = "$type";
					every_nth = $every_nth;
					user_start_time_in_usecs = $user_start_time_in_usecs;
					start_times_in_usecs = @(
						$user_start_time_in_usecs
					);
					retention_policy = @{
						local_max_snapshots = $local_max_snapshots
					};
					app_consistent = $app_consistent
				}
				$payload = ConvertTo-Json $content -Depth 9
				$result = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $payload
				Write-Host "$(get-date) [SUCCESS] Successfully added schedule to protection domain $($myvar_folder)" -ForegroundColor Cyan

				#increment start time by interval minutes
				$myvar_start_time = ($myvar_start_time).AddMinutes($interval)
				$user_start_time_in_usecs = ([int][double]::Parse((Get-Date -Date $myvar_start_time -UFormat %s))).ToString() + "000000"
			#endregion
			
			#! resume coding effort here
			#* 7: replicate now if required
			#region replicate now
				if ($replicateNow)
				{#user wants to replicate now
					Write-Host "$(get-date) [INFO] Replicating now protection domain $($myvar_folder)" -ForegroundColor Green
				}
			#endregion
		}
	}

	Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
	Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
	

#endregion

#region cleanup
	#let's figure out how much time this all took
	OutputLogData -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
	Remove-Variable folder -ErrorAction SilentlyContinue
	Remove-Variable repeatEvery -ErrorAction SilentlyContinue
	Remove-Variable startOn -ErrorAction SilentlyContinue
	Remove-Variable retention -ErrorAction SilentlyContinue
	Remove-Variable replicateNow -ErrorAction SilentlyContinue
	Remove-Variable interval -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion