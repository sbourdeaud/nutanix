<#
.SYNOPSIS
  This script can be used to start/stop fully a Nutanix cluster running the vSphere hypervisor.
.DESCRIPTION
  The script does the following steps: (1)Makes sure that redundancy status is greater than or equal to 2; (2)Makes sure there is no cluster upgrade in progress; (3)Figures out the vCenter VM, connects to it and cleanly shuts down VMs (except the vCenter VM and CVMs); (4)Forcibly shuts down any remaining user VMs after 5 minutes; (5)Stops the vCenter Server VM if it is hosted on the Nutanix cluster; (6)Stops the Nutanix cluster; (7)Powers off all the ESXi hosts cleanly.  With its start parameter, it can also (1)Start the Nutanix cluster and (2)Power on the vCenter VM if it is hosted on Nutanix.
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
.PARAMETER start
  Use this parameter to start a Nutanix cluster (after its hosts and CVMs have been powered on).
.PARAMETER cvm
  A CVM IP. Used with start to start the Nutanix cluster. The script will prompt for this information if it is not specified.
.PARAMETER vcentervmname
  Used with start to specify which VM is the vCenter VM. The script will prompt for this information if it is not specified.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\ntnx-clusterShutdown.ps1 -cluster ntnxc1.local -username admin -password admin
Stop the Nutanix cluster of your choice
.EXAMPLE
.\ntnx-clusterShutdown.ps1 -cluster ntnxc1.local -username admin -password admin -start
Start the Nutanix cluster of your choice
.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 4th 2021
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] [switch]$start,
        [parameter(mandatory = $false)] [string]$cvm,
        [parameter(mandatory = $false)] [string]$vcentervmname,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] $vcenterCreds
    )
#endregion

#region functions

#endregion

#region prepwork (where we make sure everything is ready to execute the script)
    # get rid of annoying error messages
    if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
    if ($debugme) {$VerbosePreference = "Continue"}

    #check if we need to display help and/or history
    $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 04/17/2018 sb   Initial release.
 05/11/2020 sb   Multiple fixes in params and help.
 02/05/2021 sb   Multiple updates and fixes based on API and AOS updates.
                 Thanks to Jason Terpstra (zycomtec.com) for testing and 
                 code updates suggestions.
################################################################################
'@
    $myvarScriptName = ".\ntnx-clusterShutdown.ps1"
    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

    #check PoSH version
	if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}
  
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

    #region SSHSessions
    if (!(Get-Module SSHSessions)) {
        if (!(Import-Module SSHSessions)) {
            Write-Host "$(get-date) [WARNING] We need to install the SSHSessions module!" -ForegroundColor Yellow
            try {Install-Module SSHSessions -ErrorAction Stop -Scope CurrentUser}
            catch {throw "Could not install the SSHSessions module : $($_.Exception.Message)"}
            try {Import-Module SSHSessions}
            catch {throw "Could not load the SSHSessions module : $($_.Exception.Message)"}
        }
    }
    #endregion

#endregion

#region variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
#endregion

#region parameters validation
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
#endregion

#region processing	
    
    #todo: include check for Nutanix Files
    if ($start) 
    {#starting the cluster
        #region let's start the Nutanix cluster
        if (!$cvm) {$cvm = Read-Host "Enter the IP address of a running CVM"}
        $CVMCreds = Get-Credential -Message "Please enter CVM credentials" -UserName nutanix
        
        Write-Host "$(get-date) [INFO] Opening ssh session to $cvm..." -ForegroundColor Green
        try {$sshSession = New-SshSession -ComputerName $cvm -Credential $CVMCreds -ErrorAction Stop}
        catch {throw "$(get-date) [ERROR] Could not open ssh session to CVM $cvm : $($_.Exception.Message)"}
        Write-Host "$(get-date) [SUCCESS] Opened ssh session to $cvm." -ForegroundColor Cyan

        Write-Host "$(get-date) [INFO] Sending cluster start command to $cvm..." -ForegroundColor Green
        try {$clusterStart = Invoke-SshCommand -ComputerName $cvm -Command "/usr/local/nutanix/cluster/bin/cluster start" -ErrorAction Stop}
        catch {throw "$(get-date) [ERROR] Could not send cluster start command to $cvm : $($_.Exception.Message)"}
        Write-Host "$(get-date) [SUCCESS] Sent cluster start command to $cvm." -ForegroundColor Cyan

        Write-Host "$(get-date) [INFO] Waiting 2 minutes for the cluster to initialize..." -ForegroundColor Green
        Start-Sleep -Seconds 120
        #endregion

        #figure out some basic information about the cluster
        Write-Host "$(get-date) [INFO] Retrieving cluster basic information..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $clusterInfo = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved information from $cluster!" -ForegroundColor Cyan

        if ($clusterInfo.hypervisor_types -eq "kVmware") {

            Write-Host "$(get-date) [INFO] Retrieving hosts basic information..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/hosts/"
            $method = "GET"
            $hostsInfo = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from $cluster!" -ForegroundColor Cyan
    
            #$hostsInfo.entities | %{$_.service_vmexternal_ip,$_.hypervisor_address,$_.management_server_name,$_.ipmi_address}
            $cvmIPs = $hostsInfo.entities | %{$_.service_vmexternal_ip}
            $hostIPs = $hostsInfo.entities | %{$_.hypervisor_address}
            $ipmiIPs = $hostsInfo.entities | %{$_.ipmi_address}

            #now that we know the vCenter VM IP, we need to figure out its name (assuming it is hosted on the same platform)
            #let's start by connecting to the ESXi hosts API
            try {
                Write-Host "$(get-date) [INFO] Connecting to ESXi hosts" -ForegroundColor Green
                $ESXiCreds = Get-Credential -Message "Please enter the ESXi hosts credentials" -UserName root
                try {$ESXiHostsConnectionObject = Connect-VIServer $hostIPs -Credential $ESXiCreds -ErrorAction Stop}
                catch {throw "$(get-date) [ERROR] Could not connect to ESXi hosts : $($_.Exception.Message)"}
                Write-Host "$(get-date) [SUCCESS] Successfully connected to ESXi hosts" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not connect to ESXi hosts : $($_.Exception.Message)"}
        
            #figure out the vCenter VM name
            try {
                Write-Host "$(get-date) [INFO] Retrieving powered off VMs..." -ForegroundColor Green
                Get-VM -ErrorAction Stop | where {$_.PowerState -eq "PoweredOff"} | select -Property Name,PowerState | ft -AutoSize
                if (!$vcentervmname) {$vcentervmname = Read-Host "Enter the name of the vCenter VM"}
                Write-Host "$(get-date) [INFO] Powering on the vCenter VM $vcentervmname..." -ForegroundColor Green
                try {$vCenterPowerOn = Get-VM $vcentervmname | Start-VM -ErrorAction Stop}
                catch {throw "$(get-date) [ERROR] Could not power on the vCenter VM $vcentervmname : $($_.Exception.Message)"}
                Write-Host "$(get-date) [SUCCESS] Powered on the vCenter VM $vcentervmname" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not retrieve powered off VMs : $($_.Exception.Message)"}
            
            Write-Host "$(get-date) [INFO] Retrieving vCenter information..." -ForegroundColor Green
            #region assign cluster name and vcenter ip
                $myvar_ntnx_cluster_name = $clusterInfo.name
                Write-Host "$(get-date) [DATA] Nutanix cluster name is $($myvar_ntnx_cluster_name)" -ForegroundColor White
                $myvar_management_server = $clusterInfo.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                if ($myvar_management_server -is [array]) 
                {#houston, we have a problem, there is more than one registered vcenter
                    Throw "$(get-date) [ERROR] There is more than 1 registered management server for cluster $($cluster). Exiting."
                } 
                else 
                {
                    $myvar_vcenter_ip = ($clusterInfo.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                    Write-Host "$(get-date) [DATA] vCenter IP address for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_vcenter_ip)" -ForegroundColor White
                }
            #endregion

            Remove-SshSession -RemoveAll -ErrorAction SilentlyContinue
            Disconnect-ViServer * -ErrorAction SilentlyContinue -Confirm:$false

            Write-Host "$(get-date) [INFO] All done! The vCenter VM can take up to 15 minutes to power on and initialize properly. Its IP is $($myvar_vcenter_ip)" -ForegroundColor Green
        }


    } 
    else 
    {#shutting down the cluster

        #region figure out some basic information about the cluster and do some pre-checks
            Write-Host "$(get-date) [INFO] Retrieving cluster basic information..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
            $method = "GET"
            $clusterInfo = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved information from $cluster!" -ForegroundColor Cyan
        
            #let's make sure our current redundancy is at least 2
            if ($clusterInfo.cluster_redundancy_state.current_redundancy_factor -lt 2) {throw "$(get-date) [ERROR] Current redundancy is less than 2. Exiting."}
            #check if there is an upgrade in progress
            if ($clusterInfo.is_upgrade_in_progress) {throw "$(get-date) [ERROR] Cluster upgrade is in progress. Exiting."}
        

            Write-Host "$(get-date) [INFO] Retrieving hosts basic information..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/hosts/"
            $method = "GET"
            $hostsInfo = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from $cluster!" -ForegroundColor Cyan
        
            #$hostsInfo.entities | %{$_.service_vmexternal_ip,$_.hypervisor_address,$_.management_server_name,$_.ipmi_address}
            $cvmIPs = $hostsInfo.entities | %{$_.service_vmexternal_ip}
            $hostIPs = $hostsInfo.entities | %{$_.hypervisor_address}
            $ipmiIPs = $hostsInfo.entities | %{$_.ipmi_address}
        #endregion

        #region shutdown user VMs based on the hypervisor
            if ($clusterInfo.hypervisor_types -eq "kVmware") 
            {

                #we start by making sure we're not connected to anything else already...
                Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue
            
                #region figuring out vCenter ($vCenterVMName), compute clusters ($computeClusters) and CVM info ($cvmNames, $cvmIPs)

                    #region assign cluster name and vcenter ip
                        $myvar_ntnx_cluster_name = $clusterInfo.name
                        Write-Host "$(get-date) [DATA] Nutanix cluster name is $($myvar_ntnx_cluster_name)" -ForegroundColor White
                        $myvar_management_server = $clusterInfo.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                        if ($myvar_management_server -is [array]) 
                        {#houston, we have a problem, there is more than one registered vcenter
                            Throw "$(get-date) [ERROR] There is more than 1 registered management server for cluster $($cluster). Exiting."
                        } 
                        else 
                        {
                            $myvar_vcenter_ip = ($clusterInfo.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                            Write-Host "$(get-date) [DATA] vCenter IP address for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_vcenter_ip)" -ForegroundColor White
                        }
                    #endregion

                    if (!$myvar_vcenter_ip) {Write-Host "$(get-date) [ERROR] vCenter registration is not done in Prism for cluster $cluster!" -ForegroundColor Red;exit}

                    #now that we know the vCenter VM IP, we need to figure out its name (assuming it is hosted on the same platform)
                    #region connect to vCenter
                        Write-Host "$(get-date) [INFO] Connecting to vCenter server $($myvar_vcenter_ip) ..." -ForegroundColor Green
                        try 
                        {#connect to vcenter
                            $myvar_vcenter_connection = Connect-VIServer -Server $myvar_vcenter_ip -Credential $vcenterCredentials -ErrorAction Stop
                        }
                        catch 
                        {#could not connect to vcenter
                            throw "$(get-date) [ERROR] Could not connect to vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
                        }
                        Write-Host "$(get-date) [SUCCESS] Successfully connected to vCenter server $($myvar_vcenter_ip)" -ForegroundColor Cyan
                    #endregion
                
                    #figure out the vCenter VM name
                    try {
                        Write-Host "$(get-date) [INFO] Figuring out vCenter VM name..." -ForegroundColor Green
                        $vCenterVMName = (Get-VM -ErrorAction Stop| Select Name, @{N="IP Address";E={@($_.guest.IPAddress[0])}} | ?{$_."IP address" -eq $myvar_vcenter_ip}).Name
                        Write-Host "$(get-date) [SUCCESS] Successfully queried VMs from $myvar_vcenter_ip" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Host "$(get-date) [ERROR] Could not retrieve vCenter VM from $myvar_vcenter_ip : $($_.Exception.Message)" -ForegroundColor Red
                        exit
                    }

                    #figure out which compute cluster we belong to
                    $computeClusters = @()
                    try {
                        Write-Host "$(get-date) [INFO] Retrieving VMHosts..." -ForegroundColor Green
                        $vmHosts = Get-VMHost -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved VMHosts" -ForegroundColor Cyan
                    }
                    catch {
                        Write-Host "$(get-date) [ERROR] Could not retrieve VMHosts from $myvar_vcenter_ip : $($_.Exception.Message)" -ForegroundColor Red
                        exit
                    }
                    Write-Host "$(get-date) [INFO] Figuring out the name(s) of the compute cluster(s)..." -ForegroundColor Green
                    ForEach ($NtnxHost in $hostsInfo.entities) {
                        ForEach ($vmHost in $vmHosts) {
                            $vmHostVmk0Ip = ($vmHost.NetworkInfo.VirtualNic | where {$_.Name -eq "vmk0"}).IP
                            If ($vmHostVmk0Ip -eq $NtnxHost.hypervisor_address) {
                                try {
                                    Write-Host "$(get-date) [INFO] Figuring out the cluster for host $($vmHost.Name)..." -ForegroundColor Green
                                    $computeCluster = $vmHost | Get-Cluster -ErrorAction Stop
                                    Write-Host "$(get-date) [SUCCESS] Figured out the cluster for host $($vmHost.Name)" -ForegroundColor Cyan
                                }
                                catch {
                                    Write-Host "$(get-date) [ERROR] Could not retrieve cluster for host $($vmHost.Name) : $($_.Exception.Message)" -ForegroundColor Red
                                    exit
                                }
                                Write-Host "$(get-date) [INFO] Host $($vmHost.Name) with IP $vmHostVmk0Ip is part of the compute cluster $($computeCluster.Name)" -ForegroundColor Green                
                                if (!($computeClusters | where {$_ -eq $computeCluster})) {
                                    Write-Host "$(get-date) [INFO] Adding cluster $($computeCluster.Name) to the cluster name(s) list..." -ForegroundColor Green
                                    $computeClusters += $computeCluster
                                }
                            }
                        }
                    }
                
                    #figure out the CVM VM names
                    [System.Collections.ArrayList]$cvmNames = New-Object System.Collections.ArrayList($null)
                    ForEach ($cvmIP in $cvmIPs) {
                        try {$cvmName = (Get-VM -ErrorAction Stop | Select Name, @{N="IP Address";E={@($_.guest.IPAddress[0])}} | ?{$_."IP address" -eq $cvmIP}).Name}
                        catch {throw "Could not retrieve list of VMs from $myvar_vcenter_ip : $($_.Exception.Message)"}
                        $cvmNames += $cvmName
                    }

                    #figure out if the vCenter VM runs on one of the Nutanix compute cluster
                    $vCenterVMCluster = Get-VM -Name $vCenterVMName | Get-Cluster
                    if ($computeClusters | where {$_.Name -eq $vCenterVMCluster.Name}) {$vCenterNtnxHosted = $true} else {$vCenterNtnxHosted = $false}

                #endregion

                #region shutting down VMs which are not CVMs or vCenter
                    ForEach ($computeCluster in $computeClusters) 
                    { #process each cluster
                        $clusterVmList = Get-Cluster -Name $computeCluster.Name -ErrorAction Stop | Get-VM -ErrorAction Stop | where{$_.PowerState -eq "PoweredOn"} #retrieve all powered on vms in the cluster and exclude vCenter
                        $vmList = $clusterVmList  | where{$_.Name -ne $vCenterVMName} #exclude vCenter VM
                        ForEach ($cvmName in $cvmNames) {$vmList = $vmList | where {$_.Name -ne $cvmName}} #exclude CVMs

                        if ($vmList) {
                            ForEach ($vm in $vmList) {
                                try {
                                    Write-Host "$(get-date) [INFO] Shutting down VM $($vm.Name)..." -ForegroundColor Green
                                    $stopVM = Stop-VMGuest -VM $vm -Confirm:$False -ErrorAction Stop
                                    Write-Host "$(get-date) [SUCCESS] Sent shutdown instruction to VM $($vm.Name)" -ForegroundColor Cyan
                                }
                                catch {throw "$(get-date) [ERROR] Could not shut down VM $($vm.Name) : $($_.Exception.Message)"}
                            }
                        } else {
                            Write-Host "$(get-date) [WARNING] There were no user VMs to shut down!" -ForegroundColor Yellow
                        }

                        #wait 5 minutes for VMs to shut down, otherwise power them off
                        if ($vmList | where {$_.PowerState -eq "PoweredOn"}) {
                            Write-Host "$(get-date) [INFO] Waiting 5 minutes before powering off VMs which are still powered on..." -ForegroundColor Green
                            Start-Sleep -Seconds 300
                            ForEach ($vm in $vmList) {
                                if ((Get-VM $vm).PowerState -eq "PoweredOn") {
                                    Write-Host "$(get-date) [INFO] Forcefully powering off $($vm.Name)..." -ForegroundColor Green
                                    try {$stopVM = Stop-VM -Confirm:$False -ErrorAction Stop -VM $vm -RunAsync}
                                    catch {throw "$(get-date) [ERROR] Could not power off VM $($vm.Name) : $($_.Exception.Message)"}
                                }
                            }
                        }
                    }
                #endregion

                #region shutting down the vCenter VM
                    if ($vCenterNtnxHosted-eq $true) 
                    { #if the vCenter VM is running on the Nutanix cluster...
                        #figure out which ESXi host the vCenter VM is currently running on
                        $vCenterVM = Get-VM -Name $vCenterVMName
                        $vCenterVMHost = $vCenterVM | Get-VMhost

                        #disconnecting from vCenter and connecting to its ESXi host
                        Write-Host "$(get-date) [INFO] Disconnecting from vCenter..." -ForegroundColor Green
                        Disconnect-viserver -Confirm:$False #cleanup after ourselves and disconnect from vcenter

                        #connecting to the vCenter VM ESXi host
                        $ESXiCreds = Get-Credential -Message "Please enter credentials to the ESXi hosts" -UserName root
                        try {
                            Write-Host "$(get-date) [INFO] Connecting to ESXi host $($vCenterVMHost.Name)" -ForegroundColor Green
                            $vCenterHostObject = Connect-VIServer $vCenterVMHost.Name -Credentials $ESXiCreds -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] Successfully connected to ESXi host $($vCenterVMHost.Name)" -ForegroundColor Cyan
                        }
                        catch {throw "$(get-date) [ERROR] Could not connect to the ESXi host $($vCenterVMHost.Name) : $($_.Exception.Message)"}

                        #shutting down vCenter VM
                        $vCenterVM = Get-VM -Name $vCenterVMName
                    
                        if ($vCenterVM.PowerState -eq "PoweredOn") {
                            Write-Host "$(get-date) [INFO] Shutting down vCenter VM..." -ForegroundColor Green
                            try {$stopvCenterVM = Stop-VMGuest -ErrorAction Stop -VM $vCenterVM -Confirm:$False}
                            catch {throw "$(get-date) [ERROR] Could not power off vCenter VM : $($_.Exception.Message)"}
                            Write-Host "$(get-date) [INFO] Waiting 5 minutes before powering off forcibly the vCenter VM..." -ForegroundColor Green
                            Start-Sleep -Seconds 300
                            $vCenterVM = Get-VM -Name $vCenterVMName
                            if ($vCenterVM.PowerState -eq "PoweredOn") {
                                Write-Host "$(get-date) [INFO] Forcefully powering off vCenter VM $vCenterVMName..." -ForegroundColor Green
                                try {$stopVM = Stop-VM -Confirm:$False -ErrorAction Stop -VM $vCenterVM -RunAsync}
                                catch {throw "$(get-date) [ERROR] Could not power off vCenter VM $vCenterVMName : $($_.Exception.Message)"}
                            }
                        }
                    }
                #endregion

                #finishing things
                Write-Host "$(get-date) [INFO] Disconnecting from ESXi host..." -ForegroundColor Green
                Disconnect-viserver -Confirm:$False
            }
        #endregion

        #region stopping the Nutanix cluster
            #ssh into the first CVM
            $CVMCreds = Get-Credential -Message "Please enter CVM credentials" -Username nutanix
            Write-Host "$(get-date) [INFO] Opening ssh session to $($cvmIPs[0])..." -ForegroundColor Green
            try {$SSHSession = New-SshSession -ComputerName $cvmIPs[0] -Credential $CVMCreds -ErrorAction Stop}
            catch {throw "$(get-date) [ERROR] Could not open ssh session to $($cvmIPs[0]) : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Opened ssh session to $($cvmIPs[0])." -ForegroundColor Cyan
            #sending the cluster stop command
            Write-Host "$(get-date) [INFO] Sending cluster stop command to $($cvmIPs[0])..." -ForegroundColor Green
            try {$clusterStop = Invoke-SshCommand -ComputerName $cvmIPs[0] -Command "export ZOOKEEPER_HOST_PORT_LIST=zk3:9876,zk2:9876,zk1:9876 && echo 'I agree' | /usr/local/nutanix/cluster/bin/cluster stop" -ErrorAction Stop}
            catch {throw "$(get-date) [ERROR] Could not send cluster stop command to $($cvmIPs[0]) : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Sent cluster stop command to $($cvmIPs[0])." -ForegroundColor Cyan
        #endregion

        #region shutting down CVMs based on hypervisor
            if ($clusterInfo.hypervisor_types -eq "kVmware") 
            {
                Write-Host "$(get-date) [INFO] Sending the shutdown command to all hosts..." -ForegroundColor Green
                try {$cvmShutdown = Invoke-SshCommand -ComputerName $cvmIPs[0] -Command "/usr/local/nutanix/cluster/bin/hostssh 'poweroff'" -ErrorAction Stop}
                catch {throw "$(get-date) [ERROR] Could not power down hosts : $($_.Exception.Message)"}
                Write-Host "$(get-date) [SUCCESS] Sent the shutdown command to all hosts." -ForegroundColor Cyan
                Remove-SshSession -RemoveAll
            }
        #endregion

        Write-Host "$(get-date) [INFO] All done! Note that nodes may take as long as 20 minutes to shutdown completely. To restart your cluster, use the following IP addresses:" -ForegroundColor Green
        Write-Host "IPMI:" $ipmiIPs
        Write-Host "Hosts:" $hostIPs
        Write-Host "CVMs:" $cvmIPs
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
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
	Remove-Variable username -ErrorAction SilentlyContinue
	Remove-Variable password -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion