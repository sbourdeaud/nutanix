<#
.SYNOPSIS
  This script configures the HA and DRS recommended settings for Nutanix CVMs in a given cluster.
.DESCRIPTION
  This script will disable DRS, change HA restart priority to disabled, disable HA VM monitoring and change HA host isolation response to "leave powered on" for all CVMs in a given cluster or vCenter server. In addition, it will change the host isolation response to "power off and restart" on the cluster.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER vcenter
  VMware vCenter server hostname. Default is localhost. You can specify several hostnames by separating entries with commas.
.PARAMETER cluster
  Name of compute HA/DRS cluster as shown in vCenter.
.EXAMPLE
  Configure all CVMs in the vCenter server of your choice:
  PS> .\set-cvms.ps1 -vcenter myvcenter.local
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
	[parameter(mandatory = $false)] [string]$cluster
)
#endregion

#region prepwork
# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed -log parameter and OutputLogData function; updated PowerCLI handling
10/08/2018 sb   Updated help and removed indication that all clusters would be processed by default.
04/26/2018 sb   Updated prepwork; removed use of OutputLogData function; added try{]catch{} statements. 
10/01/2015 sb   Added setting advanced HA cluster option
                 (das.ignoreInsufficientHbDatastore)
                 Removed requirement for Nutanix cmdlets. 
09/03/2015 sb   Added disabling of HA VM Monitoring on CVM objects
06/19/2015 sb   Initial release. 
################################################################################
'@
$myvarScriptName = ".\set-cvms.ps1"
 
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

#endregion

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
#endregion

#region parameters validation
	if (!$vcenter) {$vcenter = read-host "Enter vCenter server name or IP address"}#prompt for vcenter server name
	$myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
    if (!$cluster) {$cluster = read-host "Enter the vSphere cluster name"}
#endregion	

#region processing
	################################
	##  foreach vCenter loop      ##
	################################
	foreach ($myvarvCenter in $myvarvCenterServers)	
	{
        try {
            Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
            $myvarvCenterObject = Connect-VIServer $myvarvCenter -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter" -ForegroundColor Cyan
        }
        catch {throw "$(get-date) [ERROR] Could not connect to vCenter server $myvarvCenter : $($_.Exception.Message)"}
		
		if ($myvarvCenterObject)
		{
		
			######################
			#main processing here#
			######################
			
            #region get cvm objects
            try {
                Write-Host "$(get-date) [INFO] Retrieving CVM objects..." -ForegroundColor Green
                $myvarCVMs = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VM -Name ntnx-*-cvm -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Retrieved CVM objects" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not retrieve CVM objects : $($_.Exception.Message)"}
            #endregion

			#region process cluster wide settings
	
            #configuring advanced HA cluster option
            try {
                Write-Host "$(get-date) [INFO] Setting advanced HA cluster option das.ignoreInsufficientHbDatastore to true on $cluster..." -ForegroundColor Green
                $setAdvancedSettingAction = New-AdvancedSetting -Type ClusterHA -entity (get-cluster -Name $cluster) -name 'das.ignoreInsufficientHbDatastore' -value true -Confirm:$false -ErrorAction Stop -Force
                Write-Host "$(get-date) [SUCCESS] Changed cluster advanced option for heartbeat datastore on $cluster" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not change cluster advanced option for heartbeat datastore on $cluster : $($_.Exception.Message)"}

            #changing default host isolation response to poweroff
            try {
                Write-Host "$(get-date) [INFO] Changing HA host isolation response to Power Off and Restart on $cluster..." -ForegroundColor Green
                $changeHostIsolationResponseAction = Get-Cluster $cluster -ErrorAction Stop | Set-Cluster -HAIsolationResponse "PowerOff" -Confirm:$false -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Changed HA host isolation response to Power Off and Restart on $cluster" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not change HA host isolation response to Power Off and Restart on $cluster : $($_.Exception.Message)"}

            #endregion
			
            #region process CVM settings
			foreach ($myvarCVM in $myvarCVMs)
			{
                
                try {
                    Write-Host "$(get-date) [INFO] Disabling DRS on $myvarCVM..." -ForegroundColor Green
                    $disableDRSAction = $myvarCVM | Set-VM -DrsAutomationLevel Disabled -Confirm:$false -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Disabled DRS on $myvarCVM" -ForegroundColor Cyan
                }
                catch {throw "$(get-date) [ERROR] Could not disable DRS on $myvarCVM : $($_.Exception.Message)"}

                try {
                    Write-Host "$(get-date) [INFO] Changing HA restart priority on $myvarCVM..." -ForegroundColor Green
                    $changeHARestartPriorityAction = $myvarCVM | Set-VM -HARestartPriority Disabled -Confirm:$false -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Changed HA restart priority on $myvarCVM" -ForegroundColor Cyan
                }
                catch {throw "$(get-date) [ERROR] Could not change HA restart priority on $myvarCVM : $($_.Exception.Message)"}

                try {
                    Write-Host "$(get-date) [INFO] Changing HA host isolation response to 'do nothing' on $myvarCVM..." -ForegroundColor Green
                    $changeHAHostIsolationResponseAction = $myvarCVM | Set-VM -HAIsolationResponse DoNothing -Confirm:$false -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Changed HA host isolation response to 'do nothing' on $myvarCVM" -ForegroundColor Cyan
                }
                catch {throw "$(get-date) [ERROR] Could not change HA host isolation response to 'do nothing' on $myvarCVM : $($_.Exception.Message)"}

                try {
                    Write-Host "$(get-date) [INFO] Disabling HA VM monitoring on $myvarCVM..." -ForegroundColor Green
                    ## get the .NET View object of the cluster, with a couple of choice properties
				    $myvarViewMyCluster = Get-View -ViewType ClusterComputeResource -Property Name, Configuration.DasVmConfig -Filter @{"Name" = "^${cluster}$"} -ErrorAction Stop
				    ## make a standard VmSettings object
				    $myvarDasVmSettings = New-Object VMware.Vim.ClusterDasVmSettings -Property @{
				        vmToolsMonitoringSettings = New-Object VMware.Vim.ClusterVmToolsMonitoringSettings -Property @{
				            enabled = $false
				            vmMonitoring = "vmMonitoringDisabled"
				            clusterSettings = $false
				        } ## end new-object
				    } -ErrorAction Stop ## end new-object
				    ## create a new ClusterConfigSpec object with which to reconfig the cluster
				    $myvaroClusterConfigSpec = New-Object VMware.Vim.ClusterConfigSpec -ErrorAction Stop
				    ## for each VM View, add a DasVmConfigSpec to the ClusterConfigSpec object
				    $myvarVMView = $myvarCVM | Get-View -ErrorAction Stop
				    ## the operation for this particular DasVmConfigSpec; if a spec already exists for the cluster for this VM, "edit" it, else, "add" it
			        $myvarStrOperationForThisVM = if ($myvarViewMyCluster.Configuration.DasVmConfig | ?{($_.Key -eq $myvarVMView.MoRef)}) {"edit"} else {"add"}
			        $myvaroClusterConfigSpec.DasVmConfigSpec += New-Object VMware.Vim.ClusterDasVmConfigSpec -Property @{
			            operation = $myvarStrOperationForThisVM     ## set the operation to "edit" or "add"
			            info = New-Object VMware.Vim.ClusterDasVmConfigInfo -Property @{
			                key = [VMware.Vim.ManagedObjectReference]$myvarVMView.MoRef
			                dasSettings = $myvarDasVmSettings
			            } ## end new-object
			        } -ErrorAction Stop ## end new-object
				    ## reconfigure the cluster with the given ClusterConfigSpec for all of the VMs
				    $DasVmConfigAction = $myvarViewMyCluster.ReconfigureCluster_Task($myvaroClusterConfigSpec, $true)
                    Write-Host "$(get-date) [SUCCESS] Disabled HA VM monitoring on $myvarCVM" -ForegroundColor Cyan
                }
                catch {throw "$(get-date) [ERROR] Could not disable HA VM monitoring on $myvarCVM : $($_.Exception.Message)"}
				
			}
            #endregion

		}#endif
        Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
		Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
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
    Remove-Variable cluster -ErrorAction SilentlyContinue
#endregion