<#
.SYNOPSIS
  You can use this script to move all vms (except the cvm) off an ESXi host to a pre-defined group of hosts.
.DESCRIPTION
  Using pre-defined groups of hosts (defined as constants in the script), move all vms (except the cvm) using vmotion to the host in the same group as the specified host which has the least running VMs.
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
.PARAMETER vmhost
  Name of the vSphere host to drain of VMs as displayed in vCenter.
.EXAMPLE
.\invoke-VmDrain.ps1 -vcenter myvcenter.local -vmhost myhost01
Move all VMs (except the cvm) off host myhost01 in vcenter myvcenter.local. VMs will be moved to hosts in the same group as myhost01.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 15th 2019
#>

#region parameters
#let's start with some command line parsing
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$vcenter,
    [parameter(mandatory = $false)] [string]$vmhost,
    [parameter(mandatory = $false)] [int]$balance
)
#endregion

#region functions
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
 10/15/2019 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\template.ps1"
 
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

#endregion

#! customize this section
#region variables
#misc variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
#! edit the constants below to match your environment. Only 2 host groups are supported
#constants
$myvar_host_group_01 = @("prdntx001.ltrf.fr","prdntx002.ltrf.fr","prdntx003.ltrf.fr","prdntx004.ltrf.fr")
$myvar_host_group_02 = @("prdntx101.ltrf.fr","prdntx102.ltrf.fr","prdntx103.ltrf.fr","prdntx104.ltrf.fr")
#endregion

#region parameters validation
#let's initialize parameters if they haven't been specified
if (!$vcenter) {$vcenter = read-host "Enter vCenter server name or IP address"}#prompt for vcenter server name
$myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
if (!$balance -and !$vmhost) {$vmhost = read-host "Enter the name of the vmhost you want to drain"}
#endregion

#region processing
    #region balance
    if ($balance) {
        if ($balance -eq 1) {
            $myvar_vmhosts = $myvar_host_group_01
        } 
        elseif ($balance -eq 2) {
            $myvar_vmhosts = $myvar_host_group_02
        }
        else {
            throw "$(get-date) [ERROR] Balance must be 1 or 2"
        }

        #* foreach vcenter loop
        foreach ($myvarvCenter in $myvarvCenterServers)	
        {
            #* connect to vcenter
            try {
                Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
                $myvarvCenterObject = Connect-VIServer $myvarvCenter -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not connect to vCenter server $myvarvCenter : $($_.Exception.Message)"}
            
            #* determine the number of vms on each host
            $vm_qty = 0
            $total_vm_qty = 0
            $base_qty = 0
            $target_host = ""
            foreach ($myvar_vmhost in $myvar_vmhosts) {
                $vm_qty = (Get-VMHost -Name $myvar_vmhost | get-vm | where-object {$_.Name -notlike "NTNX-*-CVM"}).length
                $total_vm_qty += $vm_qty
                if ($debugme) {Write-Host "$(get-date) [DEBUG] $myvar_vmhost has $vm_qty vms" -ForegroundColor White}
                if ($base_qty -eq 0) {
                    $base_qty = $vm_qty
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] $myvar_vmhost has $vm_qty vms" -ForegroundColor White}
                    $target_host = $myvar_vmhost
                    $target_host_vm_qty = $vm_qty
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] target host is $myvar_vmhost" -ForegroundColor White}
                } 
                elseif ($vm_qty -lt $base_qty) {
                    $target_host = $myvar_vmhost
                    $target_host_vm_qty = $vm_qty
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] $vm_qty is less than $base_qty" -ForegroundColor White}
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] target host is $myvar_vmhost" -ForegroundColor White}
                }
                else {
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] $vm_qty is more than $base_qty" -ForegroundColor White}
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] target stays $target_host" -ForegroundColor White}
                }
            }
            $vm_qty_per_vmhost = [math]::Round($total_vm_qty / $myvar_vmhosts.length)
            
            if ($target_host_vm_qty -ge $vm_qty_per_vmhost) {
                write-host "$(get-date) [WARNING] No rebalancing is required." -ForegroundColor Yellow
            }
            else {
                $vm_qty_required = $vm_qty_per_vmhost - $target_host_vm_qty
                $vm_qty_to_move_per_host = [math]::Round($vm_qty_required / ($myvar_vmhosts.length - 1))
                $myvar_vmhosts = $myvar_vmhosts | where-object {$_ -ne $target_host}
                foreach ($target in $myvar_vmhosts) {
                    $vms_to_move = Get-VMHost -Name $target | get-vm | where-object {$_.Name -notlike "NTNX-*-CVM"} | select -First $vm_qty_to_move_per_host
                    foreach ($vm in $vms_to_move) {
                        try {
                            Write-Host "$(get-date) [INFO] Moving vm $($vm.Name) from $target to host $($target_host)" -ForegroundColor Green
                            if (!$debugme) {
                                $result = Move-Vm -VM $vm -Destination $target_host -confirm:$false -RunAsync:$false -ErrorAction Stop
                                Write-Host "$(get-date) [SUCCESS] VM $($vm.Name) has moved from $target to host $($target_host)" -ForegroundColor Cyan
                            }
                        }
                        catch{
                            Write-Host "$(get-date) [WARNING] Could not move vm $($vm.Name) from $target to host $($target_host) : $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    }
                }
            }

            Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
        }#end foreach vCenter        
    }
    #endregion
    #region drain
    else {
        #* check the specified host belongs to a defined host group
        if ($myvar_host_group_01 -contains $vmhost) {
            $myvar_vmhosts = $myvar_host_group_01 | where-object {$_ -ne $vmhost}
        }
        elseif ($myvar_host_group_02 -contains $vmhost) {
            $myvar_vmhosts = $myvar_host_group_02 | where-object {$_ -ne $vmhost}
        }
        else {
            throw "$(get-date) [ERROR] $vmhost does not belong to any pre-defined host groups!"
        }

        #* foreach vcenter loop
        foreach ($myvarvCenter in $myvarvCenterServers)	
        {
            #* connect to vcenter
            try {
                Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
                $myvarvCenterObject = Connect-VIServer $myvarvCenter -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not connect to vCenter server $myvarvCenter : $($_.Exception.Message)"}

            #* check the vmhost exists
            try {
                Write-Host "$(get-date) [INFO] Checking hosts $vmhost exists in vCenter $myvarvCenter..." -ForegroundColor Green
                $myvar_vmhostObject = Get-VMHost $vmhost -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Found host $vmhost in $myvarvCenter" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not find host $vmhost in vCenter server $myvarvCenter : $($_.Exception.Message)"}

            #* get the list of vms running on that host and exclude the cvm
            try {
                $myvar_vms = $myvar_vmhostObject | get-vm -ErrorAction Stop | where-object {$_.Name -notlike "NTNX-*-CVM"}
            }
            catch {
                throw "$(get-date) [ERROR] Could not retrieve the list of VMs on host $vmhost : $($_.Exception.Message)"
            }
            if ($myvar_vms.length -eq 0) {
                throw "$(get-date) [ERROR] There are no VMs except the CVM on host $vmhost"
            }

            #* vmotion loop
            foreach ($vm in $myvar_vms) {
                try {
                    #* determine which host in the host group has the least VMs
                    $base_qty = 0
                    $target_host = ""
                    foreach ($target in $myvar_vmhosts) {
                        try {
                            $vm_qty = (Get-VMHost -Name $target | Get-Vm | where-object {$_.PowerState -eq "PoweredOn"}).length
                            if ($debugme) {Write-Host "$(get-date) [DEBUG] $target has $vm_qty vms" -ForegroundColor White}
                            if ($base_qty -eq 0) {
                                $base_qty = $vm_qty
                                if ($debugme) {Write-Host "$(get-date) [DEBUG] $target has $vm_qty vms" -ForegroundColor White}
                                $target_host = $target
                                if ($debugme) {Write-Host "$(get-date) [DEBUG] target host is $target" -ForegroundColor White}
                            } 
                            elseif ($vm_qty -lt $base_qty) {
                                $target_host = $target
                                if ($debugme) {Write-Host "$(get-date) [DEBUG] $vm_qty is less than $base_qty" -ForegroundColor White}
                                if ($debugme) {Write-Host "$(get-date) [DEBUG] target host is $target" -ForegroundColor White}
                            }
                            else {
                                if ($debugme) {Write-Host "$(get-date) [DEBUG] $vm_qty is more than $base_qty" -ForegroundColor White}
                                if ($debugme) {Write-Host "$(get-date) [DEBUG] target stays $target_host" -ForegroundColor White}
                            }
                        }
                        catch {
                            throw "$(get-date) [ERROR] Could not find $target_host"
                        }
                    }

                    Write-Host "$(get-date) [INFO] Moving vm $($vm.Name) to host $($target_host)" -ForegroundColor Green
                    if (!$debugme) {
                        try {
                            $result = Move-Vm -VM $vm -Destination $target_host -confirm:$false -RunAsync:$false -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] VM $($vm.Name) has moved to host $($target_host)" -ForegroundColor Cyan
                        }
                        catch {
                            Write-Host "$(get-date) [WARNING] Could not move vm $($vm.Name) to host $($myvar_vmhosts[$index]) : $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    }
                }
                catch {
                    Write-Host "$(get-date) [WARNING] Could not move vm $($vm.Name) to host $($myvar_vmhosts[$index]) : $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }

            Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
        }#end foreach vCenter
    }
    #endregion
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
	Remove-Variable vcenter -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion