<#
.SYNOPSIS
  Use this script to collect software versions from a Nutanix cluster.
.DESCRIPTION
  Th script will collect information about the following components: AOS, NCC, Foundation, Hypervisor, LCM.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER nolcm
  Specifies you don't want to retrieve lcm version information.
.PARAMETER csv
  Specifies you want to export results to a csv file in the current directory.
.EXAMPLE
.\get-NutanixSoftwareVersions.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix cluster of your choice and collect software information:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: Apr 16th 2020
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
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [switch]$nolcm,
    [parameter(mandatory = $false)] [switch]$csv
)
#endregion

#region functions

#endregion

#region prepwork

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/16/2020 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\get-NutanixSoftwareVersions.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

#check if we have all the required PoSH modules
Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

#region module sbourdeaud is used for facilitating Prism REST calls
$required_version = "3.0.7"
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

$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
#endregion

#region parameters validation

if (!$prismCreds) 
{#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
    if (!$username) 
    {#if Prism username has not been specified ask for it
        $username = Read-Host "Enter the Prism username"
    } 

    if (!$password) 
    {#if password was not passed as an argument, let's prompt for it
        $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
    }
    else 
    {#if password was passed as an argument, let's convert the string to a secure string and flush the memory
        $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
        Remove-Variable password
    }
    $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
} 
else 
{ #we are using custom credentials, so let's grab the username and password from that
    try 
    {
        $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
        $username = $prismCredentials.UserName
        $PrismSecurePassword = $prismCredentials.Password
    }
    catch 
    {
        $credname = Read-Host "Enter the credentials name"
        Set-CustomCredentials -credname $credname
        $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
        $username = $prismCredentials.UserName
        $PrismSecurePassword = $prismCredentials.Password
    }
    $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
}
#endregion

#region processing	

    #region get cluster information
        Write-Host "$(get-date) [INFO] Retrieving cluster information..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $myvar_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information!" -ForegroundColor Cyan
    #endregion

    #region get nodes information
        #building the list of nodes
        $myvar_cluster_nodes_uuids = @()
        Foreach ($myvar_block in $myvar_cluster_info.rackable_units) {
            $myvar_cluster_nodes_uuids += $myvar_block.node_uuids
        }

        #querying each node
        $myvar_cluster_hypervisors = @()
        $myvar_cluster_node_types = @()
        $myvar_cluster_bios_versions = @()
        $myvar_cluster_bmc_versions = @()
        $myvar_cluster_disk_types = @()
        $myvar_cluster_disk_firmwares = @()
        Foreach ($myvar_node in $myvar_cluster_nodes_uuids) {
            Write-Host "$(get-date) [INFO] Retrieving information for node uuid $($myvar_node)..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/hosts/$($myvar_node)"
            $method = "GET"
            $myvar_node_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved information for node uuid $($myvar_node)!" -ForegroundColor Cyan
            if ($myvar_cluster_hypervisors -notcontains $myvar_node_info.hypervisor_full_name) {
                $myvar_cluster_hypervisors += $myvar_node_info.hypervisor_full_name
            }
            if ($myvar_cluster_node_types -notcontains $myvar_node_info.block_model_name) {
                $myvar_cluster_node_types += $myvar_node_info.block_model_name
            }
            if ($myvar_cluster_bios_versions -notcontains $myvar_node_info.bios_version) {
                $myvar_cluster_bios_versions += $myvar_node_info.bios_version
            }
            if ($myvar_cluster_bmc_versions -notcontains $myvar_node_info.bmc_version) {
                $myvar_cluster_bmc_versions += $myvar_node_info.bmc_version
            }
            #processsing disks information
            ($myvar_node_info.disk_hardware_configs | Get-Member -MemberType NoteProperty).Name | ForEach-Object {
                if ($myvar_cluster_disk_types -notcontains $myvar_node_info.disk_hardware_configs.$_.model) {
                    $myvar_cluster_disk_types += $myvar_node_info.disk_hardware_configs.$_.model
                }
                if ($myvar_cluster_disk_firmwares -notcontains $myvar_node_info.disk_hardware_configs.$_.current_firmware_version) {
                    $myvar_cluster_disk_firmwares += $myvar_node_info.disk_hardware_configs.$_.current_firmware_version
                }
            }
        }
    #endregion

    #region get lcm version
        if (!$nolcm) {
            Write-Host "$(get-date) [INFO] Retrieving lcm information..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/genesis"
            $method = "POST"
            $payload = @"
{
    "value": "{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"get_config\"}}"
}
"@      
            $myvar_lcm_info = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved lcm information!" -ForegroundColor Cyan
        }
    #endregion

    #region process results
        $myvar_software_versions = [ordered]@{
            #from cluster information
            "cluster_name" = $myvar_cluster_info.name;
            "cluster_id" = $myvar_cluster_info.id;
            "aos_version" = $myvar_cluster_info.version;
            "ncc_version" = $myvar_cluster_info.ncc_version;
            "num_nodes" = $myvar_cluster_info.num_nodes
            #from node information
            "hypervisor(s)" = $myvar_cluster_hypervisors -join ',';
            "node_type(s)" = $myvar_cluster_node_types -join ',';
            "bios_version(s)" = $myvar_cluster_bios_versions -join ',';
            "bmc_version(s)" = $myvar_cluster_bmc_versions -join ',';
            "disk_types" = $myvar_cluster_disk_types -join ',';
            "disk_firmwares" = $myvar_cluster_disk_firmwares -join ',';
        }
        if (!$nolcm) {
            $myvar_software_versions.lcm_version = ($myvar_lcm_info.value | ConvertFrom-Json).".return".version
        }
        $myvarResults.Add((New-Object PSObject -Property $myvar_software_versions)) | Out-Null
        $myvar_software_versions | ft
        Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($myvar_cluster_info.name)_sw_versions.csv" -ForegroundColor Green
        $myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($myvar_cluster_info.name)+"_sw_versions.csv")
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
Remove-Variable cluster -ErrorAction SilentlyContinue
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion