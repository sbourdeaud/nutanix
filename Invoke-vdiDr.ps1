<#
.SYNOPSIS
  This script can be used to automate the failover (planned or unplanned) of Horizon View desktop pool(s) using manual assignment and full clones and hosted on a Nutanix cluster.
.DESCRIPTION
  This script can be used to automate the failover (planned or unplanned) of Horizon View desktop pool(s) using manual assignment and full clones and hosted on a Nutanix cluster.
  The script has four main workflows: (1)failover, (2)cleanup, (3)scan and (4)deactivate.

  Failover is either (1)planned or (2)unplanned.
  When planned, failover will:
    (1)Check that the targeted desktop pools on the source Horizon View server are disabled
    (2)Remove all machines from the targeted desktop pools on the source Horizon View server
    (3)Initiate migrate on the matching protection domains on the source Nutanix cluster, which will shutdown all the VMs and replicate them to the target site
    (4)Remove orphaned inventory entries from the source vCenter server
    (5)Move the VMs to the correct folder on the target vCenter server, and reconnect their vNIC to the distributed vSwitch if applicable
    (6)Add VMs to the desktop pools on the target Horizon View server
    (7)Assign users to their VM on the target Horizon View server
  When unplanned, failover will:
    (1)Activate the matching protection domains (for the given desktop pools) on the target Nutanix cluster
    (2)Move the VMs to the correct folder on the target vCenter server, and reconnect their vNIC to the distributed vSwitch if applicable
    (3)Add VMs to the desktop pools on the target Horizon View server
    (4)Assign users to their VM on the target Horizon View server

  Cleanup is either (1)planned or (2)unplanned.
  When planned, cleanup will:
    (1)Remove schedules from all matching protection domains on the source Nutanix cluster
  When unplanned, cleanup will:
    (1)Check that the targeted desktop pools on the source Horizon View server are disabled
    (2)Remove all machines from the targeted desktop pools on the source Horizon View server
    (3)Disable the matching protection domains on the source Nutanix cluster, which will DELETE ALL VMs on that cluster
    (4)Remove orphaned inventory entries from the source vCenter server

  Scan will:
    (1)Retrieve desktop pool information from the specified Horizon View server and save the desktop pool name and assigned user for each VM. A reference file is created in the specified directory.
    (2)Retrieve matching VMs information from the source vCenter server and save the Folder and portgroup name for each VM. A reference file is created in the specified directory.

  Deactivate will:
    (1)Disable the specified protection domain on the specified Nutanix cluster which will DELETE ALL VMs on that cluster

  In order to work properly, the script requires a reference file matching desktop pools to protection domain names. The file should be called poolRef.csv and be either in the script working directory, or the specified reference path.
  That reference file contains the following fields (in that order): desktop_pool,protection_domain. Headers should be specified in the csv file.

  Example:

  desktop_pool,protection_domain
  VDI1,async1
  VDI2,async2
  VDI3,async3
  VDI4,async4

.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER scan
  Specifies you want to create the reference files.  See the script description for more information.
.PARAMETER failover
  Specifies you want to trigger a failover workflow, either planned or unplanned.  See the script description for more information.
.PARAMETER cleanup
  Specifies you want to trigger a cleanup workflow, either planned or unplanned.  See the script description for more information.
.PARAMETER planned
  Used in conjunction with failover or cleanup. When used with failover, planned assumes both the source and target sites are available. See the script description for more information.
.PARAMETER unplanned
  Used in conjunction with failover or cleanup. When used with failover, unplanned assumes only the target site is available. See the script description for more information.
.PARAMETER deactivate
  Specifies you want to disable a protection domain and DELETE ALL VMs on that cluster that belong to that protection domain.  See the script description for more information.
.PARAMETER referentialPath
  Specifies the path where reference files are stored. Reference files are required for the failover and cleanup workflows. If no reference path is specified, the script working directory is used instead.
.PARAMETER target_pg
  Specifies the name of the portgroup you want to reconnect VMs to. If none is specified, the script figures out if there is a single distributed portgroup available, in which case it will use it.  If not, it looks for a matching portgroup name.  If there are none, it sees if there is a single portgroup on vSwitch0. If not, the script will fail.
.PARAMETER protection_domains
  Lets you specify which protection domain(s) you want to failover. Only works with planned.
.PARAMETER desktop_pools
  Lets you specify which protection domain(s) you want to failover or cleanup.
.PARAMETER source_cluster
  Specifies the source Nutanix cluster (IP or FQDN).
.PARAMETER source_vc
  Specifies the source vCenter server (IP or FQDN).
.PARAMETER source_hv
  Specifies the source Horizon View server (IP or FQDN).
.PARAMETER target_cluster
  Specifies the target Nutanix cluster (IP or FQDN).
.PARAMETER target_vc
  Specifies the target vCenter server (IP or FQDN).
.PARAMETER target_hv
  Specifies the target Horizon View (IP or FQDN).
.PARAMETER prismCreds
  Specifies a custom credentials file name for Prism authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt).
.PARAMETER vcCreds
  Specifies a custom credentials file name for vCenter authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$vcCreds.txt).
.PARAMETER hvCreds
  Specifies a custom credentials file name for Horizon View authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$hvCreds.txt).
.PARAMETER noprompt
  Specifies that you do not want to be prompted for confirmation at each specific step. If neither prompt nor noprompt are used, the script will prompt once to determine if steps should be confirmed at the beginning of code execution (except for the scan workflow).
.PARAMETER prompt
  Specifies that you want to be prompted for confirmation at each specific step. If neither prompt nor noprompt are used, the script will prompt once to determine if steps should be confirmed at the beginning of code execution (except for the scan workflow).
.EXAMPLE
.\Invoke-vdiDr.ps1 -source_cluster <ip> -source_vc <ip> -source_hv <ip> -referentialPath c:\temp -scan -prismCreds prism_api-user
Trigger a scan of the source environment to create reference file and update protection domains as required. Use the previously stored credentials in the %USERPROFILE%\Documents\WindowsPowerShell\Credentials\prism_api-user.txt file (use the Set-CustomCredentials function in the sbourdeaud module to create the credentials file).
.EXAMPLE
.\Invoke-vdiDr.ps1 -source_cluster <ip> -source_vc <ip> -source_hv <ip> -referentialPath c:\temp -target_cluster <ip> -target_vc <ip> -target_hv <ip> -failover -planned  -username admin -password <secret>
Trigger a planned failover for all disabled desktop pools on the source Horizon View server which contain VMs.
.EXAMPLE
.\Invoke-vdiDr.ps1 -source_cluster <ip> -source_vc <ip> -source_hv <ip> -referentialPath c:\temp -target_cluster <ip> -target_vc <ip> -target_hv <ip> -failover -planned  -username admin -password <secret> -desktop_pools VDI1
Trigger a planned failover for the specified desktop pool on the source Horizon View server which contain VMs.
.EXAMPLE
.\Invoke-vdiDr.ps1 -referentialPath c:\temp -source_cluster <ip> -cleanup -planned  -username admin -password <secret> -desktop_pools VDI1,VDI3
Remove schedules for the matching protection domains (based on desktop pools) at the source Nutanix cluster after a planned failover has completed.
.EXAMPLE
.\Invoke-vdiDr.ps1 -referentialPath c:\temp -target_cluster <ip> -target_vc <ip> -target_hv <ip> -failover -unplanned  -username admin -password <secret> -desktop_pools VDI1,VDI3
Perform an unplanned failover of the designated desktop pools to a target Nutanix cluster.
.EXAMPLE
.\Invoke-vdiDr.ps1 -referentialPath c:\temp -source_cluster <ip> -source_vc <ip> -source_hv <ip> -cleanup -unplanned  -username admin -password <secret> -desktop_pools VDI1,VDI3
Empty desktop pools, disable protection domains, delete VMs and remove them from vCenter inventory on the source Nutanix cluster after an unplanned failover has been done to a target Nutanix cluster.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: July 27th 2018
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
    [parameter(mandatory = $false)] [switch]$scan,
    [parameter(mandatory = $false)] [switch]$failover,
    [parameter(mandatory = $false)] [switch]$deactivate,
    [parameter(mandatory = $false)] [switch]$planned,
    [parameter(mandatory = $false)] [switch]$unplanned,
    [parameter(mandatory = $false)] [switch]$cleanup,
    [parameter(mandatory = $false)] [string]$source_cluster,
    [parameter(mandatory = $false)] [string]$target_cluster,
    [parameter(mandatory = $false)] [string]$source_hv,
    [parameter(mandatory = $false)] [string]$target_hv,
    [parameter(mandatory = $false)] [string]$source_vc,
    [parameter(mandatory = $false)] [string]$target_vc,
    [parameter(mandatory = $false)] $target_pg,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] [string]$referentialPath,
    [parameter(mandatory = $false)] $protection_domains,
    [parameter(mandatory = $false)] $desktop_pools,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] $vcCreds,
    [parameter(mandatory = $false)] $hvCreds,
    [parameter(mandatory = $false)] [switch]$noprompt,
    [parameter(mandatory = $false)] [switch]$prompt
)
#endregion

#region functions
########################
##   main functions   ##
########################

#function update protection domain
Function Update-NutanixProtectionDomain
{
	#input: method (add or remove), cluster, username, password, protection domain name, vm name
	#output: POST method result response in json format
<#
.SYNOPSIS
  Adds/removes a VM to/from a Nutanix protection domain.
.DESCRIPTION
  Adds/removes a VM to/from a Nutanix protection domain.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER method
  This can be add or remove.
.PARAMETER cluster
  FQDN or IP of Nutanix cluster.
.PARAMETER username
  Nutanix cluster API username.
.PARAMETER password
  Nutanix cluster API password (passed as a secure string).
.PARAMETER protection_domain
  Protection Domain name.
.PARAMETER vm
  Virtual machine name.
.EXAMPLE
Update-NutanixProtectionDomain -method add -cluster ntnx1.local -username api-user -password $secret -protection_domain pd1 -vm vm1
#>
	[CmdletBinding()]
	param
	(
        [parameter(mandatory = $true)]
        [string]
        [ValidateSet('add','remove')]
        $action,
        [parameter(mandatory = $true)]
        [string]
        $cluster,
        [parameter(mandatory = $true)]
        [secureString]
        $password,
        [parameter(mandatory = $true)]
        [string]
        $username,
        [parameter(mandatory = $true)]
        [string]
        $protection_domain,
        [parameter(mandatory = $true)]
        [string]
        $vm
	)

    begin
    {
	    switch ($action) {
            add {
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$protection_domain/protect_vms"
                $content = @{
                                app_consistent_snapshots = "false"
                                names = @(
                                            $vm
                                        )
                            }
            }
            remove {
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$protection_domain/unprotect_vms"
                $content = @($vm)
            }
        }
    }

    process
    {
        Write-Host "$(get-date) [INFO] Updating $protection_domain to $action $vm on $cluster ..." -ForegroundColor Green
        $method = "POST"
        $body = (ConvertTo-Json $content -Depth 4)
        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) -body $body
        Write-Host "$(get-date) [SUCCESS] Successfully updated $protection_domain to $action $vm on $cluster" -ForegroundColor Cyan
    }

    end
    {
        return $response
    }
}#end function Invoke-HvQuery

#this function is used to run an hv query
Function Invoke-HvQuery
{
	#input: QueryType (see https://vdc-repo.vmware.com/vmwb-repository/dcr-public/f004a27f-6843-4efb-9177-fa2e04fda984/5db23088-04c6-41be-9f6d-c293201ceaa9/doc/index-queries.html), ViewAPI service object
	#output: query result object
<#
.SYNOPSIS
  Runs a Horizon View query.
.DESCRIPTION
  Runs a Horizon View query.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER QueryType
  Type of query (see https://vdc-repo.vmware.com/vmwb-repository/dcr-public/f004a27f-6843-4efb-9177-fa2e04fda984/5db23088-04c6-41be-9f6d-c293201ceaa9/doc/index-queries.html)
.PARAMETER ViewAPIObject
  View API service object.
.EXAMPLE
  PS> Invoke-HvQuery -QueryType PersistentDiskInfo -ViewAPIObject $ViewAPI
#>
	[CmdletBinding()]
	param
	(
      [string]
        [ValidateSet('ADUserOrGroupSummaryView','ApplicationIconInfo','ApplicationInfo','DesktopSummaryView','EntitledUserOrGroupGlobalSummaryView','EntitledUserOrGroupLocalSummaryView','FarmHealthInfo','FarmSummaryView','GlobalEntitlementSummaryView','MachineNamesView','MachineSummaryView','PersistentDiskInfo','PodAssignmentInfo','RDSServerInfo','RDSServerSummaryView','RegisteredPhysicalMachineInfo','SessionGlobalSummaryView','SessionLocalSummaryView','TaskInfo','UserHomeSiteInfo')]
        $QueryType,
        [VMware.Hv.Services]
        $ViewAPIObject
	)

    begin
    {

    }

    process
    {
	    $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
        $query = New-Object "Vmware.Hv.QueryDefinition"
        $query.queryEntityType = $QueryType
        $query.MaxPageSize = 1000
        if ($query.QueryEntityType -eq 'PersistentDiskInfo') {
            $query.Filter = New-Object VMware.Hv.QueryFilterNotEquals -property @{'memberName'='storage.virtualCenter'; 'value' =$null}
        }
        if ($query.QueryEntityType -eq 'ADUserOrGroupSummaryView') {
            try {$object = $serviceQuery.QueryService_Create($ViewAPIObject,$query)}
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] : $($_.Exception.Message)"; exit}
        } else {
            try {$object = $serviceQuery.QueryService_Query($ViewAPIObject,$query)}
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] : $($_.Exception.Message)"; exit}
        }
    }

    end
    {
        if (!$object) {
            Write-Host -ForegroundColor Red "$(get-date) [ERROR] : The View API query did not return any data... Exiting!"
            Exit
        }
        return $object
    }
}#end function Invoke-HvQuery

#endregion

#region prepwork

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 05/11/2018 sb   Initial release.
 05/28/2018 sb   Added checks for PowerCLI version and corrected a parameter check bug with -failover -planned.
 05/31/2018 sb   Added prismCreds parameter.
 06/27/2018 sb   Added BetterTls module for Tls 1.2
 07/27/2018 sb   Multiple enhancements as documented on GitHub (pre-tests @customer site)
################################################################################
'@
$myvarScriptName = ".\Invoke-vdiDr.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}


#check if we have all the required PoSH modules
Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

#region module BetterTls
if (!(Get-Module -Name BetterTls)) {
    Write-Host "$(get-date) [INFO] Importing module 'BetterTls'..." -ForegroundColor Green
    try
    {
        Import-Module -Name BetterTls -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Imported module 'BetterTls'!" -ForegroundColor Cyan
    }#end try
    catch #we couldn't import the module, so let's install it
    {
        Write-Host "$(get-date) [INFO] Installing module 'BetterTls' from the Powershell Gallery..." -ForegroundColor Green
        try {Install-Module -Name BetterTls -Scope CurrentUser -ErrorAction Stop}
        catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not install module 'BetterTls': $($_.Exception.Message)"; Exit}

        try
        {
            Import-Module -Name BetterTls -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Imported module 'BetterTls'!" -ForegroundColor Cyan
        }#end try
        catch #we couldn't import the module
        {
            Write-Host "$(get-date) [ERROR] Unable to import the module BetterTls : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/BetterTls/0.1.0.0" -ForegroundColor Yellow
            Exit
        }#end catch
    }#end catch
}
Write-Host "$(get-date) [INFO] Disabling Tls..." -ForegroundColor Green
try {Disable-Tls -Tls -Confirm:$false -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not disable Tls : $($_.Exception.Message)"; Exit}
Write-Host "$(get-date) [INFO] Enabling Tls 1.2..." -ForegroundColor Green
try {Enable-Tls -Tls12 -Confirm:$false -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not enable Tls 1.2 : $($_.Exception.Message)"; Exit}
#endregion

#region module sbourdeaud is used for facilitating Prism REST calls
if (!(Get-Module -Name sbourdeaud)) {
    Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
    try
    {
        Import-Module -Name sbourdeaud -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
    }#end try
    catch #we couldn't import the module, so let's install it
    {
        Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
        try {Install-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
        catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"; Exit}

        try
        {
            Import-Module -Name sbourdeaud -ErrorAction Stop
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
if (((Get-Module -Name sbourdeaud).Version.Major -le 1) -and ((Get-Module -Name sbourdeaud).Version.Minor -le 1)) {
    Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
    try {Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
    catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"; Exit}
}
#endregion

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
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"; Exit}
        }
        catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"; Exit}
    }
}

#check PowerCLI version
if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) {
    try {Update-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"; Exit}
    Write-Host -ForegroundColor Red "$(get-date) [ERROR] Please upgrade PowerCLI to version 10 or above by running the command 'Update-Module VMware.PowerCLI' as an admin user"
    Exit
}
Write-Host "$(get-date) [INFO] Setting the PowerCLI configuration to ignore invalid certificates..." -ForegroundColor Green
try {$result = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction Stop}
catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not change the VMware.PowerCLI module configuration: $($_.Exception.Message)"; Exit}
Write-Host "$(get-date) [SUCCESS] Successfully configured the PowerCLI configuration to ignore invalid certificates" -ForegroundColor Cyan
#endregion

#region get ready to use the Nutanix REST API
#Accept self signed certs
if (!$IsLinux) {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
#we also need to use the proper encryption protocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol =  [System.Security.Authentication.SslProtocols] "tls, tls11, tls12"
}
#endregion

#endregion

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$StartEpochSeconds = Get-Date (Get-Date).ToUniversalTime() -UFormat %s

    ########## uncomment those if you want to use constants instead of variables for some of the parameters
    #######################################################################################################
    #$source_cluster = "<enter your source Nutanix cluster here>"
    #$source_vc = "<enter your source vCenter server here>"
    #$source_hv = "<enter your source VMware Horizon View here>"
    #$target_cluster = "<enter your target Nutanix cluster here>"
    #$target_vc = "<enter your target vCenter server here>"
    #$target_hv = "<enter your target VMware Horizon View server here>"
    #$username = "<enter your Prism username here>"
    #$referentialPath = "<enter your path to reference files here>"
    #$target_pg = "<enter your target portgroup name here>"
    #$hvCreds = Get-Credential -Message "Please enter the credentials for the Horizon View server(s)"
    #$vcCreds = Get-Credential -Message "Please enter the credentials for the vCenter server(s)"
#endregion

#region parameters validation
	############################################################################
	# command line arguments initialization
	############################################################################
	#let's initialize parameters if they haven't been specified

    if ($prompt -and $noprompt) {Write-Host -ForefroundColor Red "$(get-date) [ERROR] You can only use prompt OR noprompt, not both at the same time!"; Exit}
    if (!$scan -and !$failover -and !$deactivate -and !$cleanup) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You haven't specified any workflow (-scan, -failover, -deactivate or -cleanup)"; Exit}
    if ($scan -and ($failover -or $deactivate -or $cleanup)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"; Exit}
    if ($failover -and ($scan -or $deactivate -or $cleanup)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"; Exit}
    if ($deactivate -and ($failover -or $scan -or $cleanup)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"; Exit}
    if ($cleanup -and ($failover -or $deactivate -or $scan)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"; Exit}

    #region check that we have what we need to proceed
    if (!$referentialPath) {$referentialPath = (Get-Item -Path ".\").FullName} #assume all reference fiels are in the current working directory if a path has not been specified
    If ((Test-Path -Path $referentialPath) -eq $false) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not access the path where the reference files are: $($_.Exception.Message)"; Exit}
    If ((Test-Path -Path ("$referentialPath\PoolRef.csv")) -eq $false) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not access the PoolRef.csv file in $referentialPath : $($_.Exception.Message)"; Exit}
    #endregion
    if (!$prismCreds) {
        if (!$username) {$username = "admin"} #if Prism username has not been specified, assume we are using admin

        if (!$password) #if it was not passed as an argument, let's prompt for it
        {
            $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
        }
        else #if it was passed as an argument, let's convert the string to a secure string and flush the memory
        {
            $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
            Remove-Variable password
        }
    } else {
        $prismCredentials = Get-CustomCredentials -credname $prismCreds
        $username = $prismCredentials.UserName
        $PrismSecurePassword = $prismCredentials.Password
    }

    if ($vcCreds) {
        $vcCreds = Get-CustomCredentials -credname $vcCreds
    }
    if ($hvCreds) {
        $hvCreds = Get-CustomCredentials -credname $hvCreds
    }


    if (!$deactivate -and !$failover -and !$unplanned -and !$cleanup) {
        if (!$source_cluster) {$source_cluster = Read-Host "Enter the fully qualified domain name or IP address of the source Nutanix cluster"} #prompt for the Nutanix source cluster name/ip if it hasn't been specified already
        if (!$source_vc) {$source_vc = Read-Host "Enter the fully qualified domain name or IP address of the source vCenter server"} #prompt for the vCenter server name/ip if it hasn't been specified already
        if (!$source_hv) {$source_hv = Read-Host "Enter the fully qualified domain name or IP address of the source VMware Horizon View server"} #prompt for the VMware Horizon View server name/ip if it hasn't been specified already
    }

    if ($failover -or $deactivate) {
        if (!$target_cluster) {$target_cluster = Read-Host "Enter the fully qualified domain name or IP address of the target Nutanix cluster"} #prompt for the target Nutanix cluster name/ip if we are trying to failover and it hasn't been specified already
        if (!$deactivate -and !$target_vc) {$target_vc = Read-Host "Enter the fully qualified domain name or IP address of the target vCenter server"} #prompt for the target vCenter server name/ip if we are trying to failover and it hasn't been specified already
        if (!$deactivate -and !$target_hv) {$target_hv = Read-Host "Enter the fully qualified domain name or IP address of the target VMware Horizon View server"} #prompt for the target vCenter server name/ip if we are trying to failover and it hasn't been specified already
    }
    if ($failover -and (!$planned -and !$unplanned)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You need to specify -planned or -unplanned with -failover!"; Exit}
    if ($failover -and ($planned -and $unplanned)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You can only specify -planned or -unplanned with -failover, not both at the same time!"; Exit}
    if ($failover -and ($unplanned -and !$desktop_pools)) {$desktop_pools = Read-Host "You must specify which desktop pools you want to failover (unplanned)"}

    if ($cleanup) {
        if (!$source_cluster) {$source_cluster = Read-Host "Enter the fully qualified domain name or IP address of the Nutanix cluster that you want to clean up. This is usually the cluster where the VMs used to be."} #prompt for the Nutanix source cluster name/ip if it hasn't been specified already
        if ($unplanned) {
            if (!$source_vc) {$source_vc = Read-Host "Enter the fully qualified domain name or IP address of the vCenter server you want to cleanup"} #prompt for the vCenter server name/ip if it hasn't been specified already
            if (!$source_hv) {$source_hv = Read-Host "Enter the fully qualified domain name or IP address of the VMware Horizon View server you want to cleanup"} #prompt for the VMware Horizon View server name/ip if it hasn't been specified already
        }
    }
    if ($cleanup -and (!$planned -and !$unplanned)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You need to specify -planned or -unplanned with -cleanup!"; Exit}
    if ($cleanup -and ($planned -and $unplanned)) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] You can only specify -planned or -unplanned with -cleanup, not both at the same time!"; Exit}

    if ($desktop_pools) {$desktop_pools = $desktop_pools.Split(",")} #make sure we process desktop_pools as an array
    if ($protection_domains) {$protection_domains = $protection_domains.Split(",")} #make sure we process protection_domains as an array

    if ($prompt) {$confirmSteps = $true}
    if ($noprompt) {$confirmSteps = $false}
#endregion

#region processing
	################################
	##  Main execution here       ##
	################################

    #region -scan
    if ($scan) {
        #load pool2pd reference
        try {$poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"; Exit}

        #region extract Horizon View data
        #connect to Horizon View server
        Write-Host "$(get-date) [INFO] Connecting to the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        try {
            if ($hvCreds) {
                $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
            } else {
                $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
            }
        }
        catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"; Exit}
        Write-Host "$(get-date) [SUCCESS] Connected to the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
        #create API object
        $source_hvObjectAPI = $source_hvObject.ExtensionData

        [System.Collections.ArrayList]$newHvRef = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect new information from the system (vm name, assigned ad username, desktop pool name, vm folder, portgroup)

        #extract desktop pools
        Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
        #####TODO add code here to paginate thru the query results
        $source_hvDesktopPoolsList = @()
        $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
        do {
            if ($source_hvDesktopPoolsList.length -ne 0) {$source_hvDesktopPools = $serviceQuery.QueryService_GetNext($source_hvObjectAPI,$source_hvDesktopPools.Id)}
            $source_hvDesktopPoolsList += $source_hvDesktopPools.Results
        } while ($source_hvDesktopPools.remainingCount -gt 0)
        Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

        #map the user id to a username
        Write-Host "$(get-date) [INFO] Retrieving Active Directory user information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        $source_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $source_hvObjectAPI
        $source_hvADUsersList = @()
        $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
        do {
            if ($source_hvADUsersList.length -ne 0) {$source_hvADUsers = $serviceQuery.QueryService_GetNext($source_hvObjectAPI,$source_hvADUsers.Id)}
            $source_hvADUsersList += $source_hvADUsers.Results
        } while ($source_hvADUsers.remainingCount -gt 0)
        Write-Host "$(get-date) [SUCCESS] Retrieved Active Directory user information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

        #extract Virtual Machines summary information
        Write-Host "$(get-date) [INFO] Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
        #####TODO add code here to paginate thru the query results
        $source_hvVMsList = @()
        $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
        do {
            if ($source_hvVMsList.length -ne 0) {$source_hvVMs = $serviceQuery.QueryService_GetNext($source_hvObjectAPI,$source_hvVMs.Id)}
            $source_hvVMsList += $source_hvVMs.Results
        } while ($source_hvVMs.remainingCount -gt 0)
        Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

        #figure out the info we need for each VM (VM name, user, desktop pool name)
        Write-Host "$(get-date) [INFO] Figuring out usernames for vms (this can take a while)..." -ForegroundColor Green
        #########TODO: add code to filter VMs which belong only to the specified desktop_pool
        ForEach ($vm in $source_hvVMsList) { #let's process each vm
            #figure out the vm assigned username
            $vmUsername = ($source_hvADUsersList | Where-Object {$_.Id.Id -eq $vm.Base.User.Id}).Base.DisplayName #grab the user name whose id matches the id of the assigned user on the desktop machine

            #figure out the desktop pool name
            $vmDesktopPool = ($source_hvDesktopPoolsList | Where-Object {$_.Id.Id -eq $vm.Base.Desktop.Id}).DesktopSummaryData.Name

            $vmInfo = @{"vmName" = $vm.Base.Name;"assignedUser" = $vmUsername;"desktop_pool" = "$vmDesktopPool"} #we build the information for that specific machine
            $result = $newHvRef.Add((New-Object PSObject -Property $vmInfo))
        }

        Disconnect-HVServer -Confirm:$false
        Write-Host "$(get-date) [INFO] Disconnected from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        #endregion

        #region extract information from vSphere
        #connect to the vCenter server
        Write-Host "$(get-date) [INFO] Connecting to the SOURCE vCenter server $source_vc ..." -ForegroundColor Green
        try {
            if ($vcCreds) {
                $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
            } else {
                $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
            }
        }
        catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"; Exit}
        Write-Host "$(get-date) [SUCCESS] Connected to SOURCE vCenter server $source_vc" -ForegroundColor Cyan

        [System.Collections.ArrayList]$newVcRef = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect new information from the system (vm name, assigned ad username, desktop pool name, vm folder, portgroup)

        #process each vm and figure out the folder and portgroup name
        ForEach ($vm in $newHvRef) {
            #########TODO: add code to filter VMs which belong only to the specified desktop_pool
            Write-Host "$(get-date) [INFO] Retrieving VM $($vm.vmName) ..." -ForegroundColor Green
            try{$vmObject = Get-VM $vm.vmName -ErrorAction Stop} catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not retrieve VM $($vm.vmName) : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [INFO] Retrieving portgroup name for VM $($vm.vmName) ..." -ForegroundColor Green
            try {$vmPortGroup = ($vmObject | Get-NetworkAdapter -ErrorAction Stop).NetworkName} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not retrieve portgroup name for VM $($vm.vmName) : $($_.Exception.Message)"; Exit}
            if ($vmPortGroup -is [array]) {
                $vmPortGroup = $vmPortGroup | Select-Object -First 1
                Write-Host "$(get-date) [WARNING] : There is more than one portgroup for $($vm.vmName). Only keeping the first one ($vmPortGroup)."  -ForegroundColor Yellow
            }
            $vmInfo = @{"vmName" = $vm.vmName;"folder" = $vmObject.Folder.Name;"portgroup" = $vmPortGroup} #we build the information for that specific machine
            $result = $newVcRef.Add((New-Object PSObject -Property $vmInfo))
        }

        #disconnect from vCenter
        Write-Host "$(get-date) [INFO] Disconnecting from SOURCE vCenter server $source_vc..." -ForegroundColor Green
		Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
        #endregion

        #region extract Nutanix Prism data
        #extract protection domains
        Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
        $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        $newPrismRef = $sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name,vms
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan
        #endregion

        #region update reference files and figure out which vms need to be added/removed to protection domain(s)

        #compare reference file with pool & pd content
        #foreach vm in hv, find out if it is already in the right protection domain, otherwise, add it to the list of vms to add to that pd
        [System.Collections.ArrayList]$vms2Add = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect which vms need to be added to which protection domain
        ForEach ($vm in $newHvRef) {
            #figure out which protection domain this vm should be based on its current desktop pool and the assigned protection domain for that pool
            $assignedPd = ($poolRef | Where-Object {$_.desktop_pool -eq $vm.desktop_pool}).protection_domain
            if (!$assignedPd) {Write-Host "$(get-date) [WARNING] : Could not process protection domain addition for VM $($vm.vmName) because there is no assigned protection domain defined in $referentialPath\poolRef.csv for $($vm.desktop_pool)!"  -ForegroundColor Yellow}
            else {
                #now find out if that vm is already in that protection domain
                if (!($newPrismRef | Where-Object {$_.name -eq $assignedPd} | Where-Object {$_.vms.vm_name -eq $vm.vmName})) {
                    $vmInfo = @{"vmName" = $vm.vmName;"protection_domain" = $assignedPd}
                    #add vm to name the list fo vms to add to that pd
                    $result = $vms2Add.Add((New-Object PSObject -Property $vmInfo))
                }
            }
        }

        #foreach protection domain, figure out if there are vms which are no longer in horizon view and which need to be removed from the protection domain
        [System.Collections.ArrayList]$vms2Remove = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect which vms need to be removed from which protection domain
        #$vmNames2remove = $newHvRef.vmname | Where-Object {($newPrismRef | Where-Object {$poolRef.protection_domain -Contains $_.name}).vms.vm_name -notcontains $_} #figuring out which vms are in a protection domain in Prism which has a mapping but are no longer in view
        $protectedVMs = ($newPrismRef | Where-Object {$poolRef.protection_domain -Contains $_.name}).vms.vm_name
        $vmNames2remove = $protectedVMs | Where-Object {$newHvRef.vmname -notcontains $_}
        ForEach ($vm in $vmNames2remove) { #process each vm identified above
            $pd = (($newPrismRef | Where-Object {$poolRef.protection_domain -Contains $_.name}) | Where-Object {$_.vms.vm_name -eq $vm}).name
            $vmInfo = @{"vmName" = $vm;"protection_domain" = $pd}
            #add vm to name the list fo vms to add to that pd
            $result = $vms2Remove.Add((New-Object PSObject -Property $vmInfo))
        }

        #endregion

        #region update protection domains
        #if required, add vms to pds
        ForEach ($vm2add in $vms2add) {
            $reponse = Update-NutanixProtectionDomain -action add -cluster $source_cluster -username $username -password $PrismSecurePassword -protection_domain $vm2add.protection_domain -vm $vm2add.vmName
        }
        #if required, remove vms from pds
        ForEach ($vm2remove in $vms2remove) {
            $reponse = Update-NutanixProtectionDomain -action remove -cluster $source_cluster -username $username -password $PrismSecurePassword -protection_domain $vm2remove.protection_domain -vm $vm2remove.vmName
        }
        #endregion

        #export new references
        $newHvRefExport = $newHvRef | Export-Csv -NoTypeInformation -Path "$referentialPath\hvRef.csv"
        $newVcRefExport = $newVcRef | Export-Csv -NoTypeInformation -Path "$referentialPath\vcRef.csv"
    }
    #endregion

    #region -failover
    if ($failover) {

        #insert here prompt for step by step confirmation
        if ((!$prompt) -and (!$noprompt))
        {
            do {$promptUser = Read-Host -Prompt "Do you want to confirm every step? (y/n)"}
            while ($promptUser -notmatch '[ynYN]')
            switch ($promptUser)
            {
                "y" {$confirmSteps = $true}
                "n" {$confirmSteps = $false}
            }
        }

        #region prechecks
        #code to check pre-requisites before starting the workflow. That will prevent us from having a half completed workflow which would require manual recovery
        Write-Host ""
        Write-Host "$(get-date) [INFO] Performing pre-checks..." -ForegroundColor Green

        #region check we have the appropriate references
            #load pool2pd reference
            try {$poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"; Exit}
            #load old references
            If (Test-Path -Path ("$referentialPath\hvRef.csv")) {
            try {$oldHvRef = Import-Csv -Path ("$referentialPath\hvRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\hvRef.csv : $($_.Exception.Message)"; Exit}
        }
            If (Test-Path -Path ("$referentialPath\vcRef.csv")) {
            try {$oldVcRef = Import-Csv -Path ("$referentialPath\vcRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\vcRef.csv : $($_.Exception.Message)"; Exit}
        }
        #endregion

        #region applies to planned only
        if ($planned) {
        #region check there are matching desktop pools with VMs to process and which are disabled on the source hv
            #start by connecting to the source view server
            Write-Host "$(get-date) [INFO] Connecting to the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            try {
                if ($hvCreds) {
                    $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                } else {
                    $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                }
            }
            catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
            #create API object
            $source_hvObjectAPI = $source_hvObject.ExtensionData

            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
            ###TODO
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #find out which pool we are working with (assume all which are disabled if none have been specified)
            if (!$desktop_pools) {
                if ($protection_domains) { #no pool was specified, but one or more protection domain(s) was/were, so let's match those to desktop pools using the reference file
                    $test_desktop_pools = @()
                    ForEach ($protection_domain in $protection_domains) {
                        $test_desktop_pools += ($poolRef | Where-Object {$_.protection_domain -eq $protection_domain}).desktop_pool
                    }
                    $test_disabled_desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                    $test_desktop_pools = $test_disabled_desktop_pools | Where-Object {$test_desktop_pools -contains $_.DesktopSummaryData.Name}
                } else { #no pd and no pool were specified, so let's assume we have to process all disabled pools
                    $test_desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                }
            } else { #extract the desktop pools information
                $test_disabled_desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                $test_desktop_pools = $test_disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
            }

            if (!$test_desktop_pools) {
                Write-Host -ForegroundColor Red "$(get-date) [ERROR] There are no desktop pool(s) to process on SOURCE horizon view server $source_hv! Make sure the desktop pool(s) you want to failover are disabled and contain VMs."; Exit
            }

            Remove-Variable test_desktop_pools -ErrorAction SilentlyContinue
            Remove-Variable test_disabled_desktop_pools -ErrorAction SilentlyContinue

            #diconnect from the source view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        #endregion
        #region check there are matching protection domains in the correct status and with remote sites defined
            #let's retrieve the list of protection domains from the source
            Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan

            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
            if (!$protection_domains) {
                if ($desktop_pools) { #no protection domain was specified, but one or more dekstop pool(s) was/were, so let's match to protection domains using the reference file
                    $test_protection_domains = @()
                    ForEach ($desktop_pool in $desktop_pools) {
                        $test_protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                    }
                    $test_activeProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                    $test_protection_domains = $test_activeProtectionDomains | Where-Object {$test_protection_domains -contains $_}
                } else { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains
                    $test_protection_domains = ($poolRef | Select-Object -Property protection_domain -Unique).protection_domain
                    $test_protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$test_protection_domains -contains $_}
                }
            } else {
                $test_protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
            }

            if (!$test_protection_domains) {
                Write-Host -ForegroundColor Red "$(get-date) [ERROR] There are no protection domains in the correct status on $source_cluster!"; Exit
            }

            ForEach ($test_pd2migrate in $test_protection_domains) {

                #figure out if there is more than one remote site defined for the protection domain
                $test_remoteSite = $sourceClusterPd.entities | Where-Object {$_.name -eq $test_pd2migrate} | Select-Object -Property remote_site_names
                if (!$test_remoteSite.remote_site_names) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] : There is no remote site defined for protection domain $test_pd2migrate"; Exit}
                if ($test_remoteSite -is [array]) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] : There is more than one remote site for protection domain $test_pd2migrate"; Exit}
            }

            Remove-Variable test_protection_domains -ErrorAction SilentlyContinue
            Remove-Variable test_activeProtectionDomains -ErrorAction SilentlyContinue

        #endregion
        #region check we can connect to source vc
            Write-Host "$(get-date) [INFO] Connecting to the SOURCE vCenter server $source_vc ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            try {
                if ($vcCreds) {
                    $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                } else {
                    $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to SOURCE vCenter server $source_vc" -ForegroundColor Cyan

            #diconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from SOURCE vCenter server $source_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
        #endregion
        }
        #endregion

        #region applies to unplanned only
        if ($unplanned) {
            #region check there are matching protection domains in the correct status on the target prism
                #let's retrieve the list of protection domains from the target
                Write-Host "$(get-date) [INFO] Retrieving protection domains from target Nutanix cluster $target_cluster ..." -ForegroundColor Green
                if ($confirmSteps) {
                    do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                    while ($promptUser -notmatch '[ynYN]')
                    switch ($promptUser)
                    {
                        "y" {}
                        "n" {Exit}
                    }
                }
                $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from target Nutanix cluster $target_cluster" -ForegroundColor Cyan

                $test_matching_protection_domains = @()
                $test_pds2activate = @()
                ForEach ($desktop_pool in $desktop_pools) {$test_matching_protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain}

                #make sure the matching protection domains are not active already on the target Prism, then build the list of protection domains to process
                ForEach ($test_matching_protection_domain in $test_matching_protection_domains) {
                    if (($targetClusterPd.entities | Where-Object {$_.name -eq $test_matching_protection_domain}).active -eq $true) {
                        Write-Host "$(get-date) [WARNING] Protection domain $test_matching_protection_domain is already active on target Prism $target_cluster. Skipping." -ForegroundColor Yellow
                    } else {
                        $test_pds2activate += $targetClusterPd.entities | Where-Object {$_.name -eq $test_matching_protection_domain}
                    }
                }

                if (!$test_pds2activate) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] There were no matching protection domain(s) to process. Make sure the selected desktop pools have a matching protection domain in the reference file and that those protection domains exist on the target Prism cluster and are in standby status."; Exit}

                Remove-Variable pds2activate -ErrorAction SilentlyContinue
            #endregion
        }
        #endregion

        #region applies to both
        #region check we can connect to the target hv
            #connect to the target view server
            Write-Host "$(get-date) [INFO] Connecting to the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            try {
                if ($hvCreds) {
                    $target_hvObject = Connect-HVServer -Server $target_hv -Credential $hvCreds -ErrorAction Stop
                } else {
                    $target_hvObject = Connect-HVServer -Server $target_hv -ErrorAction Stop
                }
            }
            catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to the TARGET Horizon View server $target_hv" -ForegroundColor Cyan

            #disconnect from the target view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
        #endregion
        #region check we can connect to the target vc
            #connect to the target vCenter
            Write-Host "$(get-date) [INFO] Connecting to the TARGET vCenter server $target_vc ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            try {
                if ($vcCreds) {
                    $target_vcObject = Connect-VIServer $target_vc -Credential $vcCreds -ErrorAction Stop
                } else {
                    $target_vcObject = Connect-VIServer $target_vc -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to TARGET vCenter server $target_vc" -ForegroundColor Cyan

            #disconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from TARGET vCenter server $source_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
        #endregion
        #endregion

        Write-Host "$(get-date) [SUCCESS] Performed pre-checks." -ForegroundColor Cyan
        Write-Host ""

        #endregion

        #region -planned
        if ($planned) { #we're doing a planned failover

            #region deal with the source view bits
            Write-Host "$(get-date) [INFO] Processing items on SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            #start by connecting to the source view server
            Write-Host "$(get-date) [INFO] Connecting to the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            try {
                if ($hvCreds) {
                    $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                } else {
                    $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                }
            }
            catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
            #create API object
            $source_hvObjectAPI = $source_hvObject.ExtensionData

            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
            #####TODO add code here to paginate thru the query results
            $source_hvDesktopPoolsList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($source_hvDesktopPoolsList.length -ne 0) {$source_hvDesktopPools = $serviceQuery.QueryService_GetNext($source_hvObjectAPI,$source_hvDesktopPools.Id)}
                $source_hvDesktopPoolsList += $source_hvDesktopPools.Results
            } while ($source_hvDesktopPools.remainingCount -gt 0)
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #extract Virtual Machines summary information
            Write-Host "$(get-date) [INFO] Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
            #####TODO add code here to paginate thru the query results
            $source_hvVMsList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($source_hvVMsList.length -ne 0) {$source_hvVMs = $serviceQuery.QueryService_GetNext($source_hvObjectAPI,$source_hvVMs.Id)}
                $source_hvVMsList += $source_hvVMs.Results
            } while ($source_hvVMs.remainingCount -gt 0)
            Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #find out which pool we are working with (assume all which are disabled if none have been specified)
            if (!$desktop_pools) {
                if ($protection_domains) { #no pool was specified, but one or more protection domain(s) was/were, so let's match those to desktop pools using the reference file
                    $desktop_pools = @()
                    ForEach ($protection_domain in $protection_domains) {
                        $desktop_pools += ($poolRef | Where-Object {$_.protection_domain -eq $protection_domain}).desktop_pool
                    }
                    $disabled_desktop_pools = $source_hvDesktopPoolsList | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                    $desktop_pools = $disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
                } else { #no pd and no pool were specified, so let's assume we have to process all disabled pools
                    $desktop_pools = $source_hvDesktopPoolsList | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                }
            } else { #extract the desktop pools information
                $disabled_desktop_pools = $source_hvDesktopPoolsList | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                $desktop_pools = $disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
            }

            if (!$desktop_pools) {
                Write-Host -ForegroundColor Red "$(get-date) [ERROR] There are no desktop pool(s) to process on SOURCE horizon view server $source_hv!"
                Exit
            }

            #process each desktop pool
            $poolProcessed = $false
            ForEach ($desktop_pool in $desktop_pools) {
                #check that the pool is disabled
                if ($desktop_pool.DesktopSummaryData.Enabled -eq $true) {Write-Host "$(get-date) [WARNING] Skipping $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv because the desktop pool is enabled" -ForegroundColor Yellow; continue}
                #figure out which machines are in that desktop pool
                $vms = $source_hvVMsList | Where-Object {$_.Base.Desktop.id -eq $desktop_pool.Id.Id}
                #remove machines from the desktop pool
                if ($vms -is [array]) {#we use different methods based on the number of vms in the pool
                    Write-Host "$(get-date) [INFO] Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {$result = $source_hvObjectAPI.Machine.Machine_DeleteMachines($vms.Id,$null)} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"; Exit}
                    Write-Host "$(get-date) [SUCCESS] Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv" -ForegroundColor Cyan
                    $poolProcessed = $true
                } else {
                    if ($vms -ne $null) {#there is only a single vm in the pool to remove, so we use a different method
                        Write-Host "$(get-date) [INFO] Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..." -ForegroundColor Green
                        if ($confirmSteps) {
                            do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                            while ($promptUser -notmatch '[ynYN]')
                            switch ($promptUser)
                            {
                                "y" {}
                                "n" {Exit}
                            }
                        }
                        try {$result = $source_hvObjectAPI.Machine.Machine_Delete($vms.Id,$null)} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"; Exit}
                        Write-Host "$(get-date) [SUCCESS] Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv" -ForegroundColor Cyan
                        $poolProcessed = $true
                    } else {#there were no vms in the pool
                        Write-Host "$(get-date) [WARNING] There were no vms to remove from pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv!" -ForegroundColor Yellow
                    }
                }
            }

            if (!$poolProcessed) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] There were no disabled desktop pools with VMs in their inventory. Stopping execution here."; Exit}

            #save the desktop pool names we processed for later
            $desktop_pool_names = $desktop_pools.DesktopSummaryData.Name

            #diconnect from the source view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green

            Write-Host "$(get-date) [SUCCESS] Done processing items on SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
            Write-Host ""
            #endregion

            #region deal with the source Prism bits
            Write-Host "$(get-date) [INFO] Processing items on SOURCE Nutanix cluster $source_cluster..." -ForegroundColor Green
            #let's retrieve the list of protection domains from the source
            Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan

            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
            if (!$protection_domains) {
                if ($desktop_pools) { #no protection domain was specified, but one or more dekstop pool(s) was/were, so let's match to protection domains using the reference file
                    $protection_domains = @()
                    ForEach ($desktop_pool in $desktop_pools) {
                        $protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool.DesktopSummaryData.Name}).protection_domain
                    }
                    $activeProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                    $protection_domains = $activeProtectionDomains | Where-Object {$protection_domains -contains $_}
                } else { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains
                    $protection_domains = ($poolRef | Select-Object -Property protection_domain -Unique).protection_domain
                    $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                }
            } else {
                $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
            }

            if (!$protection_domains) {
                Write-Host -ForegroundColor Red "$(get-date) [ERROR] There are no protection domains in the correct status on $source_cluster!"
                Exit
            }

            #now let's call the migrate workflow
            ForEach ($pd2migrate in $protection_domains) {

                #figure out if there is more than one remote site defined for the protection domain
                $remoteSite = $sourceClusterPd.entities | Where-Object {$_.name -eq $pd2migrate} | Select-Object -Property remote_site_names
                if (!$remoteSite.remote_site_names) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] : There is no remote site defined for protection domain $pd2migrate"; Exit}
                if ($remoteSite -is [array]) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] : There is more than one remote site for protection domain $pd2migrate"; Exit}

                #migrate the protection domain
                Write-Host "$(get-date) [INFO] Migrating $pd2migrate to $($remoteSite.remote_site_names) ..." -ForegroundColor Green
                if ($confirmSteps) {
                    do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                    while ($promptUser -notmatch '[ynYN]')
                    switch ($promptUser)
                    {
                        "y" {}
                        "n" {Exit}
                    }
                }
                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                $method = "POST"
                $content = @{
                                value = $($remoteSite.remote_site_names)
                            }
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                Write-Host "$(get-date) [SUCCESS] Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)" -ForegroundColor Cyan

            }

            #let's make sure all protection domain migrations have been processed successfully
            #retrieve the list of tasks in the cluster
            Write-Host "$(get-date) [INFO] Retrieving list of tasks on the SOURCE cluster $source_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Retrieved list of tasks on the SOURCE cluster $source_cluster" -ForegroundColor Cyan
            #select only the tasks of operation type "deactivate" which were created after this script was started
            $pdMigrateTasks = $response.entities | Where-Object {$_.operation -eq "deactivate"} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
            #let's loop now until the tasks status are completed and successfull. If a task fails, we'll throw an exception.
            ForEach ($pdMigrateTask in $pdMigrateTasks) {
                if ($pdMigrateTask.percentageCompleted -ne "100") {
                    Do {
                        Write-Host "$(get-date) [WARNING] Waiting 5 seconds for task $($pdMigrateTask.taskName) to complete : $($pdMigrateTask.percentageCompleted)%" -ForegroundColor Yellow
                        Sleep 5
                        Write-Host "$(get-date) [INFO] Retrieving list of tasks on the SOURCE cluster $source_cluster ..." -ForegroundColor Green
                        $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                        $method = "GET"
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        Write-Host "$(get-date) [SUCCESS] Retrieved list of tasks on the SOURCE cluster $source_cluster" -ForegroundColor Cyan
                        $task = $response.entities | Where-Object {$_.taskName -eq $pdMigrateTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                        if ($task.status -ne "running") {
                            if ($task.status -ne "succeeded") {
                                Write-Host -ForegroundColor Red "$(get-date) [ERROR] Task $($pdMigrateTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)"
                                Exit
                            }
                        }
                    }
                    While ($task.percentageCompleted -ne "100")
                    Write-Host "$(get-date) [SUCCESS] Protection domain migration task $($pdMigrateTask.taskName) completed on the SOURCE cluster $source_cluster" -ForegroundColor Cyan
                } else {
                    Write-Host "$(get-date) [SUCCESS] Protection domain migration task $($pdMigrateTask.taskName) completed on the SOURCE cluster $source_cluster" -ForegroundColor Cyan
                }
            }

            Write-Host "$(get-date) [SUCCESS] All protection domain migration tasks have completed. Moving on to vCenter." -ForegroundColor CYAN

            Write-Host "$(get-date) [SUCCESS] Done processing items on SOURCE Nutanix server $source_cluster" -ForegroundColor Cyan
            Write-Host ""
            #endregion

            #region deal with the source vCenter bits
            Write-Host "$(get-date) [INFO] Processing items on SOURCE vCenter server $source_vc..." -ForegroundColor Green
            #connect to the source vCenter
            Write-Host "$(get-date) [INFO] Connecting to the SOURCE vCenter server $source_vc ..." -ForegroundColor Green
            try {
                if ($vcCreds) {
                    $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                } else {
                    $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to SOURCE vCenter server $source_vc" -ForegroundColor Cyan

            #remove orphaned entries from SOURCE vCenter
            #our reference point is the desktop pool, so let's process vms in each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                #process all vms for that desktop pool
                ForEach ($vm in $vms) {
                    Write-Host "$(get-date) [INFO] Removing $($vm.vmName) from inventory in $source_vc ..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {$result = Get-VM -Name $vm.vmName | Where-Object {$_.ExtensionData.Summary.OverallStatus -eq 'gray'} | remove-vm -Confirm:$false} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not remove VM $($vm.vmName): $($_.Exception.Message)"}
                    Write-Host "$(get-date) [SUCCESS] Removed $($vm.vmName) from inventory in $source_vc." -ForegroundColor Cyan
                }
            }

            #diconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from SOURCE vCenter server $source_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter

            Write-Host "$(get-date) [SUCCESS] Done processing items on SOURCE vCenter server $source_vc" -ForegroundColor Cyan
            Write-Host ""
            #endregion

            #region deal with the target vCenter bits
            Write-Host "$(get-date) [INFO] Processing items on TARGET vCenter server $target_vc..." -ForegroundColor Green
            #connect to the target vCenter
            Write-Host "$(get-date) [INFO] Connecting to the TARGET vCenter server $target_vc ..." -ForegroundColor Green
            try {
                if ($vcCreds) {
                    $target_vcObject = Connect-VIServer $target_vc -Credential $vcCreds -ErrorAction Stop
                } else {
                    $target_vcObject = Connect-VIServer $target_vc -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to TARGET vCenter server $target_vc" -ForegroundColor Cyan

            #our reference point is the desktop pool, so let's process vms in each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                #process all vms for that desktop pool
                $dvPortgroups = Get-VDPortGroup | Where-Object {$_.IsUplink -eq $false} #retrieve distributed portgroup names in the target infrastructure which are not uplinks
                ForEach ($vm in $vms) {
                    #move vms to their correct folder
                    $folder = Get-Folder -Name (($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).folder) #figure out which folder this vm was in and move it
                    Write-Host "$(get-date) [INFO] Trying to move $($vm.vmName) to folder $($folder.Name)..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {
                        $vmObject = Get-VM -Name $vm.vmName -ErrorAction Stop
                        if ($vmObject.Folder.Name -ne $folder.Name) {
                            $result = $vmObject | Move-VM -InventoryLocation $folder -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] Moved $($vm.vmName) to folder $($folder.Name)" -ForegroundColor Cyan
                        } else {
                            Write-Host "$(get-date) [INFO] VM $($vm.vmName) is already in folder $($folder.Name)" -ForegroundColor Green
                        }
                    }
                    catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not move $($vm.vmName) to folder $($folder.Name) : $($_.Exception.Message)"}

                    #connect vms to the portgroup
                    Write-Host "$(get-date) [INFO] Re-connecting the virtual machine $($vm.vmName) virtual NIC..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {
                         if (!$target_pg) {#no target portgroup has been specified, so we need to figure out where to connect our vnics
                            $standard_portgroup = $false
                            Write-Host "$(get-date) [WARNING] No target portgroup was specified, figuring out which one to use..." -ForegroundColor Yellow
                            #first we'll see if there is a portgroup with the same name in the target infrastructure
                            $vmPortgroup = ($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).portgroup #retrieve the portgroup name at the source for this vm
                            $portgroups = $vmObject | Get-VMHost | Get-VirtualPortGroup -Standard #retrieve portgroup names in the target infrastructure on the VMhost running that VM
                            $vSwitch0_portGroups = ($vmObject | Get-VMHost | Get-VirtualSwitch -Name "vSwitch0" | Get-VirtualPortGroup -Standard) # get portgroups only on vSwitch0
                            if ($target_pgObject = $dvPortgroups | Where-Object {$_.Name -eq $vmPortGroup}) {
                                Write-Host "$(get-date) [INFO] There is a matching distributed portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                            } elseIf ($target_pgObject = $portgroups | Where-Object {$_.Name -eq $vmPortGroup}) {
                                Write-Host "$(get-date) [INFO] There is a matching standard portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                                $standard_portgroup = $true
                            } elseIf (!($dvPortGroups -is [array])) {#if not, we'll see if there is a dvswitch, and see if there is only one portgroup on that dvswitch
                                $target_pgObject = $dvPortgroups
                                Write-Host "$(get-date) [INFO] There is a single distributed portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                            } elseIf (!($vSwitch0_portGroups -is [array])) {#if not, we'll see if there is a single portgroup on vSwitch0
                                $target_pgObject = $vSwitch0_portGroups
                                Write-Host "$(get-date) [INFO] There is a single standard portgroup on vSwitch0 $($target_pgObject.Name) which will be used." -ForegroundColor Green
                                $standard_portgroup = $true
                            } else {#if not, we'll warn the user we could not process that VM
                                Write-Host "$(get-date) [WARNING] Could not figure out which portgroup to use, so skipping connecting this VM's vNIC!" -ForegroundColor Yellow
                                continue
                            }
                         } else { #fetching the specified portgroup
                            Write-Host "$(get-date) [INFO] Retrieving the specified target portgroup $target_pg..." -ForegroundColor Green
                            try {$target_pgObject = Get-VirtualPortGroup -Name $target_pg} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not retrieve the specified target portgroup : $($_.Exception.Message)"; Continue}
                            if ($target_pgObject -is [array]) {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] There is more than one portgroup with the specified name!"; Continue}
                            Write-Host "$(get-date) [SUCCESS] Retrieved the specified target portgroup $target_pg" -ForegroundColor Cyan
                         }
                         #now that we know which portgroup to connect the vm to, let's connect its vnic to that portgroup
                         if (!$standard_portgroup) {
                            $result = $vmObject | Get-NetworkAdapter -ErrorAction Stop | Select-Object -First 1 |Set-NetworkAdapter -NetworkName $target_pgObject.Name -Confirm:$false -ErrorAction Stop
                         }
                    }
                    catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not reconnect $($vm.vmName) to the network : $($_.Exception.Message)"; Continue}
                    if (!$standard_portgroup) {Write-Host "$(get-date) [SUCCESS] Re-connected the virtual machine $($vm.vmName) to the network $($target_pgObject.Name)" -ForegroundColor Cyan} else {Write-Host "$(get-date) [INFO] Virtual machine $($vm.vmName) is already connected to an existing standard portgroup, so skipping reconnection..." -ForegroundColor Green}
                }
            }

            #disconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from TARGET vCenter server $target_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter

            Write-Host "$(get-date) [SUCCESS] Done processing items on TARGET vCenter server $target_vc" -ForegroundColor Cyan
            Write-Host ""
            #endregion

            #region deal with the target view bits
            Write-Host "$(get-date) [INFO] Processing items on TARGET Horizon View server $target_hv..." -ForegroundColor Green
            #connect to the target view server
            Write-Host "$(get-date) [INFO] Connecting to the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            try {
                if ($hvCreds) {
                    $target_hvObject = Connect-HVServer -Server $target_hv -Credential $hvCreds -ErrorAction Stop
                } else {
                    $target_hvObject = Connect-HVServer -Server $target_hv -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
            #create API object
            $target_hvObjectAPI = $target_hvObject.ExtensionData

            #retrieve basic information we'll need
            #retrieve the view object
            $target_hvVirtualCenter = $target_hvObjectAPI.VirtualCenter.VirtualCenter_List() | Where-Object {$_.Enabled -eq $true}
            if ($target_hvVirtualCenter -is [array]) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] There is more than one enabled vCenter on $target_hv!"; Exit}
            
            #retrieve the list of available vms in vCenter
            Write-Host "$(get-date) [INFO] Retrieving virtual machines information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $target_hvAvailableVms = $target_hvObjectAPI.VirtualMachine.VirtualMachine_List($target_hvVirtualCenter.Id)
            ##TODO add code here to paginate thru the results
            $target_hvAvailableVmsList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($target_hvAvailableVmsList.length -ne 0) {$target_hvAvailableVms = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvAvailableVms.Id)}
                $target_hvAvailableVmsList += $target_hvAvailableVms.Results
            } while ($target_hvAvailableVms.remainingCount -gt 0)

            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $target_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $target_hvObjectAPI
            #####TODO add code here to paginate thru the query results
            $target_hvDesktopPoolsList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($target_hvDesktopPoolsList.length -ne 0) {$target_hvDesktopPools = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvDesktopPools.Id)}
                $target_hvDesktopPoolsList += $target_hvDesktopPools.Results
            } while ($target_hvDesktopPools.remainingCount -gt 0)
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the TARGET Horizon View server $target_hv." -ForegroundColor Cyan
            #extract Active Directory users & groups
            Write-Host "$(get-date) [INFO] Retrieving Active Directory user information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $target_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $target_hvObjectAPI
            $target_hvADUsersList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($target_hvADUsersList.length -ne 0) {$target_hvADUsers = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvADUsers.Id)}
                $target_hvADUsersList += $target_hvADUsers.Results
            } while ($target_hvADUsers.remainingCount -gt 0)
            Write-Host "$(get-date) [SUCCESS] Retrieved Active Directory user information from the TARGET Horizon View server $target_hv." -ForegroundColor Cyan

            #process each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #figure out the desktop pool Id
                $desktop_poolId = ($target_hvDesktopPoolsList | Where-Object {$_.DesktopSummaryData.Name -eq $desktop_pool}).Id
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}

                #add vms to the desktop pools
                if ($vms) {
                    #process all vms for that desktop pool
                    #we start by building the list of vms to add to the pool (this will be more efficient than adding them one by one)
                    $vmIds = @()
                    ForEach ($vm in $vms) {
                        #figure out the virtual machine id
                        $vmId = ($target_hvAvailableVmsList | Where-Object {$_.Name -eq $vm.vmName}).Id
                        $vmIds += $vmId
                    }

                    if (!$vmIds) {Write-Host "$(get-date) [ERROR] No Virtual Machines summary information was found from the TARGET Horizon View server $target_hv..." -ForegroundColor Red; Exit}

                    Write-Host "$(get-date) [INFO] Adding virtual machines to desktop pool $desktop_pool..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {$result = $target_hvObjectAPI.Desktop.Desktop_AddMachinesToManualDesktop($desktop_poolId,$vmIds)} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not add virtual machines to desktop pool $desktop_pool : $($_.Exception.Message)"; Continue}
                    Write-Host "$(get-date) [SUCCESS] Added virtual machines to desktop pool $desktop_pool." -ForegroundColor Cyan

                    #retrieve the list of machines now registered in the TARGET Horizon View server (we need their ids)
                    #extract Virtual Machines summary information
                    Write-Host "$(get-date) [INFO] Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
                    Sleep 15
                    $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                    ####TODO add code here to paginate thru the results
                    $target_hvVMsList = @()
                    $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
                    do {
                        if ($target_hvVMsList.length -ne 0) {$target_hvVMs = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvVMs.Id)}
                        $target_hvVMsList += $target_hvVMs.Results
                    } while ($target_hvVMs.remainingCount -gt 0)
                    Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv" -ForegroundColor Cyan

                    #register users to their vms
                    ForEach ($vm in $vms) {
                        #figure out the object id of the assigned user
                        if ($vm.assignedUser) {#process the assigned user if there was one
                            #figure out the virtual machine id
                            while (!($vmId = ($target_hvVMsList | Where-Object {$_.Base.Name -eq $vm.vmName}).Id)) {
                                Write-Host "$(get-date) [INFO] Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
                                Sleep 15
                                $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                                $target_hvVMsList = @()
                                $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
                                do {
                                    if ($target_hvVMsList.length -ne 0) {$target_hvVMs = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvVMs.Id)}
                                    $target_hvVMsList += $target_hvVMs.Results
                                } while ($target_hvVMs.remainingCount -gt 0)
                                Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
                            }

                            $vmUserId = ($target_hvADUsersList | Where-Object {$_.Base.DisplayName -eq $vm.assignedUser}).Id #grab the user name whose id matches the id of the assigned user on the desktop machine
                            if (!$vmUserId) {Write-Host "$(get-date) [WARNING] Could not find a matching Active Directory object for user $($vm.AssignedUser) for VM $($vm.vmName)!" -ForegroundColor Yellow; continue}

                            #create the MapEntry object required for updating the machine
                            $MapEntry = New-Object "Vmware.Hv.MapEntry"
                            $MapEntry.key = "base.user"
                            $MapEntry.value = $vmUserId
                            #update the machine
                            Write-Host "$(get-date) [INFO] Updating assigned user for $($vm.vmName)..." -ForegroundColor Green
                            if ($confirmSteps) {
                                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                                while ($promptUser -notmatch '[ynYN]')
                                switch ($promptUser)
                                {
                                    "y" {}
                                    "n" {Exit}
                                }
                            }
                            try {$result = $target_hvObjectAPI.Machine.Machine_Update($vmId,$MapEntry)} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not update assigned user to $($vm.vmName) : $($_.Exception.Message)"; Continue}
                            Write-Host "$(get-date) [SUCCESS] Updated assigned user for $($vm.vmName) to $($vm.assignedUser)." -ForegroundColor Cyan
                        }
                    }
                } else {
                    Write-Host "$(get-date) [WARNING] There were no virtual machines to add to desktop pool $desktop_pool..." -ForegroundColor Yellow
                }
            }

            #disconnect from the target view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the TARGET Horizon View server $target_hv..." -ForegroundColor Green

            Write-Host "$(get-date) [SUCCESS] Done processing items on TARGET Horizon View server $target_hv" -ForegroundColor Cyan
            Write-Host ""
            #endregion

            Write-Host "$(get-date) [SUCCESS] Done!" -ForegroundColor Cyan
            Write-Host ""
        }
        #endregion

        #region -unplanned
        if ($unplanned) {
            #we need to know the desktop pools and protection domains for unplanned, so let's figure that out now
            if (!$desktop_pools) {$desktop_pools = Read-Host "Please enter the desktop pool(s) you want to failover (unplanned)"}
            #figure out the matching protection domains from the reference file
            $matching_protection_domains = @()
            ForEach ($desktop_pool in $desktop_pools) {$matching_protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain}

            #region deal with the target Prism bits
            Write-Host "$(get-date) [INFO] Processing items on TARGET Nutanix cluster $target_cluster..." -ForegroundColor Green
            #let's retrieve the list of protection domains from the target
            Write-Host "$(get-date) [INFO] Retrieving protection domains from target Nutanix cluster $target_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from target Nutanix cluster $target_cluster" -ForegroundColor Cyan

            #make sure the matching protection domains are not active already on the target Prism, then build the list of protection domains to process
            $pds2activate = @()
            ForEach ($matching_protection_domain in $matching_protection_domains) {
                if (($targetClusterPd.entities | Where-Object {$_.name -eq $matching_protection_domain}).active -eq $true) {
                    Write-Host "$(get-date) [WARNING] Protection domain $matching_protection_domain is already active on target Prism $target_cluster. Skipping." -ForegroundColor Yellow
                } else {
                    $pds2activate += $targetClusterPd.entities | Where-Object {$_.name -eq $matching_protection_domain}
                }
            }

            if (!$pds2activate) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] There were no matching protection domain(s) to process. Make sure the selected desktop pools have a matching protection domain in the reference file and that those protection domains exist on the target Prism cluster and are in standby status."; Exit}

            #now let's call the activate workflow
            ForEach ($pd2activate in $pds2activate) {

                #activate the protection domain
                Write-Host "$(get-date) [INFO] Activating protection domain $($pd2activate.name) on $target_cluster ..." -ForegroundColor Green
                if ($confirmSteps) {
                    do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                    while ($promptUser -notmatch '[ynYN]')
                    switch ($promptUser)
                    {
                        "y" {}
                        "n" {Exit}
                    }
                }
                $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate.name)/activate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                Write-Host "$(get-date) [SUCCESS] Successfully activated protection domain $($pd2activate.name) on $target_cluster" -ForegroundColor Cyan

            }

            #let's make sure all protection domain migrations have been processed successfully
            #retrieve the list of tasks in the cluster
            Write-Host "$(get-date) [INFO] Retrieving list of tasks on the TARGET cluster $target_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Retrieved list of tasks on the TARGET cluster $target_cluster" -ForegroundColor Cyan
            #select only the tasks of operation type "deactivate" which were created after this script was started
            $pdActivateTasks = $response.entities | Where-Object {$_.operation -eq "activate"} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
            #let's loop now until the tasks status are completed and successfull. If a task fails, we'll throw an exception.
            ForEach ($pdActivateTask in $pdActivateTasks) {
                if ($pdActivateTask.percentageCompleted -ne "100") {
                    Do {
                        Write-Host "$(get-date) [WARNING] Waiting 5 seconds for task $($pdActivateTask.taskName) to complete : $($pdActivateTask.percentageCompleted)%" -ForegroundColor Yellow
                        Sleep 5
                        Write-Host "$(get-date) [INFO] Retrieving list of tasks on the TARGET cluster $target_cluster ..." -ForegroundColor Green
                        $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                        $method = "GET"
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        Write-Host "$(get-date) [SUCCESS] Retrieved list of tasks on the TARGET cluster $target_cluster" -ForegroundColor Cyan
                        $task = $response.entities | Where-Object {$_.taskName -eq $pdActivateTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                        if ($task.status -ne "running") {
                            if ($task.status -ne "succeeded") {
                                Write-Host -ForegroundColor Red "$(get-date) [ERROR] Task $($pdActivateTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)"
                                Exit
                            }
                        }
                    }
                    While ($task.percentageCompleted -ne "100")
                    Write-Host "$(get-date) [SUCCESS] Protection domain migration task $($pdActivateTask.taskName) completed on the TARGET cluster $target_cluster" -ForegroundColor Cyan
                } else {
                    Write-Host "$(get-date) [SUCCESS] Protection domain migration task $($pdActivateTask.taskName) completed on the TARGET cluster $target_cluster" -ForegroundColor Cyan
                }
            }

            Write-Host "$(get-date) [SUCCESS] All protection domain activation tasks have completed. Moving on to vCenter." -ForegroundColor CYAN

            Write-Host "$(get-date) [SUCCESS] Done processing items on TARGET Nutanix server $target_cluster" -ForegroundColor Cyan
            Write-Host ""
            #endregion

            #region deal with the target vCenter bits
            #connect to the target vCenter
            Write-Host "$(get-date) [INFO] Connecting to the TARGET vCenter server $target_vc ..." -ForegroundColor Green
            try {
                if ($vcCreds) {
                    $target_vcObject = Connect-VIServer $target_vc -Credential $vcCreds -ErrorAction Stop
                } else {
                    $target_vcObject = Connect-VIServer $target_vc -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to TARGET vCenter server $target_vc" -ForegroundColor Cyan

            #our reference point is the desktop pool, so let's process vms in each desktop pool
            ForEach ($desktop_pool in $desktop_pools) {
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                #process all vms for that desktop pool
                $dvPortgroups = Get-VDPortGroup | Where-Object {$_.IsUplink -eq $false} #retrieve distributed portgroup names in the target infrastructure which are not uplinks
                ForEach ($vm in $vms) {
                    #move vms to their correct folder
                    $folder = Get-Folder -Name (($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).folder) #figure out which folder this vm was in and move it
                    Write-Host "$(get-date) [INFO] Trying to move $($vm.vmName) to folder $($folder.Name)..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {
                        $vmObject = Get-VM -Name $vm.vmName -ErrorAction Stop
                        if ($vmObject.Folder.Name -ne $folder.Name) {
                            $result = $vmObject | Move-VM -InventoryLocation $folder -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] Moved $($vm.vmName) to folder $($folder.Name)" -ForegroundColor Cyan
                        } else {
                            Write-Host "$(get-date) [INFO] VM $($vm.vmName) is already in folder $($folder.Name)" -ForegroundColor Green
                        }
                    }
                    catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not move $($vm.vmName) to folder $($folder.Name) : $($_.Exception.Message)"; Continue}

                    #connect vms to the portgroup
                    Write-Host "$(get-date) [INFO] Re-connecting the virtual machine $($vm.vmName) virtual NIC..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {
                         if (!$target_pg) {#no target portgroup has been specified, so we need to figure out where to connect our vnics
                            $standard_portgroup = $false
                            Write-Host "$(get-date) [WARNING] No target portgroup was specified, figuring out which one to use..." -ForegroundColor Yellow
                            #first we'll see if there is a portgroup with the same name in the target infrastructure
                            $vmPortgroup = ($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).portgroup #retrieve the portgroup name at the source for this vm
                            $portgroups = $vmObject | Get-VMHost | Get-VirtualPortGroup -Standard #retrieve portgroup names in the target infrastructure on the VMhost running that VM
                            $vSwitch0_portGroups = ($vmObject | Get-VMHost | Get-VirtualSwitch -Name "vSwitch0" | Get-VirtualPortGroup -Standard) # get portgroups only on vSwitch0
                            if ($target_pgObject = $dvPortgroups | Where-Object {$_.Name -eq $vmPortGroup}) {
                                Write-Host "$(get-date) [INFO] There is a matching distributed portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                            } elseIf ($target_pgObject = $portgroups | Where-Object {$_.Name -eq $vmPortGroup}) {
                                Write-Host "$(get-date) [INFO] There is a matching standard portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                                $standard_portgroup = $true
                            } elseIf (!($dvPortGroups -is [array])) {#if not, we'll see if there is a dvswitch, and see if there is only one portgroup on that dvswitch
                                $target_pgObject = $dvPortgroups
                                Write-Host "$(get-date) [INFO] There is a single distributed portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                            } elseIf (!($vSwitch0_portGroups -is [array])) {#if not, we'll see if there is a single portgroup on vSwitch0
                                $target_pgObject = $vSwitch0_portGroups
                                Write-Host "$(get-date) [INFO] There is a single standard portgroup on vSwitch0 $($target_pgObject.Name) which will be used." -ForegroundColor Green
                                $standard_portgroup = $true
                            } else {#if not, we'll warn the user we could not process that VM
                                Write-Host "$(get-date) [WARNING] Could not figure out which portgroup to use, so skipping connecting this VM's vNIC!" -ForegroundColor Yellow
                                continue
                            }
                         } else { #fetching the specified portgroup
                            Write-Host "$(get-date) [INFO] Retrieving the specified target portgroup $target_pg..." -ForegroundColor Green
                            try {$target_pgObject = Get-VirtualPortGroup -Name $target_pg} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not retrieve the specified target portgroup : $($_.Exception.Message)"; Continue}
                            if ($target_pgObject -is [array]) {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] There is more than one portgroup with the specified name!"; Continue}
                            Write-Host "$(get-date) [SUCCESS] Retrieved the specified target portgroup $target_pg" -ForegroundColor Cyan
                         }
                         #now that we know which portgroup to connect the vm to, let's connect its vnic to that portgroup
                         if (!$standard_portgroup) {
                            $result = $vmObject | Get-NetworkAdapter -ErrorAction Stop | Select-Object -First 1 |Set-NetworkAdapter -NetworkName $target_pgObject.Name -Confirm:$false -ErrorAction Stop
                         }
                    }
                    catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not reconnect $($vm.vmName) to the network : $($_.Exception.Message)"; Continue}
                    if (!$standard_portgroup) {Write-Host "$(get-date) [SUCCESS] Re-connected the virtual machine $($vm.vmName) to the network $($target_pgObject.Name)" -ForegroundColor Cyan} else {Write-Host "$(get-date) [INFO] Virtual machine $($vm.vmName) is already connected to an existing standard portgroup, so skipping reconnection..." -ForegroundColor Green}
                }
            }

            #disconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from TARGET vCenter server $source_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
            #endregion

            #region deal with the target view bits
            #connect to the target view server
            Write-Host "$(get-date) [INFO] Connecting to the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            try {
                if ($hvCreds) {
                    $target_hvObject = Connect-HVServer -Server $target_hv -Credential $hvCreds -ErrorAction Stop
                } else {
                    $target_hvObject = Connect-HVServer -Server $target_hv -ErrorAction Stop
                }
            }
            catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
            #create API object
            $target_hvObjectAPI = $target_hvObject.ExtensionData

            #retrieve basic information we'll need
            #retrieve the vCenter object
            $target_hvVirtualCenter = $target_hvObjectAPI.VirtualCenter.VirtualCenter_List() | Where-Object {$_.Enabled -eq $true}
            if ($target_hvVirtualCenter -is [array]) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] There is more than one enabled vCenter on $target_hv!"; Exit}
            #retrieve the list of available vms in vCenter
            $target_hvAvailableVms = $target_hvObjectAPI.VirtualMachine.VirtualMachine_List($target_hvVirtualCenter.Id)
            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $target_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $target_hvObjectAPI
            #####TODO add code here to paginate thru the query results
            $target_hvDesktopPoolsList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($target_hvDesktopPoolsList.length -ne 0) {$target_hvDesktopPools = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvDesktopPools.Id)}
                $target_hvDesktopPoolsList += $target_hvDesktopPools.Results
            } while ($target_hvDesktopPools.remainingCount -gt 0)
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the TARGET Horizon View server $target_hv." -ForegroundColor Cyan
            #extract Active Directory users & groups
            Write-Host "$(get-date) [INFO] Retrieving Active Directory user information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $target_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $target_hvObjectAPI
            $target_hvADUsersList = @()
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
            do {
                if ($target_hvADUsersList.length -ne 0) {$target_hvADUsers = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvADUsers.Id)}
                $target_hvADUsersList += $target_hvADUsers.Results
            } while ($target_hvADUsers.remainingCount -gt 0)
            Write-Host "$(get-date) [SUCCESS] Retrieved Active Directory user information from the TARGET Horizon View server $target_hv." -ForegroundColor Cyan

            #process each desktop pool
            ForEach ($desktop_pool in $desktop_pools) {
                #figure out the desktop pool Id
                $desktop_poolId = ($target_hvDesktopPoolsList | Where-Object {$_.DesktopSummaryData.Name -eq $desktop_pool}).Id
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}

                #add vms to the desktop pools
                if ($vms) {
                    #process all vms for that desktop pool
                    #we start by building the list of vms to add to the pool (this will be more efficient than adding them one by one)
                    $vmIds = @()
                    ForEach ($vm in $vms) {
                        #figure out the virtual machine id
                        $vmId = ($target_hvAvailableVms | Where-Object {$_.Name -eq $vm.vmName}).Id
                        $vmIds += $vmId
                    }

                    Write-Host "$(get-date) [INFO] Adding virtual machines to desktop pool $desktop_pool..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {$result = $target_hvObjectAPI.Desktop.Desktop_AddMachinesToManualDesktop($desktop_poolId,$vmIds)} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not add virtual machines to desktop pool $desktop_pool : $($_.Exception.Message)"; Continue}
                    Write-Host "$(get-date) [SUCCESS] Added virtual machines to desktop pool $desktop_pool." -ForegroundColor Cyan

                    #retrieve the list of machines now registered in the TARGET Horizon View server (we need their ids)
                    #extract Virtual Machines summary information
                    Write-Host "$(get-date) [INFO] Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
                    Sleep 15
                    $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                    $target_hvVMsList = @()
                    $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
                    do {
                        if ($target_hvVMsList.length -ne 0) {$target_hvVMs = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvVMs.Id)}
                        $target_hvVMsList += $target_hvVMs.Results
                    } while ($target_hvVMs.remainingCount -gt 0)
                    Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv" -ForegroundColor Cyan

                    #register users to their vms
                    ForEach ($vm in $vms) {
                        #figure out the object id of the assigned user
                        if ($vm.assignedUser) {#process the assigned user if there was one
                            #figure out the virtual machine id
                            while (!($vmId = ($target_hvVMsList | Where-Object {$_.Base.Name -eq $vm.vmName}).Id)) {
                                Write-Host "$(get-date) [INFO] Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
                                Sleep 15
                                $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                                $target_hvVMsList = @()
                                $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
                                do {
                                    if ($target_hvVMsList.length -ne 0) {$target_hvVMs = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$target_hvVMs.Id)}
                                    $target_hvVMsList += $target_hvVMs.Results
                                } while ($target_hvVMs.remainingCount -gt 0)
                                Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
                            }

                            $vmUserId = ($target_hvADUsersList | Where-Object {$_.Base.DisplayName -eq $vm.assignedUser}).Id #grab the user name whose id matches the id of the assigned user on the desktop machine
                            if (!$vmUserId) {Write-Host "$(get-date) [WARNING] Could not find a matching Active Directory object for user $($vm.AssignedUser) for VM $($vm.vmName)!" -ForegroundColor Yellow; continue}
                            #create the MapEntry object required for updating the machine
                            $MapEntry = New-Object "Vmware.Hv.MapEntry"
                            $MapEntry.key = "base.user"
                            $MapEntry.value = $vmUserId
                            #update the machine
                            Write-Host "$(get-date) [INFO] Updating assigned user for $($vm.vmName)..." -ForegroundColor Green
                            if ($confirmSteps) {
                                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                                while ($promptUser -notmatch '[ynYN]')
                                switch ($promptUser)
                                {
                                    "y" {}
                                    "n" {Exit}
                                }
                            }
                            try {$result = $target_hvObjectAPI.Machine.Machine_Update($vmId,$MapEntry)} catch {Write-Host -ForegroundColor Yellow "$(get-date) [WARNING] Could not update assigned user to $($vm.vmName) : $($_.Exception.Message)"; Continue}
                            Write-Host "$(get-date) [SUCCESS] Updated assigned user for $($vm.vmName) to $($vm.assignedUser)." -ForegroundColor Cyan
                        }
                    }
                } else {
                    Write-Host "$(get-date) [WARNING] There were no virtual machines to add to desktop pool $desktop_pool..." -ForegroundColor Yellow
                }
            }

            #disconnect from the target view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            #endregion
        }
        #endregion
    }
    #endregion

    #region -cleanup
    if ($cleanup) {

        #insert here prompt for step by step confirmation
        if ((!$prompt) -and (!$noprompt))
        {
            do {$promptUser = Read-Host -Prompt "Do you want to confirm every step? (y/n)"}
            while ($promptUser -notmatch '[ynYN]')
            switch ($promptUser)
            {
                "y" {$confirmSteps = $true}
                "n" {$confirmSteps = $false}
            }
        }

        #region -planned
        if ($planned) {

            #load pool2pd reference
            try {$poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"; Exit}

            #let's retrieve the list of protection domains from the source
            Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan

            #first, we need to figure out which protection domains need to be updated. If none have been specified, we'll assume all those which are referenced in the PoolRef.csv file.
            if (!$protection_domains) {
                if ($desktop_pools) { #no protection domain was specified, but one or more dekstop pool(s) was/were, so let's match to protection domains using the reference file
                    $protection_domains = @()
                    ForEach ($desktop_pool in $desktop_pools) {
                        $protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                    }
                    $standbyProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name
                    $protection_domains = $standbyProtectionDomains | Where-Object {$protection_domains -contains $_}
                } else { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains referenced in PoolRef.csv
                    $protection_domains = ($poolRef | Select-Object -Property protection_domain -Unique).protection_domain
                    $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                }
            } else {
                $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
            }

            if (!$protection_domains) {
                Write-Host -ForegroundColor Red "$(get-date) [ERROR] There are no protection domains in the correct status on $source_cluster!"
                Exit
            }

            #now let's remove the schedules
            ForEach ($pd2update in $protection_domains) {

                #remove all schedules from the protection domain
                Write-Host "$(get-date) [INFO] Removing all schedules from protection domain $pd2update on $source_cluster ..." -ForegroundColor Green
                if ($confirmSteps) {
                    do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                    while ($promptUser -notmatch '[ynYN]')
                    switch ($promptUser)
                    {
                        "y" {}
                        "n" {Exit}
                    }
                }
                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2update/schedules"
                $method = "DELETE"
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-Host "$(get-date) [SUCCESS] Successfully removed all schedules from protection domain $pd2update on $source_cluster" -ForegroundColor Cyan

            }
        }
        #endregion

        #region -unplanned
        if ($unplanned) {

            #region check we have the appropriate references
            #load pool2pd reference
            try {$poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"; Exit}
            #load old references
            If (Test-Path -Path ("$referentialPath\hvRef.csv")) {
                try {$oldHvRef = Import-Csv -Path ("$referentialPath\hvRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\hvRef.csv : $($_.Exception.Message)"; Exit}
            }
            If (Test-Path -Path ("$referentialPath\vcRef.csv")) {
                try {$oldVcRef = Import-Csv -Path ("$referentialPath\vcRef.csv") -ErrorAction Stop} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not import data from $referentialPath\vcRef.csv : $($_.Exception.Message)"; Exit}
            }
        #endregion

            #region figure out what needs to be processed
            #we need to know the desktop pools and protection domains for unplanned, so let's figure that out now
            if (!$desktop_pools) {$desktop_pools = Read-Host "Please enter the desktop pool(s) you want to failover (unplanned)"}
            #figure out the matching protection_domains
            $protection_domains = @()
            ForEach ($desktop_pool in $desktop_pools) {
                $protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
            }
            #let's retrieve the list of protection domains from the target
            Write-Host "$(get-date) [INFO] Retrieving protection domains from SOURCE Nutanix cluster $source_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from SOURCE Nutanix cluster $source_cluster" -ForegroundColor Cyan
            #keep only those that are active and match
            $activeProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
            $protection_domains = $activeProtectionDomains | Where-Object {$protection_domains -contains $_}
            if (!$protection_domains) {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not find any matching protection domains in the reference file!"; Exit}
            #endregion

            #cleanup source/primary View
            #region deal with the source view bits
            #start by connecting to the source view server
            Write-Host "$(get-date) [INFO] Connecting to the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            try {
                if ($hvCreds) {
                    $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                } else {
                    $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                }
            }
            catch{Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
            #create API object
            $source_hvObjectAPI = $source_hvObject.ExtensionData

            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #extract Virtual Machines summary information
            Write-Host "$(get-date) [INFO] Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #find out which pool we are working with (assume all which are disabled if none have been specified)
            if (!$desktop_pools) {
                $desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
            } else { #extract the desktop pools information
                $disabled_desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                $desktop_pools = $disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
            }

            if (!$desktop_pools) {
                Write-Host -ForegroundColor Red "$(get-date) [ERROR] There are no desktop pool(s) to process on SOURCE horizon view server $source_hv!"
                Exit
            }

            #process each desktop pool
            ForEach ($desktop_pool in $desktop_pools) {
                #check that the pool is disabled
                if ($desktop_pool.DesktopSummaryData.Enabled -eq $true) {Write-Host "$(get-date) [WARNING] Skipping $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv because the desktop pool is enabled" -ForegroundColor Yellow; continue}
                #figure out which machines are in that desktop pool
                $vms = $source_hvVMs.Results | Where-Object {$_.Base.Desktop.id -eq $desktop_pool.Id.Id}
                #remove machines from the desktop pool
                if ($vms -is [array]) {#we use different methods based on the number of vms in the pool
                    Write-Host "$(get-date) [INFO] Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {$result = $source_hvObjectAPI.Machine.Machine_DeleteMachines($vms.Id,$null)} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"; Exit}
                    Write-Host "$(get-date) [SUCCESS] Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv" -ForegroundColor Cyan
                } else {
                    if ($vms -ne $null) {#there is only a single vm in the pool to remove, so we use a different method
                        Write-Host "$(get-date) [INFO] Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..." -ForegroundColor Green
                        if ($confirmSteps) {
                            do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                            while ($promptUser -notmatch '[ynYN]')
                            switch ($promptUser)
                            {
                                "y" {}
                                "n" {Exit}
                            }
                        }
                        try {$result = $source_hvObjectAPI.Machine.Machine_Delete($vms.Id,$null)} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"; Exit}
                        Write-Host "$(get-date) [SUCCESS] Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv" -ForegroundColor Cyan
                    } else {#there were no vms in the pool
                        Write-Host "$(get-date) [WARNING] There were no vms to remove from pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv!" -ForegroundColor Yellow
                    }
                }
            }

            #save the desktop pool names we processed for later
            $desktop_pool_names = $desktop_pools.DesktopSummaryData.Name

            #diconnect from the source view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            #endregion

            #cleanup source/primary Prism
            #region deal with source Prism
            #let's call the deactivate workflow
            ForEach ($pd2deactivate in $protection_domains) {

                #activate the protection domain
                Write-Host "$(get-date) [INFO] De-activating protection domain $pd2deactivate on $source_cluster ..." -ForegroundColor Green
                if ($confirmSteps) {
                    do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                    while ($promptUser -notmatch '[ynYN]')
                    switch ($promptUser)
                    {
                        "y" {}
                        "n" {Exit}
                    }
                }
                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                Write-Host "$(get-date) [SUCCESS] Successfully de-activated protection domain $pd2deactivate on $source_cluster" -ForegroundColor Cyan
                Write-Host "$(get-date) [INFO] Waiting 1 minute for tasks to complete..."
                Sleep 60
            }
            #endregion

            #cleanup source/primary vCenter
            #region deal with the source vCenter bits
            #connect to the source vCenter
            Write-Host "$(get-date) [INFO] Connecting to the SOURCE vCenter server $source_vc ..." -ForegroundColor Green
            try {
                if ($vcCreds) {
                    $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                } else {
                    $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                }
            }
            catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"; Exit}
            Write-Host "$(get-date) [SUCCESS] Connected to SOURCE vCenter server $source_vc" -ForegroundColor Cyan

            #remove orphaned entries from SOURCE vCenter
            #our reference point is the desktop pool, so let's process vms in each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                #process all vms for that desktop pool
                ForEach ($vm in $vms) {
                    Write-Host "$(get-date) [INFO] Removing $($vm.vmName) from inventory in $source_vc ..." -ForegroundColor Green
                    if ($confirmSteps) {
                        do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                        while ($promptUser -notmatch '[ynYN]')
                        switch ($promptUser)
                        {
                            "y" {}
                            "n" {Exit}
                        }
                    }
                    try {$result = Get-VM -Name $vm.vmName | Where-Object {$_.ExtensionData.Summary.OverallStatus -eq 'gray'} | remove-vm -Confirm:$false} catch {Write-Host -ForegroundColor Red "$(get-date) [ERROR] Could not remove VM $($vm.vmName): $($_.Exception.Message)"; Exit}
                    Write-Host "$(get-date) [SUCCESS] Removed $($vm.vmName) from inventory in $source_vc." -ForegroundColor Cyan
                }
            }

            #diconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from SOURCE vCenter server $source_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
            #endregion
        }
        #endregion
    }
    #endregion

    #region -deactivate
    if ($deactivate) {

        #insert here prompt for step by step confirmation
        if ((!$prompt) -and (!$noprompt))
        {
            do {$promptUser = Read-Host -Prompt "Do you want to confirm every step? (y/n)"}
            while ($promptUser -notmatch '[ynYN]')
            switch ($promptUser)
            {
                "y" {$confirmSteps = $true}
                "n" {$confirmSteps = $false}
            }
        }

        #let's retrieve the list of protection domains from the target
        Write-Host "$(get-date) [INFO] Retrieving protection domains from target Nutanix cluster $target_cluster ..." -ForegroundColor Green
        if ($confirmSteps) {
            do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
            while ($promptUser -notmatch '[ynYN]')
            switch ($promptUser)
            {
                "y" {}
                "n" {Exit}
            }
        }
        $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from target Nutanix cluster $target_cluster" -ForegroundColor Cyan

        #first, we need to figure out which protection domains need to be deactivated.
        if (!$protection_domains) {$protection_domains = Read-Host "Enter the name of the protection domain(s) you want to deactivate on $target_cluster. !!!WARNING!!! All VMs in that protection domain will be deleted!"}

        #now let's call the deactivate workflow
        ForEach ($pd2deactivate in $protection_domains) {

            #activate the protection domain
            Write-Host "$(get-date) [INFO] De-activating protection domain $pd2deactivate on $target_cluster ..." -ForegroundColor Green
            if ($confirmSteps) {
                do {$promptUser = Read-Host -Prompt "Do you want to continue? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {}
                    "n" {Exit}
                }
            }
            $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
            $method = "POST"
            $content = @{}
            $body = (ConvertTo-Json $content -Depth 4)
            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
            Write-Host "$(get-date) [SUCCESS] Successfully de-activated protection domain $pd2deactivate on $target_cluster" -ForegroundColor Cyan

        }
    }
    #endregion
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
	Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion