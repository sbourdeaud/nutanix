<#
.SYNOPSIS
  This is a summary of what the script is (!!!!!!!!!!WORK IN PROGRESS: DO NOT USE!!!!!!!!!!).
.DESCRIPTION
  This is a detailed description of what the script does and how it is used.
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
.EXAMPLE
  Connect to a Nutanix cluster of your choice:
  PS> .\template.ps1 -cluster ntnxc1.local -username admin -password admin
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: July 22nd 2015
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
    [parameter(mandatory = $false)] [switch]$log,
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
    [parameter(mandatory = $false)] [string]$target_pg,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] [string]$referentialPath,
    [parameter(mandatory = $false)] $protection_domains
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
            catch {throw "$(get-date) [ERROR] : $($_.Exception.Message)"}
        } else {
            try {$object = $serviceQuery.QueryService_Query($ViewAPIObject,$query)}
            catch {throw "$(get-date) [ERROR] : $($_.Exception.Message)"}
        }
    }

    end
    {
        if (!$object) {
            throw "$(get-date) [ERROR] : The View API query did not return any data... Exiting!"
        }
        return $object
    }
}#end function Invoke-HvQuery

#function add vms to desktop pool
#function assign users to desktop
#function move vms to folders
#function remove vms from desktop pool

#endregion

#region prepwork

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/19/2015 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\template_prism_rest.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}


#check if we have all the required PoSH modules
Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

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
        catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

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
            catch {throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"}
        }
        catch {throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"} 
    }
}
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
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")

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
#endregion

#region parameters validation
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
    
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

    if (!$deactivate -and !$failover -and !$unplanned) {
        if (!$source_cluster) {$source_cluster = Read-Host "Enter the fully qualified domain name or IP address of the source Nutanix cluster"} #prompt for the Nutanix source cluster name/ip if it hasn't been specified already
        if (!$source_vc) {$source_vc = Read-Host "Enter the fully qualified domain name or IP address of the source vCenter server"} #prompt for the vCenter server name/ip if it hasn't been specified already
        if (!$source_hv) {$source_hv = Read-Host "Enter the fully qualified domain name or IP address of the source VMware Horizon View server"} #prompt for the VMware Horizon View server name/ip if it hasn't been specified already
    }

    if (!$referentialPath) {$referentialPath = (Get-Item -Path ".\").FullName} #assume all reference fiels are in the current working directory if a path has not been specified

    if ($failover -or $cleanup -or $deactivate) {
        if (!$target_cluster) {$target_cluster = Read-Host "Enter the fully qualified domain name or IP address of the target Nutanix cluster"} #prompt for the target Nutanix cluster name/ip if we are trying to failover and it hasn't been specified already
        if (!$deactivate -and !$target_vc) {$target_vc = Read-Host "Enter the fully qualified domain name or IP address of the target vCenter server"} #prompt for the target vCenter server name/ip if we are trying to failover and it hasn't been specified already
        if (!$deactivate -and !$target_hv) {$target_hv = Read-Host "Enter the fully qualified domain name or IP address of the target VMware Horizon View server"} #prompt for the target vCenter server name/ip if we are trying to failover and it hasn't been specified already
    }

#endregion

#region processing	
	################################
	##  Main execution here       ##
	################################
	
    #region check that we have what we need to proceed
    If ((Test-Path -Path $referentialPath) -eq $false) {throw "$(get-date) [ERROR] Could not access the path where the reference files are: $($_.Exception.Message)"}
    If ((Test-Path -Path ("$referentialPath\PoolRef.csv")) -eq $false) {throw "$(get-date) [ERROR] Could not access the PoolRef.csv file in $referentialPath : $($_.Exception.Message)"}
    #endregion

    #region -scan
    if ($scan) {
        #check if this is the first run

        #if it is, build the first reference file

        #load pool2pd reference
        try {$pool2PdReferential = Import-Csv -Path ("$referentialPath\PoolRef.csv") -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"}

        #load old vm reference
        If (Test-Path -Path ("$referentialPath\ViewVmRef.csv")) {
            try {$savedReferential = Import-Csv -Path ("$referentialPath\ViewVmRef.csv") -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not import data from $referentialPath\ViewVmRef.csv : $($_.Exception.Message)"}
        }

        #extract desktop pools and their content
        
        #extract protection domains
        Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
        $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan

        #build new reference
        $actualVms2PdRef = $sourceClusterPd.entities | select -Property name,vms

        #compare reference file with pool & pd content
        #$vms2add = @("fullprivm-001","fullprivm-002","fullprivm-003")
        #$vms2remove = @("fullprivm-001","fullprivm-002","fullprivm-003")
        #$pd = "async1"

        #if required, add vms to pds
        ForEach ($vm2add in $vms2add) {
            $reponse = Update-NutanixProtectionDomain -action add -cluster $source_cluster -username $username -password $PrismSecurePassword -protection_domain $pd -vm $vm2add
        }
        #if required, remove vms from pds
        ForEach ($vm2remove in $vms2remove) {
            $reponse = Update-NutanixProtectionDomain -action remove -cluster $source_cluster -username $username -password $PrismSecurePassword -protection_domain $pd -vm $vm2remove
        }
    }
    #endregion

    #region -failover
    if ($failover) {
        #region -planned
        if ($planned) { #we're doing a planned failover
            
            #let's retrieve the list of protection domains from the source
            Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan
            
            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
            if (!$protection_domains) {$protection_domains = ($sourceClusterPd.entities | where {$_.active -eq $true} | select -Property name).name}

            #now let's call the migrate workflow
            ForEach ($pd2migrate in $protection_domains) {

                #figure out if there is more than one remote site defined for the protection domain
                $remoteSite = $sourceClusterPd.entities | where {$_.name -eq $pd2migrate} | select -Property remote_site_names
                if (!$remoteSite.remote_site_names) {throw "$(get-date) [ERROR] : There is no remote site defined for protection domain $pd2migrate"}
                if ($remoteSite -is [array]) {throw "$(get-date) [ERROR] : There is more than one remote site for protection domain $pd2migrate"}
                
                #migrate the protection domain
                Write-Host "$(get-date) [INFO] Migrating $pd2migrate to $($remoteSite.remote_site_names) ..." -ForegroundColor Green
                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                $method = "POST"
                $content = @{
                                value = $($remoteSite.remote_site_names)
                            }
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                Write-Host "$(get-date) [SUCCESS] Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)" -ForegroundColor Cyan

            }
        }
        #endregion
        
        #region -unplanned
        if ($unplanned) {

            #let's retrieve the list of protection domains from the target
            Write-Host "$(get-date) [INFO] Retrieving protection domains from target Nutanix cluster $target_cluster ..." -ForegroundColor Green
            $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from target Nutanix cluster $target_cluster" -ForegroundColor Cyan

            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are inactive.
            if (!$protection_domains) {$protection_domains = ($sourceClusterPd.entities | where {$_.active -eq $false} | select -Property name).name}

            #now let's call the activate workflow
            ForEach ($pd2activate in $protection_domains) {
                
                #activate the protection domain
                Write-Host "$(get-date) [INFO] Activating protection domain $pd2activate on $target_cluster ..." -ForegroundColor Green
                $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2activate/activate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                Write-Host "$(get-date) [SUCCESS] Successfully activated protection domain $pd2activate on $target_cluster" -ForegroundColor Cyan

            }
        }
        #endregion
    }  
    #endregion

    #region -cleanup
    if ($cleanup) {
        #region -planned
        if ($planned) {
            #let's retrieve the list of protection domains from the source
            Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan
            
            #first, we need to figure out which protection domains need to be updated. If none have been specified, we'll assume all of them.
            if (!$protection_domains) {$protection_domains = ($sourceClusterPd.entities | where {$_.active -eq $false} | select -Property name).name}

            #now let's remove the schedules
            ForEach ($pd2update in $protection_domains) {
                
                #remove all schedules from the protection domain
                Write-Host "$(get-date) [INFO] Removing all schedules from protection domain $pd2update on $source_cluster ..." -ForegroundColor Green
                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2update/schedules"
                $method = "DELETE"
                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-Host "$(get-date) [SUCCESS] Successfully removed all schedules from protection domain $pd2update on $source_cluster" -ForegroundColor Cyan

            }
        }
        #endregion
        
        #region -unplanned
        if ($unplanned) {

        }
        #endregion 
    }   
    #endregion

    #region -deactivate
    if ($deactivate) {
        #let's retrieve the list of protection domains from the target
        Write-Host "$(get-date) [INFO] Retrieving protection domains from target Nutanix cluster $target_cluster ..." -ForegroundColor Green
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