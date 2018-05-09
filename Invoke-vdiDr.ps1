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
    [parameter(mandatory = $false)] $target_pg,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] [string]$referentialPath,
    [parameter(mandatory = $false)] $protection_domains,
    [parameter(mandatory = $false)] $desktop_pools
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
        #load pool2pd reference
        try {$poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"}

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
        catch{throw "$(get-date) [ERROR] Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"}
        Write-Host "$(get-date) [SUCCESS] Connected to the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
        #create API object
        $source_hvObjectAPI = $source_hvObject.ExtensionData
        
        [System.Collections.ArrayList]$newHvRef = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect new information from the system (vm name, assigned ad username, desktop pool name, vm folder, portgroup)

        #extract desktop pools
        Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
        Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
        
        #map the user id to a username
        Write-Host "$(get-date) [INFO] Retrieving Active Directory user information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        $source_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $source_hvObjectAPI
        Write-Host "$(get-date) [SUCCESS] Retrieved Active Directory user information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

        #extract Virtual Machines summary information
        Write-Host "$(get-date) [INFO] Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
        $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
        Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
        
        #figure out the info we need for each VM (VM name, user, desktop pool name)
        ForEach ($vm in $source_hvVMs.Results) { #let's process each vm
            #figure out the vm assigned username
            $hvADUsers = $source_hvADUsers #save the ADUsers query results as this is a paginated result and we need to search a specific user
            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService" #we'll use this object to retrieve other pages from the ADUsers request
            while ($hvADUsers.Results -ne $null) { #start a loop to look at each page of the ADUsers query results
                if (!($vmUsername = ($hvADUsers.Results | where {$_.Id.Id -eq $vm.Base.User.Id}).Base.DisplayName)) { #grab the user name whose id matches the id of the assigned user on the desktop machine
                    #couldn't find our userId, let's fetch the next page of AD objects
                    if ($hvADUsers.id -eq $null) {break}
                    try {$hvADUsers = $serviceQuery.QueryService_GetNext($source_hvObjectAPI,$hvADUsers.id)}
                    catch{throw "$(get-date) [ERROR] $($_.Exception.Message)"}
                } else {break} #we found our user, let's get out of this loop
            }

            #figure out the desktop pool name
            $vmDesktopPool = ($source_hvDesktopPools.Results | where {$_.Id.Id -eq $vm.Base.Desktop.Id}).DesktopSummaryData.Name

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
        catch {throw "$(get-date) [ERROR] Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"}
        Write-Host "$(get-date) [SUCCESS] Connected to SOURCE vCenter server $source_vc" -ForegroundColor Cyan

        [System.Collections.ArrayList]$newVcRef = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect new information from the system (vm name, assigned ad username, desktop pool name, vm folder, portgroup)

        #process each vm and figure out the folder and portgroup name
        ForEach ($vm in $newHvRef) {
            Write-Host "$(get-date) [INFO] Retrieving VM $($vm.vmName) ..." -ForegroundColor Green
            try{$vmObject = Get-VM $vm.vmName -ErrorAction Stop} catch{throw "$(get-date) [ERROR] Could not retrieve VM $($vm.vmName) : $($_.Exception.Message)"}
            Write-Host "$(get-date) [INFO] Retrieving portgroup name for VM $($vm.vmName) ..." -ForegroundColor Green
            try {$vmPortGroup = ($vmObject | Get-NetworkAdapter -ErrorAction Stop).NetworkName} catch {throw "$(get-date) [ERROR] Could not retrieve portgroup name for VM $($vm.vmName) : $($_.Exception.Message)"}
            if ($vmPortGroup -is [array]) {
                $vmPortGroup = $vmPortGroup | Select -First 1
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
        $newPrismRef = $sourceClusterPd.entities | where {$_.active -eq $true} | select -Property name,vms
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan
        #endregion

        #region update reference files and figure out which vms need to be added/removed to protection domain(s)

        #compare reference file with pool & pd content
        #foreach vm in hv, find out if it is already in the right protection domain, otherwise, add it to the list of vms to add to that pd
        [System.Collections.ArrayList]$vms2Add = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect which vms need to be added to which protection domain
        ForEach ($vm in $newHvRef) {
            #figure out which protection domain this vm should be based on its current desktop pool and the assigned protection domain for that pool
            $assignedPd = ($poolRef | where {$_.desktop_pool -eq $vm.desktop_pool}).protection_domain
            if (!$assignedPd) {Write-Host "$(get-date) [WARNING] : Could not process protection domain addition for VM $($vm.vmName) because there is no assigned protection domain defined in $referentialPath\poolRef.csv for $($vm.desktop_pool)!"  -ForegroundColor Yellow}
            else {
                #now find out if that vm is already in that protection domain
                if (!($newPrismRef | where {$_.name -eq $assignedPd} | where {$_.vms.vm_name -eq $vm.vmName})) {
                    $vmInfo = @{"vmName" = $vm.vmName;"protection_domain" = $assignedPd}
                    #add vm to name the list fo vms to add to that pd
                    $result = $vms2Add.Add((New-Object PSObject -Property $vmInfo))
                }
            }
        }
        
        #foreach protection domain, figure out if there are vms which are no longer in horizon view and which need to be removed from the protection domain
        [System.Collections.ArrayList]$vms2Remove = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect which vms need to be removed from which protection domain
        #$vmNames2remove = $newHvRef.vmname | where {($newPrismRef | where {$poolRef.protection_domain -Contains $_.name}).vms.vm_name -notcontains $_} #figuring out which vms are in a protection domain in Prism which has a mapping but are no longer in view
        $protectedVMs = ($newPrismRef | where {$poolRef.protection_domain -Contains $_.name}).vms.vm_name
        $vmNames2remove = $protectedVMs | where {$newHvRef.vmname -notcontains $_}
        ForEach ($vm in $vmNames2remove) { #process each vm identified above
            $pd = (($newPrismRef | where {$poolRef.protection_domain -Contains $_.name}) | where {$_.vms.vm_name -eq $vmNames2remove}).name
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

        #load pool2pd reference
        try {$poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"}
        #load old references
        If (Test-Path -Path ("$referentialPath\hvRef.csv")) {
            try {$oldHvRef = Import-Csv -Path ("$referentialPath\hvRef.csv") -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not import data from $referentialPath\hvRef.csv : $($_.Exception.Message)"}
        }
        If (Test-Path -Path ("$referentialPath\vcRef.csv")) {
            try {$oldVcRef = Import-Csv -Path ("$referentialPath\vcRef.csv") -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not import data from $referentialPath\vcRef.csv : $($_.Exception.Message)"}
        }

        #region -planned
        if ($planned) { #we're doing a planned failover
            
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
            catch{throw "$(get-date) [ERROR] Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Connected to the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
            #create API object
            $source_hvObjectAPI = $source_hvObject.ExtensionData
            
            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan
        
            #map the user id to a username
            Write-Host "$(get-date) [INFO] Retrieving Active Directory user information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            $source_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $source_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved Active Directory user information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #extract Virtual Machines summary information
            Write-Host "$(get-date) [INFO] Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv" -ForegroundColor Cyan

            #find out which pool we are working with (assume all which are disabled if none have been specified)
            if (!$desktop_pools) {
                if ($protection_domains) { #no pool was specified, but one or more protection domain(s) was/were, so let's match those to desktop pools using the reference file
                    $desktop_pools = @()
                    ForEach ($protection_domain in $protection_domains) {
                        $desktop_pools += ($poolRef | where {$_.protection_domain -eq $protection_domain}).desktop_pool
                    }
                    $disabled_desktop_pools = $source_hvDesktopPools.Results | where {$_.DesktopSummaryData.Enabled -eq $false}
                    $desktop_pools = $disabled_desktop_pools | where {$desktop_pools -contains $_.DesktopSummaryData.Name}
                } else { #no pd and no pool were specified, so let's assume we have to process all disabled pools
                    $desktop_pools = $source_hvDesktopPools.Results | where {$_.DesktopSummaryData.Enabled -eq $false}
                }
            } else { #extract the desktop pools information
                $disabled_desktop_pools = $source_hvDesktopPools.Results | where {$_.DesktopSummaryData.Enabled -eq $false}
                $desktop_pools = $disabled_desktop_pools | where {$desktop_pools -contains $_.DesktopSummaryData.Name}
            }

            if (!$desktop_pools) {
                throw "$(get-date) [ERROR] There are no desktop pool(s) to process on SOURCE horizon view server $source_hv!"
            }

            #process each desktop pool
            $poolProcessed = $false
            ForEach ($desktop_pool in $desktop_pools) {
                #check that the pool is disabled
                if ($desktop_pool.DesktopSummaryData.Enabled -eq $true) {Write-Host "$(get-date) [WARNING] Skipping $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv because the desktop pool is enabled" -ForegroundColor Yellow; continue}
                #figure out which machines are in that desktop pool
                $vms = $source_hvVMs.Results | where {$_.Base.Desktop.id -eq $desktop_pool.Id.Id}
                #remove machines from the desktop pool
                if ($vms -is [array]) {#we use different methods based on the number of vms in the pool
                    Write-Host "$(get-date) [INFO] Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..." -ForegroundColor Green
                    try {$result = $source_hvObjectAPI.Machine.Machine_DeleteMachines($vms.Id,$null)} catch {throw "$(get-date) [ERROR] Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"}
                    Write-Host "$(get-date) [SUCCESS] Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv" -ForegroundColor Cyan
                    $poolProcessed = $true
                } else {
                    if ($vms -ne $null) {#there is only a single vm in the pool to remove, so we use a different method
                        Write-Host "$(get-date) [INFO] Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..." -ForegroundColor Green
                        try {$result = $source_hvObjectAPI.Machine.Machine_Delete($vms.Id,$null)} catch {throw "$(get-date) [ERROR] Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"}
                        Write-Host "$(get-date) [SUCCESS] Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv" -ForegroundColor Cyan
                        $poolProcessed = $true
                    } else {#there were no vms in the pool
                        Write-Host "$(get-date) [WARNING] There were no vms to remove from pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv!" -ForegroundColor Yellow
                    }
                }
            }

            if (!$poolProcessed) {throw "$(get-date) [ERROR] There were no disabled desktop pools with VMs in their inventory. Stopping execution here."}

            #save the desktop pool names we processed for later
            $desktop_pool_names = $desktop_pools.DesktopSummaryData.Name

            #diconnect from the source view server
            Disconnect-HVServer * -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the SOURCE Horizon View server $source_hv..." -ForegroundColor Green
            #endregion

            #region deal with the source Prism bits
            #let's retrieve the list of protection domains from the source
            Write-Host "$(get-date) [INFO] Retrieving protection domains from source Nutanix cluster $source_cluster ..." -ForegroundColor Green
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from source Nutanix cluster $source_cluster" -ForegroundColor Cyan
            
            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
            if (!$protection_domains) {
                if ($desktop_pools) { #no protection domain was specified, but one or more dekstop pool(s) was/were, so let's match to protection domains using the reference file
                    $protection_domains = @()
                    ForEach ($desktop_pool in $desktop_pools) {
                        $protection_domains += ($poolRef | where {$_.desktop_pool -eq $desktop_pool.DesktopSummaryData.Name}).protection_domain
                    }
                    $activeProtectionDomains = ($sourceClusterPd.entities | where {$_.active -eq $true} | select -Property name).name
                    $protection_domains = $activeProtectionDomains | where {$protection_domains -contains $_}
                } else { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains
                    $protection_domains = ($sourceClusterPd.entities | where {$_.active -eq $true} | select -Property name).name
                }
            }

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

            #let's make sure all protection domain migrations have been processed successfully
            #retrieve the list of tasks in the cluster
            Write-Host "$(get-date) [INFO] Retrieving list of tasks on the SOURCE cluster $source_cluster ..." -ForegroundColor Green
            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Retrieved list of tasks on the SOURCE cluster $source_cluster" -ForegroundColor Cyan
            #select only the tasks of operation type "deactivate" which were created after this script was started
            $pdMigrateTasks = $response.entities | where {$_.operation -eq "deactivate"} | where {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
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
                        $task = $response.entities | where {$_.taskName -eq $pdMigrateTask.taskName} | where {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                        if ($task.status -ne "running") {
                            if ($task.status -ne "succeeded") {
                                throw "$(get-date) [ERROR] Task $($pdMigrateTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)"
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

            #endregion

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
            catch {throw "$(get-date) [ERROR] Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Connected to SOURCE vCenter server $source_vc" -ForegroundColor Cyan

            #remove orphaned entries from SOURCE vCenter
            #our reference point is the desktop pool, so let's process vms in each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | where {$_.desktop_pool -eq $desktop_pool}
                #process all vms for that desktop pool
                ForEach ($vm in $vms) {
                    Write-Host "$(get-date) [INFO] Removing $($vm.vmName) from inventory in $source_vc ..." -ForegroundColor Green
                    try {$result = Get-VM -Name $vm.vmName | where {$_.ExtensionData.Summary.OverallStatus -eq 'gray'} | remove-vm -Confirm:$false} catch {throw "$(get-date) [ERROR] Could not remove VM $($vm.vmName): $($_.Exception.Message)"}
                    Write-Host "$(get-date) [SUCCESS] Removed $($vm.vmName) from inventory in $source_vc." -ForegroundColor Cyan
                }
            }

            #diconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from SOURCE vCenter server $source_vc..." -ForegroundColor Green
		    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
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
            catch {throw "$(get-date) [ERROR] Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Connected to TARGET vCenter server $target_vc" -ForegroundColor Cyan
            
            #our reference point is the desktop pool, so let's process vms in each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | where {$_.desktop_pool -eq $desktop_pool}
                #process all vms for that desktop pool
                $dvPortgroups = Get-VDPortGroup | where {$_.IsUplink -eq $false} #retrieve distributed portgroup names in the target infrastructure which are not uplinks
                ForEach ($vm in $vms) {
                    #move vms to their correct folder
                    $folder = Get-Folder -Name (($oldVcRef | where {$_.vmName -eq $vm.vmName}).folder) #figure out which folder this vm was in and move it
                    Write-Host "$(get-date) [INFO] Trying to move $($vm.vmName) to folder $($folder.Name)..." -ForegroundColor Green
                    try {
                        $vmObject = Get-VM -Name $vm.vmName -ErrorAction Stop
                        if ($vmObject.Folder.Name -ne $folder.Name) {
                            $result = $vmObject | Move-VM -InventoryLocation $folder -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] Moved $($vm.vmName) to folder $($folder.Name)" -ForegroundColor Cyan
                        } else {
                            Write-Host "$(get-date) [INFO] VM $($vm.vmName) is already in folder $($folder.Name)" -ForegroundColor Green
                        }
                    }
                    catch {throw "$(get-date) [ERROR] Could not move $($vm.vmName) to folder $($folder.Name) : $($_.Exception.Message)"}
                    
                    #connect vms to the portgroup
                    Write-Host "$(get-date) [INFO] Re-connecting the virtual machine $($vm.vmName) virtual NIC..." -ForegroundColor Green
                    try {
                         if (!$target_pg) {#no target portgroup has been specified, so we need to figure out where to connect our vnics
                            $standard_portgroup = $false
                            Write-Host "$(get-date) [WARNING] No target portgroup was specified, figuring out which one to use..." -ForegroundColor Yellow
                            #first we'll see if there is a portgroup with the same name in the target infrastructure
                            $vmPortgroup = ($oldVcRef | where {$_.vmName -eq $vm.vmName}).portgroup #retrieve the portgroup name at the source for this vm
                            $portgroups = $vmObject | Get-VMHost | Get-VirtualPortGroup -Standard #retrieve portgroup names in the target infrastructure on the VMhost running that VM
                            $vSwitch0_portGroups = ($vmObject | Get-VMHost | Get-VirtualSwitch -Name "vSwitch0" | Get-VirtualPortGroup -Standard) # get portgroups only on vSwitch0
                            if ($target_pgObject = $dvPortgroups | where {$_.Name -eq $vmPortGroup}) {
                                Write-Host "$(get-date) [INFO] There is a matching distributed portgroup $($target_pgObject.Name) which will be used." -ForegroundColor Green
                            } elseIf ($target_pgObject = $portgroups | where {$_.Name -eq $vmPortGroup}) {
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
                            try {$target_pgObject = Get-VirtualPortGroup -Name $target_pg} catch {throw "$(get-date) [ERROR] Could not retrieve the specified target portgroup : $($_.Exception.Message)"}
                            if ($target_pgObject -is [array]) {throw "$(get-date) [ERROR] There is more than one portgroup with the specified name!"}
                            Write-Host "$(get-date) [SUCCESS] Retrieved the specified target portgroup $target_pg" -ForegroundColor Cyan
                         }
                         #now that we know which portgroup to connect the vm to, let's connect its vnic to that portgroup
                         if (!$standard_portgroup) {
                            $result = $vmObject | Get-NetworkAdapter -ErrorAction Stop | Select -First 1 |Set-NetworkAdapter -NetworkName $target_pgObject.Name -Confirm:$false -ErrorAction Stop
                         }
                    }
                    catch {throw "$(get-date) [ERROR] Could not reconnect $($vm.vmName) to the network : $($_.Exception.Message)"}
                    if (!$standard_portgroup) {Write-Host "$(get-date) [SUCCESS] Re-connected the virtual machine $($vm.vmName) to the network $($target_pgObject.Name)" -ForegroundColor Cyan} else {Write-Host "$(get-date) [INFO] Virtual machine $($vm.vmName) is already connected to an existing standard portgroup, so skipping reconnection..." -ForegroundColor Green}
                }
            }
            
            #diconnect from vCenter
            Write-Host "$(get-date) [INFO] Disconnecting from TARGET vCenter server $target_vc..." -ForegroundColor Green
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
            catch {throw "$(get-date) [ERROR] Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Connected to the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
            #create API object
            $target_hvObjectAPI = $target_hvObject.ExtensionData
            
            #retrieve basic information we'll need
            #retrieve the vCenter object
            $target_hvVirtualCenter = $target_hvObjectAPI.VirtualCenter.VirtualCenter_List() | where {$_.Enabled -eq $true}
            if ($target_hvVirtualCenter -is [array]) {throw "$(get-date) [ERROR] There is more than one enabled vCenter on $target_hv!"}
            #retrieve the list of available vms in vCenter
            $target_hvAvailableVms = $target_hvObjectAPI.VirtualMachine.VirtualMachine_List($target_hvVirtualCenter.Id)
            #extract desktop pools
            Write-Host "$(get-date) [INFO] Retrieving desktop pools information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            $target_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $target_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved desktop pools information from the TARGET Horizon View server $target_hv." -ForegroundColor Cyan
            #extract Active Directory users & groups
            Write-Host "$(get-date) [INFO] Retrieving Active Directory user information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            $target_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $target_hvObjectAPI
            Write-Host "$(get-date) [SUCCESS] Retrieved Active Directory user information from the TARGET Horizon View server $target_hv." -ForegroundColor Cyan

            #process each desktop pool
            ForEach ($desktop_pool in $desktop_pool_names) {
                #figure out the desktop pool Id
                $desktop_poolId = ($target_hvDesktopPools.Results | where {$_.DesktopSummaryData.Name -eq $desktop_pool}).Id
                #determine which vms belong to the desktop pool(s) we are processing
                $vms = $oldHvRef | where {$_.desktop_pool -eq $desktop_pool}
                
                #add vms to the desktop pools
                if ($vms) {
                    #process all vms for that desktop pool
                    #we start by building the list of vms to add to the pool (this will be more efficient than adding them one by one)
                    $vmIds = @()
                    ForEach ($vm in $vms) {
                        #figure out the virtual machine id
                        $vmId = ($target_hvAvailableVms | where {$_.Name -eq $vm.vmName}).Id
                        $vmIds += $vmId
                    }

                    Write-Host "$(get-date) [INFO] Adding virtual machines to desktop pool $desktop_pool..." -ForegroundColor Green
                    try {$result = $target_hvObjectAPI.Desktop.Desktop_AddMachinesToManualDesktop($desktop_poolId,$vmIds)} catch {throw "$(get-date) [ERROR] Could not add virtual machines to desktop pool $desktop_pool : $($_.Exception.Message)"}
                    Write-Host "$(get-date) [SUCCESS] Added virtual machines to desktop pool $desktop_pool." -ForegroundColor Cyan

                    #register users to their vms
                    ForEach ($vm in $vms) {
                        #figure out the object id of the assigned user
                        if ($vm.assignedUser) {#process the assigned user if there was one
                            #retrieve the list of machines now registered in the TARGET Horizon View server (we need their ids)
                            #extract Virtual Machines summary information
                            Write-Host "$(get-date) [INFO] Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
                            Sleep 15
                            $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                            Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
                            
                            #figure out the virtual machine id
                            while (!($vmId = ($target_hvVMs.Results | where {$_.Base.Name -eq $vm.vmName}).Id)) {
                                Write-Host "$(get-date) [INFO] Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
                                Sleep 15
                                $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                                Write-Host "$(get-date) [SUCCESS] Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
                            }

                            $hvADUsers = $target_hvADUsers #save the ADUsers query results as this is a paginated result and we need to search a specific user
                            $serviceQuery = New-Object "Vmware.Hv.QueryServiceService" #we'll use this object to retrieve other pages from the ADUsers request
                            while ($hvADUsers.Results -ne $null) { #start a loop to look at each page of the ADUsers query results
                                if (!($vmUserId = ($hvADUsers.Results | where {$_.Base.DisplayName -eq $vm.assignedUser}).Id)) { #grab the user name whose id matches the id of the assigned user on the desktop machine
                                    #couldn't find our userId, let's fetch the next page of AD objects
                                    if ($hvADUsers.id -eq $null) {break}
                                    try {$hvADUsers = $serviceQuery.QueryService_GetNext($target_hvObjectAPI,$hvADUsers.id)}
                                    catch {throw "$(get-date) [ERROR] $($_.Exception.Message)"}
                                } else {break} #we found our user, let's get out of this loop
                            }
                            if (!$vmUserId) {Write-Host "$(get-date) [ERROR] Could not find a matching Active Directory object for user $($vm.AssignedUser) for VM $($vm.vmName)!" -ForegroundColor Red; continue}   
                            #create the MapEntry object required for updating the machine
                            $MapEntry = New-Object "Vmware.Hv.MapEntry"
                            $MapEntry.key = "base.user"
                            $MapEntry.value = $vmUserId
                            #update the machine
                            Write-Host "$(get-date) [INFO] Updating assigned user for $($vm.vmName)..." -ForegroundColor Green
                            try {$result = $target_hvObjectAPI.Machine.Machine_Update($vmId,$MapEntry)} catch {throw "$(get-date) [ERROR] Could not update assigned user to $($vm.vmName) : $($_.Exception.Message)"}
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
        
        #region -unplanned
        if ($unplanned) {
            #region deal with the target Prism bits
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
            catch {throw "$(get-date) [ERROR] Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Connected to TARGET vCenter server $target_vc" -ForegroundColor Cyan
            
            #move vms to their correct folder
            #connect vms to the portgroup
            
            #diconnect from vCenter
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
            catch{throw "$(get-date) [ERROR] Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"}
            Write-Host "$(get-date) [SUCCESS] Connected to the TARGET Horizon View server $target_hv" -ForegroundColor Cyan
            #create API object
            $target_hvObjectAPI = $target_hvObject.ExtensionData
            
            #add vms to the desktop pools
            
            #register users to their vms
            
            #disconnect from the target view server
            Disconnect-HVServer -Confirm:$false
            Write-Host "$(get-date) [INFO] Disconnected from the TARGET Horizon View server $target_hv..." -ForegroundColor Green
            #endregion
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