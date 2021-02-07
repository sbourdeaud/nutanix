<#
.SYNOPSIS
  This is a summary of what the script is.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\template.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 7th 2021
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
        [parameter(mandatory = $false)] [string]$prismCreds,
        [parameter(mandatory = $false)] [string]$vcenterCreds
    )
#endregion

#region functions

#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
02/07/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-metroCapacity.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

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
    if ((Get-PowerCLIConfiguration | where-object {$_.Scope -eq "User"}).InvalidCertificateAction -ne "Ignore") 
    {#ignore invalid certificates for vCenter
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

#* constants and configuration here
#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

    #* constants
    $myvar_cpu_over_subscription_ratio = 4
    $myvar_ram_over_subscription_ratio = 1
    $myvar_cvm_cpu_reservation = 0 #if this is set to 0, we'll use the sum of cvm cpu allocation
    $myvar_cvm_ram_gib_reservation = 0 #if this is set to 0, we'll use the sum of cvm ram allocation
    $myvar_hypervisor_cpu_overhead = 0 #if this is set to 0, we'll look at the replication factor, then subtract the assume biggest host(s) cpu capacity
    $myvar_hypervisor_ram_gib_overhead = 0 #if this is set to 0, we'll look at the replication factor, then subtract the assume biggest host(s) ram capacity

    #* configuration
    $myvar_smtp_server = ""
    $myvar_smtp_from = ""
    $myvar_smtp_to = ""
    $myvar_zabbix_server = ""
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
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        catch 
        {
            Set-CustomCredentials -credname $prismCreds
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }

    if ($vcenterCreds) 
    {#vcenterCreds was specified
        try 
        {
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
            $vcenterUsername = $vcenterCredentials.UserName
            $vcenterSecurePassword = $vcenterCredentials.Password
        }
        catch 
        {
            Set-CustomCredentials -credname $vcenterCreds
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
            $vcenterUsername = $vcenterCredentials.UserName
            $vcenterSecurePassword = $vcenterCredentials.Password
        }
        $vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword
    }
	else 
	{#no vcenter creds were given
		$vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
	}
#endregion

#* processing here
#region processing	
    #* retrieve information from Prism
    #region retrieve information from Prism
        #* retrieve cluster information
        #region GET cluster
            Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $($cluster) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $($cluster)" -ForegroundColor Cyan

            $myvar_ntnx_cluster_name = $myvar_ntnx_cluster_info.name
            Write-Host "$(get-date) [DATA] Nutanix cluster name is $($myvar_ntnx_cluster_name)" -ForegroundColor White
            $myvar_ntnx_cluster_rf = $myvar_ntnx_cluster_info.cluster_redundancy_state.desired_redundancy_factor
            Write-Host "$(get-date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) replication factor is $($myvar_ntnx_cluster_rf)" -ForegroundColor White

            if (($myvar_ntnx_cluster_info.hypervisor_types).count -gt 1)
            {#cluster has mixed hypervisors
                Write-Host "$(get-date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) has multiple hypervisors" -ForegroundColor White
                if ($myvar_ntnx_cluster_info.hypervisor_types -notcontains "kVMware")
                {#none of the nodes are running VMware
                    Throw "$(get-date) [ERROR] None of the cluster hosts are running VMware vSphere. Exiting!"    
                }
            }
            else 
            {#cluster has single hypervisor: let's make sure it is vmware
                if (($myvar_ntnx_cluster_info.hypervisor_types)[0] -eq "kVMware")
                {#hypervisor is vSphere
                    Write-Host "$(get-date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) is of hypervisor type $($myvar_ntnx_cluster_info.hypervisor_types[0])" -ForegroundColor White    
                }
                else 
                {#hypervisor is not vmware
                    Write-Host "$(get-date) [ERROR] Nutanix cluster $($myvar_ntnx_cluster_name) is of hypervisor type $($myvar_ntnx_cluster_info.hypervisor_types[0])" -ForegroundColor Red
                    Throw "$(get-date) [ERROR] Hypervisor is not kVMware. Exiting!"    
                }
            }

            #region figure out vcenter ip
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

            #let's make sure our current redundancy is at least 2
            if ($myvar_ntnx_cluster_info.cluster_redundancy_state.current_redundancy_factor -lt $myvar_ntnx_cluster_rf) 
            {#cluster redundancy state is < replication factor (a host must be down)
                throw "$(get-date) [ERROR] Current redundancy is less than $($myvar_ntnx_cluster_rf). Exiting."
            }
            #check if there is an upgrade in progress
            if ($myvar_ntnx_cluster_info.is_upgrade_in_progress) 
            {#cluster has an upgrade in progress
                throw "$(get-date) [ERROR] Cluster upgrade is in progress. Exiting."
            }
        #endregion
        
        #* retrieve host information
        #region GET hosts
            Write-Host "$(get-date) [INFO] Retrieving hosts information from Nutanix cluster $($myvar_ntnx_cluster_name) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_hosts = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Cyan
            
            $myvar_ntnx_cluster_hosts_ips = ($myvar_ntnx_hosts.entities).hypervisor_address
            [System.Collections.ArrayList]$myvar_ntnx_cluster_hosts_config = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_ntnx_cluster_host in $myvar_ntnx_cluster_hosts.entities)
            {#process each cluster host
                $myvar_host_config = [ordered]@{
                    "num_cpu_sockets" = $myvar_ntnx_cluster_host.num_cpu_sockets;
                    "num_cpu_cores" = $myvar_ntnx_cluster_host.num_cpu_cores;
                    "cpu_model" = $myvar_ntnx_cluster_host.cpu_model;
                    "cpu_capacity_in_hz" = $myvar_ntnx_cluster_host.cpu_capacity_in_hz;
                    "memory_capacity_in_bytes" = $myvar_ntnx_cluster_host.memory_capacity_in_bytes;
                    "hypervisor_full_name" = $myvar_ntnx_cluster_host.hypervisor_full_name;
                    "hypervisor_type" = $myvar_ntnx_cluster_host.hypervisor_type;
                    "service_vmid" = $myvar_ntnx_cluster_host.service_vmid;
                }
                #store the results for this entity in our overall result variable
                $myvar_ntnx_cluster_hosts_config.Add((New-Object PSObject -Property $myvar_host_config)) | Out-Null
            }
            if ($debugme) {$myvar_ntnx_cluster_hosts_config}
        #endregion
        
        #* retrieve storage containers information
        #region GET containers
            Write-Host "$(get-date) [INFO] Retrieving storage containers information from Nutanix cluster $($myvar_ntnx_cluster_name) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/storage_containers/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_storage_containers = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved storage containers information from Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Cyan    
        #endregion
        
        #* retrieve protection domains information
        #region GET protection_domains
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $($myvar_ntnx_cluster_name) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_pds = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Cyan

            $myvar_ntnx_cluster_ma_active_ctrs = ($myvar_ntnx_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
            $myvar_ntnx_cluster_ma_active_pds = $myvar_ntnx_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}
            if (!$myvar_ntnx_cluster_ma_active_pds)
            {#there are no active metro availability protection domains on this cluster
                Write-Host "$(get-date) [DATA] There are no active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor White
            }
            else 
            {#there are active metro availability protection domains on this cluster
                Write-Host "$(get-date) [DATA] There are $($myvar_ntnx_cluster_ma_active_pds.count) active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor White
            }
        #endregion
        
        #* retrieve vms information
        #region GET vms
            Write-Host "$(get-date) [INFO] Retrieving virtual machines from Nutanix cluster $($myvar_ntnx_cluster_name) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v1/vms/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_vms = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved virtual machines from Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Cyan
        #endregion

        #* retrieve remote site information
        #region retrieve remote site cluster information
            #region GET remote_site
                Write-Host "$(get-date) [INFO] Retrieving remote sites from Nutanix cluster $($myvar_ntnx_cluster_name) ..." -ForegroundColor Green
                $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/remote_sites/" -f $cluster
                $method = "GET"
                $myvar_ntnx_cluster_remote_sites = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved remote sites from Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Cyan

                <#
                $remote_site_name = $pd_list.remote_site | select-object -unique
                if ($remote_site_name -is [array]) 
                {#houston we have a problem: active metro pds are pointing to more than one remote site!
                    Throw "$(get-date) [ERROR] Cluster $($cluster) has metro availability protection domains which are pointing to different remote sites. Exiting."
                } 
                else 
                {
                    Write-Host "$(get-date) [DATA] Remote site name is $($remote_site_name)" -ForegroundColor White
                }
                
                #* grab ip for our remote site
                $myvar_remote_site_ip = (($myvar_remote_sites.entities | Where-Object {$_.name -eq $remote_site_name}).remote_ip_ports).psobject.properties.name
                Write-Host "$(get-date) [DATA] Remote site $($remote_site_name) ip address is $($myvar_remote_site_ip)" -ForegroundColor White

                #>
            #endregion
            
            #* retrieve remote cluster information
            #region GET remote_site cluster

            #endregion
            
            #* retrieve remote host information
            #region GET remote_site hosts

            #endregion
            
            #* retrieve remote storage containers information
            #region GET remote_site containers

            #endregion

            #* retrieve remote vms information
            #region GET remote_site vms

            #endregion
        #endregion
    #endregion

    #* retrieve information from vCenter
    #region retrieve information from vCenter
        #* connect to vCenter
        #region connect-viserver
            Write-Host "$(get-date) [INFO] Connecting to vCenter server $($myvar_vcenter_ip) ..." -ForegroundColor Green
            try 
            {#connecting to vcenter
                $myvar_vcenter_connection = Connect-VIServer -Server $myvar_vcenter_ip -Credential $vcenterCredentials -ErrorAction Stop
            }
            catch 
            {#could not connect to vcenter
                throw "$(get-date) [ERROR] Could not connect to vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully connected to vCenter server $($myvar_vcenter_ip)" -ForegroundColor Cyan    
        #endregion

        #* figure out ha/drs cluster
        #region figure out ha/drs cluster

        #endregion
        
        #* retrieve vms
        #region Get-Vm

        #endregion

        Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
    #endregion

    #* compute capacity numbers
    #region compute capacity numbers
        #* total clusters capacity (cpu/ram)
        #region total clusters capacity (cpu/ram)
            #for ntnx_cluster
            $myvar_ntnx_cluster_cpu_capacity_total = ($myvar_ntnx_cluster_hosts_config | Measure-Object num_cpu_cores -sum).Sum
            $myvar_ntnx_cluster_ram_gib_capacity_total = [math]::round(($myvar_ntnx_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -sum).Sum / 1024 / 1024 / 1024,0)
            #for ntnx_remote_site_cluster
        #endregion
        
        #* cvm reserved (cpu/ram)
        #region cvm reserved (cpu/ram)
            #for ntnx_cluster
            if (!$myvar_cvm_cpu_reservation)
            {#no specific value for $myvar_cvm_cpu_reservation, so we assume add up all cvm vcpus
                $myvar_ntnx_cluster_cvm_reserved_cpu = (($myvar_ntnx_cluster_vms.entities | Where-Object {$_.controllerVm -eq $true}) | Measure-Object numVCpus -sum).Sum
            }
            else 
            {#a value was specified for $myvar_cvm_cpu_reservation so we multiply that by the number of hosts in the cluster
                $myvar_ntnx_cluster_cvm_reserved_cpu = $myvar_cvm_cpu_reservation * ($myvar_ntnx_cluster_hosts.count)
            }
            if (!$myvar_cvm_ram_gib_reservation)
            {#no specific value for $myvar_cvm_ram_gib_reservation, so we assume add up all cvm vram
                $myvar_ntnx_cluster_cvm_reserved_ram = [math]::round((($myvar_ntnx_cluster_vms.entities | Where-Object {$_.controllerVm -eq $true}) | Measure-Object memoryCapacityInBytes -sum).Sum /1024/1024/1024,0)
            }
            else 
            {#a value was specified for $myvar_cvm_ram_gib_reservation so we multiply that by the number of hosts in the cluster
                $myvar_ntnx_cluster_cvm_reserved_ram = [math]::round($myvar_cvm_cpu_reservation * ($myvar_ntnx_cluster_hosts.count) /1024/1024/1024,0)
            }
            #for ntnx_remote_site_cluster
        #endregion
        
        #! resume coding effort here
        #* hypervisor overhead (cpu/ram)
        #for ntnx_cluster
        #for ntnx_remote_site_cluster

        #* uvm clusters capacity (cpu/ram)
        #for ntnx_cluster
        #for ntnx_remote_site_cluster

        #* uvm allocated (cpu/ram)
        #for ntnx_cluster
        #for ntnx_remote_site_cluster

        #* metro uvm allocated (cpu/ram)
        #for ntnx_cluster
        #for ntnx_remote_site_cluster

        #* uvm remaining (cpu/ram)
        #for ntnx_cluster
        #for ntnx_remote_site_cluster
    #endregion

    #* create output
    #region create output
        #* html output
        #region html output

        #endregion
        
        #* console output
        #region console output
            Write-Host "$(get-date) [DATA] Total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cpu_capacity_total) cores" -ForegroundColor White
            Write-Host "$(get-date) [DATA] Total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ram_gib_capacity_total) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] CVM CPU reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_cpu)" -ForegroundColor White
            Write-Host "$(get-date) [DATA] CVM RAM reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_ram) GiB" -ForegroundColor White
        #endregion

        #* smtp output
        #region smtp output
            
        #endregion

        #* zabbix output
        #region zabbix output
            
        #endregion
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion