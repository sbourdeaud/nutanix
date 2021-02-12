<#
.SYNOPSIS
  This script retrieves allocated compute capacity information from a Nutanix cluster and produces an interactive html report.
.DESCRIPTION
  Report will show remaining UVM capacity in a color coded output. Report configuration settings can be customized in the variables region.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER html
  Produces an html output in addition to console output.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\get-UvmCapacity.ps1 -cluster ntnxc1.local
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
        [parameter(mandatory = $false)] [switch]$html,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] [string]$prismCreds
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
    $myvarScriptName = ".\get-UvmCapacity.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

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

    #region module PSWriteHTML
    if ($html)
    {#we need html output, so let's load the PSWriteHTML module
        if (!(Get-Module -Name PSWriteHTML)) 
        {#we could not get the module, let's try to load it
            try
            {#import the module
                Import-Module -Name PSWriteHTML -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
            }#end try
            catch 
            {#we couldn't import the module, so let's install it
                Write-Host "$(get-date) [INFO] Installing module 'PSWriteHTML' from the Powershell Gallery..." -ForegroundColor Green
                try {Install-Module -Name PSWriteHTML -Scope CurrentUser -Force -ErrorAction Stop}
                catch {throw "$(get-date) [ERROR] Could not install module 'PSWriteHTML': $($_.Exception.Message)"}

                try
                {#now that it is intalled, let's import it
                    Import-Module -Name PSWriteHTML -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
                }#end try
                catch 
                {#we couldn't import the module
                    Write-Host "$(get-date) [ERROR] Unable to import the module PSWriteHTML.psm1 : $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/PSWriteHTML/0.0.132" -ForegroundColor Yellow
                    Exit
                }#end catch
            }#end catch
        }
    }
    #endregion
#endregion

#todo: color code output when remaining capacity is too small
#todo: look into sending metrics to influxdb using REST (https://github.com/markwragg/Powershell-Influx)
#* constants and configuration here
#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

    #* constants
    $myvar_cpu_over_subscription_ratio = 4
    $myvar_ram_over_subscription_ratio = 1
    $myvar_cvm_cpu_reservation = 4 #if this is set to 0, we'll use the sum of cvm cpu allocation, otherwise this number will be used on a per host basis
    $myvar_cvm_ram_gib_reservation = 0 #if this is set to 0, we'll use the sum of cvm ram allocation, otherwise this number will be used on a per host basis
    $myvar_hypervisor_cpu_overhead = 1 #this is on a per host basis
    $myvar_hypervisor_ram_gib_overhead = 4 #this is on a per host basis
    $myvar_desired_capacity_headroom_percentage = 10 #this is a percentage of UVM total capacity that you want available at all times. Report will alert if this is not currently met.

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
#endregion

#* processing here
#region processing	
    #* retrieve information from Prism
    Write-Host "$(get-date) [STEP] Retrieving information from Nutanix cluster $($cluster)..." -ForegroundColor Magenta
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

            if (($myvar_ntnx_cluster_info.hypervisor_types).count -gt 1)
            {#cluster has mixed hypervisors
                Write-Host "$(get-date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) has multiple hypervisors" -ForegroundColor White
                if ($myvar_ntnx_cluster_info.hypervisor_types -notcontains "kVMware")
                {#none of the nodes are running VMware
                    Throw "$(get-date) [ERROR] None of the cluster hosts are running VMware vSphere. Exiting!"    
                }
            }
            else 
            {#cluster has single hypervisor
                Write-Host "$(get-date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) is of hypervisor type $($myvar_ntnx_cluster_info.hypervisor_types[0])" -ForegroundColor White
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
                if (!$myvar_vcenter_ip) {Write-Host "$(get-date) [WARNING] vCenter registration is not done in Prism for cluster $cluster!" -ForegroundColor Yellow}
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
            
            #$myvar_ntnx_cluster_hosts_ips = ($myvar_ntnx_hosts.entities).hypervisor_address
            [System.Collections.ArrayList]$myvar_ntnx_cluster_hosts_config = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_ntnx_cluster_host in $myvar_ntnx_cluster_hosts.entities)
            {#process each cluster host
                $myvar_host_config = [ordered]@{
                    "name" = $myvar_ntnx_cluster_host.name;
                    "block_model_name" = $myvar_ntnx_cluster_host.block_model_name;
                    "hypervisor_type" = $myvar_ntnx_cluster_host.hypervisor_type;
                    "hypervisor_full_name" = $myvar_ntnx_cluster_host.hypervisor_full_name;
                    "cpu_model" = $myvar_ntnx_cluster_host.cpu_model;
                    "num_cpu_sockets" = $myvar_ntnx_cluster_host.num_cpu_sockets;
                    "num_cpu_cores" = $myvar_ntnx_cluster_host.num_cpu_cores;
                    "memory_capacity_in_GiB" = [math]::round($myvar_ntnx_cluster_host.memory_capacity_in_bytes /1024 /1024 /1024,0);
                    "hypervisor_ip" = $myvar_ntnx_cluster_host.hypervisor_address;
                    "ipmi_address" = $myvar_ntnx_cluster_host.ipmi_address;
                    "cpu_capacity_in_hz" = $myvar_ntnx_cluster_host.cpu_capacity_in_hz;
                    "memory_capacity_in_bytes" = $myvar_ntnx_cluster_host.memory_capacity_in_bytes;
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

            #! for testing purposes
            $myvar_ntnx_cluster_ma_active_ctrs_names = "steph-test"
            #$myvar_ntnx_cluster_ma_active_ctrs_names = ($myvar_ntnx_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
            
            [System.Collections.ArrayList]$myvar_ntnx_cluster_ma_active_ctrs = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_ntnx_cluster_ma_active_ctr in $myvar_ntnx_cluster_ma_active_ctrs_names)
            {#figure out the uuid of each active metro enabled storage container
                $myvar_ntnx_cluster_ma_active_ctr_info = [ordered]@{
                    "name" = $myvar_ntnx_cluster_ma_active_ctr;
                    "uuid" = ($myvar_ntnx_cluster_storage_containers.entities | Where-Object {$_.name -eq $myvar_ntnx_cluster_ma_active_ctr}).storage_container_uuid;
                    "user_free_bytes" = ($myvar_ntnx_cluster_storage_containers.entities | Where-Object {$_.name -eq $myvar_ntnx_cluster_ma_active_ctr}).usage_stats.storage.user_free_bytes;
                }
                #store the results for this entity in our overall result variable
                $myvar_ntnx_cluster_ma_active_ctrs.Add((New-Object PSObject -Property $myvar_ntnx_cluster_ma_active_ctr_info)) | Out-Null
            }

            $myvar_ntnx_cluster_ma_active_pds = $myvar_ntnx_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}
            if (!$myvar_ntnx_cluster_ma_active_pds)
            {#there are no active metro availability protection domains on this cluster
                Write-Host "$(get-date) [WARNING] There are no active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Yellow
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

            $myvar_ntnx_cluster_cvms = $myvar_ntnx_cluster_vms.entities | Where-Object {$_.controllerVm -eq $true}
            $myvar_ntnx_cluster_uvms = $myvar_ntnx_cluster_vms.entities | Where-Object {$_.controllerVm -eq $false} | Where-Object {$_.powerState -eq "on"}

            #building list of uvms
            [System.Collections.ArrayList]$myvar_ntnx_cluster_uvms_info = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_ntnx_cluster_uvm in $myvar_ntnx_cluster_uvms)
            {#collect specific information for each UVM
                $myvar_ntnx_cluster_uvm_info = [ordered]@{
                    "vm_name" = $myvar_ntnx_cluster_uvm.vmName;
                    "numVCpus" = $myvar_ntnx_cluster_uvm.numVCpus;
                    "memoryCapacityInGiB" = [math]::round($myvar_ntnx_cluster_uvm.memoryCapacityInBytes /1024 /1024 /1024,0);
                    "host" = $myvar_ntnx_cluster_uvm.hostName;
                    "container_name" = ($myvar_ntnx_cluster_storage_containers.entities | Where-Object {$_.storage_container_uuid -eq $myvar_ntnx_cluster_uvm.containerUuids[0]}).name;
                    "diskCapacityInGiB" = [math]::round($myvar_ntnx_cluster_uvm.diskCapacityInBytes /1024 /1024 /1024,0);
                    "protectionType" = $myvar_ntnx_cluster_uvm.protectionType;
                    "protectionDomainName" = $myvar_ntnx_cluster_uvm.protectionDomainName;
                }
                #store the results for this entity in our overall result variable
                $myvar_ntnx_cluster_uvms_info.Add((New-Object PSObject -Property $myvar_ntnx_cluster_uvm_info)) | Out-Null
            }

            #figure out which uvms are metro protected
            [System.Collections.ArrayList]$myvar_ntnx_cluster_ma_uvms = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_ntnx_cluster_ma_active_ctr in $myvar_ntnx_cluster_ma_active_ctrs)
            {#collect VMs in each MA enabled container
                $myvar_ntnx_cluster_ma_active_ctr_uvms = $myvar_ntnx_cluster_uvms | Where-Object {$_.containerUuids -contains $myvar_ntnx_cluster_ma_active_ctr.uuid}
                ForEach ($myvar_ntnx_cluster_ma_active_ctr_uvm in $myvar_ntnx_cluster_ma_active_ctr_uvms)
                {#collect specific information for each UVM
                    $myvar_ntnx_cluster_ma_active_ctr_uvm_info = [ordered]@{
                        "vm_name" = $myvar_ntnx_cluster_ma_active_ctr_uvm.vmName;
                        "numVCpus" = $myvar_ntnx_cluster_ma_active_ctr_uvm.numVCpus;
                        "memoryCapacityInGiB" = [math]::round($myvar_ntnx_cluster_ma_active_ctr_uvm.memoryCapacityInBytes /1024 /1024 /1024,0);
                        "host" = $myvar_ntnx_cluster_ma_active_ctr_uvm.hostName;
                        "container_name" = $myvar_ntnx_cluster_ma_active_ctr.name;
                        "memoryCapacityInBytes" = $myvar_ntnx_cluster_ma_active_ctr_uvm.memoryCapacityInBytes;
                        "container_uuid" = $myvar_ntnx_cluster_ma_active_ctr.uuid;
                    }
                    #store the results for this entity in our overall result variable
                    $myvar_ntnx_cluster_ma_uvms.Add((New-Object PSObject -Property $myvar_ntnx_cluster_ma_active_ctr_uvm_info)) | Out-Null
                }
            }
        #endregion

        #todo: retrieve remote site information
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
            
            #todo: retrieve remote cluster information
            #region GET remote_site cluster

            #endregion
            
            #todo: retrieve remote host information
            #region GET remote_site hosts

            #endregion
            
            #todo: retrieve remote storage containers information
            #region GET remote_site containers

            #endregion

            #todo: retrieve remote vms information
            #region GET remote_site vms

            #endregion
        #endregion
    #endregion
    Write-Host ""

    Write-Host "$(get-date) [STEP] Computing numbers..." -ForegroundColor Magenta
    #* compute capacity numbers
    #region compute capacity numbers
        #* total clusters capacity (cpu/ram)
        #region total clusters capacity (cpu/ram)
            #for ntnx_cluster
            $myvar_ntnx_cluster_hosts_config |  ForEach-Object {$myvar_ntnx_cluster_cpu_capacity_total += $_.num_cpu_sockets * $_.num_cpu_cores}
            $myvar_ntnx_cluster_ram_gib_capacity_total = [math]::round(($myvar_ntnx_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -sum).Sum / 1024 / 1024 / 1024,0)
            #todo: for ntnx_remote_site_cluster
        #endregion
        
        #* compute number of nodes to take out based on high availability (which is based on RF)
        #for ntnx_cluster
        $myvar_ntnx_cluster_ha_reserved_hosts = $myvar_ntnx_cluster_rf - 1
        $myvar_ntnx_cluster_ha_available_hosts = ($myvar_ntnx_cluster_hosts.entities).count - $myvar_ntnx_cluster_ha_reserved_hosts
        #todo: for ntnx_remote_site_cluster

        #* cvm reserved (cpu/ram)
        #region cvm reserved (cpu/ram)
            #for ntnx_cluster
            if (!$myvar_cvm_cpu_reservation)
            {#no specific value for $myvar_cvm_cpu_reservation, so we assume add up all cvm vcpus
                $myvar_ntnx_cluster_cvm_reserved_cpu = ($myvar_ntnx_cluster_cvms | Measure-Object numVCpus -sum).Sum - ($myvar_ntnx_cluster_cvms | Measure-Object numVCpus -Maximum).Maximum * $myvar_ntnx_cluster_ha_reserved_hosts
            }
            else 
            {#a value was specified for $myvar_cvm_cpu_reservation so we multiply that by the number of hosts in the cluster
                $myvar_ntnx_cluster_cvm_reserved_cpu = $myvar_cvm_cpu_reservation * $myvar_ntnx_cluster_ha_available_hosts
            }
            if (!$myvar_cvm_ram_gib_reservation)
            {#no specific value for $myvar_cvm_ram_gib_reservation, so we assume add up all cvm vram
                $myvar_ntnx_cluster_cvm_reserved_ram = [math]::round((($myvar_ntnx_cluster_cvms | Measure-Object memoryCapacityInBytes -sum).Sum - (($myvar_ntnx_cluster_cvms | Measure-Object memoryCapacityInBytes -Maximum).Maximum * $myvar_ntnx_cluster_ha_reserved_hosts)) /1024/1024/1024,0)
            }
            else 
            {#a value was specified for $myvar_cvm_ram_gib_reservation so we multiply that by the number of hosts in the cluster
                $myvar_ntnx_cluster_cvm_reserved_ram = [math]::round($myvar_cvm_cpu_reservation * $myvar_ntnx_cluster_ha_available_hosts /1024/1024/1024,0)
            }
            #todo: for ntnx_remote_site_cluster
        #endregion
        
        #* hypervisor overhead (cpu/ram)
        #region hypervisor overhead and ha reserved
            #for ntnx_cluster
            $myvar_ntnx_cluster_largest_host_cpu_cores = $myvar_ntnx_cluster_hosts_config | Where-Object {$_.num_cpu_cores -eq (($myvar_ntnx_cluster_hosts_config | Measure-Object num_cpu_cores -Maximum).Maximum)} | Where-Object {$_.num_cpu_sockets -eq (($myvar_ntnx_cluster_hosts_config | Measure-Object num_cpu_sockets -Maximum).Maximum)} | Select-Object -First 1
            $myvar_ntnx_cluster_ha_cpu_reserved = $myvar_ntnx_cluster_largest_host_cpu_cores.num_cpu_cores * $myvar_ntnx_cluster_largest_host_cpu_cores.num_cpu_sockets * $myvar_ntnx_cluster_ha_reserved_hosts
            $myvar_ntnx_cluster_ha_ram_gib_reserved = [math]::round(($myvar_ntnx_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -Maximum).Maximum * $myvar_ntnx_cluster_ha_reserved_hosts /1024/1024/1024,0)
            $myvar_ntnx_cluster_hypervisor_overhead_cpu_total = $myvar_hypervisor_cpu_overhead * $myvar_ntnx_cluster_ha_available_hosts
            $myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total = $myvar_hypervisor_ram_gib_overhead * $myvar_ntnx_cluster_ha_available_hosts
            #todo: for ntnx_remote_site_cluster
        #endregion

        #* uvm clusters capacity (cpu/ram)
        #for ntnx_cluster
        $myvar_ntnx_cluster_uvm_capacity_total_cpu = ($myvar_ntnx_cluster_cpu_capacity_total - $myvar_ntnx_cluster_cvm_reserved_cpu - $myvar_ntnx_cluster_hypervisor_overhead_cpu_total - $myvar_ntnx_cluster_ha_cpu_reserved) * $myvar_cpu_over_subscription_ratio
        $myvar_ntnx_cluster_uvm_capacity_total_ram_gib = ($myvar_ntnx_cluster_ram_gib_capacity_total - $myvar_ntnx_cluster_cvm_reserved_ram - $myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total - $myvar_ntnx_cluster_ha_ram_gib_reserved) * $myvar_ram_over_subscription_ratio
        $myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores = [math]::round(($myvar_desired_capacity_headroom_percentage * $myvar_ntnx_cluster_uvm_capacity_total_cpu) / 100,0)
        $myvar_ntnx_cluster_desired_capacity_headroom_ram_gib = [math]::round(($myvar_desired_capacity_headroom_percentage * $myvar_ntnx_cluster_uvm_capacity_total_ram_gib) / 100,0)
        #todo: for ntnx_remote_site_cluster

        #* uvm allocated (cpu/ram)
        #for ntnx_cluster
        $myvar_ntnx_cluster_uvm_allocated_cpu = ($myvar_ntnx_cluster_uvms | Measure-Object numVCpus -Sum).Sum
        $myvar_ntnx_cluster_uvm_allocated_ram_gib = [math]::round(($myvar_ntnx_cluster_uvms | Measure-Object memoryCapacityInBytes -Sum).Sum /1024/1024/1024,0)
        #todo: for ntnx_remote_site_cluster

        #* metro uvm allocated (cpu/ram)
        #for ntnx_cluster
        if ($myvar_ntnx_cluster_ma_uvms)
        {#there are powered on vms protected by metro availability
            $myvar_ntnx_cluster_ma_uvm_allocated_cpu = ($myvar_ntnx_cluster_ma_uvms | Measure-Object numVCpus -Sum).Sum
            $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib = [math]::round(($myvar_ntnx_cluster_ma_uvms | Measure-Object memoryCapacityInBytes -Sum).Sum /1024/1024/1024,0)
        }
        else 
        {#there are no powered on vms protected by metro availability
            Write-Host "$(get-date) [WARNING] Nutanix cluster $($myvar_ntnx_cluster_name) has no metro protected powered on UVM!" -ForegroundColor Yellow
        }
        #todo: for ntnx_remote_site_cluster

        #* uvm remaining (cpu/ram)
        #for ntnx_cluster
        $myvar_ntnx_cluster_uvm_remaining_cpu = $myvar_ntnx_cluster_uvm_capacity_total_cpu - $myvar_ntnx_cluster_uvm_allocated_cpu
        $myvar_ntnx_cluster_uvm_remaining_ram_gib = $myvar_ntnx_cluster_uvm_capacity_total_ram_gib - $myvar_ntnx_cluster_uvm_allocated_ram_gib
        #todo: for ntnx_remote_site_cluster

        #* building variables with all those results to facilitate output construction
        #general cluster information
        $myvar_ntnx_cluster_general_information = [ordered]@{
            "Cluster Name" = $myvar_ntnx_cluster_name;
            "Replication Factor" = $myvar_ntnx_cluster_rf;
            "AOS Version" = $myvar_ntnx_cluster_info.version;
            "Hypervisor" = ($myvar_ntnx_cluster_info.hypervisor_types)[0];
            "Number of Nodes" = $myvar_ntnx_cluster_info.num_nodes;
            "Total CPU cores Capacity" = $myvar_ntnx_cluster_cpu_capacity_total;
            "Total RAM GiB Capacity" = $myvar_ntnx_cluster_ram_gib_capacity_total;
            "Actual cores:vcpus ratio" = [math]::round(($myvar_ntnx_cluster_uvm_allocated_cpu + ($myvar_ntnx_cluster_cvms | Measure-Object numVCpus -sum).Sum) / $myvar_ntnx_cluster_cpu_capacity_total,1);
        }
        #report configuration
        $myvar_report_configuration_settings = [ordered]@{
            "CPU Oversubscription Ratio" = $myvar_cpu_over_subscription_ratio;
            "Memory Oversubscription Ratio" = $myvar_ram_over_subscription_ratio;
            "CVM CPU Reservation"  = $myvar_cvm_cpu_reservation;
            "CVM RAM Reservation" = $myvar_cvm_ram_gib_reservation;
            "Hypervisor CPU cores Overhead" = $myvar_hypervisor_cpu_overhead;
            "Hypervisor RAM GiB Overhead" = $myvar_hypervisor_ram_gib_overhead;
            "Desired UVM Capacity Headroom Percentage" = $myvar_desired_capacity_headroom_percentage;
        }
        #reserved capacity
        $myvar_ntnx_cluster_reserved_capacity = [ordered]@{
            "CPU cores Reserved for CVMs" = $myvar_ntnx_cluster_cvm_reserved_cpu;
            "Memory GiB Reserved for CVMs" = $myvar_ntnx_cluster_cvm_reserved_ram;
            "CPU cores Reserved for High Availability" = $myvar_ntnx_cluster_ha_cpu_reserved;
            "Memory GiB Reserved for High Availability" = $myvar_ntnx_cluster_ha_ram_gib_reserved;
            "CPU cores Reserved for Hypervisor Overhead" = $myvar_ntnx_cluster_hypervisor_overhead_cpu_total;
            "Memory GiB Reserved for Hypervisor Overhead" = $myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total;
            "Total CPU cores Reserved" = $myvar_ntnx_cluster_cvm_reserved_cpu + $myvar_ntnx_cluster_ha_cpu_reserved + $myvar_ntnx_cluster_hypervisor_overhead_cpu_total;
            "Total Memory GiB Reserved" = $myvar_ntnx_cluster_cvm_reserved_ram + $myvar_ntnx_cluster_ha_ram_gib_reserved + $myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total
        }
        #uvm capacities
        $myvar_ntnx_cluster_uvm_capacity = [ordered]@{
            "Total CPU cores Capacity for UVMs" = $myvar_ntnx_cluster_uvm_capacity_total_cpu;
            "Total Memory GiB Capacity for UVMs" = $myvar_ntnx_cluster_uvm_capacity_total_ram_gib;
            "CPU cores Allocated to UVMs" = $myvar_ntnx_cluster_uvm_allocated_cpu;
            "Memory GiB Allocated to UVMs" = $myvar_ntnx_cluster_uvm_allocated_ram_gib;
            "Remaining CPU cores for UVMs" = $myvar_ntnx_cluster_uvm_remaining_cpu;
            "Remaining Memory GiB for UVMs" = $myvar_ntnx_cluster_uvm_remaining_ram_gib;
        }
        #metro availability capacity
        if ($myvar_ntnx_cluster_ma_uvms)
        {#there are powered on vms protected by metro availability
            $myvar_ntnx_cluster_ma_uvms_capacity_allocated = [ordered]@{
                "CPU cores Allocated to metro protected UVMs" = $myvar_ntnx_cluster_ma_uvm_allocated_cpu;
                "Memory GiB Allocated to metro protected UVMs" = $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib
            }
        }
    #endregion
    Write-Host ""
    
    #! resume coding effort here
    #* create output
    #region create output
        #todo: html output
        #region html output
        if ($html) 
        {#we need html output
            Write-Host "$(get-date) [STEP] Creating HTML report..." -ForegroundColor Magenta
            New-Html -TitleText "Capacity Report" -ShowHtml -Online {
                New-HTMLTableStyle -BackgroundColor Black -TextColor White -Type Button
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#4C4C4E" -TextColor White -TextAlign center -Type Header
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#4C4C4E" -TextColor White -TextAlign center -Type Footer
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor White -TextColor Black -TextAlign center -Type RowOdd
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor WhiteSmoke -TextColor Black -TextAlign center -Type RowEven
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowSelected
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowHoverSelected
                New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowHover
                New-HTMLTableStyle -Type Header -BorderLeftStyle dashed -BorderLeftColor "#4C4C4E" -BorderLeftWidthSize 1px
                New-HTMLTableStyle -Type Footer -BorderLeftStyle dotted -BorderLeftColor "#4C4C4E" -BorderleftWidthSize 1px
                New-HTMLTableStyle -Type Footer -BorderTopStyle none -BorderTopColor Black -BorderTopWidthSize 5px -BorderBottomColor "#4C4C4E" -BorderBottomStyle solid

                New-HtmlSection -HeaderText "General Information" -Wrap wrap -CanCollapse  -Collapsed -HeaderBackGroundColor "#168CF5" -HeaderTextColor White -Direction Row {
                    New-HtmlSection -HeaderText "Report Configuration Settings" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                        New-HtmlTable -DataTable ($myvar_report_configuration_settings) -HideFooter
                    }
                    New-HtmlSection -HeaderText "$($myvar_ntnx_cluster_name)" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_general_information) -HideFooter
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_reserved_capacity) -HideFooter
                    }
                }

                New-HtmlSection -HeaderText "UVM Capacity" -Wrap wrap -CanCollapse  -HeaderBackGroundColor "#024DA1" -HeaderTextColor White {
                    
                    #showing capacity numbers for the queried cluster
                    New-HtmlSection -HeaderText "$($myvar_ntnx_cluster_name)" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White -Wrap wrap {
                        #showing capacity status widget
                        New-HTMLPanel -Invisible {   
                            if ($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_cluster_uvm_remaining_cpu)
                            {#there is enough remaining cpu capacity
                                #New-HTMLStatusItem -Name 'Remaining CPU Capacity' -Status 'Good' -Percentage '100%'
                                New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                            }
                            else 
                            {#there is not enough cpu capacity remaining
                                #New-HTMLStatusItem -Name 'Remaining CPU Capacity' -Status 'Dead' -Percentage '0%'
                                New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                            }

                            if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
                            {#there is enough remaining memory capacity
                                #New-HTMLStatusItem -Name 'Remaining Memory Capacity' -Status 'Good' -Percentage '100%'
                                New-HTMLToast -TextHeader 'Remaining Memory Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                            }
                            else 
                            {#there is not enough memory capacity remaining
                                #New-HTMLStatusItem -Name 'Remaining Memory Capacity' -Status 'Dead' -Percentage '0%'
                                New-HTMLToast -TextHeader 'Remaining Memory Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                            }
                        }
                        
                        #showing capacity numbers 
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_uvm_capacity) -HideFooter
                    }
                    
                    #showing capacity details for metro protected uvms
                    if ($myvar_ntnx_cluster_ma_uvms)
                    {#there are powered on vms protected by metro availability
                        New-HtmlSection -HeaderText "Metro enabled UVM Allocated Capacity for $($myvar_ntnx_cluster_name)" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_ntnx_cluster_ma_uvms_capacity_allocated) -HideFooter
                        }
                    }

                    #showing capacity graphs
                    if ($myvar_ntnx_cluster_ma_uvms)
                    {#there are powered on vms protected by metro availability
                        New-HTMLPanel {
                            New-HTMLChart {
                                New-ChartToolbar -Download
                                New-ChartBarOptions -Type barStacked
                                New-ChartLegend -Name 'Free', 'Allocated', 'Metro'
                                New-ChartBar -Name 'CPU Cores' -Value $myvar_ntnx_cluster_uvm_remaining_cpu, ($myvar_ntnx_cluster_uvm_allocated_cpu - $myvar_ntnx_cluster_ma_uvm_allocated_cpu), $myvar_ntnx_cluster_ma_uvm_allocated_cpu
                                New-ChartBar -Name 'Memory GiB' -Value $myvar_ntnx_cluster_uvm_remaining_ram_gib, ($myvar_ntnx_cluster_uvm_allocated_ram_gib - $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib), $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib
                            }
                        }
                    }
                    else 
                    {#there are no powered on vms protected by metro availability
                        New-HTMLPanel {
                            New-HTMLChart {
                                New-ChartToolbar -Download
                                New-ChartBarOptions -Type barStacked
                                New-ChartLegend -Name 'Free', 'Allocated'
                                New-ChartBar -Name 'CPU Cores' -Value $myvar_ntnx_cluster_uvm_remaining_cpu, $myvar_ntnx_cluster_uvm_allocated_cpu
                                New-ChartBar -Name 'Memory GiB' -Value $myvar_ntnx_cluster_uvm_remaining_ram_gib, $myvar_ntnx_cluster_uvm_allocated_ram_gib
                            }
                        }
                    }
                }

                #showing details of metro enabled uvms
                if ($myvar_ntnx_cluster_ma_uvms)
                {#there are powered on vms protected by metro availability
                    New-HtmlSection -HeaderText "Metro enabled UVMs details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_ma_uvms) -HideFooter
                    }
                }

                #showing queried cluster hosts details
                New-HtmlSection -HeaderText "Hosts details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                    New-HtmlTable -DataTable ($myvar_ntnx_cluster_hosts_config) -HideFooter
                }
                
                #showing queried cluster uvms details
                New-HtmlSection -HeaderText "UVM details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                    New-HtmlTable -DataTable ($myvar_ntnx_cluster_uvms_info) -HideFooter
                }             
            }
            Write-Host ""
        }
        #endregion
        
        #* console output
        #todo: add remote site console output
        #region console output
            Write-Host "$(get-date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) replication factor is $($myvar_ntnx_cluster_rf)" -ForegroundColor White
            Write-Host "$(get-date) [DATA] Total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cpu_capacity_total) cores" -ForegroundColor White
            Write-Host "$(get-date) [DATA] Total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ram_gib_capacity_total) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] CPU reserved for high availability for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ha_cpu_reserved) cores" -ForegroundColor White
            Write-Host "$(get-date) [DATA] RAM reserved for high availability for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ha_ram_gib_reserved) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] CVM CPU reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_cpu)" -ForegroundColor White
            Write-Host "$(get-date) [DATA] CVM RAM reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_ram) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] Hypervisor CPU overhead for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_hypervisor_overhead_cpu_total)" -ForegroundColor White
            Write-Host "$(get-date) [DATA] Hypervisor RAM overhead for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] UVM total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_capacity_total_cpu) cores" -ForegroundColor White
            Write-Host "$(get-date) [DATA] UVM total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_capacity_total_ram_gib) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_allocated_cpu) cores" -ForegroundColor White
            Write-Host "$(get-date) [DATA] UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_allocated_ram_gib) GiB" -ForegroundColor White
            Write-Host "$(get-date) [DATA] UVM remaining CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_remaining_cpu) cores" -ForegroundColor White
            Write-Host "$(get-date) [DATA] UVM remaining RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_remaining_ram_gib) GiB" -ForegroundColor White
            if ($myvar_ntnx_cluster_ma_uvms)
            {#there are powered on vms protected by metro availability
                Write-Host "$(get-date) [DATA] Metro enabled UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ma_uvm_allocated_cpu) cores" -ForegroundColor White
                Write-Host "$(get-date) [DATA] Metro enabled UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) GiB" -ForegroundColor White
            }

            #* checking remaining capacity is sufficient
            if ($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_cluster_uvm_remaining_cpu)
            {#there is enough remaining cpu capacity
                Write-Host "$(get-date) [INFO] There are $($myvar_ntnx_cluster_uvm_remaining_cpu) CPU cores still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores) CPU cores." -ForegroundColor Green
            }
            else 
            {#there is not enough cpu capacity remaining
                Write-Host "$(get-date) [WARNING] There are $($myvar_ntnx_cluster_uvm_remaining_cpu) CPU cores still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores) CPU cores!" -ForegroundColor Yellow
            }
            if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
            {#there is enough remaining memory capacity
                Write-Host "$(get-date) [INFO] There are $($myvar_ntnx_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib) GiB." -ForegroundColor Green
            }
            else 
            {#there is not enough memory capacity remaining
                Write-Host "$(get-date) [WARNING] There are $($myvar_ntnx_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib) GiB!" -ForegroundColor Yellow
            }
        #endregion

        #todo: smtp output
        #region smtp output
            
        #endregion

        #todo: zabbix output
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