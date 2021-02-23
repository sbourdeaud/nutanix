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
.PARAMETER viewnow
  Means you want the script to open the html report in your default browser immediately after creation.
.PARAMETER dir
  Directory/path where to save the html report.  By default, it will be created in the current directory. Note that the name of the report is always capacity_report.html and that you can change this in the script variables section.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER influxdb
  Specifies you want to send data to influxdb server. You will need to configure the influxdb server URL and database instance in the variables section of this script.  The timeseries created by default is called uvm_capacity.
.PARAMETER influxdbCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$influxdbCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\get-UvmCapacity.ps1 -cluster ntnxc1.local
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 22nd 2021
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
        [parameter(mandatory = $false)] [switch]$viewnow,
        [parameter(mandatory = $false)] [string]$dir,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] [string]$prismCreds,
        [parameter(mandatory = $false)] [switch]$influxdb,
        [parameter(mandatory = $false)] [string]$influxdbCreds
    )
#endregion

#region functions
    #this function is used to process output to console (timestamped and color coded) and log file
    function Write-LogOutput
    {
    <#
    .SYNOPSIS
    Outputs color coded messages to the screen and/or log file based on the category.

    .DESCRIPTION
    This function is used to produce screen and log output which is categorized, time stamped and color coded.

    .PARAMETER Category
    This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".

    .PARAMETER Message
    This is the actual message you want to display.

    .PARAMETER LogFile
    If you want to log output to a file as well, use logfile to pass the log file full path name.

    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

    .EXAMPLE
    .\Write-LogOutput -category "ERROR" -message "You must be kidding!"
    Displays an error message.

    .LINK
    https://github.com/sbourdeaud
    #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param
        (
            [Parameter(Mandatory)]
            [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG','DATA')]
            [string]
            $Category,

            [string]
            $Message,

            [string]
            $LogFile
        )

        process
        {
            $Date = get-date #getting the date so we can timestamp the output entry
            $FgColor = "Gray" #resetting the foreground/text color
            switch ($Category) #we'll change the text color depending on the selected category
            {
                "INFO" {$FgColor = "Green"}
                "WARNING" {$FgColor = "Yellow"}
                "ERROR" {$FgColor = "Red"}
                "SUM" {$FgColor = "Magenta"}
                "SUCCESS" {$FgColor = "Cyan"}
                "STEP" {$FgColor = "Magenta"}
                "DEBUG" {$FgColor = "White"}
                "DATA" {$FgColor = "Gray"}
            }

            Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
            if ($LogFile) #add the entry to the log file if -LogFile has been specified
            {
                Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
                Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
            }
        }

    }#end function Write-LogOutput
    #this function is used to test a given IP address
	Function TestIp 
	{#ping an ip address, return true or false
		#input: ip
		#output: boolean
	<#
	.SYNOPSIS
	Tries to ping the IP address provided and returns true or false.
	.DESCRIPTION
	Tries to ping the IP address provided and returns true or false.
	.NOTES
	Author: Stephane Bourdeaud
	.PARAMETER ip
	An IP address to test.
	.EXAMPLE
	PS> TestIp -ip 10.10.1.1
	#>
		param 
		(
			[string] $ip
		)

		begin
		{
			
		}

		process
		{
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Trying to ping IP $($ip)..."
			if (Test-Connection $ip -Count 5 -Quiet)
            {
                $myvar_ping_test = $true
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Successfully pinged IP $($ip)..."
            }
            else 
            {
                $myvar_ping_test = $false
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Could not ping IP $($ip)..."
            }
		}

		end
		{
		return $myvar_ping_test
		}
	}#end function TestIp
    #this function loads a powershell module
    Function LoadModule
    {#tries to load a module, import it, install it if necessary
    <#
	.SYNOPSIS
	Tries to load the specified module and installs it if it can't.
	.DESCRIPTION
	Tries to load the specified module and installs it if it can't.
	.NOTES
	Author: Stephane Bourdeaud
	.PARAMETER module
	Name of PowerShell module to import.
	.EXAMPLE
	PS> LoadModule -module PSWriteHTML
	#>
		param 
		(
			[string] $module
		)

		begin
		{
			
		}

		process
		{   
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Trying to get module $($module)..."
			if (!(Get-Module -Name $module)) 
            {#we could not get the module, let's try to load it
                try
                {#import the module
                    Import-Module -Name $module -ErrorAction Stop
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
                }#end try
                catch 
                {#we couldn't import the module, so let's install it
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Installing module '$($module)' from the Powershell Gallery..."
                    try 
                    {#install module
                        Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                    }
                    catch 
                    {#could not install module
                        Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Could not install module '$($module)': $($_.Exception.Message)"
                        exit 1
                    }

                    try
                    {#now that it is intalled, let's import it
                        Import-Module -Name $module -ErrorAction Stop
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
                    }#end try
                    catch 
                    {#we couldn't import the module
                        Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Unable to import the module $($module).psm1 : $($_.Exception.Message)"
                        Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Please download and install from https://www.powershellgallery.com"
                        Exit 1
                    }#end catch
                }#end catch
            }
		}

		end
		{

		}
    }
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
02/07/2021 sb   Initial release.
02/22/2021 sb   Adding influxdb output.
################################################################################
'@
    $myvar_script_name = ".\get-UvmCapacity.ps1"

    if ($help) {get-help $myvar_script_name; exit}
    if ($History) {$HistoryText; exit}
    
    if (!$dir)
    {#no report directory was specified, so we'll use the current directory
        $dir = Get-Location | Select-Object -ExpandProperty Path
    }

    if (!$dir.EndsWith("\")) 
    {#make sure given log path has a trailing \
        $dir += "\"
    }
    if (Test-Path -path $dir)
    {#specified path exists
        $myvar_html_report_name = $dir + $myvar_html_report_name
    }
    else 
    {#specified path does not exist
        Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Specified log path $($dir) does not exist! Exiting."
        Exit 1
    }

    if ($log) 
    {#we want a log file
        $myvar_log_file = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvar_log_file += "$($cluster)_"
        $myvar_log_file += "get-UvmCapacity.log"
        $myvar_log_file = $dir + $myvar_log_file
    }

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) 
    {#PowerShell version is too old
        Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
        Exit 1
    }

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Checking for required Powershell modules..."

    #region module sbourdeaud is used for facilitating Prism REST calls
        $myvar_required_version = "3.0.8"
        LoadModule -module sbourdeaud
        $myvar_module_version = Get-Module -Name sbourdeaud | Select-Object -Property Version
        if (($myvar_module_version.Version.Major -lt $($myvar_required_version.split('.')[0])) -or (($myvar_module_version.Version.Major -eq $($myvar_required_version.split('.')[0])) -and ($myvar_module_version.Version.Minor -eq $($myvar_required_version.split('.')[1])) -and ($myvar_module_version.Version.Build -lt $($myvar_required_version.split('.')[2])))) 
        {#module needs to be updated
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Updating module 'sbourdeaud'..."
            Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
            Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
            try 
            {#update and import module
                Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
                Import-Module -Name sbourdeaud -ErrorAction Stop
            }
            catch 
            {#could not import and update module
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Could not update module 'sbourdeaud': $($_.Exception.Message)"
            }
        }
    #endregion
    Set-PoSHSSLCerts
    Set-PoshTls

    #region module PSWriteHTML
        if ($html)
        {#we need html output, so let's load the PSWriteHTML module
            LoadModule -module PSWriteHTML
        }
    #endregion

    #region module Influx
        if ($influxdb)
        {#we need influxdb output, so let's load the Influx module
            LoadModule -module Influx
        }
    #endregion
#endregion

#todo: add smtp code.
#todo: change script structure to enable loop processing of multiple clusters (exp: with prism central as entry point)

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
    $myvar_html_report_name = "capacity_report.html"
    $myvar_smtp_server = ""
    $myvar_smtp_from = ""
    $myvar_smtp_to = ""
    $myvar_zabbix_server = ""
    $myvar_influxdb_url = "http://10.68.97.46:8086"
    $myvar_influxdb_database = "ntnx"
#endregion

#region parameters validation
    if (!$prismCreds) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
       $prismCredentials = Get-Credential -Message "Please enter Prism credentials"
    } 
    else 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {#Get-CustomCredentials
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        catch 
        {#could not Get-CustomeCredentials, so Set-CustomCredentials
            Set-CustomCredentials -credname $prismCreds
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }

    if (!$influxdbCreds -and $influxdb) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
       $influxdbCredentials = Get-Credential -Message "Please enter InfluxDB credentials"
    } 
    elseif ($influxdb) 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {#Get-CustomCredentials
            $influxdbCredentials = Get-CustomCredentials -credname $influxdbCreds -ErrorAction Stop
            $username = $influxdbCredentials.UserName
            $InfluxDBSecurePassword = $influxdbCredentials.Password
        }
        catch 
        {#could not Get-CustomeCredentials, so Set-CustomCredentials
            Set-CustomCredentials -credname $influxdbCreds
            $influxdbCredentials = Get-CustomCredentials -credname $influxdbCreds -ErrorAction Stop
            $username = $influxdbCredentials.UserName
            $InfluxDBSecurePassword = $influxdbCredentials.Password
        }
        $influxdbCredentials = New-Object PSCredential $username, $InfluxDBSecurePassword
    }
#endregion

#* processing here
#region processing	
    #* retrieve information from Prism
    Write-LogOutput -Category "STEP" -LogFile $myvar_log_file -Message "Retrieving information from Nutanix cluster $($cluster)..."
    #region retrieve information from Prism
        #* retrieve cluster information
        #region GET cluster
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving cluster information from Nutanix cluster $($cluster)..."
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

            $myvar_ntnx_cluster_name = $myvar_ntnx_cluster_info.name
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster name is $($myvar_ntnx_cluster_name)"
            $myvar_ntnx_cluster_rf = $myvar_ntnx_cluster_info.cluster_redundancy_state.desired_redundancy_factor

            if (($myvar_ntnx_cluster_info.hypervisor_types).count -gt 1)
            {#cluster has mixed hypervisors
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_cluster_name) has multiple hypervisors"
                if ($myvar_ntnx_cluster_info.hypervisor_types -notcontains "kVMware")
                {#none of the nodes are running VMware
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "None of the cluster hosts are running VMware vSphere!"
                }
            }
            else 
            {#cluster has single hypervisor
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_cluster_name) is of hypervisor type $($myvar_ntnx_cluster_info.hypervisor_types[0])"
            }

            #region figure out vcenter ip
                $myvar_management_server = $myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                if ($myvar_management_server -is [array]) 
                {#houston, we have a problem, there is more than one registered vcenter
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "There is more than 1 registered management server for cluster $($cluster). Exiting."
                } 
                else 
                {#grab vcenter ip
                    $myvar_vcenter_ip = ($myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                    Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "vCenter IP address for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_vcenter_ip)"
                }
                if (!$myvar_vcenter_ip) 
                {#found no vcenter ip
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "vCenter registration is not done in Prism for cluster $cluster!"
                }
            #endregion

            #let's make sure our current redundancy is at least 2
            if ($myvar_ntnx_cluster_info.cluster_redundancy_state.current_redundancy_factor -lt $myvar_ntnx_cluster_rf) 
            {#cluster redundancy state is < replication factor (a host must be down)
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Current redundancy is less than $($myvar_ntnx_cluster_rf). Exiting."
                Exit 1
            }
            #check if there is an upgrade in progress
            if ($myvar_ntnx_cluster_info.is_upgrade_in_progress) 
            {#cluster has an upgrade in progress
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Cluster upgrade is in progress. Exiting."
                Exit 1
            }
        #endregion
        
        #* retrieve host information
        #region GET hosts
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving hosts information from Nutanix cluster $($myvar_ntnx_cluster_name)..."
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_hosts = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
            
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
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving storage containers information from Nutanix cluster $($myvar_ntnx_cluster_name)..."
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/storage_containers/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_storage_containers = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
            
            [System.Collections.ArrayList]$myvar_ntnx_cluster_storage_containers_info = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_ntnx_cluster_storage_container in $myvar_ntnx_cluster_storage_containers.entities)
            {#collect specific information for each storage container
                $myvar_ntnx_cluster_storage_container_info = [ordered]@{
                    "name" = $myvar_ntnx_cluster_storage_container.name;
                    "user_capacity_gib" = [math]::round($myvar_ntnx_cluster_storage_container.usage_stats."storage.user_capacity_bytes" /1024 /1024 /1024,0);
                    "user_free_gib" = [math]::round($myvar_ntnx_cluster_storage_container.usage_stats."storage.user_free_bytes" /1024 /1024 /1024,0);
                    "replication_factor" = $myvar_ntnx_cluster_storage_container.replication_factor;
                    "erasure_code" = $myvar_ntnx_cluster_storage_container.erasure_code;
                    "finger_print_on_write" = $myvar_ntnx_cluster_storage_container.finger_print_on_write;
                    "on_disk_dedup" = $myvar_ntnx_cluster_storage_container.on_disk_dedup;
                    "compression_enabled" = $myvar_ntnx_cluster_storage_container.compression_enabled;
                    "compression_delay_in_secs" = $myvar_ntnx_cluster_storage_container.compression_delay_in_secs;
                    "user_capacity_bytes" = $myvar_ntnx_cluster_storage_container.usage_stats."storage.user_capacity_bytes";
                    "user_free_bytes" = $myvar_ntnx_cluster_storage_container.usage_stats."storage.user_free_bytes";
                }
                #store the results for this entity in our overall result variable
                $myvar_ntnx_cluster_storage_containers_info.Add((New-Object PSObject -Property $myvar_ntnx_cluster_storage_container_info)) | Out-Null
            }
        #endregion
        
        #* retrieve protection domains information
        #region GET protection_domains
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving protection domains from Nutanix cluster $($myvar_ntnx_cluster_name)..."
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_pds = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            
            $myvar_ntnx_cluster_ma_active_ctrs_names = ($myvar_ntnx_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
            
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
                Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There are no active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)"
            }
            else 
            {#there are active metro availability protection domains on this cluster
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_cluster_ma_active_pds.count) active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)"
            }
        #endregion
        
        #* retrieve vms information
        #region GET vms
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving virtual machines from Nutanix cluster $($myvar_ntnx_cluster_name)..."
            $url = "https://{0}:9440/PrismGateway/services/rest/v1/vms/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_vms = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

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
                        "diskCapacityInGiB" = [math]::round($myvar_ntnx_cluster_ma_active_ctr_uvm.diskCapacityInBytes /1024 /1024 /1024,0);
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

        #* retrieve remote site information
        #region retrieve remote site cluster information          
            if ($myvar_ntnx_cluster_ma_active_ctrs_names)
            {#we have metro protected containers, so we need to query our remote site as well
                #region GET remote_site
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving remote sites from Nutanix cluster $($myvar_ntnx_cluster_name)..."
                    $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/remote_sites/" -f $cluster
                    $method = "GET"
                    $myvar_ntnx_cluster_remote_sites = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials

                    $myvar_remote_site_name = $myvar_ntnx_cluster_ma_active_pds.metro_avail.remote_site | select-object -unique
                    if ($myvar_remote_site_name -is [array]) 
                    {#houston we have a problem: active metro pds are pointing to more than one remote site!
                        Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Cluster $($cluster) has metro availability protection domains which are pointing to different remote sites. Exiting."
                        Exit 1
                    } 
                    else 
                    {#we have figured out the remote site name
                        Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Remote site name is $($myvar_remote_site_name)"
                    }
                    
                    #* grab ip for our remote site
                    $myvar_remote_site_ip = (($myvar_ntnx_cluster_remote_sites.entities | Where-Object {$_.name -eq $myvar_remote_site_name}).remote_ip_ports).psobject.properties.name
                    Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Remote site $($myvar_remote_site_name) ip address is $($myvar_remote_site_ip)"

                    #* checking that our remote site is available
                    if (($myvar_ntnx_cluster_ma_active_pds.metro_avail.status | Select-Object -Unique) -ne "Enabled")
                    {#all active metro pds are not in "enabled" status, we need to check that we can ping the remote site
                        if (TestIp -ip $myvar_remote_site_ip)
                        {#remote site Prism does ping
                            $myvar_remote_site_online = $true
                        }
                        else 
                        {#remote site Prism does not ping
                            $myvar_remote_site_online = $false
                        }
                    }
                    else 
                    {#all metro pds are in enabled state so remote site must be available
                        $myvar_remote_site_online = $true
                    }
                #endregion
                
                if ($myvar_remote_site_online)
                {#remote site is available
                    #* retrieve remote cluster information
                    #region GET remote_site cluster
                        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving cluster information from Nutanix cluster $($myvar_remote_site_ip)..."
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            
                        $myvar_ntnx_remote_cluster_name = $myvar_ntnx_remote_cluster_info.name
                        Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Remote Nutanix cluster name is $($myvar_ntnx_remote_cluster_name)"
                        $myvar_ntnx_remote_cluster_rf = $myvar_ntnx_remote_cluster_info.cluster_redundancy_state.desired_redundancy_factor
            
                        if (($myvar_ntnx_remote_cluster_info.hypervisor_types).count -gt 1)
                        {#cluster has mixed hypervisors
                            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_remote_cluster_name) has multiple hypervisors"
                            if ($myvar_ntnx_remote_cluster_info.hypervisor_types -notcontains "kVMware")
                            {#none of the nodes are running VMware
                                Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "None of the cluster hosts are running VMware vSphere!"
                            }
                        }
                        else 
                        {#cluster has single hypervisor
                            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_remote_cluster_name) is of hypervisor type $($myvar_ntnx_remote_cluster_info.hypervisor_types[0])"
                        }
            
                        #region figure out vcenter ip
                            $myvar_remote_management_server = $myvar_ntnx_remote_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                            if ($myvar_remote_management_server -is [array]) 
                            {#houston, we have a problem, there is more than one registered vcenter
                                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "There is more than 1 registered management server for cluster $($myvar_remote_site_ip). Exiting."
                                Exit 1
                            } 
                            else 
                            {#grab vcenter ip
                                $myvar_remote_vcenter_ip = ($myvar_ntnx_remote_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "vCenter IP address for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_remote_vcenter_ip)"
                            }
                            if (!$myvar_remote_vcenter_ip) 
                            {#found no vcenter ip
                                Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "vCenter registration is not done in Prism for cluster $myvar_remote_site_ip!"
                            }
                        #endregion
            
                        #let's make sure our current redundancy is at least 2
                        if ($myvar_ntnx_remote_cluster_info.cluster_redundancy_state.current_redundancy_factor -lt $myvar_ntnx_remote_cluster_rf) 
                        {#cluster redundancy state is < replication factor (a host must be down)
                            Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Current redundancy is less than $($myvar_ntnx_remote_cluster_rf). Exiting."
                            Exit 1
                        }
                        #check if there is an upgrade in progress
                        if ($myvar_ntnx_remote_cluster_info.is_upgrade_in_progress) 
                        {#cluster has an upgrade in progress
                            Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Cluster upgrade is in progress. Exiting."
                            Exit 1
                        }
                    #endregion
                    
                    #* retrieve remote host information
                    #region GET remote_site hosts
                        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving hosts information from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..."
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_hosts = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
                        
                        #$myvar_ntnx_remote_cluster_hosts_ips = ($myvar_ntnx_hosts.entities).hypervisor_address
                        [System.Collections.ArrayList]$myvar_ntnx_remote_cluster_hosts_config = New-Object System.Collections.ArrayList($null)
                        ForEach ($myvar_ntnx_remote_cluster_host in $myvar_ntnx_remote_cluster_hosts.entities)
                        {#process each cluster host
                            $myvar_host_config = [ordered]@{
                                "name" = $myvar_ntnx_remote_cluster_host.name;
                                "block_model_name" = $myvar_ntnx_remote_cluster_host.block_model_name;
                                "hypervisor_type" = $myvar_ntnx_remote_cluster_host.hypervisor_type;
                                "hypervisor_full_name" = $myvar_ntnx_remote_cluster_host.hypervisor_full_name;
                                "cpu_model" = $myvar_ntnx_remote_cluster_host.cpu_model;
                                "num_cpu_sockets" = $myvar_ntnx_remote_cluster_host.num_cpu_sockets;
                                "num_cpu_cores" = $myvar_ntnx_remote_cluster_host.num_cpu_cores;
                                "memory_capacity_in_GiB" = [math]::round($myvar_ntnx_remote_cluster_host.memory_capacity_in_bytes /1024 /1024 /1024,0);
                                "hypervisor_ip" = $myvar_ntnx_remote_cluster_host.hypervisor_address;
                                "ipmi_address" = $myvar_ntnx_remote_cluster_host.ipmi_address;
                                "cpu_capacity_in_hz" = $myvar_ntnx_remote_cluster_host.cpu_capacity_in_hz;
                                "memory_capacity_in_bytes" = $myvar_ntnx_remote_cluster_host.memory_capacity_in_bytes;
                            }
                            #store the results for this entity in our overall result variable
                            $myvar_ntnx_remote_cluster_hosts_config.Add((New-Object PSObject -Property $myvar_host_config)) | Out-Null
                        }
                        if ($debugme) {$myvar_ntnx_remote_cluster_hosts_config}
                    #endregion

                    #* retrieve remote storage containers information
                    #region GET remote_site containers
                        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving storage containers information from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..."
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/storage_containers/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_storage_containers = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials

                        [System.Collections.ArrayList]$myvar_ntnx_remote_cluster_storage_containers_info = New-Object System.Collections.ArrayList($null)
                        ForEach ($myvar_ntnx_remote_cluster_storage_container in $myvar_ntnx_cluster_storage_containers.entities)
                        {#collect specific information for each storage container
                            $myvar_ntnx_remote_cluster_storage_container_info = [ordered]@{
                                "name" = $myvar_ntnx_remote_cluster_storage_container.name;
                                "user_capacity_gib" = [math]::round($myvar_ntnx_remote_cluster_storage_container.usage_stats."storage.user_capacity_bytes" /1024 /1024 /1024,0);
                                "user_free_gib" = [math]::round($myvar_ntnx_remote_cluster_storage_container.usage_stats."storage.user_free_bytes" /1024 /1024 /1024,0);
                                "replication_factor" = $myvar_ntnx_remote_cluster_storage_container.replication_factor;
                                "erasure_code" = $myvar_ntnx_remote_cluster_storage_container.erasure_code;
                                "finger_print_on_write" = $myvar_ntnx_remote_cluster_storage_container.finger_print_on_write;
                                "on_disk_dedup" = $myvar_ntnx_remote_cluster_storage_container.on_disk_dedup;
                                "compression_enabled" = $myvar_ntnx_remote_cluster_storage_container.compression_enabled;
                                "compression_delay_in_secs" = $myvar_ntnx_remote_cluster_storage_container.compression_delay_in_secs;
                                "user_capacity_bytes" = $myvar_ntnx_remote_cluster_storage_container.usage_stats."storage.user_capacity_bytes";
                                "user_free_bytes" = $myvar_ntnx_remote_cluster_storage_container.usage_stats."storage.user_free_bytes";
                            }
                            #store the results for this entity in our overall result variable
                            $myvar_ntnx_remote_cluster_storage_containers_info.Add((New-Object PSObject -Property $myvar_ntnx_remote_cluster_storage_container_info)) | Out-Null
                        }
                    #endregion

                    #* retrieve remote protection domains information
                    #region GET remote_site containers
                        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving protection domains from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..."
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_pds = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                        
                        $myvar_ntnx_remote_cluster_ma_active_ctrs_names = ($myvar_ntnx_remote_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
                        
                        [System.Collections.ArrayList]$myvar_ntnx_remote_cluster_ma_active_ctrs = New-Object System.Collections.ArrayList($null)
                        ForEach ($myvar_ntnx_remote_cluster_ma_active_ctr in $myvar_ntnx_remote_cluster_ma_active_ctrs_names)
                        {#figure out the uuid of each active metro enabled storage container
                            $myvar_ntnx_remote_cluster_ma_active_ctr_info = [ordered]@{
                                "name" = $myvar_ntnx_remote_cluster_ma_active_ctr;
                                "uuid" = ($myvar_ntnx_remote_cluster_storage_containers.entities | Where-Object {$_.name -eq $myvar_ntnx_remote_cluster_ma_active_ctr}).storage_container_uuid;
                                "user_free_bytes" = ($myvar_ntnx_remote_cluster_storage_containers.entities | Where-Object {$_.name -eq $myvar_ntnx_remote_cluster_ma_active_ctr}).usage_stats.storage.user_free_bytes;
                            }
                            #store the results for this entity in our overall result variable
                            $myvar_ntnx_remote_cluster_ma_active_ctrs.Add((New-Object PSObject -Property $myvar_ntnx_remote_cluster_ma_active_ctr_info)) | Out-Null
                        }
            
                        $myvar_ntnx_remote_cluster_ma_active_pds = $myvar_ntnx_remote_cluster_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}
                        if (!$myvar_ntnx_remote_cluster_ma_active_pds)
                        {#there are no active metro availability protection domains on this cluster
                            Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There are no active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_remote_cluster_name)"
                        }
                        else 
                        {#there are active metro availability protection domains on this cluster
                            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_remote_cluster_ma_active_pds.count) active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_remote_cluster_name)"
                        }
                    #endregion

                    #* retrieve remote vms information
                    #region GET remote_site vms
                        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving virtual machines from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..."
                        $url = "https://{0}:9440/PrismGateway/services/rest/v1/vms/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_vms = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            
                        $myvar_ntnx_remote_cluster_cvms = $myvar_ntnx_remote_cluster_vms.entities | Where-Object {$_.controllerVm -eq $true}
                        $myvar_ntnx_remote_cluster_uvms = $myvar_ntnx_remote_cluster_vms.entities | Where-Object {$_.controllerVm -eq $false} | Where-Object {$_.powerState -eq "on"}
            
                        #building list of uvms
                        [System.Collections.ArrayList]$myvar_ntnx_remote_cluster_uvms_info = New-Object System.Collections.ArrayList($null)
                        ForEach ($myvar_ntnx_remote_cluster_uvm in $myvar_ntnx_remote_cluster_uvms)
                        {#collect specific information for each UVM
                            $myvar_ntnx_remote_cluster_uvm_info = [ordered]@{
                                "vm_name" = $myvar_ntnx_remote_cluster_uvm.vmName;
                                "numVCpus" = $myvar_ntnx_remote_cluster_uvm.numVCpus;
                                "memoryCapacityInGiB" = [math]::round($myvar_ntnx_remote_cluster_uvm.memoryCapacityInBytes /1024 /1024 /1024,0);
                                "host" = $myvar_ntnx_remote_cluster_uvm.hostName;
                                "container_name" = ($myvar_ntnx_remote_cluster_storage_containers.entities | Where-Object {$_.storage_container_uuid -eq $myvar_ntnx_remote_cluster_uvm.containerUuids[0]}).name;
                                "diskCapacityInGiB" = [math]::round($myvar_ntnx_remote_cluster_uvm.diskCapacityInBytes /1024 /1024 /1024,0);
                                "protectionType" = $myvar_ntnx_remote_cluster_uvm.protectionType;
                                "protectionDomainName" = $myvar_ntnx_remote_cluster_uvm.protectionDomainName;
                            }
                            #store the results for this entity in our overall result variable
                            $myvar_ntnx_remote_cluster_uvms_info.Add((New-Object PSObject -Property $myvar_ntnx_remote_cluster_uvm_info)) | Out-Null
                        }
            
                        #figure out which uvms are metro protected
                        [System.Collections.ArrayList]$myvar_ntnx_remote_cluster_ma_uvms = New-Object System.Collections.ArrayList($null)
                        ForEach ($myvar_ntnx_remote_cluster_ma_active_ctr in $myvar_ntnx_remote_cluster_ma_active_ctrs)
                        {#collect VMs in each MA enabled container
                            $myvar_ntnx_remote_cluster_ma_active_ctr_uvms = $myvar_ntnx_remote_cluster_uvms | Where-Object {$_.containerUuids -contains $myvar_ntnx_remote_cluster_ma_active_ctr.uuid}
                            ForEach ($myvar_ntnx_remote_cluster_ma_active_ctr_uvm in $myvar_ntnx_remote_cluster_ma_active_ctr_uvms)
                            {#collect specific information for each UVM
                                $myvar_ntnx_remote_cluster_ma_active_ctr_uvm_info = [ordered]@{
                                    "vm_name" = $myvar_ntnx_remote_cluster_ma_active_ctr_uvm.vmName;
                                    "numVCpus" = $myvar_ntnx_remote_cluster_ma_active_ctr_uvm.numVCpus;
                                    "memoryCapacityInGiB" = [math]::round($myvar_ntnx_remote_cluster_ma_active_ctr_uvm.memoryCapacityInBytes /1024 /1024 /1024,0);
                                    "diskCapacityInGiB" = [math]::round($myvar_ntnx_remote_cluster_ma_active_ctr_uvm.diskCapacityInBytes /1024 /1024 /1024,0);
                                    "host" = $myvar_ntnx_remote_cluster_ma_active_ctr_uvm.hostName;
                                    "container_name" = $myvar_ntnx_remote_cluster_ma_active_ctr.name;
                                    "memoryCapacityInBytes" = $myvar_ntnx_remote_cluster_ma_active_ctr_uvm.memoryCapacityInBytes;
                                    "container_uuid" = $myvar_ntnx_remote_cluster_ma_active_ctr.uuid;
                                }
                                #store the results for this entity in our overall result variable
                                $myvar_ntnx_remote_cluster_ma_uvms.Add((New-Object PSObject -Property $myvar_ntnx_remote_cluster_ma_active_ctr_uvm_info)) | Out-Null
                            }
                        }
                    #endregion
                }
            }          
        #endregion
    #endregion
    Write-Host ""
    
    Write-LogOutput -Category "STEP" -LogFile $myvar_log_file -Message "Computing numbers..."
    #* compute capacity numbers
    #region compute capacity numbers
        #* total clusters capacity (cpu/ram)
        #region total clusters capacity (cpu/ram)
            #for ntnx_cluster
            $myvar_ntnx_cluster_hosts_config |  ForEach-Object {$myvar_ntnx_cluster_cpu_capacity_total += $_.num_cpu_sockets * $_.num_cpu_cores}
            $myvar_ntnx_cluster_ram_gib_capacity_total = [math]::round(($myvar_ntnx_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -sum).Sum / 1024 / 1024 / 1024,0)
            #for ntnx_remote_site_cluster
            if ($myvar_remote_site_online)
            {#remote site is available
                $myvar_ntnx_remote_cluster_hosts_config |  ForEach-Object {$myvar_ntnx_remote_cluster_cpu_capacity_total += $_.num_cpu_sockets * $_.num_cpu_cores}
                $myvar_ntnx_remote_cluster_ram_gib_capacity_total = [math]::round(($myvar_ntnx_remote_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -sum).Sum / 1024 / 1024 / 1024,0)
            }
        #endregion
        
        #* compute number of nodes to take out based on high availability (which is based on RF)
        #for ntnx_cluster
        $myvar_ntnx_cluster_ha_reserved_hosts = $myvar_ntnx_cluster_rf - 1
        $myvar_ntnx_cluster_ha_available_hosts = ($myvar_ntnx_cluster_hosts.entities).count - $myvar_ntnx_cluster_ha_reserved_hosts
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_ha_reserved_hosts = $myvar_ntnx_remote_cluster_rf - 1
            $myvar_ntnx_remote_cluster_ha_available_hosts = ($myvar_ntnx_remote_cluster_hosts.entities).count - $myvar_ntnx_remote_cluster_ha_reserved_hosts
        }

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
            #for ntnx_remote_site_cluster
            if ($myvar_remote_site_online)
            {#remote site is available
                if (!$myvar_cvm_cpu_reservation)
                {#no specific value for $myvar_cvm_cpu_reservation, so we assume add up all cvm vcpus
                    $myvar_ntnx_remote_cluster_cvm_reserved_cpu = ($myvar_ntnx_remote_cluster_cvms | Measure-Object numVCpus -sum).Sum - ($myvar_ntnx_remote_cluster_cvms | Measure-Object numVCpus -Maximum).Maximum * $myvar_ntnx_remote_cluster_ha_reserved_hosts
                }
                else 
                {#a value was specified for $myvar_cvm_cpu_reservation so we multiply that by the number of hosts in the cluster
                    $myvar_ntnx_remote_cluster_cvm_reserved_cpu = $myvar_cvm_cpu_reservation * $myvar_ntnx_remote_cluster_ha_available_hosts
                }
                if (!$myvar_cvm_ram_gib_reservation)
                {#no specific value for $myvar_cvm_ram_gib_reservation, so we assume add up all cvm vram
                    $myvar_ntnx_remote_cluster_cvm_reserved_ram = [math]::round((($myvar_ntnx_remote_cluster_cvms | Measure-Object memoryCapacityInBytes -sum).Sum - (($myvar_ntnx_remote_cluster_cvms | Measure-Object memoryCapacityInBytes -Maximum).Maximum * $myvar_ntnx_remote_cluster_ha_reserved_hosts)) /1024/1024/1024,0)
                }
                else 
                {#a value was specified for $myvar_cvm_ram_gib_reservation so we multiply that by the number of hosts in the cluster
                    $myvar_ntnx_remote_cluster_cvm_reserved_ram = [math]::round($myvar_cvm_cpu_reservation * $myvar_ntnx_remote_cluster_ha_available_hosts /1024/1024/1024,0)
                }
            }
        #endregion
        
        #* hypervisor overhead (cpu/ram)
        #region hypervisor overhead and ha reserved
            #for ntnx_cluster
            $myvar_ntnx_cluster_largest_host_cpu_cores = $myvar_ntnx_cluster_hosts_config | Where-Object {$_.num_cpu_cores -eq (($myvar_ntnx_cluster_hosts_config | Measure-Object num_cpu_cores -Maximum).Maximum)} | Where-Object {$_.num_cpu_sockets -eq (($myvar_ntnx_cluster_hosts_config | Measure-Object num_cpu_sockets -Maximum).Maximum)} | Select-Object -First 1
            $myvar_ntnx_cluster_ha_cpu_reserved = $myvar_ntnx_cluster_largest_host_cpu_cores.num_cpu_cores * $myvar_ntnx_cluster_largest_host_cpu_cores.num_cpu_sockets * $myvar_ntnx_cluster_ha_reserved_hosts
            $myvar_ntnx_cluster_ha_ram_gib_reserved = [math]::round(($myvar_ntnx_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -Maximum).Maximum * $myvar_ntnx_cluster_ha_reserved_hosts /1024/1024/1024,0)
            $myvar_ntnx_cluster_hypervisor_overhead_cpu_total = $myvar_hypervisor_cpu_overhead * $myvar_ntnx_cluster_ha_available_hosts
            $myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total = $myvar_hypervisor_ram_gib_overhead * $myvar_ntnx_cluster_ha_available_hosts
            #for ntnx_remote_site_cluster
            if ($myvar_remote_site_online)
            {#remote site is available
                $myvar_ntnx_remote_cluster_largest_host_cpu_cores = $myvar_ntnx_remote_cluster_hosts_config | Where-Object {$_.num_cpu_cores -eq (($myvar_ntnx_remote_cluster_hosts_config | Measure-Object num_cpu_cores -Maximum).Maximum)} | Where-Object {$_.num_cpu_sockets -eq (($myvar_ntnx_remote_cluster_hosts_config | Measure-Object num_cpu_sockets -Maximum).Maximum)} | Select-Object -First 1
                $myvar_ntnx_remote_cluster_ha_cpu_reserved = $myvar_ntnx_remote_cluster_largest_host_cpu_cores.num_cpu_cores * $myvar_ntnx_remote_cluster_largest_host_cpu_cores.num_cpu_sockets * $myvar_ntnx_remote_cluster_ha_reserved_hosts
                $myvar_ntnx_remote_cluster_ha_ram_gib_reserved = [math]::round(($myvar_ntnx_remote_cluster_hosts_config | Measure-Object memory_capacity_in_bytes -Maximum).Maximum * $myvar_ntnx_remote_cluster_ha_reserved_hosts /1024/1024/1024,0)
                $myvar_ntnx_remote_cluster_hypervisor_overhead_cpu_total = $myvar_hypervisor_cpu_overhead * $myvar_ntnx_remote_cluster_ha_available_hosts
                $myvar_ntnx_remote_cluster_hypervisor_overhead_ram_gib_total = $myvar_hypervisor_ram_gib_overhead * $myvar_ntnx_remote_cluster_ha_available_hosts
            }
        #endregion

        #* uvm clusters capacity (cpu/ram)
        #for ntnx_cluster
        $myvar_ntnx_cluster_uvm_capacity_total_cpu = ($myvar_ntnx_cluster_cpu_capacity_total - $myvar_ntnx_cluster_cvm_reserved_cpu - $myvar_ntnx_cluster_hypervisor_overhead_cpu_total - $myvar_ntnx_cluster_ha_cpu_reserved) * $myvar_cpu_over_subscription_ratio
        $myvar_ntnx_cluster_uvm_capacity_total_ram_gib = ($myvar_ntnx_cluster_ram_gib_capacity_total - $myvar_ntnx_cluster_cvm_reserved_ram - $myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total - $myvar_ntnx_cluster_ha_ram_gib_reserved) * $myvar_ram_over_subscription_ratio
        $myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores = [math]::round(($myvar_desired_capacity_headroom_percentage * $myvar_ntnx_cluster_uvm_capacity_total_cpu) / 100,0)
        $myvar_ntnx_cluster_desired_capacity_headroom_ram_gib = [math]::round(($myvar_desired_capacity_headroom_percentage * $myvar_ntnx_cluster_uvm_capacity_total_ram_gib) / 100,0)
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_uvm_capacity_total_cpu = ($myvar_ntnx_remote_cluster_cpu_capacity_total - $myvar_ntnx_remote_cluster_cvm_reserved_cpu - $myvar_ntnx_remote_cluster_hypervisor_overhead_cpu_total - $myvar_ntnx_remote_cluster_ha_cpu_reserved) * $myvar_cpu_over_subscription_ratio
            $myvar_ntnx_remote_cluster_uvm_capacity_total_ram_gib = ($myvar_ntnx_remote_cluster_ram_gib_capacity_total - $myvar_ntnx_remote_cluster_cvm_reserved_ram - $myvar_ntnx_remote_cluster_hypervisor_overhead_ram_gib_total - $myvar_ntnx_remote_cluster_ha_ram_gib_reserved) * $myvar_ram_over_subscription_ratio
            $myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores = [math]::round(($myvar_desired_capacity_headroom_percentage * $myvar_ntnx_remote_cluster_uvm_capacity_total_cpu) / 100,0)
            $myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib = [math]::round(($myvar_desired_capacity_headroom_percentage * $myvar_ntnx_remote_cluster_uvm_capacity_total_ram_gib) / 100,0)
        }     

        #* uvm allocated (cpu/ram)
        #for ntnx_cluster
        $myvar_ntnx_cluster_uvm_allocated_cpu = ($myvar_ntnx_cluster_uvms | Measure-Object numVCpus -Sum).Sum
        $myvar_ntnx_cluster_uvm_allocated_ram_gib = [math]::round(($myvar_ntnx_cluster_uvms | Measure-Object memoryCapacityInBytes -Sum).Sum /1024/1024/1024,0)
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_uvm_allocated_cpu = ($myvar_ntnx_remote_cluster_uvms | Measure-Object numVCpus -Sum).Sum
            $myvar_ntnx_remote_cluster_uvm_allocated_ram_gib = [math]::round(($myvar_ntnx_remote_cluster_uvms | Measure-Object memoryCapacityInBytes -Sum).Sum /1024/1024/1024,0)
        }

        #* metro uvm allocated (cpu/ram)
        #for ntnx_cluster
        if ($myvar_ntnx_cluster_ma_uvms)
        {#there are powered on vms protected by metro availability
            $myvar_ntnx_cluster_ma_uvm_allocated_cpu = ($myvar_ntnx_cluster_ma_uvms | Measure-Object numVCpus -Sum).Sum
            $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib = [math]::round(($myvar_ntnx_cluster_ma_uvms | Measure-Object memoryCapacityInBytes -Sum).Sum /1024/1024/1024,0)
        }
        else 
        {#there are no powered on vms protected by metro availability
            Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_cluster_name) has no metro protected powered on UVM!"
        }
        #for ntnx_remote_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            if ($myvar_ntnx_remote_cluster_ma_uvms)
            {#there are powered on vms protected by metro availability
                $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu = ($myvar_ntnx_remote_cluster_ma_uvms | Measure-Object numVCpus -Sum).Sum
                $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib = [math]::round(($myvar_ntnx_remote_cluster_ma_uvms | Measure-Object memoryCapacityInBytes -Sum).Sum /1024/1024/1024,0)
            }
            else 
            {#there are no powered on vms protected by metro availability
                Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_remote_cluster_name) has no metro protected powered on UVM!"
            }
        }

        #* uvm remaining (cpu/ram)
        #for ntnx_cluster
        $myvar_ntnx_cluster_uvm_remaining_cpu = $myvar_ntnx_cluster_uvm_capacity_total_cpu - $myvar_ntnx_cluster_uvm_allocated_cpu
        $myvar_ntnx_cluster_uvm_remaining_ram_gib = $myvar_ntnx_cluster_uvm_capacity_total_ram_gib - $myvar_ntnx_cluster_uvm_allocated_ram_gib
        #for ntnx_remote_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_uvm_remaining_cpu = $myvar_ntnx_remote_cluster_uvm_capacity_total_cpu - $myvar_ntnx_remote_cluster_uvm_allocated_cpu
            $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib = $myvar_ntnx_remote_cluster_uvm_capacity_total_ram_gib - $myvar_ntnx_remote_cluster_uvm_allocated_ram_gib
        }

        #* failover capacity
        if ($myvar_remote_site_online)
        {#remote site is available
            #for ntnx_cluster
            if (($myvar_ntnx_remote_cluster_uvm_remaining_cpu -lt $myvar_ntnx_cluster_ma_uvm_allocated_cpu) -and ($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib -lt $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib))
            {#remote site cpu and memory capacity is less than metro uvm allocated: there is insufficient capacity for failover
                $myvar_ntnx_cluster_failover_capacity_status = "Insufficient CPU ($($myvar_ntnx_remote_cluster_uvm_remaining_cpu - $myvar_ntnx_cluster_ma_uvm_allocated_cpu) vcpus) and Memory ($($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib - $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) GiB) on cluster $($myvar_ntnx_remote_cluster_name)"
                $myvar_ntnx_cluster_failover_capacity_color = "Red"
                $myvar_ntnx_cluster_failover_capacity_icon = "bell"
            }
            elseif ($myvar_ntnx_remote_cluster_uvm_remaining_cpu -lt $myvar_ntnx_cluster_ma_uvm_allocated_cpu)
            {#remote site cpu capacity is less than metro uvm allocated: there is insufficient cpu capacity for failover
                $myvar_ntnx_cluster_failover_capacity_status = "Insufficient CPU ($($myvar_ntnx_remote_cluster_uvm_remaining_cpu - $myvar_ntnx_cluster_ma_uvm_allocated_cpu) vcpus) on cluster $($myvar_ntnx_remote_cluster_name)"
                $myvar_ntnx_cluster_failover_capacity_color = "Red"
                $myvar_ntnx_cluster_failover_capacity_icon = "bell"
            }
            elseif ($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib -lt $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) 
            {#remote site memory capacity is less than metro uvm allocated: there is insufficient memory capacity for failover
                $myvar_ntnx_cluster_failover_capacity_status = "Insufficient Memory ($($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib - $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) GiB) on cluster $($myvar_ntnx_remote_cluster_name)"
                $myvar_ntnx_cluster_failover_capacity_color = "Red"
                $myvar_ntnx_cluster_failover_capacity_icon = "bell"
            }
            else 
            {#remote site cpu or memory capacity is more than metro uvm allocated: there is sufficient capacity for failover
                $myvar_ntnx_cluster_failover_capacity_status = "Sufficient CPU ($($myvar_ntnx_remote_cluster_uvm_remaining_cpu - $myvar_ntnx_cluster_ma_uvm_allocated_cpu) vcpus) and Memory ($($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib - $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) GiB) on cluster $($myvar_ntnx_remote_cluster_name)"
                $myvar_ntnx_cluster_failover_capacity_color = "Green"
                $myvar_ntnx_cluster_failover_capacity_icon = "check"
            }

            #for ntnx_remote_cluster
            if (($myvar_ntnx_cluster_uvm_remaining_cpu -lt $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu) -and ($myvar_ntnx_cluster_uvm_remaining_ram_gib -lt $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib))
            {#remote site cpu and memory capacity is less than metro uvm allocated: there is insufficient capacity for failover
                $myvar_ntnx_remote_cluster_failover_capacity_status = "Insufficient CPU ($($myvar_ntnx_cluster_uvm_remaining_cpu - $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu) vcpus) and Memory ($($myvar_ntnx_cluster_uvm_remaining_ram_gib - $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib) GiB) on cluster $($myvar_ntnx_cluster_name)"
                $myvar_ntnx_remote_cluster_failover_capacity_color = "Red"
                $myvar_ntnx_remote_cluster_failover_capacity_icon = "bell"
            }
            elseif ($myvar_ntnx_cluster_uvm_remaining_cpu -lt $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu)
            {#remote site cpu capacity is less than metro uvm allocated: there is insufficient cpu capacity for failover
                $myvar_ntnx_remote_cluster_failover_capacity_status = "Insufficient CPU ($($myvar_ntnx_cluster_uvm_remaining_cpu - $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu) vcpus) on cluster $($myvar_ntnx_cluster_name)"
                $myvar_ntnx_remote_cluster_failover_capacity_color = "Red"
                $myvar_ntnx_remote_cluster_failover_capacity_icon = "bell"
            }
            elseif ($myvar_ntnx_cluster_uvm_remaining_ram_gib -lt $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib) 
            {#remote site memory capacity is less than metro uvm allocated: there is insufficient memory capacity for failover
                $myvar_ntnx_remote_cluster_failover_capacity_status = "Insufficient Memory ($($myvar_ntnx_cluster_uvm_remaining_ram_gib - $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib) GiB) on cluster $($myvar_ntnx_cluster_name)"
                $myvar_ntnx_remote_cluster_failover_capacity_color = "Red"
                $myvar_ntnx_remote_cluster_failover_capacity_icon = "bell"
            }
            else 
            {#remote site cpu or memory capacity is more than metro uvm allocated: there is sufficient capacity for failover
                $myvar_ntnx_remote_cluster_failover_capacity_status = "Sufficient CPU ($($myvar_ntnx_cluster_uvm_remaining_cpu - $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu) vcpus) and Memory ($($myvar_ntnx_cluster_uvm_remaining_ram_gib - $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib) GiB) on cluster $($myvar_ntnx_cluster_name)"
                $myvar_ntnx_remote_cluster_failover_capacity_color = "Green"
                $myvar_ntnx_remote_cluster_failover_capacity_icon = "check"
            }
        }

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
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_general_information = [ordered]@{
                "Cluster Name" = $myvar_ntnx_remote_cluster_name;
                "Replication Factor" = $myvar_ntnx_remote_cluster_rf;
                "AOS Version" = $myvar_ntnx_remote_cluster_info.version;
                "Hypervisor" = ($myvar_ntnx_remote_cluster_info.hypervisor_types)[0];
                "Number of Nodes" = $myvar_ntnx_remote_cluster_info.num_nodes;
                "Total CPU cores Capacity" = $myvar_ntnx_remote_cluster_cpu_capacity_total;
                "Total RAM GiB Capacity" = $myvar_ntnx_remote_cluster_ram_gib_capacity_total;
                "Actual cores:vcpus ratio" = [math]::round(($myvar_ntnx_remote_cluster_uvm_allocated_cpu + ($myvar_ntnx_remote_cluster_cvms | Measure-Object numVCpus -sum).Sum) / $myvar_ntnx_remote_cluster_cpu_capacity_total,1);
            }
        }

        #report configuration
        $myvar_report_configuration_settings = [ordered]@{
            "Configured CPU Oversubscription Ratio" = $myvar_cpu_over_subscription_ratio;
            "Configured Memory Oversubscription Ratio" = $myvar_ram_over_subscription_ratio;
            "Configured CVM CPU Reservation"  = $myvar_cvm_cpu_reservation;
            "Configured CVM RAM Reservation" = $myvar_cvm_ram_gib_reservation;
            "Configured Hypervisor CPU cores Overhead" = $myvar_hypervisor_cpu_overhead;
            "Configured Hypervisor RAM GiB Overhead" = $myvar_hypervisor_ram_gib_overhead;
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
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_reserved_capacity = [ordered]@{
                "CPU cores Reserved for CVMs" = $myvar_ntnx_remote_cluster_cvm_reserved_cpu;
                "Memory GiB Reserved for CVMs" = $myvar_ntnx_remote_cluster_cvm_reserved_ram;
                "CPU cores Reserved for High Availability" = $myvar_ntnx_remote_cluster_ha_cpu_reserved;
                "Memory GiB Reserved for High Availability" = $myvar_ntnx_remote_cluster_ha_ram_gib_reserved;
                "CPU cores Reserved for Hypervisor Overhead" = $myvar_ntnx_remote_cluster_hypervisor_overhead_cpu_total;
                "Memory GiB Reserved for Hypervisor Overhead" = $myvar_ntnx_remote_cluster_hypervisor_overhead_ram_gib_total;
                "Total CPU cores Reserved" = $myvar_ntnx_remote_cluster_cvm_reserved_cpu + $myvar_ntnx_remote_cluster_ha_cpu_reserved + $myvar_ntnx_remote_cluster_hypervisor_overhead_cpu_total;
                "Total Memory GiB Reserved" = $myvar_ntnx_remote_cluster_cvm_reserved_ram + $myvar_ntnx_remote_cluster_ha_ram_gib_reserved + $myvar_ntnx_remote_cluster_hypervisor_overhead_ram_gib_total
            }
        }

        #uvm capacities
        $myvar_ntnx_cluster_uvm_capacity = [ordered]@{
            "Total vCPUs Capacity for UVMs" = $myvar_ntnx_cluster_uvm_capacity_total_cpu;
            "Total Memory GiB Capacity for UVMs" = $myvar_ntnx_cluster_uvm_capacity_total_ram_gib;
            "vCPUs Allocated to UVMs" = $myvar_ntnx_cluster_uvm_allocated_cpu;
            "Memory GiB Allocated to UVMs" = $myvar_ntnx_cluster_uvm_allocated_ram_gib;
            "Remaining vCPUs for UVMs" = $myvar_ntnx_cluster_uvm_remaining_cpu;
            "Remaining Memory GiB for UVMs" = $myvar_ntnx_cluster_uvm_remaining_ram_gib;
        }
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            $myvar_ntnx_remote_cluster_uvm_capacity = [ordered]@{
                "Total vCPUs Capacity for UVMs" = $myvar_ntnx_remote_cluster_uvm_capacity_total_cpu;
                "Total Memory GiB Capacity for UVMs" = $myvar_ntnx_remote_cluster_uvm_capacity_total_ram_gib;
                "vCPUs Allocated to UVMs" = $myvar_ntnx_remote_cluster_uvm_allocated_cpu;
                "Memory GiB Allocated to UVMs" = $myvar_ntnx_remote_cluster_uvm_allocated_ram_gib;
                "Remaining vCPUs for UVMs" = $myvar_ntnx_remote_cluster_uvm_remaining_cpu;
                "Remaining Memory GiB for UVMs" = $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib;
            }
        }

        #metro availability capacity
        if ($myvar_ntnx_cluster_ma_uvms)
        {#there are powered on vms protected by metro availability
            $myvar_ntnx_cluster_ma_uvms_capacity_allocated = [ordered]@{
                "vCPUs Allocated to metro protected UVMs" = $myvar_ntnx_cluster_ma_uvm_allocated_cpu;
                "Memory GiB Allocated to metro protected UVMs" = $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib
            }
        }
        #for ntnx_remote_site_cluster
        if ($myvar_remote_site_online)
        {#remote site is available
            if ($myvar_ntnx_remote_cluster_ma_uvms)
            {#there are powered on vms protected by metro availability
                $myvar_ntnx_remote_cluster_ma_uvms_capacity_allocated = [ordered]@{
                    "vCPUs Allocated to metro protected UVMs" = $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu;
                    "Memory GiB Allocated to metro protected UVMs" = $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib
                }
            }
        }
    #endregion
    Write-Host ""
    
    #* create output
    #region create output
        #* html output
        #region html output
            if ($html) 
            {#we need html output
                Write-LogOutput -Category "STEP" -LogFile $myvar_log_file -Message "Creating HTML report in file $($dir)$($myvar_html_report_name)..."

                #region determine colors for status widgets
                    if ($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_cluster_uvm_remaining_cpu)
                    {#there is enough remaining cpu capacity
                        $myvar_ntnx_cluster_cpu_color = "Green"
                    }
                    else 
                    {#there is not enough cpu capacity remaining
                        $myvar_ntnx_cluster_cpu_color = "Red"
                    }

                    if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
                    {#there is enough remaining memory capacity
                        $myvar_ntnx_cluster_memory_color = "Green"
                    }
                    else 
                    {#there is not enough memory capacity remaining
                        $myvar_ntnx_cluster_memory_color = "Red"
                    }

                    if ($myvar_remote_site_online)
                    {#remote site is available
                        if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_remote_cluster_uvm_remaining_cpu)
                        {#there is enough remaining cpu capacity
                            $myvar_ntnx_remote_cluster_cpu_color = "Green"
                        }
                        else 
                        {#there is not enough cpu capacity remaining
                            $myvar_ntnx_remote_cluster_cpu_color = "Red"
                        }

                        if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib)
                        {#there is enough remaining memory capacity
                            $myvar_ntnx_remote_cluster_memory_color = "Green"
                        }
                        else 
                        {#there is not enough memory capacity remaining
                            $myvar_ntnx_remote_cluster_memory_color = "Red"
                        }

                        $myvar_ntnx_cluster_widget_header = "$myvar_ntnx_cluster_name Metro Failover"
                        $myvar_ntnx_remote_cluster_widget_header = "$myvar_ntnx_remote_cluster_name Metro Failover"
                    }
                #endregion

                #* html report creation/formatting starts here
                $myvar_html_report = New-Html -TitleText "Capacity Report" -Online {
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

                    #* this is the collapsed general info section at the top which contains configuration settings and cluster details
                    New-HtmlSection -HeaderText "General Information" -Wrap wrap -CanCollapse  -Collapsed -HeaderBackGroundColor "#168CF5" -HeaderTextColor White -Direction Row {
                        New-HtmlSection -HeaderText "Report Configuration Settings" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_report_configuration_settings) -HideFooter
                        }
                        New-HtmlSection -HeaderText "$($myvar_ntnx_cluster_name)" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_ntnx_cluster_general_information) -HideFooter
                            New-HtmlTable -DataTable ($myvar_ntnx_cluster_reserved_capacity) -HideFooter
                        }
                        if ($myvar_remote_site_online)
                        {#remote site is available
                            New-HtmlSection -HeaderText "$($myvar_ntnx_remote_cluster_name)" -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                                New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_general_information) -HideFooter
                                New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_reserved_capacity) -HideFooter
                            }
                        }
                    }

                    #* this is the section containing the metro failover capability status widgets
                    if ($myvar_remote_site_online)
                    {#remote site is available
                        New-HtmlSection -HeaderText "Metro Failover Capability" -Wrap wrap -CanCollapse -HeaderBackGroundColor "#024DA1" -HeaderTextColor White {
                            #showing capacity status widget
                            New-HTMLPanel -Invisible {   
                                New-HTMLToast -TextHeader $myvar_ntnx_cluster_widget_header -Text $myvar_ntnx_cluster_failover_capacity_status -TextColor $myvar_ntnx_cluster_failover_capacity_color -TextHeaderColor $myvar_ntnx_cluster_failover_capacity_color -BarColorLeft $myvar_ntnx_cluster_failover_capacity_color -BarColorRight $myvar_ntnx_cluster_failover_capacity_color -IconSolid $myvar_ntnx_cluster_failover_capacity_icon -IconColor $myvar_ntnx_cluster_failover_capacity_color
                                New-HTMLToast -TextHeader $myvar_ntnx_remote_cluster_widget_header -Text $myvar_ntnx_remote_cluster_failover_capacity_status -TextColor $myvar_ntnx_remote_cluster_failover_capacity_color -TextHeaderColor $myvar_ntnx_remote_cluster_failover_capacity_color -BarColorLeft $myvar_ntnx_remote_cluster_failover_capacity_color -BarColorRight $myvar_ntnx_remote_cluster_failover_capacity_color -IconSolid $myvar_ntnx_remote_cluster_failover_capacity_icon -IconColor $myvar_ntnx_remote_cluster_failover_capacity_color
                            }
                        }
                    }

                    #* this is the section containing virtual machines capacity details
                    New-HtmlSection -HeaderText "UVM Capacity" -Wrap wrap -CanCollapse -Collapsed -HeaderBackGroundColor "#024DA1" -HeaderTextColor White {
                        
                        #showing capacity numbers for the queried cluster
                        New-HtmlSection -HeaderText "$($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White -Wrap wrap {
                            #* showing capacity status widget
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
                            
                            #* showing capacity numbers 
                            New-HtmlTable -DataTable ($myvar_ntnx_cluster_uvm_capacity) -HideFooter {
                                #New-HTMLTableCondition -Name 'HandleCount' -Type number -Operator gt -Value 300 -BackgroundColor Yellow
                                #New-HTMLTableCondition -Name 'ID' -Type number -Operator gt -Value 16000 -BackgroundColor Green
                                New-HTMLTableCondition -Name 'Name' -Type string -Operator eq -Value 'Remaining vCPUs for UVMs' -BackgroundColor $myvar_ntnx_cluster_cpu_color -Row -Color White
                                New-HTMLTableCondition -Name 'Name' -Type string -Operator eq -Value 'Remaining Memory GiB for UVMs' -BackgroundColor $myvar_ntnx_cluster_memory_color -Row  -Color White
                            }

                            #* showing capacity bar graphs
                            if ($myvar_ntnx_cluster_ma_uvms)
                            {#there are powered on vms protected by metro availability
                                New-HTMLPanel {
                                    New-HTMLChart {
                                        New-ChartToolbar -Download
                                        New-ChartBarOptions -Type barStacked
                                        New-ChartLegend -Name 'Free', 'Allocated', 'Metro'
                                        New-ChartBar -Name 'vCPUs' -Value $myvar_ntnx_cluster_uvm_remaining_cpu, ($myvar_ntnx_cluster_uvm_allocated_cpu - $myvar_ntnx_cluster_ma_uvm_allocated_cpu), $myvar_ntnx_cluster_ma_uvm_allocated_cpu
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
                                        New-ChartBar -Name 'vCPUs' -Value $myvar_ntnx_cluster_uvm_remaining_cpu, $myvar_ntnx_cluster_uvm_allocated_cpu
                                        New-ChartBar -Name 'Memory GiB' -Value $myvar_ntnx_cluster_uvm_remaining_ram_gib, $myvar_ntnx_cluster_uvm_allocated_ram_gib
                                    }
                                }
                            }
                        }
                        
                        #* showing capacity details for metro protected uvms
                        if ($myvar_ntnx_cluster_ma_uvms)
                        {#there are powered on vms protected by metro availability
                            New-HtmlSection -HeaderText "Metro enabled UVM Allocated Capacity for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                                New-HtmlTable -DataTable ($myvar_ntnx_cluster_ma_uvms_capacity_allocated) -HideFooter
                            }
                        }

                        
                        #* showing stuff for the remote site
                        if ($myvar_remote_site_online)
                        {#remote site is available
                            #* showing capacity numbers for the remote cluster
                            New-HtmlSection -HeaderText "$($myvar_ntnx_remote_cluster_name)" -CanCollapse -Collapsed -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White -Wrap wrap {
                                #* showing capacity status widget
                                New-HTMLPanel -Invisible {   
                                    if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_remote_cluster_uvm_remaining_cpu)
                                    {#there is enough remaining cpu capacity
                                        #New-HTMLStatusItem -Name 'Remaining CPU Capacity' -Status 'Good' -Percentage '100%'
                                        New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                                    }
                                    else 
                                    {#there is not enough cpu capacity remaining
                                        #New-HTMLStatusItem -Name 'Remaining CPU Capacity' -Status 'Dead' -Percentage '0%'
                                        New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                                    }

                                    if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib)
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
                                
                                #* showing capacity numbers 
                                New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_uvm_capacity) -HideFooter {
                                    #New-HTMLTableCondition -Name 'HandleCount' -Type number -Operator gt -Value 300 -BackgroundColor Yellow
                                    #New-HTMLTableCondition -Name 'ID' -Type number -Operator gt -Value 16000 -BackgroundColor Green
                                    New-HTMLTableCondition -Name 'Name' -Type string -Operator eq -Value 'Remaining vCPUs for UVMs' -BackgroundColor $myvar_ntnx_remote_cluster_cpu_color -Row -Color White
                                    New-HTMLTableCondition -Name 'Name' -Type string -Operator eq -Value 'Remaining Memory GiB for UVMs' -BackgroundColor $myvar_ntnx_remote_cluster_memory_color -Row  -Color White
                                }

                                #* showing capacity graphs
                                if ($myvar_ntnx_remote_cluster_ma_uvms)
                                {#there are powered on vms protected by metro availability
                                    New-HTMLPanel {
                                        New-HTMLChart {
                                            New-ChartToolbar -Download
                                            New-ChartBarOptions -Type barStacked
                                            New-ChartLegend -Name 'Free', 'Allocated', 'Metro'
                                            New-ChartBar -Name 'vCPUs' -Value $myvar_ntnx_remote_cluster_uvm_remaining_cpu, ($myvar_ntnx_remote_cluster_uvm_allocated_cpu - $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu), $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu
                                            New-ChartBar -Name 'Memory GiB' -Value $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib, ($myvar_ntnx_remote_cluster_uvm_allocated_ram_gib - $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib), $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib
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
                                            New-ChartBar -Name 'vCPUs' -Value $myvar_ntnx_remote_cluster_uvm_remaining_cpu, $myvar_ntnx_remote_cluster_uvm_allocated_cpu
                                            New-ChartBar -Name 'Memory GiB' -Value $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib, $myvar_ntnx_remote_cluster_uvm_allocated_ram_gib
                                        }
                                    }
                                }
                            }
                            
                            #showing capacity details for metro protected uvms
                            if ($myvar_ntnx_remote_cluster_ma_uvms)
                            {#there are powered on vms protected by metro availability
                                New-HtmlSection -HeaderText "Metro enabled UVM Allocated Capacity for $($myvar_ntnx_remote_cluster_name)" -CanCollapse -Collapsed -HeaderBackGroundColor "#3ABFEF" -HeaderTextColor White {
                                    New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_ma_uvms_capacity_allocated) -HideFooter
                                }
                            }
                        }
                    }

                    #showing queried cluster details of metro enabled uvms
                    if ($myvar_ntnx_cluster_ma_uvms)
                    {#there are powered on vms protected by metro availability
                        New-HtmlSection -HeaderText "Metro enabled UVMs details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_ntnx_cluster_ma_uvms) -HideFooter
                        }
                    }

                    #showing remote cluster details of metro enabled uvms
                    if ($myvar_remote_site_online)
                    {#remote site is available
                        if ($myvar_ntnx_remote_cluster_ma_uvms)
                        {#there are powered on vms protected by metro availability
                            New-HtmlSection -HeaderText "Metro enabled UVMs details for $($myvar_ntnx_remote_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                                New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_ma_uvms) -HideFooter
                            }
                        }
                    }

                    #showing queried cluster hosts details
                    New-HtmlSection -HeaderText "Hosts details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_hosts_config) -HideFooter
                    }

                    #showing remote cluster hosts details
                    if ($myvar_remote_site_online)
                    {#remote site is available
                        New-HtmlSection -HeaderText "Hosts details for $($myvar_ntnx_remote_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_hosts_config) -HideFooter
                        }
                    }
                    
                    #showing queried cluster uvms details
                    New-HtmlSection -HeaderText "UVM details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_uvms_info) -HideFooter
                    }
                    
                    #showing remote cluster uvms details
                    if ($myvar_remote_site_online)
                    {#remote site is available
                        New-HtmlSection -HeaderText "UVM details for $($myvar_ntnx_remote_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_uvms_info) -HideFooter
                        }
                    }

                    #showing queried cluster storage containers details
                    New-HtmlSection -HeaderText "Storage containers details for $($myvar_ntnx_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                        New-HtmlTable -DataTable ($myvar_ntnx_cluster_storage_containers_info) -HideFooter
                    }

                    #showing remote cluster storage containers details
                    if ($myvar_remote_site_online)
                    {#remote site is available
                        New-HtmlSection -HeaderText "Storage containers details for $($myvar_ntnx_remote_cluster_name)" -CanCollapse -Collapsed  -HeaderBackGroundColor "#AFD135" -HeaderTextColor White {
                            New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_storage_containers_info) -HideFooter
                        }
                    }
                }
                $myvar_html_report | Out-File -FilePath $($myvar_html_report_name)
                Write-Host ""

                if ($viewnow)
                {#open the html report now in the default browser
                    Invoke-Item $myvar_html_report_name
                }
            }
        #endregion
        
        #* console output
        #region console output
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_cluster_name) replication factor is $($myvar_ntnx_cluster_rf)"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cpu_capacity_total) cores"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ram_gib_capacity_total) GiB"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "CPU reserved for high availability for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ha_cpu_reserved) cores"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "RAM reserved for high availability for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ha_ram_gib_reserved) GiB"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "CVM CPU reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_cpu)"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "CVM RAM reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_ram) GiB"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Hypervisor CPU overhead for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_hypervisor_overhead_cpu_total)"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Hypervisor RAM overhead for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total) GiB"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_capacity_total_cpu) vCPUs"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_capacity_total_ram_gib) GiB"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_allocated_cpu) vCPUs"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_allocated_ram_gib) GiB"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM remaining CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_remaining_cpu) vCPUs"
            Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM remaining RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_remaining_ram_gib) GiB"
            if ($myvar_ntnx_cluster_ma_uvms)
            {#there are powered on vms protected by metro availability
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Metro enabled UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ma_uvm_allocated_cpu) cores"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Metro enabled UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) GiB"
            }

            #* checking remaining capacity is sufficient
            if ($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_cluster_uvm_remaining_cpu)
            {#there is enough remaining cpu capacity
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores) vCPUs."
            }
            else 
            {#there is not enough cpu capacity remaining
                Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores) vCPUs!"
            }
            if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
            {#there is enough remaining memory capacity
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib) GiB."
            }
            else 
            {#there is not enough memory capacity remaining
                Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib) GiB!"
            }

            if ($myvar_remote_site_online)
            {#remote site is available
                Write-Host ""
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster $($myvar_ntnx_remote_cluster_name) replication factor is $($myvar_remote_ntnx_cluster_rf)"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Total CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_cpu_capacity_total) cores"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Total RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ram_gib_capacity_total) GiB"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "CPU reserved for high availability for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ha_cpu_reserved) cores"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "RAM reserved for high availability for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ha_ram_gib_reserved) GiB"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "CVM CPU reserved capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_cvm_reserved_cpu)"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "CVM RAM reserved capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_cvm_reserved_ram) GiB"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Hypervisor CPU overhead for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_hypervisor_overhead_cpu_total)"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Hypervisor RAM overhead for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_hypervisor_overhead_ram_gib_total) GiB"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM total CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_capacity_total_cpu) vCPUs"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM total RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_capacity_total_ram_gib) GiB"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_allocated_cpu) vCPUs"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_allocated_ram_gib) GiB"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM remaining CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_remaining_cpu) vCPUs"
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "UVM remaining RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib) GiB"
                if ($myvar_ntnx_remote_cluster_ma_uvms)
                {#there are powered on vms protected by metro availability
                    Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Metro enabled UVM allocated vCPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu) vCPUs"
                    Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Metro enabled UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib) GiB"
                }

                #* checking remaining capacity is sufficient
                if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_remote_cluster_uvm_remaining_cpu)
                {#there is enough remaining cpu capacity
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_remote_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores) vCPUs."
                }
                else 
                {#there is not enough cpu capacity remaining
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_remote_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores) vCPUs!"
                }
                if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
                {#there is enough remaining memory capacity
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib) GiB."
                }
                else 
                {#there is not enough memory capacity remaining
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There are $($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib) GiB!"
                }

                Write-Host ""
                if ($myvar_ntnx_cluster_failover_capacity_color -eq "Green")
                {#capacity is green
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Cluster $($myvar_ntnx_cluster_name) Metro Failover capability is: $($myvar_ntnx_cluster_failover_capacity_status)"
                }
                elseif ($myvar_ntnx_cluster_failover_capacity_color -eq "Red")
                {#capacity is red
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Cluster $($myvar_ntnx_cluster_name) Metro Failover capability is: $($myvar_ntnx_cluster_failover_capacity_status)"
                }

                if ($myvar_ntnx_remote_cluster_failover_capacity_color -eq "Green")
                {#capacity is green
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Cluster $($myvar_ntnx_remote_cluster_name) Metro Failover capability is: $($myvar_ntnx_remote_cluster_failover_capacity_status)"
                }
                elseif ($myvar_ntnx_remote_cluster_failover_capacity_color -eq "Red")
                {#capacity is red
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Cluster $($myvar_ntnx_remote_cluster_name) Metro Failover capability is: $($myvar_ntnx_remote_cluster_failover_capacity_status)"
                }
                Write-Host ""
            }
        #endregion

        #* influxdb output
        #region influxdb output
            if ($influxdb)
            {#we need to insert data into influxdb database
                try 
                {#sending data to influxdb
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Sending UVM capacity data for cluster $($myvar_ntnx_cluster_name) to InfluxDB server $($myvar_influxdb_url) in database $($myvar_influxdb_database) as time series uvm_capacity..."
                    if ($myvar_ntnx_cluster_ma_uvms)
                    {#there are powered on vms protected by metro availability
                        Write-Influx -Measure uvm_capacity -Tags @{cluster=$myvar_ntnx_cluster_name} -Metrics @{
                            cpu_failover_capacity=$($myvar_ntnx_remote_cluster_uvm_remaining_cpu - $myvar_ntnx_cluster_ma_uvm_allocated_cpu);
                            ram_failover_capacity=$($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib - $myvar_ntnx_cluster_ma_uvm_allocated_ram_gib);
                            cpu_remaining_capacity=$myvar_ntnx_cluster_uvm_remaining_cpu;
                            ram_remaining_capacity=$myvar_ntnx_cluster_uvm_remaining_ram_gib;
                            metro_uvm_allocated_cpu=$myvar_ntnx_cluster_ma_uvm_allocated_cpu;
                            metro_uvm_allocated_ram_gib=$myvar_ntnx_cluster_ma_uvm_allocated_ram_gib;
                        } -Database $myvar_influxdb_database -Credential $influxdbCredentials -Server $myvar_influxdb_url -ErrorAction Stop
                    }
                    else 
                    {#there no metro availability vms
                        Write-Influx -Measure uvm_capacity -Tags @{cluster=$myvar_ntnx_cluster_name} -Metrics @{
                            cpu_remaining_capacity=$myvar_ntnx_cluster_uvm_remaining_cpu;
                            ram_remaining_capacity=$myvar_ntnx_cluster_uvm_remaining_ram_gib;
                        } -Database $myvar_influxdb_database -Credential $influxdbCredentials -Server $myvar_influxdb_url -ErrorAction Stop
                    }

                    if ($myvar_remote_site_online)
                    {#remote site is available
                        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Sending UVM capacity data for cluster $($myvar_ntnx_remote_cluster_name) to InfluxDB server $($myvar_influxdb_url) in database $($myvar_influxdb_database) as time series uvm_capacity..."
                        if ($myvar_ntnx_remote_cluster_ma_uvms)
                        {#there are powered on vms protected by metro availability
                            Write-Influx -Measure uvm_capacity -Tags @{cluster=$myvar_ntnx_remote_cluster_name} -Metrics @{
                                cpu_failover_capacity=$($myvar_ntnx_cluster_uvm_remaining_cpu - $myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu);
                                ram_failover_capacity=$($myvar_ntnx_cluster_uvm_remaining_ram_gib - $myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib);
                                cpu_remaining_capacity=$myvar_ntnx_remote_cluster_uvm_remaining_cpu;
                                ram_remaining_capacity=$myvar_ntnx_remote_cluster_uvm_remaining_ram_gib;
                                metro_uvm_allocated_cpu=$myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu;
                                metro_uvm_allocated_ram_gib=$myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib;
                            } -Database $myvar_influxdb_database -Credential $influxdbCredentials -Server $myvar_influxdb_url -ErrorAction Stop
                        }
                        else 
                        {#there no metro availability vms
                            Write-Influx -Measure uvm_capacity -Tags @{cluster=$myvar_ntnx_remote_cluster_name} -Metrics @{
                                cpu_remaining_capacity=$myvar_ntnx_remote_cluster_uvm_remaining_cpu;
                                ram_remaining_capacity=$myvar_ntnx_remote_cluster_uvm_remaining_ram_gib;
                            } -Database $myvar_influxdb_database -Credential $influxdbCredentials -Server $myvar_influxdb_url -ErrorAction Stop
                        }
                    }
                }
                catch 
                {#could not send data to influxdb
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Could not send data to influxdb: $($_.Exception.Message)"
                }
            }
        #endregion

        #todo: smtp output
        #region smtp output
            
        #endregion
    #endregion
#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-LogOutput -Category "SUM" -LogFile $myvar_log_file -Message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion