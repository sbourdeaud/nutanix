<#
.SYNOPSIS
  This script generates a csv containing stats for the specified cluster performance metric for the given time period.
.DESCRIPTION
  The script uses v2 REST API in Prism to GET stats using the /clusters/stats endpoint.

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
.PARAMETER hour
  Will set the start time and end time to match the last 1 hour minus 5 minutes.
.PARAMETER day
  Will set the start time and end time to match the last 24 hours minus 5 minutes.
.PARAMETER week
  Will set the start time and end time to match the last 7 days minus 5 minutes.
.PARAMETER month
  Will set the start time and end time to match the last 28 days minus 5 minutes.
.PARAMETER startdate
  Specifies the start date in the "DD/MM/YYYY" format (depending on your locale; this will actually accept any date time format).
.PARAMETER enddate
  Specifies the end date in the "DD/MM/YYYY" format (depending on your locale; this will actually accept any date time format).
.PARAMETER interval
  Specifies the stats interval in seconds (default is 60 seconds; depending on the time period, this can usually be no smaller than 30 seconds).
.PARAMETER metric
  Specify the name of the performance metric (for a full list of available metrics, use the API explorer documentation; some popular examples are: controller_avg_io_latency_usecs, controller_io_bandwidth_kBps, num_iops, hypervisor_cpu_usage_ppm, hypervisor_memory_usage_ppm).  You can TAB a couple times to see which metrics are available.
.PARAMETER overview
  Will generate csvs for each of the following metrics: controller_avg_io_latency_usecs, controller_io_bandwidth_kBps, num_iops, hypervisor_cpu_usage_ppm, hypervisor_memory_usage_ppm.
.PARAMETER graph
  Will generate bar graphs in the console in addition to the csv files (using this parameter will install an external module from the PowerShell library).
.PARAMETER influxdb
  Specifies you want to send data to influxdb server. You will need to configure the influxdb server URL and database instance in the variables section of this script.  The timeseries created by default is called ntnx_cluster_stats.
.PARAMETER influxdbCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$influxdbCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\get-ntnxClusterStats.ps1 -cluster ntnxc1.local -overview -week
Generate one csv file per overview metric for the last 7 days.

.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
#>

#TODO: graphs - deal with unplotted values (because single linear value or below first y axis step)

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [switch]$hour,
        [parameter(mandatory = $false)] [switch]$day,
        [parameter(mandatory = $false)] [switch]$week,
        [parameter(mandatory = $false)] [switch]$month,
        [parameter(mandatory = $false)] [switch]$overview,
        [parameter(mandatory = $false)] [int]$interval,
        [parameter(mandatory = $false)] [Datetime]$startdate,
        [parameter(mandatory = $false)] [Datetime]$enddate,
        
        [parameter(mandatory = $false)]
        [ValidateSet(
            "hypervisor_avg_io_latency_usecs",
            "num_read_iops",
            "hypervisor_write_io_bandwidth_kBps",
            "timespan_usecs",
            "controller_num_read_iops",
            "read_io_ppm",
            "controller_num_iops",
            "total_read_io_time_usecs",
            "controller_total_read_io_time_usecs",
            "replication_transmitted_bandwidth_kBps",
            "hypervisor_num_io",
            "controller_total_transformed_usage_bytes",
            "hypervisor_cpu_usage_ppm",
            "controller_num_write_io",
            "avg_read_io_latency_usecs",
            "content_cache_logical_ssd_usage_bytes",
            "controller_total_io_time_usecs",
            "controller_total_read_io_size_kbytes",
            "controller_num_seq_io",
            "controller_read_io_ppm",
            "content_cache_num_lookups",
            "controller_total_io_size_kbytes",
            "content_cache_hit_ppm",
            "controller_num_io",
            "hypervisor_avg_read_io_latency_usecs",
            "content_cache_num_dedup_ref_count_pph",
            "num_write_iops",
            "controller_num_random_io",
            "num_iops",
            "replication_received_bandwidth_kBps",
            "hypervisor_num_read_io",
            "hypervisor_total_read_io_time_usecs",
            "controller_avg_io_latency_usecs",
            "hypervisor_hyperv_cpu_usage_ppm",
            "num_io",
            "controller_num_read_io",
            "hypervisor_num_write_io",
            "controller_seq_io_ppm",
            "controller_read_io_bandwidth_kBps",
            "controller_io_bandwidth_kBps",
            "hypervisor_hyperv_memory_usage_ppm",
            "hypervisor_timespan_usecs",
            "hypervisor_num_write_iops",
            "replication_num_transmitted_bytes",
            "total_read_io_size_kbytes",
            "hypervisor_total_io_size_kbytes",
            "avg_io_latency_usecs",
            "hypervisor_num_read_iops",
            "content_cache_saved_ssd_usage_bytes",
            "controller_write_io_bandwidth_kBps",
            "controller_write_io_ppm",
            "hypervisor_avg_write_io_latency_usecs",
            "hypervisor_total_read_io_size_kbytes",
            "read_io_bandwidth_kBps",
            "hypervisor_esx_memory_usage_ppm",
            "hypervisor_memory_usage_ppm",
            "hypervisor_num_iops",
            "hypervisor_io_bandwidth_kBps",
            "controller_num_write_iops",
            "total_io_time_usecs",
            "hypervisor_kvm_cpu_usage_ppm",
            "content_cache_physical_ssd_usage_bytes",
            "controller_random_io_ppm",
            "controller_avg_read_io_size_kbytes",
            "total_transformed_usage_bytes",
            "avg_write_io_latency_usecs",
            "num_read_io",
            "write_io_bandwidth_kBps",
            "hypervisor_read_io_bandwidth_kBps",
            "random_io_ppm",
            "content_cache_num_hits",
            "total_untransformed_usage_bytes",
            "hypervisor_total_io_time_usecs",
            "num_random_io",
            "hypervisor_kvm_memory_usage_ppm",
            "controller_avg_write_io_size_kbytes",
            "controller_avg_read_io_latency_usecs",
            "num_write_io",
            "hypervisor_esx_cpu_usage_ppm",
            "total_io_size_kbytes",
            "io_bandwidth_kBps",
            "content_cache_physical_memory_usage_bytes",
            "replication_num_received_bytes",
            "controller_timespan_usecs",
            "num_seq_io",
            "content_cache_saved_memory_usage_bytes",
            "seq_io_ppm",
            "write_io_ppm",
            "controller_avg_write_io_latency_usecs",
            "content_cache_logical_memory_usage_bytes",
            "data_reduction.overall.saving_ratio_ppm",
            "storage.reserved_free_bytes",
            "storage_tier.das-sata.usage_bytes",
            "data_reduction.compression.saved_bytes",
            "data_reduction.saving_ratio_ppm",
            "data_reduction.erasure_coding.post_reduction_bytes",
            "storage_tier.ssd.pinned_usage_bytes",
            "storage.reserved_usage_bytes",
            "data_reduction.erasure_coding.saving_ratio_ppm",
            "data_reduction.thin_provision.saved_bytes",
            "storage_tier.das-sata.capacity_bytes",
            "storage_tier.das-sata.free_bytes",
            "storage.usage_bytes",
            "data_reduction.erasure_coding.saved_bytes",
            "data_reduction.compression.pre_reduction_bytes",
            "storage_tier.das-sata.pinned_bytes",
            "storage_tier.das-sata.pinned_usage_bytes",
            "data_reduction.pre_reduction_bytes",
            "storage_tier.ssd.capacity_bytes",
            "data_reduction.clone.saved_bytes",
            "storage_tier.ssd.free_bytes",
            "data_reduction.dedup.pre_reduction_bytes",
            "data_reduction.erasure_coding.pre_reduction_bytes",
            "storage.capacity_bytes",
            "data_reduction.dedup.post_reduction_bytes",
            "data_reduction.clone.saving_ratio_ppm",
            "storage.logical_usage_bytes",
            "data_reduction.saved_bytes",
            "storage.free_bytes",
            "storage_tier.ssd.usage_bytes",
            "data_reduction.compression.post_reduction_bytes",
            "data_reduction.post_reduction_bytes",
            "data_reduction.dedup.saved_bytes",
            "data_reduction.overall.saved_bytes",
            "data_reduction.thin_provision.saving_ratio_ppm",
            "data_reduction.compression.saving_ratio_ppm",
            "data_reduction.dedup.saving_ratio_ppm",
            "storage_tier.ssd.pinned_bytes",
            "storage.reserved_capacity_bytes"
        )]
        [string]$metric,
        [parameter(mandatory = $false)] [switch]$influxdb,
        [parameter(mandatory = $false)] [string]$influxdbCreds,
        
        [parameter(mandatory = $false)] [switch]$graph
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
    #check if we need to display help and/or history
    $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 05/12/2020 sb   Initial release.
 02/06/2021 sb   Replaced username with get-credential
 04/28/2021 sb   Fixed some incorrect script name references in the code 
                (thx Aritro!)
################################################################################
'@
    $myvarScriptName = ".\get-ntnxClusterStats.ps1"
    
    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

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

    #region module Influx
    if ($influxdb)
    {#we need influxdb output, so let's load the Influx module
        LoadModule -module Influx
    }
    #endregion
#endregion

#region variables
    #initialize variables
	$ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

    $myvar_metrics_list = @()
    $myvar_metrics_results = @{}

    $api_server_port = "9440"

    #* configuration
    $myvar_influxdb_url = "http://localhost:8086"
    $myvar_influxdb_database = "prism"
#endregion

#region parameters validation

    #make sure we have a time period specified
    if ((!$hour) -and (!$day) -and (!$week) -and (!$month) -and (!($startdate -and $enddate))) {
        Throw "$(get-date) [ERROR] You must specify a time period with -day, -week, -month or with -startdate and -enddate!"
    }

    #make sure we have an interval specified
    if (!$interval) {$interval = 60}

    #make sure we have a metric specified
    if ((!$metric) -and (!$overview)) {
        Throw "$(get-date) [ERROR] You must specify a metric with -metric or use -overview (to specify a standard set of metrics)!"
    }

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

#region processing	
    
    #region figure out startdate and enddate in epoch microseconds
        if ($hour) {
            $startdate = ((Get-Date).AddMinutes(-5)).AddHours(-1)
            $enddate = (Get-Date).AddMinutes(-5)

            $starttime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $startdate -UFormat %s))).ToString() + "000000"
            $endtime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $enddate -UFormat %s))).ToString() + "000000"
        } elseif ($day) {
            $startdate = ((Get-Date).AddMinutes(-5)).AddDays(-1)
            $enddate = (Get-Date).AddMinutes(-5)

            $starttime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $startdate -UFormat %s))).ToString() + "000000"
            $endtime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $enddate -UFormat %s))).ToString() + "000000"
        } elseif ($week) {
            $startdate = ((Get-Date).AddMinutes(-5)).AddDays(-7)
            $enddate = (Get-Date).AddMinutes(-5)

            $starttime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $startdate -UFormat %s))).ToString() + "000000"
            $endtime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $enddate -UFormat %s))).ToString() + "000000"
        } elseif ($month) {
            $startdate = ((Get-Date).AddMinutes(-5)).AddDays(-28)
            $enddate = (Get-Date).AddMinutes(-5)

            $starttime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $startdate -UFormat %s))).ToString() + "000000"
            $endtime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $enddate -UFormat %s))).ToString() + "000000"
        } else {
            $starttime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $startdate -UFormat %s))).ToString() + "000000"
            $endtime_epoch_usecs = ([int][double]::Parse((Get-Date -Date $enddate -UFormat %s))).ToString() + "000000"
        }
    #endregion

    #region building the list of metrics to retrieve
        if ($overview) {
            $myvar_metrics_list = (
                "controller_avg_io_latency_usecs",
                "controller_avg_read_io_latency_usecs",
                "controller_avg_write_io_latency_usecs",
                "controller_io_bandwidth_kBps",
                "controller_avg_read_io_size_kbytes",
                "controller_avg_write_io_size_kbytes",
                "controller_num_iops",
                "controller_num_read_iops",
                "controller_num_write_iops",
                "hypervisor_cpu_usage_ppm",
                "hypervisor_memory_usage_ppm"
            )
        } else {
            $myvar_metrics_list += $metric
        }
    #endregion

    #region retrieving stats for all metrics
        ForEach ($metric in $myvar_metrics_list) {
            #https://10.68.97.100:9440/PrismGateway/services/rest/v2.0/cluster/stats/?metrics=hypervisor_cpu_usage_ppm&start_time_in_usecs=1589273186000000&end_time_in_usecs=1589359675000000&interval_in_secs=60
            $api_server_endpoint = "/PrismGateway/services/rest/v2.0/cluster/stats/?metrics={0}&start_time_in_usecs={1}&end_time_in_usecs={2}&interval_in_secs={3}" -f $metric,$starttime_epoch_usecs,$endtime_epoch_usecs,$interval
            $url = "https://{0}:{1}{2}" -f $cluster,$api_server_port, $api_server_endpoint
            $method = "GET"

            Write-Host "$(get-date) [INFO] Retrieving stats for $($metric) from $($startdate) to $($enddate) with interval $($interval) seconds..." -ForegroundColor Green
            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved $(($resp.stats_specific_responses[0].values).count) data points for $($metric)" -ForegroundColor Cyan
            $myvar_metrics_results.add($resp.stats_specific_responses[0].metric,$resp.stats_specific_responses[0].values)
        }
    #endregion

    #region exporting results to csv
        ForEach ($metric in $myvar_metrics_results.keys) {
            
            #region creating timestamped results
                [System.Collections.ArrayList]$myvar_metrics_timestamped_results = New-Object System.Collections.ArrayList($null)
                $timestamp = $startdate
                ForEach ($metric_value in $myvar_metrics_results.$metric) {
                    if (($metric -eq "hypervisor_cpu_usage_ppm") -or ($metric -eq "hypervisor_memory_usage_ppm") -or ($metric -eq "content_cache_hit_ppm")) {
                        $formatted_metric_value = [math]::round($metric_value/10000,2)
                    } else {
                        $formatted_metric_value = $metric_value
                    }
                    if ($formatted_metric_value -lt 0) {$formatted_metric_value=0}
                    $myvar_metric_timestamped_result = [ordered]@{
                        "timestamp" = $timestamp;
                        $metric = $formatted_metric_value
                    }
                    $myvar_metrics_timestamped_results.Add((New-Object PSObject -Property $myvar_metric_timestamped_result)) | Out-Null
                    $timestamp = $timestamp.AddSeconds($interval)
                }
            #endregion

            #exporting results to csv
            $myvar_csv_filename = "{0}_{1}_fromdate-{2}_todate-{3}.csv" -f $cluster,$metric,$(Get-Date -Date $startdate -UFormat "%Y.%m.%d.%H.%M"),$(Get-Date -Date $enddate -UFormat "%Y.%m.%d.%H.%M")
            Write-Host "$(Get-Date) [INFO] Writing results for $($metric) to $($myvar_csv_filename)" -ForegroundColor Green
            $myvar_metrics_timestamped_results | export-csv -NoTypeInformation $myvar_csv_filename
        }
    #endregion

    #region displaying graphs
        if ($graph) {
            #region installing the required module
                if (!(Get-Module -Name Graphical)) {
                    Write-Host "$(get-date) [INFO] Importing module 'Graphical'..." -ForegroundColor Green
                    try
                    {
                        Import-Module -Name Graphical -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Imported module 'Graphical'!" -ForegroundColor Cyan
                    }#end try
                    catch #we couldn't import the module, so let's install it
                    {
                        Write-Host "$(get-date) [INFO] Installing module 'Graphical' from the Powershell Gallery..." -ForegroundColor Green
                        try {Install-Module -Name Graphical -Scope CurrentUser -Force -ErrorAction Stop}
                        catch {throw "$(get-date) [ERROR] Could not install module 'Graphical': $($_.Exception.Message)"}
        
                        try
                        {
                            Import-Module -Name Graphical -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] Imported module 'Graphical'!" -ForegroundColor Cyan
                        }#end try
                        catch #we couldn't import the module
                        {
                            Write-Host "$(get-date) [ERROR] Unable to import the module Graphical : $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host "$(get-date) [WARNING] Please download and install from https://github.com/PrateekKumarSingh/Graphical" -ForegroundColor Yellow
                            Exit
                        }#end catch
                    }#end catch
                }#endif module Graphical
            #endregion

            #region creating and displaying graphs
                ForEach ($metric in $myvar_metrics_results.keys) {
                    $myvar_csv_filename = "{0}_{1}_fromdate-{2}_todate-{3}.csv" -f $cluster,$metric,$(Get-Date -Date $startdate -UFormat "%Y.%m.%d.%H.%M"),$(Get-Date -Date $enddate -UFormat "%Y.%m.%d.%H.%M")
                    $myvar_csv_data = Import-Csv -Path $myvar_csv_filename
                    $myvar_datapoints = $myvar_csv_data.$metric
                    $myvar_timestamps = $myvar_csv_data.timestamp
                    $myvar_thinned_datapoints = @()
                    $myvar_thinned_timestamps = @()

                    #thinning datasets
                    For ($i=0;$i -lt $myvar_datapoints.count; $i += [math]::Round($myvar_datapoints.count /100)) {
                        $myvar_dataset = @($myvar_datapoints[$i..($i+[math]::Round($myvar_datapoints.count /100)-1)]);
                        $myvar_thinned_datapoints += ,[math]::Round(($myvar_dataset | Measure-Object -Average).Average)
                    }
                    For ($i=0;$i -lt $myvar_timestamps.count; $i += [math]::Round($myvar_timestamps.count /10)) {
                        $myvar_dataset = @($myvar_timestamps[$i..($i+[math]::Round($myvar_timestamps.count /10)-1)]);
                        $myvar_thinned_timestamps += ,($myvar_dataset | Measure-Object -Maximum).Maximum
                    }

                    $myvar_y_axis_step = ([math]::Round((($myvar_thinned_datapoints | Measure-Object -Maximum).Maximum - ($myvar_thinned_datapoints | Measure-Object -Minimum).Minimum) / 10)).ToString()
                    if ($myvar_y_axis_step -eq 0) {
                        Show-Graph -Datapoints $myvar_thinned_datapoints -GraphTitle $metric -Type Bar -XAxisTitle "TimeIntervals" -YAxisStep 1
                    } else {
                        Show-Graph -Datapoints $myvar_thinned_datapoints -GraphTitle $metric -Type Bar -XAxisTitle "TimeIntervals" -YAxisStep $myvar_y_axis_step
                    }
                    
                    Write-Host "$(Get-Date) [WARNING] Graph is smoothed using averages to limit the number of datapoints to about 100." -ForegroundColor Yellow
                    Write-Host "$(Get-Date) [SUM] Complete data set average: $([math]::Round(($myvar_datapoints | Measure-Object -Average).Average,2))" -ForegroundColor Magenta
                    Write-Host "$(Get-Date) [SUM] Complete data set maximum: $([math]::Round(($myvar_datapoints | Measure-Object -Maximum).Maximum,2))" -ForegroundColor Magenta
                    Write-Host "$(Get-Date) [SUM] Complete data set minimum: $([math]::Round(($myvar_datapoints | Measure-Object -Minimum).Minimum,2))" -ForegroundColor Magenta
                    Write-Host "$(Get-Date) [SUM] Complete data set std dev: $([math]::Round(($myvar_datapoints | Measure-Object -StandardDeviation).StandardDeviation,2))" -ForegroundColor Magenta
                    Write-Host "$(Get-Date) [INFO] Where TimeIntervals are:" -ForegroundColor Green
                    $myvar_timeinterval = 0
                    ForEach ($timestamp in $myvar_thinned_timestamps) {
                        $myvar_timeinterval += 10
                        Write-Host "     $($myvar_timeinterval): $($timestamp)" -ForegroundColor Green
                    }
                    Write-Host "-----------------------------------------------------------" -ForegroundColor Green
                }
            #endregion
        }
    #endregion

    #* influxdb output
    #region influxdb output
        if ($influxdb)
        {#we need to insert data into influxdb database
            #* retrieve cluster information
            #region GET cluster
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving cluster information from Nutanix cluster $($cluster)..."
                $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
                $method = "GET"
                $myvar_ntnx_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

                $myvar_ntnx_cluster_name = $myvar_ntnx_cluster_info.name
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Nutanix cluster name is $($myvar_ntnx_cluster_name)"
            #endregion

            ForEach ($metric in $myvar_metrics_results.keys) {
                $myvar_csv_filename = "{0}_{1}_fromdate-{2}_todate-{3}.csv" -f $cluster,$metric,$(Get-Date -Date $startdate -UFormat "%Y.%m.%d.%H.%M"),$(Get-Date -Date $enddate -UFormat "%Y.%m.%d.%H.%M")
                $myvar_csv_data = Import-Csv -Path $myvar_csv_filename
                try 
                {#sending data to influxdb
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Sending $($metric) data for cluster $($myvar_ntnx_cluster_name) to InfluxDB server $($myvar_influxdb_url) in database $($myvar_influxdb_database) as time series ntnx_cluster_stats..."
                    ForEach ($myvar_line in $myvar_csv_data)
                    {
                        Write-Influx -Measure ntnx_cluster_stats -Tags @{cluster=$myvar_ntnx_cluster_name} -Metrics @{$metric=$myvar_line.$metric;} -TimeStamp $(Get-Date $myvar_line.timestamp) -Database $myvar_influxdb_database -Credential $influxdbCredentials -Server $myvar_influxdb_url -ErrorAction Stop
                    }
                }
                catch 
                {#could not send data to influxdb
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Could not send data to influxdb: $($_.Exception.Message)"
                }
            }
        }
    #endregion

#endregion

#region cleanup
	#let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    Remove-Variable myvar* -ErrorAction SilentlyContinue
#endregion