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
.PARAMETER vm
  List of VMs you want to collect data for. You can specify "all" (without the quotes). When using all, instead of creating 1 csv per vm metric, a single csv file will be created with the max and average values for each metric (1 row per vm) for the given period.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
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

.EXAMPLE
.\get-ntnxVmStats.ps1 -cluster ntnxc1.local -vm myvm1 -username admin -password admin -overview -week
Generate one csv file per overview metric for the last 7 days.

.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: March 24th 2022
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
        [parameter(mandatory = $false)] [switch]$hour,
        [parameter(mandatory = $false)] [switch]$day,
        [parameter(mandatory = $false)] [switch]$week,
        [parameter(mandatory = $false)] [switch]$month,
        [parameter(mandatory = $false)] [switch]$overview,
        [parameter(mandatory = $false)] [int]$interval,
        [parameter(mandatory = $false)] [Datetime]$startdate,
        [parameter(mandatory = $false)] [Datetime]$enddate,
        [parameter(mandatory = $true)] [string]$vm,
        
        [parameter(mandatory = $false)]
        [ValidateSet(
            "hypervisor_avg_io_latency_usecs",
            "num_read_iops",
            "hypervisor_write_io_bandwidth_kBps",
            "timespan_usecs",
            "controller_num_read_iops",
            "controller.storage_tier.ssd.usage_bytes",
            "read_io_ppm",
            "controller_num_iops",
            "hypervisor_memory_assigned_bytes",
            "total_read_io_time_usecs",
            "controller_total_read_io_time_usecs",
            "controller.storage_tier.ssd.configured_pinned_bytes",
            "hypervisor_num_io",
            "controller_total_transformed_usage_bytes",
            "hypervisor_cpu_usage_ppm",
            "controller_num_write_io",
            "avg_read_io_latency_usecs",
            "guest.memory_swapped_in_bytes",
            "controller_total_io_time_usecs",
            "memory_usage_ppm",
            "controller_total_read_io_size_kbytes",
            "controller_num_seq_io",
            "controller_read_io_ppm",
            "controller_total_io_size_kbytes",
            "hypervisor.cpu_ready_time_ppm",
            "controller_num_io",
            "hypervisor_avg_read_io_latency_usecs",
            "num_write_iops",
            "controller_num_random_io",
            "num_iops",
            "guest.memory_usage_ppm",
            "hypervisor_num_read_io",
            "hypervisor_total_read_io_time_usecs",
            "controller_avg_io_latency_usecs",
            "num_io",
            "controller_num_read_io",
            "hypervisor_num_write_io",
            "controller_seq_io_ppm",
            "guest.memory_usage_bytes",
            "controller_read_io_bandwidth_kBps",
            "controller_io_bandwidth_kBps",
            "hypervisor_num_received_bytes",
            "hypervisor_timespan_usecs",
            "hypervisor_num_write_iops",
            "total_read_io_size_kbytes",
            "hypervisor_total_io_size_kbytes",
            "avg_io_latency_usecs",
            "hypervisor_num_read_iops",
            "hypervisor_swap_in_rate_kBps",
            "controller_write_io_bandwidth_kBps",
            "controller_write_io_ppm",
            "controller_user_bytes",
            "hypervisor_avg_write_io_latency_usecs",
            "hypervisor_num_transmitted_bytes",
            "hypervisor_total_read_io_size_kbytes",
            "read_io_bandwidth_kBps",
            "guest.memory_swapped_out_bytes",
            "hypervisor_memory_usage_ppm",
            "hypervisor_num_iops",
            "hypervisor_io_bandwidth_kBps",
            "controller_num_write_iops",
            "total_io_time_usecs",
            "controller_random_io_ppm",
            "controller.storage_tier.das-sata.usage_bytes",
            "controller_avg_read_io_size_kbytes",
            "hypervisor_swap_out_rate_kBps",
            "total_transformed_usage_bytes",
            "avg_write_io_latency_usecs",
            "num_read_io",
            "write_io_bandwidth_kBps",
            "hypervisor_read_io_bandwidth_kBps",
            "hypervisor_consumed_memory_bytes",
            "random_io_ppm",
            "total_untransformed_usage_bytes",
            "hypervisor_total_io_time_usecs",
            "num_random_io",
            "controller_avg_write_io_size_kbytes",
            "controller_avg_read_io_latency_usecs",
            "controller.storage_tier.das-sata.configured_pinned_bytes",
            "num_write_io",
            "total_io_size_kbytes",
            "controller.storage_tier.cloud.usage_bytes",
            "io_bandwidth_kBps",
            "controller_timespan_usecs",
            "num_seq_io",
            "seq_io_ppm",
            "write_io_ppm",
            "controller_avg_write_io_latency_usecs"
        )]
        [string]$metric
    )
#endregion parameters

#region functions

#this function is used to create saved credentials for the current user
function Set-CustomCredentials 
{
#input: path, credname
	#output: saved credentials file
<#
.SYNOPSIS
  Creates a saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to create a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Set-CustomCredentials -path c:\creds -credname prism-apiuser
Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
#>
	param
	(
		[parameter(mandatory = $false)]
        [string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Set path to $path" -ForegroundColor Green
        } 
    }
    process
    {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
		$credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
		
		#put details in hashed format
		$user = $credentials.UserName
		$securePassword = $credentials.Password
        
        #convert secureString to text
        try 
        {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch 
        {
            throw "$(get-date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        #create directory to store creds if it does not already exist
        if(!(Test-Path $path))
		{
            try 
            {
                $result = New-Item -type Directory $path -ErrorAction Stop
            } 
            catch 
            {
                throw "$(get-date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
		}

        #save creds to file
        try 
        {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try 
        {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(get-date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan                
    }
    end
    {}
}

#this function is used to retrieve saved credentials for the current user
function Get-CustomCredentials 
{
#input: path, credname
	#output: credential object
<#
.SYNOPSIS
  Retrieves saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Get-CustomCredentials -path c:\creds -credname prism-apiuser
Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
#>
	param
	(
        [parameter(mandatory = $false)]
		[string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        } 
    }
    process
    {
        $credentialsFilePath = "$path\$credname.txt"
        if(!(Test-Path $credentialsFilePath))
	    {
            throw "$(get-date) [ERROR] Could not access file $credentialsFilePath : $($_.Exception.Message)"
        }

        $credFile = Get-Content $credentialsFilePath
		$user = $credFile[0]
		$securePassword = $credFile[1] | ConvertTo-SecureString

        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(get-date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan 
    }
    end
    {
        return $customCredentials
    }
}

#this function is used to make a REST api call to Prism
function Invoke-PrismAPICall
{
<#
.SYNOPSIS
  Makes api call to prism based on passed parameters. Returns the json response.
.DESCRIPTION
  Makes api call to prism based on passed parameters. Returns the json response.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER method
  REST method (POST, GET, DELETE, or PUT)
.PARAMETER credential
  PSCredential object to use for authentication.
PARAMETER url
  URL to the api endpoint.
PARAMETER payload
  JSON payload to send.
.EXAMPLE
.\Invoke-PrismAPICall -credential $MyCredObject -url https://myprism.local/api/v3/vms/list -method 'POST' -payload $MyPayload
Makes a POST api call to the specified endpoint with the specified payload.
#>
param
(
    [parameter(mandatory = $true)]
    [ValidateSet("POST","GET","DELETE","PUT")]
    [string] 
    $method,
    
    [parameter(mandatory = $true)]
    [string] 
    $url,

    [parameter(mandatory = $false)]
    [string] 
    $payload,
    
    [parameter(mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $credential
)

begin
{
    
}
process
{
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    try {
        #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($payload) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
            }
        } else {
            $username = $credential.UserName
            $password = $credential.Password
            $headers = @{
                "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($payload) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
            }
        }
        Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
        #add any last words here; this gets processed no matter what
    }
}
end
{
    return $resp
}    
}

#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{
<#
.SYNOPSIS
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.DESCRIPTION
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Set-PoshTls
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param 
    (
        
    )

    begin 
    {
    }

    process
    {
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = `
        ([Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12)
    }

    end
    {

    }
}

#this function is used to configure posh to ignore invalid ssl certificates
function Set-PoSHSSLCerts
{
<#
.SYNOPSIS
Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
.DESCRIPTION
Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
#>
    begin
    {

    }#endbegin
    process
    {
        Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates" -ForegroundColor Green
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
            $certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{
    public static void Ignore()
    {
        if(ServicePointManager.ServerCertificateValidationCallback ==null)
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
}
"@
            Add-Type $certCallback
        }#endif
        [ServerCertificateValidationCallback]::Ignore()
    }#endprocess
    end
    {

    }#endend
}#end function Set-PoSHSSLCerts

#endregion functions

#region prepwork

#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
03/24/2022 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-ntnxVmStats.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    Set-PoSHSSLCerts
    Set-PoshTls

#endregion prepwork

#region variables

    #initialize variables
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

    $myvar_metrics_list = @()
    $myvar_vms_metrics_results = @{}

    $api_server_port = "9440"

#endregion variables

#region parameters validation

    #make sure we have a time period specified
    if ((!$hour) -and (!$day) -and (!$week) -and (!$month) -and (!($startdate -and $enddate))) {
        Throw "$(get-date) [ERROR] You must specify a time period with -day, -week, -month or with -startdate and -enddate!"
    }

    #make sure we have an interval specified
    if (!$interval) {$interval = 60}

    if (($vm -ieq "all") -and !$overview)
    {
        Write-Host "$(get-date) [WARNING] You specified all vms, so setting metrics list to overview!" -ForegroundColor Yellow
        $overview = $true
    }

    #make sure we have a metric specified
    if ((!$metric) -and (!$overview)) {
        Throw "$(get-date) [ERROR] You must specify a metric with -metric or use -overview (to specify a standard set of metrics)!"
    }

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

#endregion parameters validation

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
    #endregion figure out startdate and enddate
    
    #region building the list of metrics to retrieve
        if ($overview) {
            if ($vm -ine "all")
            {
                $myvar_metrics_list = (
                    "controller_avg_io_latency_usecs",
                    "controller_avg_read_io_latency_usecs",
                    "controller_avg_write_io_latency_usecs",
                    "controller_io_bandwidth_kBps",
                    "controller_read_io_bandwidth_kBps",
                    "controller_write_io_bandwidth_kBps",
                    "controller_num_iops",
                    "controller_num_read_iops",
                    "controller_num_write_iops",
                    "hypervisor_cpu_usage_ppm",
                    "guest.memory_usage_ppm",
                    "hypervisor.cpu_ready_time_ppm"
                )
            }
            else 
            {
                $myvar_metrics_list = (
                    "hypervisor_cpu_usage_ppm",
                    "guest.memory_usage_bytes",
                    "memory_usage_ppm",
                    "controller_user_bytes",
                    "hypervisor_num_received_bytes",
                    "hypervisor_num_transmitted_bytes"
                )     
            }
        } else {
            $myvar_metrics_list += $metric
        }
    #endregion building list of metrics

    #region retrieving stats for all metrics
        #* retrieve vms
        $api_server_endpoint = "/PrismGateway/services/rest/v1/vms"
        $url = "https://{0}:{1}{2}" -f $cluster,$api_server_port, $api_server_endpoint
        $method = "GET"

        Write-Host "$(get-date) [INFO] Retrieving list of virtual machines from $($cluster)..." -ForegroundColor Green
        $vms = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of virtual machines from $($cluster)" -ForegroundColor Cyan

        #* build list of vms to process (collect uuids)
        if ($vm -eq "all") {
            $vm_list = $vms.entities
        } else {
            $vm_names = $vm.Split(",")
            $vm_list = $vms.entities | Where-Object {$_.vmName -in $vm_names}
        }
        
        #*process each vm
        if (($PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor -join ".") -gt 7.0) #making use of parallel processing feature in PoSH > 7.0
        {
            $myvar_vms_metrics_results = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
            
            $vm_list | ForEach-Object -Parallel {
                $parallel_creds = $using:prismCredentials
                $parallel_cluster = $using:cluster
                $parallel_api_server_port = $using:api_server_port
                $parallel_startdate = $using:startdate
                $parallel_enddate = $using:enddate
                $parallel_interval = $using:interval
                $parallel_starttime_epoch_usecs = $using:starttime_epoch_usecs
                $parallel_endtime_epoch_usecs = $using:endtime_epoch_usecs
                $parallel_myvar_metrics_list = $using:myvar_metrics_list
                $parallel_myvar_vms_metrics_results = $using:myvar_vms_metrics_results

                $myvar_metrics_results = @{}
                $first_metric_number=1;$last_metric_number=5 #api only supports returning values for 5 metrics at a time

                $method = "GET"
                $headers = @{
                    "Content-Type"="application/json";
                    "Accept"="application/json"
                }
                    do 
                    {   
                        $api_server_endpoint = "/PrismGateway/services/rest/v1/vms/{0}/stats/?metrics={1}&startTimeInUsecs={2}&endTimeInUsecs={3}&intervalInSecs={4}" -f $_.uuid,$($parallel_myvar_metrics_list[$($first_metric_number-1)..$($last_metric_number-1)] -join ","),$parallel_starttime_epoch_usecs,$parallel_endtime_epoch_usecs,$parallel_interval
                        $url = "https://{0}:{1}{2}" -f $parallel_cluster,$parallel_api_server_port, $api_server_endpoint

                        Write-Host "$(get-date) [INFO] Retrieving stats for vm $($_.vmName) from $($parallel_startdate) to $($parallel_enddate) with interval $($parallel_interval) seconds..." -ForegroundColor Green
                        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $parallel_creds -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved metrics data points for vm $($_.vmName)" -ForegroundColor Cyan
                        Foreach ($metric in $resp.statsSpecificResponses)
                        {
                            $myvar_metrics_results.add($metric.metric,$metric.values)
                        }

                        $first_metric_number=$first_metric_number+5;$last_metric_number=$last_metric_number+5 #incrementing to process next set of metrics
                    } until ($last_metric_number -gt ($parallel_myvar_metrics_list.count + 5))
                
                $parallel_myvar_vms_metrics_results.TryAdd($_.uuid,$myvar_metrics_results) | Out-Null #storing results in this overall hash
            } -ThrottleLimit 10
        }
        else 
        {
            Foreach ($vm_entity in $vm_list)
            {
                $myvar_metrics_results = @{}
                $first_metric_number=1;$last_metric_number=5 #api only supports returning values for 5 metrics at a time
                    do 
                    {   
                        $api_server_endpoint = "/PrismGateway/services/rest/v1/vms/{0}/stats/?metrics={1}&startTimeInUsecs={2}&endTimeInUsecs={3}&intervalInSecs={4}" -f $vm_entity.uuid,$($myvar_metrics_list[$($first_metric_number-1)..$($last_metric_number-1)] -join ","),$starttime_epoch_usecs,$endtime_epoch_usecs,$interval
                        $url = "https://{0}:{1}{2}" -f $cluster,$api_server_port, $api_server_endpoint
                        $method = "GET"

                        Write-Host "$(get-date) [INFO] Retrieving stats for vm $($vm_entity.vmName) from $($startdate) to $($enddate) with interval $($interval) seconds..." -ForegroundColor Green
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved metrics data points for vm $($vm_entity.vmName)" -ForegroundColor Cyan
                        Foreach ($metric in $resp.statsSpecificResponses)
                        {
                            $myvar_metrics_results.add($metric.metric,$metric.values)
                        }

                        $first_metric_number=$first_metric_number+5;$last_metric_number=$last_metric_number+5 #incrementing to process next set of metrics
                    } until ($last_metric_number -gt ($myvar_metrics_list.count + 5))

                $myvar_vms_metrics_results.add($vm_entity.uuid,$myvar_metrics_results) #storing results in this overall hash
            }
        }
    #endregion retrieving stats

    #region exporting results to csv
        Write-Host "$(get-date) [INFO] Building results for cluster $($cluster)..." -ForegroundColor Green
        [System.Collections.ArrayList]$myvar_vm_all_report = New-Object System.Collections.ArrayList($null)
        Foreach ($vm_entry in $myvar_vms_metrics_results.Keys)
        {
            Write-Host "$(get-date) [INFO] Calculating average and peak values for all metrics for vm $($vm_entry)..." -ForegroundColor Green
            $vm_details = $vms.entities | Where-Object {$_.uuid -eq $vm_entry}

            if ($vm -ieq "all")
            {#generate a single csv with one line per vm and max and avg values for each metric
                $myvar_vm_metrics_info = [ordered]@{
                    "vm_name" = $vm_details.vmName;
                    "vm_uuid" = $vm_entry;
                    "num_vcpus" = $vm_details.numVCpus;
                    "memoryCapacityInGiB" = [math]::round($vm_details.memoryCapacityInBytes/1024/1024/1024,2);
                    "diskCapacityInGiB" = [math]::round($vm_details.diskCapacityInBytes/1024/1024/1024,2);
                    
                    "hypervisor_cpu_usage_ppm_average" = 0;
                    "hypervisor_cpu_usage_ppm_peak" = 0;
                    
                    "guest.memory_usage_bytes_average" = 0;
                    "guest.memory_usage_bytes_peak" = 0;
                    
                    "memory_usage_ppm_average" = 0;
                    "memory_usage_ppm_peak" = 0;
                    
                    "controller_user_bytes_average" = 0;
                    "controller_user_bytes_peak" = 0;
                    
                    "hypervisor_num_received_bytes_average" = 0;
                    "hypervisor_num_received_bytes_peak" = 0;

                    "hypervisor_num_transmitted_bytes_average" = 0;
                    "hypervisor_num_transmitted_bytes_peak" = 0;
                }
                Foreach ($metric in $myvar_vms_metrics_results.$vm_entry.keys)
                {
                    #find peak and average
                    $myvar_measured_object = $myvar_vms_metrics_results.$vm_entry.$metric | measure-object -maximum -average
                    #Write-Host "VM:$($vm_details.vmName), Metric:$($metric), Average:$($myvar_measured_object.Average), Peak:$($myvar_measured_object.Maximum)"
                    if (($metric -eq "hypervisor_num_received_bytes") -or ($metric -eq "hypervisor_num_transmitted_bytes"))
                    {
                        $myvar_vm_metrics_info."$($metric)_average" = [math]::round($myvar_measured_object.Average,0)
                        $myvar_vm_metrics_info."$($metric)_peak" = [math]::round($myvar_measured_object.Maximum,0) 
                    }
                    elseif ($metric -like "*bytes")
                    {
                        $myvar_vm_metrics_info."$($metric)_average" = [math]::round($myvar_measured_object.Average/1024/1024/1024,2)
                        $myvar_vm_metrics_info."$($metric)_peak" = [math]::round($myvar_measured_object.Maximum/1024/1024/1024,2)
                    }
                    elseif ($metric -like "*ppm") 
                    {
                        $myvar_vm_metrics_info."$($metric)_average" = [math]::round($myvar_measured_object.Average/10000,2)
                        $myvar_vm_metrics_info."$($metric)_peak" = [math]::round($myvar_measured_object.Maximum/10000,2)
                    }
                    else 
                    {
                        $myvar_vm_metrics_info."$($metric)_average" = $myvar_measured_object.Average
                        $myvar_vm_metrics_info."$($metric)_peak" = $myvar_measured_object.Maximum    
                    }                   
                }
                #convert metric names here
                $myvar_vm_metrics_friendly_names_info = [ordered]@{
                    "vm_name" = $myvar_vm_metrics_info.vm_name;
                    "uuid" = $myvar_vm_metrics_info.vm_uuid;
                    "num_vcpus" = $myvar_vm_metrics_info.num_vcpus;
                    "memory_allocated_GiB" = $myvar_vm_metrics_info.memoryCapacityInGiB;
                    "disk_allocated_GiB" = $myvar_vm_metrics_info.diskCapacityInGiB;

                    "hypervisor_cpu_usage_percentage_average" = $myvar_vm_metrics_info.hypervisor_cpu_usage_ppm_average;
                    "hypervisor_cpu_usage_percentage_peak" = $myvar_vm_metrics_info.hypervisor_cpu_usage_ppm_peak;

                    "guest.memory_usage_GiB_average" = $myvar_vm_metrics_info."guest.memory_usage_bytes_average";
                    "guest.memory_usage_GiB_peak" = $myvar_vm_metrics_info."guest.memory_usage_bytes_peak";

                    "memory_usage_percentage_average" = $myvar_vm_metrics_info.memory_usage_ppm_average;
                    "memory_usage_percentage_peak" = $myvar_vm_metrics_info.memory_usage_ppm_peak;

                    "disk_usage_GiB_average" = $myvar_vm_metrics_info.controller_user_bytes_average;
                    "disk_usage_GiB_peak" = $myvar_vm_metrics_info.controller_user_bytes_peak;

                    "network_received_bytes_average" = $myvar_vm_metrics_info.hypervisor_num_received_bytes_average;
                    "network_received_bytes_peak" = $myvar_vm_metrics_info.hypervisor_num_received_bytes_peak;

                    "network_transmitted_bytes_average" = $myvar_vm_metrics_info.hypervisor_num_transmitted_bytes_average;
                    "network_transmitted_bytes_peak" = $myvar_vm_metrics_info.hypervisor_num_transmitted_bytes_peak;
                }
                #store the results for this entity in our overall result variable
                $myvar_vm_all_report.Add((New-Object PSObject -Property $myvar_vm_metrics_friendly_names_info)) | Out-Null
            }
            else 
            {#generate one csv per metric and per vm
                Foreach ($metric in $myvar_vms_metrics_results.$vm_entry.keys)
                {
                    #region creating timestamped results
                    [System.Collections.ArrayList]$myvar_metrics_timestamped_results = New-Object System.Collections.ArrayList($null)
                    $timestamp = $startdate
                    ForEach ($metric_value in $myvar_vms_metrics_results.$vm_entry.$metric) {
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

                    #exporting results to csv
                    $myvar_csv_filename = "{0}_{1}_{2}_fromdate-{3}_todate-{4}.csv" -f $cluster,$vm_details.vmName,$metric,$(Get-Date -Date $startdate -UFormat "%Y.%m.%d.%H.%M"),$(Get-Date -Date $enddate -UFormat "%Y.%m.%d.%H.%M")
                    Write-Host "$(Get-Date) [INFO] Writing results for $($metric) to $($myvar_csv_filename)" -ForegroundColor Green
                    $myvar_metrics_timestamped_results | export-csv -NoTypeInformation $myvar_csv_filename
                #endregion
                }
            }
        }
        if ($vm -ieq "all")
        {
            $myvar_csv_filename = "{0}_all_vms_fromdate-{1}_todate-{2}.csv" -f $cluster,$(Get-Date -Date $startdate -UFormat "%Y.%m.%d.%H.%M"),$(Get-Date -Date $enddate -UFormat "%Y.%m.%d.%H.%M")
            Write-Host "$(Get-Date) [INFO] Writing results to $($myvar_csv_filename)" -ForegroundColor Green
            $myvar_vm_all_report | export-csv -NoTypeInformation $myvar_csv_filename
        }
    #endregion exporting results

#endregion processing

#region cleanup

    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    Remove-Variable myvar* -ErrorAction SilentlyContinue

#endregion cleanup