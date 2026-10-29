<#
.SYNOPSIS
  This script retrieves allocated compute capacity information from a Nutanix cluster and produces an interactive html report.
.DESCRIPTION
  Report will show remaining UVM capacity in a color coded output. Report configuration settings can be customized in the variables region.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER influxdb
  Specifies you want to send data to influxdb server. You will need to configure the influxdb server URL and database instance in the variables section of this script.  The timeseries created by default is called uvm_capacity.
.PARAMETER influxdbCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$influxdbCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER email
  Specifies that you want to send an email with the html report attached. This will require that you add smtp configuration in the variables section.
.PARAMETER emailCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$emailCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\get-UvmCapacity.ps1 -cluster ntnxc1.local
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $false)] [switch]$html,
        [parameter(mandatory = $false)] [switch]$viewnow,
        [parameter(mandatory = $false)] [string]$dir,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] [string]$prismCreds,
        [parameter(mandatory = $false)] [switch]$influxdb,
        [parameter(mandatory = $false)] [string]$influxdbCreds,
        [parameter(mandatory = $false)] [switch]$email,
        [parameter(mandatory = $false)] [string]$emailCreds
    )
#endregion

#region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $true)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string]$method,

            [parameter(mandatory = $true)]
            [string]$url,

            [parameter(mandatory = $false)]
            [string]$payload,

            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]$credential
        )

        Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
        try {
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json"
                    "Accept"       = "application/json"
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
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))))
                    "Content-Type"  = "application/json"
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                } else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
            Write-Host "$(Get-Date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White }
        }
        catch {
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            throw "$(Get-Date) [ERROR] $($_.Exception.Message)"
        }
        return $resp
    }

    function Set-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $true)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Set path to $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
        $user = $credentials.UserName
        $securePassword = $credentials.Password

        try {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        if (!(Test-Path $path)) {
            try {
                New-Item -Type Directory $path -ErrorAction Stop | Out-Null
            }
            catch {
                throw "$(Get-Date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
        }

        try {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(Get-Date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan
    }

    function Get-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $true)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        if (!(Test-Path $credentialsFilePath)) {
            throw "$(Get-Date) [ERROR] Could not access file $credentialsFilePath"
        }

        $credFile = Get-Content $credentialsFilePath
        $user = $credFile[0]
        $securePassword = $credFile[1] | ConvertTo-SecureString
        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(Get-Date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan
        return $customCredentials
    }

    function Set-PoshTls {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            # PowerShell 7+ already defaults to TLS 1.2+; Invoke-PrismAPICall also sets -SslProtocol Tls12
            return
        }
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = (
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        )
    }

    function Set-PoSHSSLCerts {
        # PowerShell 6+ uses -SkipCertificateCheck on Invoke-RestMethod (see Invoke-PrismAPICall).
        # The old ServicePointManager Add-Type path is obsolete on modern .NET and fails to compile (SYSLIB0014).
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates (SkipCertificateCheck)" -ForegroundColor Green
            return
        }

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
        if (ServicePointManager.ServerCertificateValidationCallback == null)
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                delegate (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                {
                    return true;
                };
        }
    }
}
"@
            Add-Type $certCallback
        }
        [ServerCertificateValidationCallback]::Ignore()
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter; removed Write-LogOutput and LoadModule functions
02/07/2021 sb   Initial release.
02/22/2021 sb   Adding influxdb output.
################################################################################
'
    $myvar_script_name = ".\get-UvmCapacity.ps1"

    if ($help) {get-help $myvar_script_name; exit}
    if ($History) {$HistoryText; exit}
    
    if (!$dir)
    {#no report directory was specified, so we'll use the current directory
        $dir = Get-Location | Select-Object -ExpandProperty Path
    }

    if (!$dir.EndsWith("\")) 
    {#make sure given log path has a trailing \
        if ($IsMacOS -or $IsLinux)
        {#we are on Mac or Linux
            $dir += "/"
        }
        else 
        {#we are on Windows
            $dir += "\"
        }
    }
    if (Test-Path -path $dir)
    {#specified path exists
        $myvar_html_report_name = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvar_html_report_name += "$($cluster)_capacity_report.html"
        $myvar_html_report_name = $dir + $myvar_html_report_name
    }
    else 
    {#specified path does not exist
        Write-Host "$(Get-Date) [ERROR] Specified log path $($dir) does not exist! Exiting." -ForegroundColor Red
        Exit 1
    }

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) 
    {#PowerShell version is too old
        Write-Host "$(Get-Date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)" -ForegroundColor Red
        Exit 1
    }

    #check if we have all the required PoSH modules
    Write-Host "$(Get-Date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

    #region module PSWriteHTML
        if ($html)
        {#we need html output, so let's load the PSWriteHTML module
            if (!(Get-Module -Name PSWriteHTML)) {
                Write-Host "$(Get-Date) [INFO] Importing module 'PSWriteHTML'..." -ForegroundColor Green
                try
                {
                    Import-Module -Name PSWriteHTML -ErrorAction Stop
                    Write-Host "$(Get-Date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
                }
                catch 
                {
                    Write-Host "$(Get-Date) [INFO] Installing module 'PSWriteHTML' from the Powershell Gallery..." -ForegroundColor Green
                    try 
                    {
                        Install-Module -Name PSWriteHTML -Scope CurrentUser -Force -ErrorAction Stop
                    }
                    catch 
                    {
                        Write-Host "$(Get-Date) [ERROR] Could not install module 'PSWriteHTML': $($_.Exception.Message)" -ForegroundColor Red
                        exit 1
                    }

                    try
                    {
                        Import-Module -Name PSWriteHTML -ErrorAction Stop
                        Write-Host "$(Get-Date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
                    }
                    catch 
                    {
                        Write-Host "$(Get-Date) [ERROR] Unable to import the module PSWriteHTML.psm1 : $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "$(Get-Date) [WARNING] Please download and install from https://www.powershellgallery.com" -ForegroundColor Yellow
                        Exit 1
                    }
                }
            }
        }
    #endregion

    #region module Influx
        if ($influxdb)
        {#we need influxdb output, so let's load the Influx module
            if (!(Get-Module -Name Influx)) {
                Write-Host "$(Get-Date) [INFO] Importing module 'Influx'..." -ForegroundColor Green
                try
                {
                    Import-Module -Name Influx -ErrorAction Stop
                    Write-Host "$(Get-Date) [SUCCESS] Imported module 'Influx'!" -ForegroundColor Cyan
                }
                catch 
                {
                    Write-Host "$(Get-Date) [INFO] Installing module 'Influx' from the Powershell Gallery..." -ForegroundColor Green
                    try 
                    {
                        Install-Module -Name Influx -Scope CurrentUser -Force -ErrorAction Stop
                    }
                    catch 
                    {
                        Write-Host "$(Get-Date) [ERROR] Could not install module 'Influx': $($_.Exception.Message)" -ForegroundColor Red
                        exit 1
                    }

                    try
                    {
                        Import-Module -Name Influx -ErrorAction Stop
                        Write-Host "$(Get-Date) [SUCCESS] Imported module 'Influx'!" -ForegroundColor Cyan
                    }
                    catch 
                    {
                        Write-Host "$(Get-Date) [ERROR] Unable to import the module Influx.psm1 : $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "$(Get-Date) [WARNING] Please download and install from https://www.powershellgallery.com" -ForegroundColor Yellow
                        Exit 1
                    }
                }
            }
        }
    #endregion
#endregion

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
    $myvar_smtp_server = "smtp.gmail.com"
    $myvar_smtp_server_port = 25
    $myvar_smtp_to = "stephane.bourdeaud@nutanix.com"

    $myvar_influxdb_url = "http://localhost:8086"
    $myvar_influxdb_database = "prism"
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

    if (!$emailCreds -and $email)
    {#we want to send email
        $emailCredentials = Get-Credential -Message "Please enter email credentials"
    }
    elseif ($email) 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {#Get-CustomCredentials
            $emailCredentials = Get-CustomCredentials -credname $emailCreds -ErrorAction Stop
            $username = $emailCredentials.UserName
            $emailSecurePassword = $emailCredentials.Password
        }
        catch 
        {#could not Get-CustomeCredentials, so Set-CustomCredentials
            Set-CustomCredentials -credname $emailCreds
            $emailCredentials = Get-CustomCredentials -credname $emailCreds -ErrorAction Stop
            $username = $emailCredentials.UserName
            $emailSecurePassword = $emailCredentials.Password
        }
        $emailCredentials = New-Object PSCredential $username, $emailSecurePassword

        #make sure we'll use html
        $html = $true
        # Load Send-MailKitMessage module if needed
        if (!(Get-Module -Name MailKit)) {
            Write-Host "$(Get-Date) [INFO] Importing module 'MailKit'..." -ForegroundColor Green
            try { Import-Module -Name MailKit -ErrorAction Stop }
            catch {
                Write-Host "$(Get-Date) [INFO] Installing module 'MailKit' from the Powershell Gallery..." -ForegroundColor Green
                try { Install-Module -Name MailKit -Scope CurrentUser -Force -ErrorAction Stop }
                catch { Write-Host "$(Get-Date) [ERROR] Could not install module 'MailKit': $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
                Import-Module -Name MailKit -ErrorAction Stop
            }
        }
    }
#endregion

#* processing here
#region processing	
    #* retrieve information from Prism
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving information from Nutanix cluster $($cluster)..." -ForegroundColor Magenta
    #region retrieve information from Prism
        #* retrieve cluster information
        #region GET cluster
            Write-Host "$(Get-Date) [INFO] Retrieving cluster information from Nutanix cluster $($cluster)..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

            $myvar_ntnx_cluster_name = $myvar_ntnx_cluster_info.name
            Write-Host "$(Get-Date) [DATA] Nutanix cluster name is $($myvar_ntnx_cluster_name)" -ForegroundColor Gray
            $myvar_ntnx_cluster_rf = $myvar_ntnx_cluster_info.cluster_redundancy_state.desired_redundancy_factor

            if (($myvar_ntnx_cluster_info.hypervisor_types).count -gt 1)
            {#cluster has mixed hypervisors
                Write-Host "$(Get-Date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) has multiple hypervisors" -ForegroundColor Gray
                if ($myvar_ntnx_cluster_info.hypervisor_types -notcontains "kVMware")
                {#none of the nodes are running VMware
                    Write-Host "$(Get-Date) [WARNING] None of the cluster hosts are running VMware vSphere!" -ForegroundColor Yellow
                }
            }
            else 
            {#cluster has single hypervisor
                Write-Host "$(Get-Date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) is of hypervisor type $($myvar_ntnx_cluster_info.hypervisor_types[0])" -ForegroundColor Gray
            }

            #region figure out vcenter ip
                $myvar_management_server = $myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                if ($myvar_management_server -is [array]) 
                {#houston, we have a problem, there is more than one registered vcenter
                    Write-Host "$(Get-Date) [ERROR] There is more than 1 registered management server for cluster $($cluster). Exiting." -ForegroundColor Red
                } 
                else 
                {#grab vcenter ip
                    $myvar_vcenter_ip = ($myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                    Write-Host "$(Get-Date) [DATA] vCenter IP address for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_vcenter_ip)" -ForegroundColor Gray
                }
                if (!$myvar_vcenter_ip) 
                {#found no vcenter ip
                    Write-Host "$(Get-Date) [WARNING] vCenter registration is not done in Prism for cluster $cluster!" -ForegroundColor Yellow
                }
            #endregion

            #let's make sure our current redundancy is at least 2
            if ($myvar_ntnx_cluster_info.cluster_redundancy_state.current_redundancy_factor -lt $myvar_ntnx_cluster_rf) 
            {#cluster redundancy state is < replication factor (a host must be down)
                Write-Host "$(Get-Date) [ERROR] Current redundancy is less than $($myvar_ntnx_cluster_rf). Exiting." -ForegroundColor Red
                Exit 1
            }
            #check if there is an upgrade in progress
            if ($myvar_ntnx_cluster_info.is_upgrade_in_progress) 
            {#cluster has an upgrade in progress
                Write-Host "$(Get-Date) [ERROR] Cluster upgrade is in progress. Exiting." -ForegroundColor Red
                Exit 1
            }
        #endregion
        
        #* retrieve host information
        #region GET hosts
            Write-Host "$(Get-Date) [INFO] Retrieving hosts information from Nutanix cluster $($myvar_ntnx_cluster_name)..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_hosts = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            
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
            Write-Host "$(Get-Date) [INFO] Retrieving storage containers information from Nutanix cluster $($myvar_ntnx_cluster_name)..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/storage_containers/" -f $cluster
            $method = "GET"
            $myvar_ntnx_cluster_storage_containers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            
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
            Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $($myvar_ntnx_cluster_name)..." -ForegroundColor Green
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
                Write-Host "$(Get-Date) [WARNING] There are no active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Yellow
            }
            else 
            {#there are active metro availability protection domains on this cluster
                Write-Host "$(Get-Date) [DATA] There are $($myvar_ntnx_cluster_ma_active_pds.count) active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_cluster_name)" -ForegroundColor Gray
            }
        #endregion
        
        #* retrieve vms information
        #region GET vms
            Write-Host "$(Get-Date) [INFO] Retrieving virtual machines from Nutanix cluster $($myvar_ntnx_cluster_name)..." -ForegroundColor Green
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
                    Write-Host "$(Get-Date) [INFO] Retrieving remote sites from Nutanix cluster $($myvar_ntnx_cluster_name)..." -ForegroundColor Green
                    $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/remote_sites/" -f $cluster
                    $method = "GET"
                    $myvar_ntnx_cluster_remote_sites = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

                    $myvar_remote_site_name = $myvar_ntnx_cluster_ma_active_pds.metro_avail.remote_site | select-object -unique
                    if ($myvar_remote_site_name -is [array]) 
                    {#houston we have a problem: active metro pds are pointing to more than one remote site!
                        Write-Host "$(Get-Date) [ERROR] Cluster $($cluster) has metro availability protection domains which are pointing to different remote sites. Exiting." -ForegroundColor Red
                        Exit 1
                    } 
                    else 
                    {#we have figured out the remote site name
                        Write-Host "$(Get-Date) [DATA] Remote site name is $($myvar_remote_site_name)" -ForegroundColor Gray
                    }
                    
                    #* grab ip for our remote site
                    $myvar_remote_site_ip = (($myvar_ntnx_cluster_remote_sites.entities | Where-Object {$_.name -eq $myvar_remote_site_name}).remote_ip_ports).psobject.properties.name
                    Write-Host "$(Get-Date) [DATA] Remote site $($myvar_remote_site_name) ip address is $($myvar_remote_site_ip)" -ForegroundColor Gray

                    #* checking that our remote site is available
                    if (($myvar_ntnx_cluster_ma_active_pds.metro_avail.status | Select-Object -Unique) -ne "Enabled")
                    {#all active metro pds are not in "enabled" status, we need to check that we can ping the remote site
                        if (Test-Connection $myvar_remote_site_ip -Count 5 -Quiet)
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
                        Write-Host "$(Get-Date) [INFO] Retrieving cluster information from Nutanix cluster $($myvar_remote_site_ip)..." -ForegroundColor Green
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                
                        $myvar_ntnx_remote_cluster_name = $myvar_ntnx_remote_cluster_info.name
                        Write-Host "$(Get-Date) [DATA] Remote Nutanix cluster name is $($myvar_ntnx_remote_cluster_name)" -ForegroundColor Gray
                        $myvar_ntnx_remote_cluster_rf = $myvar_ntnx_remote_cluster_info.cluster_redundancy_state.desired_redundancy_factor
                
                        if (($myvar_ntnx_remote_cluster_info.hypervisor_types).count -gt 1)
                        {#cluster has mixed hypervisors
                            Write-Host "$(Get-Date) [DATA] Nutanix cluster $($myvar_ntnx_remote_cluster_name) has multiple hypervisors" -ForegroundColor Gray
                            if ($myvar_ntnx_remote_cluster_info.hypervisor_types -notcontains "kVMware")
                            {#none of the nodes are running VMware
                                Write-Host "$(Get-Date) [WARNING] None of the cluster hosts are running VMware vSphere!" -ForegroundColor Yellow
                            }
                        }
                        else 
                        {#cluster has single hypervisor
                            Write-Host "$(Get-Date) [DATA] Nutanix cluster $($myvar_ntnx_remote_cluster_name) is of hypervisor type $($myvar_ntnx_remote_cluster_info.hypervisor_types[0])" -ForegroundColor Gray
                        }
                
                        #region figure out vcenter ip
                            $myvar_remote_management_server = $myvar_ntnx_remote_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                            if ($myvar_remote_management_server -is [array]) 
                            {#houston, we have a problem, there is more than one registered vcenter
                                Write-Host "$(Get-Date) [ERROR] There is more than 1 registered management server for cluster $($myvar_remote_site_ip). Exiting." -ForegroundColor Red
                                Exit 1
                            } 
                            else 
                            {#grab vcenter ip
                                $myvar_remote_vcenter_ip = ($myvar_ntnx_remote_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                                Write-Host "$(Get-Date) [DATA] vCenter IP address for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_remote_vcenter_ip)" -ForegroundColor Gray
                            }
                            if (!$myvar_remote_vcenter_ip) 
                            {#found no vcenter ip
                                Write-Host "$(Get-Date) [WARNING] vCenter registration is not done in Prism for cluster $myvar_remote_site_ip!" -ForegroundColor Yellow
                            }
                        #endregion
                
                        #let's make sure our current redundancy is at least 2
                        if ($myvar_ntnx_remote_cluster_info.cluster_redundancy_state.current_redundancy_factor -lt $myvar_ntnx_remote_cluster_rf) 
                        {#cluster redundancy state is < replication factor (a host must be down)
                            Write-Host "$(Get-Date) [ERROR] Current redundancy is less than $($myvar_ntnx_remote_cluster_rf). Exiting." -ForegroundColor Red
                            Exit 1
                        }
                        #check if there is an upgrade in progress
                        if ($myvar_ntnx_remote_cluster_info.is_upgrade_in_progress) 
                        {#cluster has an upgrade in progress
                            Write-Host "$(Get-Date) [ERROR] Cluster upgrade is in progress. Exiting." -ForegroundColor Red
                            Exit 1
                        }
                    #endregion
                    
                    #* retrieve remote host information
                    #region GET remote_site hosts
                        Write-Host "$(Get-Date) [INFO] Retrieving hosts information from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..." -ForegroundColor Green
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_hosts = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                        
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
                        Write-Host "$(Get-Date) [INFO] Retrieving storage containers information from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..." -ForegroundColor Green
                        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/storage_containers/" -f $myvar_remote_site_ip
                        $method = "GET"
                        $myvar_ntnx_remote_cluster_storage_containers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

                        [System.Collections.ArrayList]$myvar_ntnx_remote_cluster_storage_containers_info = New-Object System.Collections.ArrayList($null)
                        ForEach ($myvar_ntnx_remote_cluster_storage_container in $myvar_ntnx_remote_cluster_storage_containers.entities)
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
                        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..." -ForegroundColor Green
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
                            Write-Host "$(Get-Date) [WARNING] There are no active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_remote_cluster_name)" -ForegroundColor Yellow
                        }
                        else 
                        {#there are active metro availability protection domains on this cluster
                            Write-Host "$(Get-Date) [DATA] There are $($myvar_ntnx_remote_cluster_ma_active_pds.count) active Metro Availability protection domain on Nutanix cluster $($myvar_ntnx_remote_cluster_name)" -ForegroundColor Gray
                        }
                    #endregion

                    #* retrieve remote vms information
                    #region GET remote_site vms
                        Write-Host "$(Get-Date) [INFO] Retrieving virtual machines from Nutanix cluster $($myvar_ntnx_remote_cluster_name)..." -ForegroundColor Green
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
    
    Write-Host "$(Get-Date) [STEP] Computing numbers..." -ForegroundColor Magenta
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
            Write-Host "$(Get-Date) [WARNING] Nutanix cluster $($myvar_ntnx_cluster_name) has no metro protected powered on UVM!" -ForegroundColor Yellow
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
                Write-Host "$(Get-Date) [WARNING] Nutanix cluster $($myvar_ntnx_remote_cluster_name) has no metro protected powered on UVM!" -ForegroundColor Yellow
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
                Write-Host "$(Get-Date) [STEP] Creating HTML report in file $($myvar_html_report_name)..." -ForegroundColor Magenta

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
                                    New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                                }
                                else 
                                {#there is not enough cpu capacity remaining
                                    New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                                }

                                if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
                                {#there is enough remaining memory capacity
                                    New-HTMLToast -TextHeader 'Remaining Memory Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                                }
                                else 
                                {#there is not enough memory capacity remaining
                                    New-HTMLToast -TextHeader 'Remaining Memory Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                                }
                            }
                            
                            #* showing capacity numbers 
                            New-HtmlTable -DataTable ($myvar_ntnx_cluster_uvm_capacity) -HideFooter {
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
                                        New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                                    }
                                    else 
                                    {#there is not enough cpu capacity remaining
                                        New-HTMLToast -TextHeader 'Remaining CPU Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                                    }

                                    if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib)
                                    {#there is enough remaining memory capacity
                                        New-HTMLToast -TextHeader 'Remaining Memory Capacity' -Text 'Good' -TextColor Green -TextHeaderColor Green -BarColorLeft Green -BarColorRight Green -IconSolid check -IconColor Green
                                    }
                                    else 
                                    {#there is not enough memory capacity remaining
                                        New-HTMLToast -TextHeader 'Remaining Memory Capacity' -Text 'Insufficient' -TextColor Red -TextHeaderColor Red -BarColorLeft Red -BarColorRight Red -IconSolid bell -IconColor Red
                                    }
                                }
                                
                                #* showing capacity numbers 
                                New-HtmlTable -DataTable ($myvar_ntnx_remote_cluster_uvm_capacity) -HideFooter {
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
            Write-Host "$(Get-Date) [DATA] Nutanix cluster $($myvar_ntnx_cluster_name) replication factor is $($myvar_ntnx_cluster_rf)" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] Total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cpu_capacity_total) cores" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] Total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ram_gib_capacity_total) GiB" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] CPU reserved for high availability for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ha_cpu_reserved) cores" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] RAM reserved for high availability for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ha_ram_gib_reserved) GiB" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] CVM CPU reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_cpu)" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] CVM RAM reserved capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_cvm_reserved_ram) GiB" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] Hypervisor CPU overhead for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_hypervisor_overhead_cpu_total)" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] Hypervisor RAM overhead for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_hypervisor_overhead_ram_gib_total) GiB" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] UVM total CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_capacity_total_cpu) vCPUs" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] UVM total RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_capacity_total_ram_gib) GiB" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_allocated_cpu) vCPUs" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_allocated_ram_gib) GiB" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] UVM remaining CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_remaining_cpu) vCPUs" -ForegroundColor Gray
            Write-Host "$(Get-Date) [DATA] UVM remaining RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_uvm_remaining_ram_gib) GiB" -ForegroundColor Gray
            if ($myvar_ntnx_cluster_ma_uvms)
            {#there are powered on vms protected by metro availability
                Write-Host "$(Get-Date) [DATA] Metro enabled UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ma_uvm_allocated_cpu) cores" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] Metro enabled UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_ntnx_cluster_ma_uvm_allocated_ram_gib) GiB" -ForegroundColor Gray
            }

            #* checking remaining capacity is sufficient
            if ($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_cluster_uvm_remaining_cpu)
            {#there is enough remaining cpu capacity
                Write-Host "$(Get-Date) [INFO] There are $($myvar_ntnx_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores) vCPUs." -ForegroundColor Green
            }
            else 
            {#there is not enough cpu capacity remaining
                Write-Host "$(Get-Date) [WARNING] There are $($myvar_ntnx_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_cpu_cores) vCPUs!" -ForegroundColor Yellow
            }
            if ($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_cluster_uvm_remaining_ram_gib)
            {#there is enough remaining memory capacity
                Write-Host "$(Get-Date) [INFO] There are $($myvar_ntnx_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib) GiB." -ForegroundColor Green
            }
            else 
            {#there is not enough memory capacity remaining
                Write-Host "$(Get-Date) [WARNING] There are $($myvar_ntnx_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_cluster_desired_capacity_headroom_ram_gib) GiB!" -ForegroundColor Yellow
            }

            if ($myvar_remote_site_online)
            {#remote site is available
                Write-Host ""
                Write-Host "$(Get-Date) [DATA] Nutanix cluster $($myvar_ntnx_remote_cluster_name) replication factor is $($myvar_ntnx_remote_cluster_rf)" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] Total CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_cpu_capacity_total) cores" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] Total RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ram_gib_capacity_total) GiB" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] CPU reserved for high availability for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ha_cpu_reserved) cores" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] RAM reserved for high availability for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ha_ram_gib_reserved) GiB" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] CVM CPU reserved capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_cvm_reserved_cpu)" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] CVM RAM reserved capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_cvm_reserved_ram) GiB" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] Hypervisor CPU overhead for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_hypervisor_overhead_cpu_total)" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] Hypervisor RAM overhead for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_hypervisor_overhead_ram_gib_total) GiB" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] UVM total CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_capacity_total_cpu) vCPUs" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] UVM total RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_capacity_total_ram_gib) GiB" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] UVM allocated CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_allocated_cpu) vCPUs" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_allocated_ram_gib) GiB" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] UVM remaining CPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_remaining_cpu) vCPUs" -ForegroundColor Gray
                Write-Host "$(Get-Date) [DATA] UVM remaining RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib) GiB" -ForegroundColor Gray
                if ($myvar_ntnx_remote_cluster_ma_uvms)
                {#there are powered on vms protected by metro availability
                    Write-Host "$(Get-Date) [DATA] Metro enabled UVM allocated vCPU capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ma_uvm_allocated_cpu) vCPUs" -ForegroundColor Gray
                    Write-Host "$(Get-Date) [DATA] Metro enabled UVM allocated RAM capacity for Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_ntnx_remote_cluster_ma_uvm_allocated_ram_gib) GiB" -ForegroundColor Gray
                }

                #* checking remaining capacity is sufficient
                if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores -lt $myvar_ntnx_remote_cluster_uvm_remaining_cpu)
                {#there is enough remaining cpu capacity
                    Write-Host "$(Get-Date) [INFO] There are $($myvar_ntnx_remote_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores) vCPUs." -ForegroundColor Green
                }
                else 
                {#there is not enough cpu capacity remaining
                    Write-Host "$(Get-Date) [WARNING] There are $($myvar_ntnx_remote_cluster_uvm_remaining_cpu) vCPUs still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_cpu_cores) vCPUs!" -ForegroundColor Yellow
                }
                if ($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib -lt $myvar_ntnx_remote_cluster_uvm_remaining_ram_gib)
                {#there is enough remaining memory capacity
                    Write-Host "$(Get-Date) [INFO] There are $($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib) GiB." -ForegroundColor Green
                }
                else 
                {#there is not enough memory capacity remaining
                    Write-Host "$(Get-Date) [WARNING] There are $($myvar_ntnx_remote_cluster_uvm_remaining_ram_gib) memory GiB still available for UVMs when the desired remaining capacity is $($myvar_ntnx_remote_cluster_desired_capacity_headroom_ram_gib) GiB!" -ForegroundColor Yellow
                }

                Write-Host ""
                if ($myvar_ntnx_cluster_failover_capacity_color -eq "Green")
                {#capacity is green
                    Write-Host "$(Get-Date) [INFO] Cluster $($myvar_ntnx_cluster_name) Metro Failover capability is: $($myvar_ntnx_cluster_failover_capacity_status)" -ForegroundColor Green
                }
                elseif ($myvar_ntnx_cluster_failover_capacity_color -eq "Red")
                {#capacity is red
                    Write-Host "$(Get-Date) [ERROR] Cluster $($myvar_ntnx_cluster_name) Metro Failover capability is: $($myvar_ntnx_cluster_failover_capacity_status)" -ForegroundColor Red
                }

                if ($myvar_ntnx_remote_cluster_failover_capacity_color -eq "Green")
                {#capacity is green
                    Write-Host "$(Get-Date) [INFO] Cluster $($myvar_ntnx_remote_cluster_name) Metro Failover capability is: $($myvar_ntnx_remote_cluster_failover_capacity_status)" -ForegroundColor Green
                }
                elseif ($myvar_ntnx_remote_cluster_failover_capacity_color -eq "Red")
                {#capacity is red
                    Write-Host "$(Get-Date) [ERROR] Cluster $($myvar_ntnx_remote_cluster_name) Metro Failover capability is: $($myvar_ntnx_remote_cluster_failover_capacity_status)" -ForegroundColor Red
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
                    Write-Host "$(Get-Date) [INFO] Sending UVM capacity data for cluster $($myvar_ntnx_cluster_name) to InfluxDB server $($myvar_influxdb_url) in database $($myvar_influxdb_database) as time series uvm_capacity..." -ForegroundColor Green
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
                        Write-Host "$(Get-Date) [INFO] Sending UVM capacity data for cluster $($myvar_ntnx_remote_cluster_name) to InfluxDB server $($myvar_influxdb_url) in database $($myvar_influxdb_database) as time series uvm_capacity..." -ForegroundColor Green
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
                    Write-Host "$(Get-Date) [WARNING] Could not send data to influxdb: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        #endregion

        #* smtp output
        #region smtp output
            if ($email)
            {#we need to send email
                #sender ([MimeKit.MailboxAddress] http://www.mimekit.net/docs/html/T_MimeKit_MailboxAddress.htm, required)
                $From=[MimeKit.MailboxAddress]$emailCredentials.UserName

                #recipient list ([MimeKit.InternetAddressList] http://www.mimekit.net/docs/html/T_MimeKit_InternetAddressList.htm, required)
                $RecipientList=[MimeKit.InternetAddressList]::new()
                $RecipientList.Add([MimeKit.InternetAddress]$myvar_smtp_to)

                #attachment list ([System.Collections.Generic.List[string]], optional)
                $AttachmentList=[System.Collections.Generic.List[string]]::new()
                $AttachmentList.Add($myvar_html_report_name)

                #* putting together mail content (as html)
                $myvar_smtp_subject = "UVM Capacity Report for Nutanix Cluster $($myvar_ntnx_cluster_name)"
                $myvar_smtp_html_body = EmailBody {
                    EmailTextBox -FontFamily 'Calibri' -Size 22 -TextDecoration underline -Color Blue -Alignment center {
                        'Virtual Machine Capacity Report'
                    }
                    EmailText -LineBreak
                    if ($myvar_remote_site_online)
                    {#remote site is available
                        EmailText -FontSize 20 -Text "Metro Failover Capacity" -Color Blue -FontFamily 'Calibri'
                        EmailText -FontSize 17 -Text $myvar_ntnx_cluster_widget_header -Color $myvar_ntnx_cluster_failover_capacity_color -FontFamily 'Calibri'
                        EmailText -FontSize 15 -Text $myvar_ntnx_cluster_failover_capacity_status -Color $myvar_ntnx_cluster_failover_capacity_color -FontFamily 'Calibri'
                        EmailText -FontSize 17 -Text $myvar_ntnx_remote_cluster_widget_header -Color $myvar_ntnx_remote_cluster_failover_capacity_color -FontFamily 'Calibri'
                        EmailText -FontSize 15 -Text $myvar_ntnx_remote_cluster_failover_capacity_status -Color $myvar_ntnx_remote_cluster_failover_capacity_color -FontFamily 'Calibri'
                        EmailText -LineBreak
                    }
                    else 
                    {
                        EmailText -FontSize 20 -Text "Remaining Virtual Machine Capacity" -Color Blue -FontFamily 'Calibri'
                        EmailTable -Table $myvar_ntnx_cluster_uvm_capacity -HideFooter -Title "Remaining Virtual Machine Capacity"
                        EmailText -LineBreak
                    }
                    
                    EmailText -FontSize 20 -Text "Report configuration settings" -Color Blue -FontFamily 'Calibri'
                    EmailTable -Table $myvar_report_configuration_settings -HideFooter -Title "Report configuration settings"
                    EmailText -LineBreak
                }

                #send message
                Write-Host "$(Get-Date) [INFO] Sending email message to $($myvar_smtp_to)..." -ForegroundColor Green
                try
                {#sending mail
                    Send-MailKitMessage -UseSecureConnectionIfAvailable -Credential $emailCredentials -SMTPServer $myvar_smtp_server -Port $myvar_smtp_server_port -From $From -RecipientList $RecipientList -Subject $myvar_smtp_subject -HtmlBody $myvar_smtp_html_body -AttachmentList $AttachmentList -ErrorAction Stop
                    Write-Host "$(Get-Date) [SUCCESS] Successfully sent email message to $($myvar_smtp_to)" -ForegroundColor Cyan
                }
                catch
                {#could not send mail
                    Write-Host "$(Get-Date) [ERROR] Could not send email message to $($myvar_smtp_to): $($_.Exception.Message)" -ForegroundColor Red
                }
            }   
        #endregion
    #endregion
#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable html -ErrorAction SilentlyContinue
    Remove-Variable viewnow -ErrorAction SilentlyContinue
    Remove-Variable dir -ErrorAction SilentlyContinue
    Remove-Variable influxdb -ErrorAction SilentlyContinue
    Remove-Variable influxdbCreds -ErrorAction SilentlyContinue
    Remove-Variable email -ErrorAction SilentlyContinue
    Remove-Variable emailCreds -ErrorAction SilentlyContinue
#endregion