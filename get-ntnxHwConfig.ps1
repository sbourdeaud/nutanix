<#
.SYNOPSIS
  This script retrieves detailed hardware configuration of all nodes managed from a Nutanix Prism Central instance.
.DESCRIPTION
  This script retrieves details of the hardware configuration of Nutanix nodes managed by Prism Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER csv
  Name of csv file to export to. By default this is date_prism-hw-report.csv in the working directory.
.EXAMPLE
.\get-ntnxHwConfig.ps1 -prism ntnxc1.local -username admin -password admin
Connect to a Nutanix Prism Central VM of your choice and retrieve the hardware configuration for all managed nodes.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: January 17th 2020
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $true)] [string]$prism,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [string]$csv
)
#endregion

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

#endregion

#region prepwork

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
01/17/2020 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\get-ntnxHwConfig.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

# ignore SSL warnings
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
}
[ServerCertificateValidationCallback]::Ignore()

# add Tls12 support
Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
[Net.ServicePointManager]::SecurityProtocol = `
    ([Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12)

#endregion

#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
#prepare our overall results variable
[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarClustersResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarHostsResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarDisksResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarClustersResultsFinal = New-Object System.Collections.ArrayList($null)
$length=500 #this specifies how many entities we want in the results of each API query
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
}
if (!$csv) {$csv = $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"prism-hw-report.csv"}
#endregion

#region processing

    #! step 1: retrieve clusters managed in Prism Central
    #region prepare api call
    $api_server_port = "9440"
    $api_server_endpoint = "/api/nutanix/v3/clusters/list"
    $url = "https://{0}:{1}{2}" -f $prism,$api_server_port, $api_server_endpoint
    $method = "POST"

    $headers = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
        "Content-Type"="application/json";
        "Accept"="application/json"
    }

    # this is used to capture the content of the payload
    $content = @{
        kind="cluster";
        offset=0;
        length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    #endregion

    #region make api call
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    Do {
        try {
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            }
            
            Write-Host "$(Get-Date) [INFO] Processing results from $($resp.metadata.offset) to $($resp.metadata.offset + $resp.metadata.length)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

            #grab the information we need in each entity
            ForEach ($entity in $resp.entities) {
                if ($entity.status.resources.nodes.hypervisor_server_list) {
                    $myvarClusterInfo = [ordered]@{
                        "name" = $entity.status.name;
                        "uuid" = $entity.metadata.uuid;
                        "nos_version" = $entity.status.resources.config.software_map.NOS.version;
                        "redundancy_factor" = $entity.status.resources.config.redundancy_factor;
                        "domain_awareness_level" = $entity.status.resources.config.domain_awareness_level;
                        "is_long_term_support" = $entity.status.resources.config.build.is_long_term_support;
                        "timezone" = $entity.status.resources.config.timezone;
                        "external_ip" = $entity.status.resources.network.external_ip
                    }
                    #store the results for this entity in our overall result variable
                    $myvarClustersResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
                }
            }

            #prepare the json payload for the next batch of entities/response
            $content = @{
                kind="cluster";
                offset=($resp.metadata.length + $resp.metadata.offset);
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
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
    While ($resp.metadata.length -eq $length)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarClustersResults
    }
    #endregion

    #! step 2: retrieve disks information from Prism Element
    #foreach cluster in $myvarClustersResults: 1/query the external_ip for the disks endpoint and capture the info needed, then 2/aggregate disk results to determine each host storage size (raw and rf)
    ForEach ($cluster in $myvarClustersResults) {
        #region prepare api call
        $api_server_port = "9440"
        $api_server_endpoint = "/PrismGateway/services/rest/v2.0/disks/"
        $url = "https://{0}:{1}{2}" -f $cluster.external_ip,$api_server_port, $api_server_endpoint
        $method = "GET"

        $headers = @{
            "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
            "Content-Type"="application/json";
            "Accept"="application/json"
        }
        #endregion

        #region make api call
        Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
        Do {
            try {
                #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
                if ($PSVersionTable.PSVersion.Major -gt 5) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                } else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
                
                Write-Host "$(Get-Date) [INFO] Processing results from $($resp.metadata.offset) to $($resp.metadata.offset + $resp.metadata.length)" -ForegroundColor Green
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) {
                    if ($entity.status.resources.block.block_model -ne "null") {
                        $myvarDiskInfo = [ordered]@{
                            "id" = $entity.id;
                            "disk_uuid" = $entity.disk_uuid;
                            "serial_number" = $entity.disk_hardware_config.serial_number;
                            "model" = $entity.disk_hardware_config.model;
                            "storage_tier_name" = $entity.storage_tier_name;
                            "disk_size" = [Int64]$entity.disk_size;
                            "online" = $entity.online;
                            "disk_status" = $entity.disk_status;
                            "location" = $entity.location;
                            "self_encrypting_drive" = $entity.self_encrypting_drive;
                            "current_firmware_version" = $entity.disk_hardware_config.current_firmware_version;
                            "host_name" = $entity.host_name;
                            "node_name" = $entity.node_name;
                            "cvm_ip_address" = $entity.cvm_ip_address;
                            "node_uuid" = $entity.node_uuid;
                            "cluster_name" = ($myvarClustersResults | Where-Object {$_.uuid -eq $entity.cluster_uuid}).name;
                            "cluster_uuid" = $entity.cluster_uuid
                        }
                        #store the results for this entity in our overall result variable
                        $myvarDisksResults.Add((New-Object PSObject -Property $myvarDiskInfo)) | Out-Null
                    }
                }

                #prepare the json payload for the next batch of entities/response
                $content = @{
                    kind="host";
                    offset=($resp.metadata.length + $resp.metadata.offset);
                    length=$length
                }
                $payload = (ConvertTo-Json $content -Depth 4)
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
        While ($resp.metadata.length -eq $length)

        if ($debugme) {
            Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
            $myvarDisksResults
        }
        
        #endregion
    }

    #!step 3: retrieve hosts managed in Prism Central
    #region prepare api call
    $api_server_port = "9440"
    $api_server_endpoint = "/api/nutanix/v3/hosts/list"
    $url = "https://{0}:{1}{2}" -f $prism,$api_server_port, $api_server_endpoint
    $method = "POST"

    $headers = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
        "Content-Type"="application/json";
        "Accept"="application/json"
    }

    # this is used to capture the content of the payload
    $content = @{
        kind="host";
        offset=0;
        length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    #endregion

    #region make api call
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    Do {
        try {
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            }
            
            Write-Host "$(Get-Date) [INFO] Processing results from $($resp.metadata.offset) to $($resp.metadata.offset + $resp.metadata.length)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

            #grab the information we need in each entity
            ForEach ($entity in $resp.entities) {
                if ($entity.status.resources.block.block_model -ne "null") {
                    $myvarHostInfo = [ordered]@{
                        "name" = $entity.status.name;
                        "uuid" = $entity.metadata.uuid;
                        "serial_number" = $entity.status.resources.serial_number;
                        "block_model" = $entity.status.resources.block.block_model;
                        "block_serial_number" = $entity.status.resources.block.block_serial_number;
                        "cpu_model" = $entity.status.resources.cpu_model;
                        "cpu_capacity_hz" = [Int64]$entity.status.resources.cpu_capacity_hz;
                        "num_cpu_sockets" = $entity.status.resources.num_cpu_sockets;
                        "num_cpu_cores" = $entity.status.resources.num_cpu_cores;
                        "memory_capacity_gib" = "{0:n0}" -f ($entity.status.resources.memory_capacity_mib /1024);
                        "storage_capacity_tib" = "{0:n2}" -f ((($myvarDisksResults | Where-Object {$_.node_name -eq $entity.status.name}).disk_size | Measure-Object -Sum).Sum /1024/1024/1024/1024);
                        "ssd_qty" = [Int32]($myvarDisksResults | Where-Object {$_.node_name -eq $entity.status.name} | Where-Object {$_.storage_tier_name -eq "SSD"}).Count;
                        "ssd_size_gib" = "{0:n0}" -f ((($myvarDisksResults | Where-Object {$_.node_name -eq $entity.status.name} | Where-Object {$_.storage_tier_name -eq "SSD"}).disk_size | Measure-Object -Minimum).Minimum /1024/1024/1024);
                        "cvm_ip" = $entity.status.resources.controller_vm.ip;
                        "hypervisor_ip" = $entity.status.resources.hypervisor.ip;
                        "ipmi_ip" = $entity.status.resources.ipmi.ip;
                        "hypervisor_full_name" = $entity.status.resources.hypervisor.hypervisor_full_name;
                        "cluster_name" = ($myvarClustersResults | Where-Object {$_.uuid -eq $entity.status.cluster_reference.uuid}).name;
                        "cluster_uuid" = $entity.status.cluster_reference.uuid
                    }
                    #store the results for this entity in our overall result variable
                    $myvarHostsResults.Add((New-Object PSObject -Property $myvarHostInfo)) | Out-Null
                }
            }

            #prepare the json payload for the next batch of entities/response
            $content = @{
                kind="host";
                offset=($resp.metadata.length + $resp.metadata.offset);
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
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
    While ($resp.metadata.length -eq $length)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarHostsResults
    }
    
    #endregion

    #! step 4: process all the results
    #create xls with multiple tabs or multiple csvs?
    #region agregate info for clusters
        ForEach ($cluster in $myvarClustersResults) {
            $myvarClusterInfo = [ordered]@{
                "name" = $cluster.name;
                "uuid" = $cluster.uuid;
                "nos_version" = $cluster.nos_version;
                "redundancy_factor" = $cluster.redundancy_factor;
                "domain_awareness_level" = $cluster.domain_awareness_level;
                "is_long_term_support" = $cluster.is_long_term_support;
                "timezone" = $cluster.timezone;
                "external_ip" = $cluster.external_ip;
                "total_capacity_tib" = "{0:n2}" -f ((($myvarHostsResults | Where-Object {$_.cluster_uuid -eq $cluster.uuid}).storage_capacity_tib | Measure-Object -Sum).Sum);
                "max_node_capacity_tib" = "{0:n2}" -f ((($myvarHostsResults | Where-Object {$_.cluster_uuid -eq $cluster.uuid}).storage_capacity_tib | Measure-Object -Maximum).Maximum);
                "min_node_ssd_qty" = "{0:n0}" -f ((($myvarHostsResults | Where-Object {$_.cluster_uuid -eq $cluster.uuid}).ssd_qty | Measure-Object -Minimum).Minimum);
                "min_ssd_size_gib" = "{0:n0}" -f ((($myvarHostsResults | Where-Object {$_.cluster_uuid -eq $cluster.uuid}).ssd_size_gib | Measure-Object -Minimum).Minimum)
                #todo add number of nodes, total ssd qty, total disk qty
            }
            $myvarClustersResultsFinal.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
        }
        if ($debugme) {
            Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
            $myvarClustersResultsFinal
        }

    #endregion

    #! step 5: export the results
    #Write-Host "$(Get-Date) [INFO] Writing results to $(csv)" -ForegroundColor Green
    #$myvarResults | export-csv -NoTypeInformation $csv
    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")DisksResults.csv" -ForegroundColor Green
    $myvarDisksResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"DisksResults.csv")
    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")HostsResults.csv" -ForegroundColor Green
    $myvarHostsResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"HostsResults.csv")
    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")ClustersResults.csv" -ForegroundColor Green
    $myvarClustersResultsFinal | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"ClustersResults.csv")


#endregion

#region Cleanup	
#let's figure out how much time this all took
Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable help -ErrorAction SilentlyContinue
Remove-Variable history -ErrorAction SilentlyContinue
Remove-Variable log -ErrorAction SilentlyContinue
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable cluster -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
