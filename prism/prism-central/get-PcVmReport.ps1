<#
.SYNOPSIS
  Generates a csv file containing a virtual machine inventory for all clusters managed by Prism Central, regardless of the hypervisor.
.DESCRIPTION
  VM inventory for all clusters managed by Prism Central. Generates a single csv file with cluster name, hypervisor, vm name, cpu, ram, vnic and vdisk information.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\template.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: May 26th 2020
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$prismcentral,
        [parameter(mandatory = $false)] [string]$username,
        [parameter(mandatory = $false)] [string]$password,
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion

#region functions

#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
05/26/2020 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-PcVmReport.ps1"

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
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = 9440
    $length = 200
    [System.Collections.ArrayList]$myvarClustersResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
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
#endregion

#region processing

    #* step 1: retrieve list of clusters managed by Prism Central
    #region get clusters
        Write-Host "$(get-date) [INFO] Retrieving list of clusters..." -ForegroundColor Green
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/clusters/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $content = @{
                kind="cluster";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion
        #region make api call
            Do {
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    $listLength = 0
                    if ($resp.metadata.offset) {
                        $firstItem = $resp.metadata.offset
                    } else {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                        $listLength = $resp.metadata.length
                    } else {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
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
                                "external_ip" = $entity.status.resources.network.external_ip;
                                "hypervisor" = $entity.status.resources.nodes.hypervisor_server_list.type | Select-Object -Unique
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
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved clusters list from $prismcentral!" -ForegroundColor Cyan
    #endregion

    #* step 2: for each cluster, get the list of vms
    #region get vms
        $api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true&include_vm_nic_config=true"
        $method = "GET"
        ForEach ($cluster in $myvarClustersResults) {
            Write-Host "$(get-date) [INFO] Retrieving list of vms for cluster $($cluster.name)..." -ForegroundColor Green
            $url = "https://{0}:{1}{2}" -f $cluster.external_ip,$api_server_port, $api_server_endpoint
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of vms for cluster $($cluster.name)!" -ForegroundColor Cyan
            ForEach ($entity in $resp.entities) {
                $myvarVmInfo = [ordered]@{
                    "cluster" = $cluster.name;
                    "hypervisor" = $cluster.hypervisor;
                    "name" = $entity.name;
                    "description" = $entity.description;
                    "uuid" = $entity.uuid;
                    "num_vcpus" = $entity.num_vcpus;
                    "num_cores_per_vcpu" = $entity.num_cores_per_vcpu;
                    "memory_mb" = $entity.memory_mb;
                    "power_state" = $entity.power_state;
                    "gpus_assigned" = $entity.gpus_assigned;
                    "uefi_boot" = $entity.boot.uefi_boot;
                    "ip_addresses" = $entity.vm_nics.ip_address -join ',';
                    "mac_addresses" = $entity.vm_nics.mac_address -join ',';
                    "vdisks" = $entity.vm_disk_info.disk_address.disk_label -join ',';
                    "vdisk_total_bytes" = ($entity.vm_disk_info | where-object {$_.is_cdrom -eq $false} | Measure-Object size -Sum).Sum;
                }
                #store the results for this entity in our overall result variable
                $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
            }
        }
    #endregion

    #* step 3: export results
    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")VmList.csv" -ForegroundColor Green
    $myvarVmResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"VmList.csv")

#endregion

#region cleanup
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable username -ErrorAction SilentlyContinue
    Remove-Variable password -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion