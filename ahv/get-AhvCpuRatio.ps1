<#
.SYNOPSIS
  This script connects to Prism Central and for each managed cluster, returns
  the CPU oversubscription ratio.
.DESCRIPTION
  This script connects to Prism Central and for each managed cluster, returns
  the CPU oversubscription ratio (total number of allocated vCPUs / number of 
  logical cores).
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER ignorePoweredOff
  Ignores VMs which are powered off.
.EXAMPLE
.\get-AhvCpuRatio.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix Prism Central VM of your choice and compute the CPU 
oversubscription ratio for each managed AHV cluster.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 6th 2020
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
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [switch]$ignorePoweredOff
)
#endregion

#region prepwork

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
09/23/2019 sb   Initial release.
04/06/2020 sb   Do over with sbourdeaud module
################################################################################
'@
$myvarScriptName = ".\get-AhvCpuRatio.ps1"

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
#endregion

#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
#prepare our overall results variable
[System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarHostResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarClusterResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarReport = New-Object System.Collections.ArrayList($null)
$length=100 #this specifies how many entities we want in the results of each API query
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

#region prepare api call (get vms)
$api_server_port = "9440"
$api_server_endpoint = "/api/nutanix/v3/vms/list"
$url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
$method = "POST"

# this is used to capture the content of the payload
$content = @{
    kind="vm";
    offset=0;
    length=$length
}
$payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call and process results (get vms)
Do {
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

    #grab the information we need in each entity
    ForEach ($entity in $resp.entities) {
        if ($entity.spec.resources.num_sockets) {
            $myvarVmInfo = [ordered]@{
                "num_sockets" = $entity.spec.resources.num_sockets;
                "power_state" = $entity.spec.resources.power_state;
                "cluster" = $entity.spec.cluster_reference.name;
                "hypervisor" = $entity.status.resources.hypervisor_type;
                "cluster_uuid" = $entity.status.cluster_reference.uuid;
            }
            #store the results for this entity in our overall result variable
            $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
        }
    }

    #prepare the json payload for the next batch of entities/response
    $content = @{
        kind="vm";
        offset=($resp.metadata.length + $resp.metadata.offset);
        length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
}
While ($resp.metadata.length -eq $length)

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $resp
}
#endregion

#region prepare api call (get hosts)
$api_server_port = "9440"
$api_server_endpoint = "/api/nutanix/v3/hosts/list"
$url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
$method = "POST"

# this is used to capture the content of the payload
$content = @{
    kind="host";
    offset=0;
    length=$length
}
$payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call and process results (get hosts)
Do {
    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
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
        if ($entity.status.resources.num_cpu_sockets) {
            $myvarHostInfo = [ordered]@{
                "num_cpu_sockets" = $entity.status.resources.num_cpu_sockets;
                "num_cpu_cores" = $entity.status.resources.num_cpu_cores;
                #"num_cpu_total_cores" = ($entity.status.resources.num_cpu_sockets * $entity.status.resources.num_cpu_cores);
                "cluster_uuid" = $entity.status.cluster_reference.uuid;
            }
            #store the results for this entity in our overall result variable
            $myvarHostResults.Add((New-Object PSObject -Property $myvarHostInfo)) | Out-Null
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
While ($resp.metadata.length -eq $length)

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $myvarHostResults
}
#endregion

#region prepare api call (get clusters)
$api_server_port = "9440"
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

#region make api call and process results (get clusters)
Do {
    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
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
    
    #grab the information we need in each entity
    ForEach ($entity in $resp.entities) {
        if ($entity.status.resources.nodes.hypervisor_server_list) {
            $myvarClusterInfo = [ordered]@{
                "cluster_name" = $entity.spec.name;
                "hypervisor" = $entity.status.resources.nodes.hypervisor_server_list[0].type;
                "cluster_uuid" = $entity.metadata.uuid;
            }
            #store the results for this entity in our overall result variable
            $myvarClusterResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
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
While ($resp.metadata.length -eq $length)

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $myvarClusterResults
}
#endregion

#region process and print overall results
ForEach ($cluster in $myvarClusterResults) {
    if ($ignorePoweredOff) {
        $myvarAllocatedvCpus = ($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | where {$_.power_state -eq "ON"} | measure num_sockets -sum).Sum
        $myvarAveragevCpuAllocation = [math]::Round(($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | where {$_.power_state -eq "ON"} | measure num_sockets -average).Average)
    }
    else {
        $myvarAllocatedvCpus = ($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | measure num_sockets -sum).Sum
        $myvarAveragevCpuAllocation = [math]::Round(($myvarVmResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | measure num_sockets -average).Average)
    }
    $myvarTotalCores = ($myvarHostResults | where {$_.cluster_uuid -eq $cluster.cluster_uuid} | measure num_cpu_cores -sum).Sum
    $myvarCpuRatio = [math]::Round($myvarAllocatedvCpus / $myvarTotalCores,2)
    $myvarClusterReport = [ordered]@{
        "cluster_name" = $cluster.cluster_name;
        "hypervisor" = $cluster.hypervisor;
        "cluster_uuid" = $cluster.cluster_uuid;
        "allocated_vcpus" = $myvarAllocatedvCpus;
        "average_vcpu_allocation" = $myvarAveragevCpuAllocation;
        "total_cores" = $myvarTotalCores;
        "cpu_ratio" = $myvarCpuRatio;
    }
    #store the results for this entity in our overall result variable
    $myvarReport.Add((New-Object PSObject -Property $myvarClusterReport)) | Out-Null
}
$myvarClusterReport | ft
#endregion

#region cleanup	
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
