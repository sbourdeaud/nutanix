<#
.SYNOPSIS
  This script retrieves the list of virtual machines which are tagged as agent VMs from Prism Element.
.DESCRIPTION
  This script retrieves the list of virtual machines which are tagged as agent VMs from Prism Element.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix Prism Element fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER update
  Use this if you want to update the vm agent status to false for all the vms returned.
.EXAMPLE
.\get-AhvVmAgent.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix Prism Element of your choice and retrieve the list of agent VMs.
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
    [parameter(mandatory = $true)] [string]$prism,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [switch]$update
)
#endregion

#region prepwork

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
02/04/2020 sb   Initial release.
04/06/2020 sb   Do over with sbourdeaud module
################################################################################
'@
$myvarScriptName = ".\get-AhvVmAgent.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

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
$MyVarModuleVersion = Get-Module -Name sbourdeaud | Select-Object -Property Version
if (($MyVarModuleVersion.Version.Major -lt 3) -or (($MyVarModuleVersion.Version.Major -eq 3) -and ($MyVarModuleVersion.Version.Minor -eq 0) -and ($MyVarModuleVersion.Version.Build -lt 1))) {
  Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
  try {Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
  catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
}
#endregion
Set-PoSHSSLCerts
Set-PoshTls
#endregion

#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
#prepare our overall results variable
[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
$length=200 #this specifies how many entities we want in the results of each API query
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

#region prepare api call
$api_server_port = "9440"
$api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/"
$url = "https://{0}:{1}{2}" -f $prism,$api_server_port, $api_server_endpoint
$method = "GET"

#endregion

#region make api call
try {
    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    
    #grab the information we need in each entity
    ForEach ($entity in $resp.entities) {
        $myvarVmInfo = [ordered]@{
            "name" = $entity.name;
            "is_agent_vm" = $entity.vm_features.AGENT_VM;
            "uuid" = $entity.uuid
        }
        #store the results for this entity in our overall result variable
        if ($myvarVmInfo.is_agent_vm) {
            $myvarResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
        }
    }

}
catch {
    $saved_error = $_.Exception.Message
    # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
    Throw "$(get-date) [ERROR] $saved_error"
}
finally {
    #add any last words here; this gets processed no matter what
}

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $myvarResults
}
#Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")VmList.csv" -ForegroundColor Green
if ($myvarResults) {
    ForEach ($vm in $myvarResults) {
        write-host "$($vm.name), $($vm.uuid)"
    }
} else {
    Write-Host "$(Get-Date) [WARNING] There are no agent VMs on cluster $($prism)!" -ForegroundColor Yellow
}
#endregion

#region update
if ($update) {
    ForEach ($vm in $myvarResults) {
        #region prepare api call
        $api_server_port = "9440"
        $api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/{0}" -f $vm.uuid 
        $url = "https://{0}:{1}{2}" -f $prism,$api_server_port, $api_server_endpoint
        $method = "PUT"

        # this is used to capture the content of the payload
        $content = @{
            vm_features= @{
                AGENT_VM= "false"
            }
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make api call
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials           
            Write-Host "$(Get-Date) [INFO] Changed vm $($vm.name) to NOT be an agent vm." -ForegroundColor Green
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Host "$(Get-Date) [INFO] Payload: $($payload)"
            Throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
        #endregion
    }
}
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
