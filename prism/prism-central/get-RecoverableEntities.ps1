<#
.SYNOPSIS
  This script retrieves the list of recoverable entities for a given recovery plan.
.DESCRIPTION
  The script uses v3 REST API in Prism Central to GET the list of recoverable entities for a given recovery plan.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER recoveryplan
  Name of the recovery plan for which you want to list recoverable entities.
.PARAMETER csv
  Export the results to csv as well as print them out to screen.

.EXAMPLE
.\get-RecoverableEntities.ps1 -cluster ntnxc1.local -recoveryplan myplan
Retrieve the list of recoverable entities for recovery plan "myplan".

.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
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
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true)] [string]$recoveryplan,
        [parameter(mandatory = $false)] [switch]$csv
    )
#endregion

#region prepwork
    # get rid of annoying error messages
    #if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
    #check if we need to display help and/or history
    $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 03/26/2020 sb   Initial release.
 04/17/2020 sb   Do over with sbourdeaud module.
 02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\get-RecoverableEntities.ps1"
    
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
            Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module -Name sbourdeaud -ErrorAction Stop
        }
        catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
        }
    #endregion
    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    #initialize variables
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
    $length = 500
    $cluster = $prismcentral
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
        }
        catch 
        {
            Set-CustomCredentials -credname $prismCreds
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
        }
    }
    $username = $prismCredentials.UserName
    $PrismSecurePassword = $prismCredentials.Password
    $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
#endregion

#region processing	
   
    #region retrieving all recovery plans
        $content = @{
            kind="recovery_plan";
            offset=0;
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        Write-Host "$(get-date) [INFO] Retrieving list of recovery plans..." -ForegroundColor Green
        $url = "https://$($cluster):9440/api/nutanix/v3/recovery_plans/list"
        $method = "POST"
        $rpList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved recovery plans list from $cluster!" -ForegroundColor Cyan

        
        Foreach ($entity in $rpList.entities) {
            if ($entity.status.name -eq $recoveryplan) {
                $myvarRpUuid = $entity.metadata.uuid
                break
            }
        }#end foreach entity
        if (!$myvarRpUuid) {
            throw "$(get-date) [ERROR] Could not find a recovery plan named $($recoveryplan) in $($prismcentral)"
        }
    #endregion

    #region retrieving recoverable entities
        Write-Host "$(get-date) [INFO] Retrieving recoverable entities for recovery plan $($recoveryplan) with uuid $($myvarRpUuid)..." -ForegroundColor Green
        $url = "https://$($cluster):9440/api/nutanix/v3/recovery_plans/$($myvarRpUuid)/entities"
        $method = "GET"
        $recoverableEntitiesList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved recoverable entities for recovery plan $($recoveryplan)!" -ForegroundColor Cyan

        
        Foreach ($entity in $recoverableEntitiesList.entities_per_availability_zone_list) {
            Foreach ($item in $entity.entity_list) {
                $myvarItemInfo = [ordered]@{
                    "name" = $item.any_entity_reference.name;
                    "kind" = $item.any_entity_reference.kind;
                    "uuid" = $item.any_entity_reference.uuid
                }
                #store the results for this entity in our overall result variable
                $myvarResults.Add((New-Object PSObject -Property $myvarItemInfo)) | Out-Null
                #Write-Host "$($item.any_entity_reference.kind):$($item.any_entity_reference.name)"
            }
        }#end foreach entity
    #endregion

    $myvarResults | ft -AutoSize
    if ($csv) {
        Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($recoveryplan)_entities.csv" -ForegroundColor Green
        $myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$recoveryplan+"_entities.csv")
    }

#endregion

#region cleanup
    Remove-Variable myvar* -ErrorAction SilentlyContinue
	#let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
#endregion