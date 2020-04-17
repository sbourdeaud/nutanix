<#
.SYNOPSIS
  This script can be used to retrieve all alerts and their configuration from a Prism instance.
.DESCRIPTION
  Given a Nutanix cluster, retrieve all alerts and healthchecks with full information, including severity, causes, resolutions, KB, etc... and export to a CSV file.
.PARAMETER prism
  IP address or FQDN of the Nutanix cluster (this can also be a single CVM IP or FQDN).
.PARAMETER username
  Prism username (with privileged cluster admin access).
.PARAMETER password
  Prism username password.
.PARAMETER csv
  Name of csv file to export to. By default this is prism-alerts-report.csv in the working directory.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
  PS> .\get-ntnxAlertPolicy.ps1 -prism 10.10.10.1 -username admin -password nutanix/4u -csv c:\temp\production-cluster-report.csv
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 17th 2020
#>

#region Parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$log,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$prism,
      [parameter(mandatory = $false)] [string]$username,
      [parameter(mandatory = $false)] [string]$password,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [string]$csv
  )
#endregion

#region prep-work
  #check if we need to display help and/or history
  $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 04/04/2017 sb   Initial release.
 12/19/2019 sb   Updated code to use REST API instead of cmdlets.
 04/17/2020 sb   Do over to use sbourdeaud module.
################################################################################
'@
  $myvarScriptName = ".\get-ntnxAlertPolicy.ps1"
  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

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
  #initialize variables
  #misc variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
  $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
  $myvarOutputLogFile += "OutputLog.log"

  [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all entries.  This is what will be exported to csv
  $api_server = $prism
  $api_server_port = "9440"

  ############################################################################
  # command line arguments initialization
  ############################################################################	
  #let's initialize parameters if they haven't been specified
  if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism"}
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
  if (!$csv) {$csv = "prism-alerts-report.csv"}
#endregion

#region processing

  #region prepare api call
    $api_server_endpoint = "/PrismGateway/services/rest/v1/health_checks/?includeInternalChecks=true"
    $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
        $api_server_endpoint
    $method = "GET"
  #endregion

  #region make the api call
    Write-Host "$(Get-Date) [INFO] Retrieving alert definitions from $prism..." -ForegroundColor Green
    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

    #process each retrieved alert and keep only what we want
    foreach ($myvarHealthCheck in $resp) {

        #figure out severity
        $myvarSeverity = ""
        if ($myvarHealthCheck.severityThresholdInfos) {
            if ($myvarHealthCheck.severityThresholdInfos[0].enabled -eq $true) {
                $myvarSeverity = $myvarHealthCheck.severityThresholdInfos[0].severity
            }
            if ($myvarHealthCheck.severityThresholdInfos[1].enabled -eq $true) {
                $myvarSeverity = $myvarHealthCheck.severityThresholdInfos[1].severity
            }
            if ($myvarHealthCheck.severityThresholdInfos[2].enabled -eq $true) {
                $myvarSeverity = $myvarHealthCheck.severityThresholdInfos[2].severity
            }
        }#endif severityInfo


        #populate hash
        $myvarHealthCheckInfo = [ordered]@{
          "alertTypeId" = $myvarHealthCheck.id.split(':')[2];
          "enabled" = $myvarHealthCheck.enabled;
          "severity" = $myvarSeverity;
          "name" = $myvarHealthCheck.name;
          "affectedEntityTypes" = $myvarHealthCheck.affectedEntityTypes -join " ";
          "description" = $myvarHealthCheck.description;
          "checkType" = $myvarHealthCheck.checkType;
          "categoryTypes" = $myvarHealthCheck.categoryTypes -join " ";
          "subCategoryTypes" = $myvarHealthCheck.subCategoryTypes -join " ";
          "scope" = $myvarHealthCheck.scope;
          "kbList" = $myvarHealthCheck.kbList -join " ";
          "causes" = $myvarHealthCheck.causes -join " ";
          "resolutions" = $myvarHealthCheck.resolutions -join " ";
          "autoresolve" = $myvarHealthCheck.autoResolve;
          "scheduleIntervalInSecs" = $myvarHealthCheck.scheduleIntervalInSecs;
          "title" = $myvarHealthCheck.title;
          "message" = $myvarHealthCheck.message;
          "isUserDefined" = $myvarHealthCheck.isUserDefined
        }
        #populate array
        $myvarResults.Add((New-Object PSObject -Property $myvarHealthCheckInfo)) | Out-Null
    }#end foreach healthcheck
  #endregion

  #region Export results
    Write-Host "$(Get-Date) [INFO] Exporting results to $csv..." -ForegroundColor Green
    $myvarResults | export-csv -NoTypeInformation $csv
  #endregion

#endregion processing

#region cleanup	
  #let's figure out how much time this all took
  Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

  #cleanup after ourselves and delete all custom variables
  Remove-Variable myvar* -ErrorAction SilentlyContinue
  Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
  Remove-Variable help -ErrorAction SilentlyContinue
  Remove-Variable history -ErrorAction SilentlyContinue
  Remove-Variable log -ErrorAction SilentlyContinue
  Remove-Variable username -ErrorAction SilentlyContinue
  Remove-Variable password -ErrorAction SilentlyContinue
  Remove-Variable prism -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
  Remove-Variable export -ErrorAction SilentlyContinue
#endregion
