<#
.SYNOPSIS
  This script retrieves the list of Leap Protection Policies configured in Prism Central.
.DESCRIPTION
  This script retrieves the list of Leap Protection Policies configured in Prism Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central instance fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\get-protectionPolicies.ps1 -prismcentral ntnxc1.local
Retrieve the list of protection policies defined in Prism Central ntnxc1.local.
.LINK
  http://www.nutanix.com/services
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
01/11/2021 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\get-protectionPolicies.ps1"

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
    $length=100 #this specifies how many entities we want in the results of each API query
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
  Write-Host "$(get-date) [INFO] Retrieving list of protection policies from $($prismcentral)..." -ForegroundColor Green
  $content = @{
    kind="protection_rule";
    offset=0;
    length=$length
  }
  $payload = (ConvertTo-Json $content -Depth 4)
  [System.Collections.ArrayList]$myvar_protection_policies = New-Object System.Collections.ArrayList($null)
  Do 
  {
    try 
    {
      $url = "https://$($prismcentral):9440/api/nutanix/v3/protection_rules/list"
      $method = "POST"

      $resp = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $payload

      $listLength = 0
      if ($resp.metadata.offset) 
      {
          $firstItem = $resp.metadata.offset
      } 
      else 
      {
          $firstItem = 0
      }
      if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) 
      {
          $listLength = $resp.metadata.length
      } 
      else 
      {
          $listLength = $resp.metadata.total_matches
      }
      Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
      if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

      ForEach ($entity in $resp.entities) 
      {
        $myvar_categories = @()
        foreach ($category in $entity.spec.resources.category_filter.params) 
        {
          foreach ($category_name in ($category| Get-Member -MemberType NoteProperty | Select -ExpandProperty Name))
          {
            foreach ($category_value in ($category.$($category_name)))
            {
              $myvar_categories += "$($category_name):$($category_value)"
            }
          }
        }

        $myvar_protection_policy = [ordered]@{
            "name" = $entity.spec.name;
            "uuid" = $entity.metadata.uuid;
            "categories" = ($myvar_categories) -join ',';
            "nb_of_categories" = ($myvar_categories).count;
            "recovery_point_objective_secs" = ($entity.spec.resources.availability_zone_connectivity_list | where {$_.source_availability_zone_index -eq 0}).snapshot_schedule_list.recovery_point_objective_secs;
            "snapshot_type" = ($entity.spec.resources.availability_zone_connectivity_list | where {$_.source_availability_zone_index -eq 0}).snapshot_schedule_list.snapshot_type;
            "local_retention_snapshots" = ($entity.spec.resources.availability_zone_connectivity_list | where {$_.source_availability_zone_index -eq 0}).snapshot_schedule_list.local_snapshot_retention_policy.num_snapshots;
            "remote_retention_snapshots" = ($entity.spec.resources.availability_zone_connectivity_list | where {$_.source_availability_zone_index -eq 0}).snapshot_schedule_list.remote_snapshot_retention_policy.num_snapshots;
            "last_update_time" = $entity.metadata.last_update_time;
            "creation_time" = $entity.metadata.creation_time;
            "owner" = $entity.metadata.owner_reference.name;
        }
        #store the results for this entity in our overall result variable
        $myvar_protection_policies.Add((New-Object PSObject -Property $myvar_protection_policy)) | Out-Null
      }

      #prepare the json payload for the next batch of entities/response
      $content = @{
        kind="protection_rule";
        offset=($resp.metadata.length + $resp.metadata.offset);
        length=$length
      }
      $payload = (ConvertTo-Json $content -Depth 4)
    }
    catch 
    {
      $saved_error = $_.Exception.Message
      # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
      Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
      Throw "$(get-date) [ERROR] $saved_error"
    }
  }
  While ($resp.metadata.length -eq $length)

  $myvar_protection_policies
#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion