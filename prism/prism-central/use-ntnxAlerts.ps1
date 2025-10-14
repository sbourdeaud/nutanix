<#
.SYNOPSIS
  This script can be used to manage alerts in Prism Central (get, acknowledge and resolve).
.DESCRIPTION
  Given a Prism Central IP or FQDN, get, acknowledge or resolve alerts.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER get
  Get active alerts.
.PARAMETER acknowledge
  Acknowledges the alert specified by -uuid or all alerts. You can also filter using -severity.
.PARAMETER resolve
  Resolves the alert specified by -uuid or all alerts. You can also filter using -severity.
.PARAMETER severity
  Filter alerts for get by severity.
.PARAMETER uuid
  Uuid of the alert to acknowledge or resolve.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER csv
  Name of csv file to export to. By default results are only printed to the default output.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\use-ntnxAlerts.ps1 -prism 10.10.10.1 -prismCreds myuser -get -severity Critical
Get all critical alerts which are neither acknowledged nor resolved from Prism Central 10.10.10.1.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: July 13th 2022
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
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [switch]$get,
    [parameter(mandatory = $false)] [string]$uuid,
    [parameter(mandatory = $false)] [switch]$acknowledge,
    [parameter(mandatory = $false)] [switch]$resolve,
    [parameter(mandatory = $false)] [ValidateSet("critical","warning","info")][string]$severity,
    [parameter(mandatory = $false)] [string]$csv
)
#endregion

#region Functions
Function GetAlerts 
{
	#input: 
	#output: 
<#
.SYNOPSIS
  This function is used to get alerts from Prism Central.
.DESCRIPTION
  This function is used to get alerts from Prism Central.
.NOTES
  Author: Stephane Bourdeaud
.EXAMPLE
  $myvar = GetAlerts
#>
	param
	(
	)

    begin
    {
      #region prepare api call
      $api_server_endpoint = "/api/nutanix/v3/alerts/list"
      $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
          $api_server_endpoint
      $method = "POST"
      $length = 500
      $filter = "resolved!=true"
      if ($severity) {$filter += ";severity==$($severity)"}
      $content = @{
          kind= "alert";
          length= $length;
          filter= $filter
      }
      $payload = (ConvertTo-Json $content -Depth 4)
      #endregion
      Write-Host "$(Get-Date) [INFO] Getting alerts from $prism..." -ForegroundColor Green
    }

    process
    {
      Do {
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            
            if ($resp -is [string]) {
              $alerts = $resp | ConvertFrom-Json -AsHashTable -Depth 20
            } else {
                $alerts = $resp
            }

            $listLength = 0
            if ($alerts.metadata.offset) {
                $firstItem = $resp.metadata.offset
            } else {
                $firstItem = 0
            }
            if (($alerts.metadata.length -le $length) -and ($alerts.metadata.length -ne 1)) {
                $listLength = $alerts.metadata.length
            } else {
                $listLength = $alerts.metadata.total_matches
            }
            Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($alerts.metadata.total_matches)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

            if ($alerts.entities.count -eq 0) {
                Write-Host "$(get-date) [WARNING] There are no active alerts of the specified type." -ForegroundColor Yellow
            } else {
                ForEach ($alert in $alerts.entities) {
                    #substituting parameter values in the default message (as this varies for every alert)
                    $alert_message = $alert.status.resources.default_message
                    if ($resp -is [string]) {
                        $alert.status.resources.default_message | Select-String -Pattern "{(.*?)}" -AllMatches | % {$_.Matches} | % {$alert_message = $alert_message -replace $_.Groups[0].Value,$alert.status.resources.parameters.$($_.Groups[1].Value).Values}
                    } else {
                        $alert.status.resources.default_message | Select-String -Pattern "{(.*?)}" -AllMatches | % {$_.Matches} | % {$alert_message = $alert_message -replace $_.Groups[0].Value,$alert.status.resources.parameters.$($_.Groups[1].Value).$((Get-Member -InputObject $alert.status.resources.parameters.$($_.Groups[1].Value) -MemberType NoteProperty).Name)}
                    }
                    
                    $kb_id = ($myvarAlertPolicy | where {$_.alert_id -eq $alert.status.resources.type}).kb_id
                    if ($kb_id)
                    {
                      $kb_url = "https://portal.nutanix.com/kb/{0}" -f $kb_id
                    }
                    else 
                    {
                      $kb_url = ""  
                    }

                    #populating the details we want to capture for each alert
                    $myvarAlert = [ordered]@{
                        "type" = $alert.status.resources.type;
                        "acknowledged" = $alert.status.resources.acknowledged_status.is_true;
                        "latest_occurrence_time" = $alert.status.resources.latest_occurrence_time;
                        "severity"= $alert.status.resources.severity;
                        "creation_time"= $alert.status.resources.creation_time;
                        "title"= $alert.status.resources.title;
                        "alert_message"= $alert_message;
                        #"default_message"= $alert.status.resources.default_message;
                        #"parameters"= $alert.status.resources.parameters;
                        "possible_cause"= $alert.status.resources.possible_cause_list.cause_list -join ',';
                        "resolution" = $alert.status.resources.possible_cause_list.resolution_list -join ',';
                        "source_entity_type"= $alert.status.resources.source_entity.entity.type;
                        "source_entity_name"= $alert.status.resources.source_entity.entity.name;
                        "uuid"= $alert.metadata.uuid;
                        "cluster_uuid"= $alert.status.resources.parameters.cluster_uuid.string_value;
                        "cluster_name"= ($myvarClustersResults | Where {$_.uuid -eq $alert.status.resources.parameters.cluster_uuid.string_value}).name;
                        "nutanix_kb"= $kb_url;
                    }
                    #adding the captured details to the final result
                    $myvarResults.Add((New-Object PSObject -Property $myvarAlert)) | Out-Null
                }
            }

            #prepare the json payload for the next batch of entities/response
            $content = @{
                kind="alert";
                offset=($alerts.metadata.length + $alerts.metadata.offset);
                length=$length;
                filter= $filter
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
    While ($alerts.metadata.length -eq $length)
    }

    end
    {
      return $myvarResults
    }
}#end function FunctionName
#endregion

#region prep-work
#check if we need to display help and/or history
if ($PSVersionTable.PSVersion.Major -lt 6) {throw "$(get-date) [ERROR] Please upgrade to Powershell Core v6 or above (https://github.com/powershell/powershell)"}

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
01/15/2020 sb   Initial release.
04/15/2020 sb   Do over with sbourdeaud module
02/06/2021 sb   Replaced username with get-credential
02/07/2022 sb   Adding cluster name, possible cause and resolution to alert data
                Adding Nutanix KB link (when there is one available)
07/13/2022 sb   Forcing PoSH core as -AsHashTable is not recognized by PoSH 5.1
################################################################################
'@
$myvarScriptName = ".\use-ntnxAlerts.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#region module sbourdeaud is used for facilitating Prism REST calls
$required_version = "3.0.7"
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
	
  #let's initialize parameters if they haven't been specified
  if ((!$get) -and !($acknowledge) -and !($resolve)) {throw "You must specify either get, acknowledge or resolve!"}
  if ($acknowledge -and $resolve) {throw "You must specify either acknowledge or resolve but not both!"}
  if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
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

  $api_server = $prism
  $api_server_port = "9440"
  $length = 200
  [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all entries.  This is what will be exported to csv
  [System.Collections.ArrayList]$myvarClustersResults = New-Object System.Collections.ArrayList($null)
  [System.Collections.ArrayList]$myvarAlertPolicy = New-Object System.Collections.ArrayList($null)
#endregion

#region processing

    #! -get
    #region -get
      if ($get) 
      {
        #region get clusters
          Write-Host "$(get-date) [INFO] Retrieving list of clusters managed by Prism Central..." -ForegroundColor Green
          #region prepare api call
              $api_server_endpoint = "/api/nutanix/v3/clusters/list"
              $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
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
          Write-Host "$(get-date) [SUCCESS] Successfully retrieved clusters list from $prism!" -ForegroundColor Cyan
        #endregion get clusters

        #region get alert policy
          $api_server_endpoint = "/api/nutanix/v3/groups"
          $alert_policy_url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
              $api_server_endpoint
          $content = @{
            "entity_type"="alert_check_schema";
            "group_member_attributes"=@(
              @{"attribute"="alert_uid"};
              @{"attribute"="kb_num_list"});
            "query_name"="prism:AlertPolicyGroupsModel";}
          $alert_policy_payload=(ConvertTo-Json $content -Depth 4)
          $alert_policy = Invoke-PrismAPICall -method 'POST' -url $alert_policy_url -payload $alert_policy_payload -credential $prismCredentials

          Foreach ($entry in $alert_policy.group_results.entity_results)
          {
            if (($entry.data | where {$_.name -eq "alert_uid"}).values.values -and ($entry.data | where {$_.name -eq "kb_num_list"}).values.values)
            {
              $alert_policy_info = [ordered]@{
                "alert_id" = ($entry.data | where {$_.name -eq "alert_uid"}).values.values;
                "kb_id" = ($entry.data | where {$_.name -eq "kb_num_list"}).values.values;
              }
              $myvarAlertPolicy.Add((New-Object PSObject -Property $alert_policy_info)) | Out-Null
            }
          }
        #endregion get alert policy

        #region get alerts
          try 
          {
              $myvarResults = GetAlerts
              if ($csv) 
              {
                Write-Host "$(Get-Date) [INFO] Exporting results to $csv..." -ForegroundColor Green
                $myvarResults | export-csv -NoTypeInformation $csv -Delimiter ";"
              } 
              else 
              {
                  $myvarResults | Sort-Object -Property latest_occurrence_time
              }
          }
          catch 
          {
              $saved_error = $_.Exception.Message
              throw "$(get-date) [ERROR] $saved_error"
          }
          finally 
          {
          }
        #endregion get alerts
      }
    #endregion

    #! -acknowledge
    #region -acknowledge
      if ($acknowledge) 
      {
          #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/alerts/action/ACKNOWLEDGE"
            $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
                $api_server_endpoint
            $method = "POST"
            $length = 500

            if (!$uuid) 
            {
              #$filter = "resolved!=true"
              #if ($severity) {$filter += ";severity==$($severity)"}
              #*retrieve alerts (as if -get)
              $myvarResults = GetAlerts
              $uuid_list = @()
              Foreach ($alert in $myvarResults) 
              {
                if ($severity) 
                {
                  $uuid_list = ($myvarResults | Where-Object {$_.severity -eq $severity}).uuid
                } 
                else 
                {
                  $uuid_list = ($myvarResults).uuid
                }
              }
              $content = @{
                alert_uuid_list= @($uuid_list)
              }
            } 
            else 
            {
              $content = @{
                alert_uuid_list= @($uuid)
              }
            }
            
            $payload = (ConvertTo-Json $content -Depth 4)
          #endregion

          #region make the api call
            Write-Host "$(Get-Date) [INFO] Acknowledging alert $uuid in $prism..." -ForegroundColor Green
            try 
            {
                $ack_task_uuid = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                $task_status = Get-PrismCentralTaskStatus -task $ack_task_uuid.task_uuid -credential $prismCredentials -cluster $prism
            }
            catch 
            {
                $saved_error = $_.Exception.Message
                throw "$(get-date) [ERROR] $saved_error"
            }
            finally 
            {
            }
          #endregion
      }
    #endregion

    #! -resolve
    #region -resolve
      if ($resolve) 
      {
          #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/alerts/action/RESOLVE"
            $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
                $api_server_endpoint
            $method = "POST"
            $length = 500
            
            #todo: add code here to process anything but $uuid
            if (!$uuid) 
            {
              #$filter = "resolved!=true"
              #if ($severity) {$filter += ";severity==$($severity)"}
              #*retrieve alerts (as if -get)
              $myvarResults = GetAlerts
              $uuid_list = @()
              Foreach ($alert in $myvarResults) 
              {
                if ($severity) 
                {
                  $uuid_list = ($myvarResults | Where-Object {$_.severity -eq $severity}).uuid
                } 
                else 
                {
                  $uuid_list = ($myvarResults).uuid
                }
              }
              $content = @{
                alert_uuid_list= @($uuid_list)
              }
            } 
            else 
            {
              $content = @{
                alert_uuid_list= @($uuid)
              }
            }

            $payload = (ConvertTo-Json $content -Depth 4)
          #endregion

          #region make the api call
            Write-Host "$(Get-Date) [INFO] Resolving alert $uuid in $prism..." -ForegroundColor Green
            try 
            {
              $resolve_task_uuid = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
              $task_status = Get-PrismCentralTaskStatus -task $resolve_task_uuid.task_uuid -credential $prismCredentials -cluster $prism
            }
            catch 
            {
                $saved_error = $_.Exception.Message
                Throw "$(get-date) [ERROR] $saved_error"
            }
            finally 
            {
            }
          #endregion
      }
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
  Remove-Variable prism -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
  Remove-Variable prismCreds -ErrorAction SilentlyContinue
#endregion