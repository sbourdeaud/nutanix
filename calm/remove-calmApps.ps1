<#
.SYNOPSIS
  Use this script to delete Calm application instances and blueprints based on a name pattern.
.DESCRIPTION
  Use this script to delete Calm application instances based on a name pattern.
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
.PARAMETER apps
  Name of the application instance(s) you want to delete. You can use wildcards, specify a single name, or comma separated values.
.PARAMETER soft
  Specifies you want to do a soft delete (which does not delete VMs).
.PARAMETER bps
  Name of the blueprint(s) you want to delete. You can use wildcards, specify a single name, or comma separated values.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\template.ps1 -prismcentral ntnxc1.local
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 2nd 2021
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
        [parameter(mandatory = $false)] [string]$apps,
        [parameter(mandatory = $false)] [switch]$soft,
        [parameter(mandatory = $false)] [string]$bps,
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion

#region functions
  function Write-LogOutput
  {
  <#
  .SYNOPSIS
  Outputs color coded messages to the screen and/or log file based on the category.

  .DESCRIPTION
  This function is used to produce screen and log output which is categorized, time stamped and color coded.

  .PARAMETER Category
  This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".

  .PARAMETER Message
  This is the actual message you want to display.

  .PARAMETER LogFile
  If you want to log output to a file as well, use logfile to pass the log file full path name.

  .NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

  .EXAMPLE
  .\Write-LogOutput -category "ERROR" -message "You must be kidding!"
  Displays an error message.

  .LINK
  https://github.com/sbourdeaud
  #>
      [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

      param
      (
          [Parameter(Mandatory)]
          [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG','DATA')]
          [string]
          $Category,

          [string]
          $Message,

          [string]
          $LogFile
      )

      process
      {
          $Date = get-date #getting the date so we can timestamp the output entry
          $FgColor = "Gray" #resetting the foreground/text color
          switch ($Category) #we'll change the text color depending on the selected category
          {
              "INFO" {$FgColor = "Green"}
              "WARNING" {$FgColor = "Yellow"}
              "ERROR" {$FgColor = "Red"}
              "SUM" {$FgColor = "Magenta"}
              "SUCCESS" {$FgColor = "Cyan"}
              "STEP" {$FgColor = "Magenta"}
              "DEBUG" {$FgColor = "White"}
              "DATA" {$FgColor = "Gray"}
          }

          Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
          if ($LogFile) #add the entry to the log file if -LogFile has been specified
          {
              Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
              Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
          }
      }

  }#end function Write-LogOutput
  
  #this function loads a powershell module
  Function LoadModule
  {#tries to load a module, import it, install it if necessary
  <#
  .SYNOPSIS
  Tries to load the specified module and installs it if it can't.
  .DESCRIPTION
  Tries to load the specified module and installs it if it can't.
  .NOTES
  Author: Stephane Bourdeaud
  .PARAMETER module
  Name of PowerShell module to import.
  .EXAMPLE
  PS> LoadModule -module PSWriteHTML
  #>
  param 
  (
    [string] $module
  )

  begin
  {
    
  }

  process
  {   
          Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Trying to get module $($module)..."
    if (!(Get-Module -Name $module)) 
          {#we could not get the module, let's try to load it
              try
              {#import the module
                  Import-Module -Name $module -ErrorAction Stop
                  Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
              }#end try
              catch 
              {#we couldn't import the module, so let's install it
                  Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Installing module '$($module)' from the Powershell Gallery..."
                  try 
                  {#install module
                      Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                  }
                  catch 
                  {#could not install module
                      Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Could not install module '$($module)': $($_.Exception.Message)"
                      exit 1
                  }

                  try
                  {#now that it is intalled, let's import it
                      Import-Module -Name $module -ErrorAction Stop
                      Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
                  }#end try
                  catch 
                  {#we couldn't import the module
                      Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Unable to import the module $($module).psm1 : $($_.Exception.Message)"
                      Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Please download and install from https://www.powershellgallery.com"
                      Exit 1
                  }#end catch
              }#end catch
          }
  }

  end
  {

  }
  }
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/02/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\remove-calmApps.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    if ($log) 
    {#we want a log file
        $myvar_log_file = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvar_log_file += "$($prismcentral)_"
        $myvar_log_file += "remove-calmApps.log"
        $myvar_log_file = $dir + $myvar_log_file
    }

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
    $length = 100
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

  if (!$apps -and !$bps) 
  {
    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "You must specify either an application name or a blueprint name! Exiting."
    Exit 1
  }

  $myvar_apps = $apps.Split(",") #make sure we parse the argument in case it contains several entries
  $myvar_bps = $bps.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#region processing

    #region delete app
      if ($apps)
      {
        #POST apps/list to retrieve app uuid
        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of Calm applications..."
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/apps/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $content = @{
                kind="app";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion
        #region make api call
            [System.Collections.ArrayList]$myvarAppsResults = New-Object System.Collections.ArrayList($null)
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
                          $myvarAppInfo = [ordered]@{
                              "name" = $entity.status.name;
                              "uuid" = $entity.metadata.uuid;
                          }
                          #store the results for this entity in our overall result variable
                          $myvarAppsResults.Add((New-Object PSObject -Property $myvarAppInfo)) | Out-Null
                    }

                    #prepare the json payload for the next batch of entities/response
                    $content = @{
                        kind="app";
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
                $myvarAppsResults
            }
        #endregion
        Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved list of Calm applications from $prismcentral!"

        #region build list of apps to delete
          [array]$myvar_app_list_to_delete=@()
          ForEach ($myvar_app in $myvar_apps)
          {
            if ($myvar_item = $myvarAppsResults | Where-Object {$_.name -like $myvar_app})
            {#found a vm to delete
              $myvar_app_list_to_delete += $myvar_item
            }
          }
          if (!$myvar_app_list_to_delete)
          {#could not find any of the vms specified
            Throw "$(Get-Date) [ERROR] Could not find any Calm apps on Prism Central $($prismcentral) from the specified list!"
          }
        #endregion

        Foreach ($myvar_app in $myvar_app_list_to_delete)
        { 
          #DELETE apps/uuid
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Deleting Calm application $($myvar_app.name)..."
            #region prepare api call
              if ($soft)
              {
                $api_server_endpoint = "/api/nutanix/v3/apps/{0}?type=soft" -f $myvar_app.uuid
              }
              else 
              {
                $api_server_endpoint = "/api/nutanix/v3/apps/{0}" -f $myvar_app.uuid
              }
              $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
              $method = "DELETE"
            #endregion
            #region make api call
              try 
              {
                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
              }
              catch {
                  $saved_error = $_.Exception.Message
                  Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                  Throw "$(get-date) [ERROR] $saved_error"
              }
            #endregion
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully deleted Calm application $($myvar_app.name) from $prismcentral!"
        }
      }
    #endregion

    #region delete bp
      if ($bps)
      {
        #POST blueprints/list to retrieve app uuid
          Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of Calm blueprints..."
          #region prepare api call
              $api_server_endpoint = "/api/nutanix/v3/blueprints/list"
              $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
              $method = "POST"

              # this is used to capture the content of the payload
              $content = @{
                  kind="blueprint";
                  offset=0;
                  length=$length
              }
              $payload = (ConvertTo-Json $content -Depth 4)
          #endregion
          #region make api call
              [System.Collections.ArrayList]$myvarBlueprintsResults = New-Object System.Collections.ArrayList($null)
              Do 
              {
                  try 
                  {
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
                            $myvarBlueprintInfo = [ordered]@{
                                "name" = $entity.status.name;
                                "uuid" = $entity.metadata.uuid;
                            }
                            #store the results for this entity in our overall result variable
                            $myvarBlueprintsResults.Add((New-Object PSObject -Property $myvarBlueprintInfo)) | Out-Null
                      }

                      #prepare the json payload for the next batch of entities/response
                      $content = @{
                          kind="blueprint";
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

              if ($debugme) 
              {
                  Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
                  $myvarBlueprintsResults
              }
          #endregion
          Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved list of Calm blueprints from $prismcentral!"
        
        #region build list of bps to delete
          [array]$myvar_bp_list_to_delete=@()
          ForEach ($myvar_bp in $myvar_bps)
          {
            if ($myvar_item = $myvarBlueprintsResults | Where-Object {$_.name -like $myvar_bp})
            {#found a vm to delete
              $myvar_bp_list_to_delete += $myvar_item
            }
          }
          if (!$myvar_bp_list_to_delete)
          {#could not find any of the vms specified
            Throw "$(Get-Date) [ERROR] Could not find any Calm blueprints on Prism Central $($prismcentral) from the specified list!"
          }
        #endregion

        Foreach ($myvar_bp in $myvar_bp_list_to_delete)
        { 
          #DELETE blueprint/uuid
          Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Deleting Calm blueprint $($myvar_bp.name)..."
          #region prepare api call
              $api_server_endpoint = "/api/nutanix/v3/blueprints/{0}" -f $myvar_bp.uuid
              $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
              $method = "DELETE"
          #endregion
          #region make api call
            try 
            {
              $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch {
                $saved_error = $_.Exception.Message
                Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                Throw "$(get-date) [ERROR] $saved_error"
            }
          #endregion
          Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully deleted Calm blueprint $($myvar_bp.name) from $prismcentral!"
        }
      }
    #endregion
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