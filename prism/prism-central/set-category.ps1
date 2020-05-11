<#
.SYNOPSIS
  This script can be used to add or remove categories from a virtual machine in Prism Central.
.DESCRIPTION
  Given a Nutanix cluster, a virtual machine name, a category name and a value name, add or remove that category from the virtual machine in Prism Central.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER username
  Prism Central username.
.PARAMETER password
  Prism Central username password.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vm
  Name of the virtual machine to edit (as displayed in Prism Central)
.PARAMETER sourcecsv
  Indicates the path of a comma separated file including a list of VMs to modify. The format of each line (with headers) is: vm_name,category_name,category_value.
.PARAMETER category
  Name of the category to assign to the vm (which must already exists in Prism Central). This is case sensitive.
.PARAMETER value
  Name of the category value to assign to the vm (which must already exists in Prism Central).  This is case sensitive.
.PARAMETER add
  Adds the specified category:value to vm.
.PARAMETER remove
  Removes the specified category:value to vm.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\set-category.ps1 -prism 10.10.10.1 -prismCreds myuser -vm myvm -category mycategory -value myvalue -add
Adds the category mycategory:myvalue to myvm.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 21st 2020
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
      [parameter(mandatory = $false)] [string]$vm,
      [parameter(mandatory = $false)] [string]$sourcecsv,
      [parameter(mandatory = $false)] [string]$category,
      [parameter(mandatory = $false)] [string]$value,
      [parameter(mandatory = $false)] [switch]$add,
      [parameter(mandatory = $false)] [switch]$remove
  )
#endregion

#region prep-work
  #check if we need to display help and/or history
  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
01/14/2020 sb   Initial release.
04/07/2020 sb   Added sourcecsv + do over with sbourdeaud module.
04/21/2020 sb   Do over with sbourdeaud module.
################################################################################
'@
  $myvarScriptName = ".\set-category.ps1"
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
  #misc variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
  $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
  $myvarOutputLogFile += "OutputLog.log"
  [System.Collections.ArrayList]$myvarListToProcess = New-Object System.Collections.ArrayList($null)

  $api_server_port = "9440"
  $api_server = $prism
    
  #let's initialize parameters if they haven't been specified
  if ((!$add) -and !($remove)) {throw "You must specify either add or remove!"}
  if ($add -and $remove) {throw "You must specify either add or remove but not both!"}
  if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
  if ($vm -and $sourcecsv) {throw "You must specify -vm OR -sourcecsv but NOT BOTH!"}
  if ((!$vm) -and !($sourcecsv)) {$vm = read-host "Enter the virtual machine name"}
  if ((!$category) -and !($sourcecsv)) {$category = read-host "Enter the category name"}
  if ((!$value) -and !($sourcecsv)) {$value = read-host "Enter the category value name"}
  if ($vm -and $category -and $value) {
    #build dict with provided values
    $myvarItem = [ordered]@{
      "vm_name" = $vm;
      "category_name" = $category;
      "category_value" = $value
    }
    #store the results for this entity in our overall result variable
    $myvarListToProcess.Add((New-Object PSObject -Property $myvarItem)) | Out-Null
  }
  if ($sourcecsv) {
    try {
      $myvarListToProcess = Import-Csv -Path $sourcecsv -ErrorAction Stop
    }
    catch {
      $saved_error = $_.Exception.Message
      throw "$(get-date) [ERROR] $saved_error"
    }
  }

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
  ForEach ($item in $myvarListToProcess) {
    $vm = $item.vm_name
    $category = $item.category_name
    $value = $item.category_value

    #! step 1: check category value pairs exists
    #region check category:value pair exists

      #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "GET"
      #endregion

      #region make the api call
        Write-Host "$(Get-Date) [INFO] Checking $($category):$($value) exists in $prism..." -ForegroundColor Green
        try {
          $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
          Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $prism" -ForegroundColor Cyan
        }
        catch {
          $saved_error = $_.Exception.Message
          if ($_.Exception.Response.StatusCode.value__ -eq 404) {
              Write-Host "$(get-date) [WARNING] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $prism" -ForegroundColor Yellow
              Continue
          }
          else {
              Write-Host "$(get-date) [WARNING] $saved_error" -ForegroundColor Yellow
              Continue
          }
        }
        finally {
        }
      #endregion

    #endregion

    #! step 2: retrieve vm details
    #region retrieve the vm details

      #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/vms/list"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "POST"
        $content = @{
            filter= "vm_name==$($vm)";
            kind= "vm"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
      #endregion

      #region make the api call
        Write-Host "$(Get-Date) [INFO] Retrieving the configuration of vm $vm from $prism..." -ForegroundColor Green
        try {
          $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
          if ($resp.metadata.total_matches -eq 0) {
              Write-Host "$(get-date) [WARNING] VM $vm was not found on $prism" -ForegroundColor Yellow
              Continue
          }
          elseif ($resp.metadata.total_matches -gt 1) {
            Write-Host "$(get-date) [WARNING] There are multiple VMs matching name $vm on $prism" -ForegroundColor Yellow
            Continue
          }
          $vm_config = $resp.entities[0]
          $vm_uuid = $vm_config.metadata.uuid
          Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved the configuration of vm $vm from $prism" -ForegroundColor Cyan
        }
        catch {
          $saved_error = $_.Exception.Message
          Write-Host "$(get-date) [WARNING] $saved_error" -ForegroundColor Yellow
          Continue
        }
        finally {
        }
      #endregion

    #endregion

    #! step 3: prepare the json payload
    #region prepare the json payload
      $vm_config.PSObject.Properties.Remove('status')
    #endregion

    #! step 4.1: process -add
    #region process add
      if ($add) {
        try {
          $myvarNull = $vm_config.metadata.categories | Add-Member -MemberType NoteProperty -Name $category -Value $value -PassThru -ErrorAction Stop
          $myvarNull = $vm_config.metadata.categories_mapping | Add-Member -MemberType NoteProperty -Name $category -Value @($value) -PassThru -ErrorAction Stop
        }
        catch {
          Write-Host "$(Get-Date) [ERROR] Could not add category:value pair ($($category):$($value)). It may already be assigned to the vm $vm in $prism" -ForegroundColor Red
          exit
        }
      }
    #endregion

    #! step 4.2: process -remove
    #region process remove
      if ($remove) {
        #todo match the exact value pair here as a category could have multiple values assigned
        #Write-Host "$(Get-Date) [WARNING] Remove hasn't been implemented yet (still working on it)" -ForegroundColor Yellow
        $myvarNull = $vm_config.metadata.categories.PSObject.Properties.Remove($category)
        $myvarNull = $vm_config.metadata.categories_mapping.PSObject.Properties.Remove($category)
      }
    #endregion

    #! step 5: update the vm object
    #region update vm

      #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/vms/{0}" -f $vm_uuid
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "PUT"
        $payload = (ConvertTo-Json $vm_config -Depth 6)
      #endregion

      #region make the api call
        Write-Host "$(Get-Date) [INFO] Updating the configuration of vm $vm in $prism..." -ForegroundColor Green
        do {
          try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully updated the configuration of vm $vm from $prism" -ForegroundColor Cyan
            $resp_return_code = 200
          }
          catch {
            $saved_error = $_.Exception
            $resp_return_code = $saved_error.Response.StatusCode.value__
            if ($resp_return_code -eq 409) {
              Write-Host "$(Get-Date) [WARNING] VM $vm cannot be updated now. Retrying in 30 seconds..." -ForegroundColor Yellow
              sleep 30
            }
            else {
              Write-Host $payload -ForegroundColor White
              Write-Host "$(get-date) [WARNING] $($saved_error.Message)" -ForegroundColor Yellow
              Break
            }
          }
          finally {
          }
        } while ($resp_return_code -eq 409)
      #endregion

    #endregion
  }
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
#endregion