<#
.SYNOPSIS
  This script can be used to delete one or more vms from AHV.
.DESCRIPTION
  Removes all specified VMs from AHV cluster. Prompts if VMs are powered on.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER vm
  Name(s) of VM(s) to delete (use a comma separated strings for multiple VMs)
.PARAMETER allowWildcards
  Specifies you want to use wildcards when specifying the VM name. This will automatically prompt before each deletion to avoid errors.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\remove-AhvVm.ps1 -cluster ntnxc1.local -vm "steph-vm1,steph-vm2"
Deletes 2 specified VMs from ntnxc1.local:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author(s): Stephane Bourdeaud (sbourdeaud@nutanix.com), Jeremie Moreau (jeremie.moreau@nutanix.com)
  Revision: February 22nd 2021
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $true)] $vm,
        [parameter(mandatory = $false)] [switch]$allowWildcards,
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
02/22/2021 sb   Initial release, with JM's help.
################################################################################
'@
    $myvarScriptName = ".\remove-AhvVm.ps1"

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
  
  $myvar_vms = $vm.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#todo: filter out cvms (and maybe fsvms as well as any agent vms)
#region processing	
    #region GET VMs
      Write-Host "$(get-date) [INFO] Retrieving list of VMs..." -ForegroundColor Green
      $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
      $method = "GET"
      $myvar_vm_list = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials
      Write-Host "$(get-date) [SUCCESS] Successfully retrieved VMs list from $($cluster)!" -ForegroundColor Cyan
    #endregion

    #region build list of VMs to delete
      [array]$myvar_vm_list_to_delete=@()
      ForEach ($myvar_vm in $myvar_vms)
      {
        if ($allowWildcards)
        {#we are using wildcards
          if ($myvar_item = $myvar_vm_list.entities | Where-Object {$_.name -like $myvar_vm})
          {#found a vm to delete
            $myvar_vm_list_to_delete += $myvar_item
          }
        }
        else 
        {#we are using explicit vm names
          if ($myvar_item = $myvar_vm_list.entities | Where-Object {$_.name -eq $myvar_vm})
          {#found a vm to delete
            $myvar_vm_list_to_delete += $myvar_item
          }
        }
      }
      if (!$myvar_vm_list_to_delete)
      {#could not find any of the vms specified
        Throw "$(Get-Date) [ERROR] Could not find any VM on cluster $($cluster) from the specified list!"
      }
    #endregion
    
    #region DELETE VMs
      ForEach ($myvar_vm_to_delete in $myvar_vm_list_to_delete)
      {#process each vm in the list of vms to delete
        if ($myvar_vm_to_delete.power_state -eq "on")
        {#vm is powered on, prompt user for confirmation
          Write-Host "$(Get-Date) [WARNING] VM $($myvar_vm_to_delete.name) is powered on: are you sure you want to delete it?" -ForegroundColor Yellow
          $myvar_user_choice = Write-CustomPrompt
        }
        else 
        {#vm is powered off, marking it for deletion
          if ($allowWildcards)
          {#we are using wildcards, so we prompt for confirmation
            Write-Host "$(Get-Date) [WARNING] Are you sure you want to delete VM $($myvar_vm_to_delete.name)?" -ForegroundColor Yellow
            $myvar_user_choice = Write-CustomPrompt
          }
          else 
          {#we are using explicit names, so no need to prompt
            $myvar_user_choice = "y" 
          }
        }
        if ($myvar_user_choice -ieq "y")
        {
          Write-Host "$(get-date) [INFO] Deleting VM $($myvar_vm_to_delete.name)..." -ForegroundColor Green
          $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/{0}" -f $myvar_vm_to_delete.uuid
          $method = "DELETE"
          $myvar_vm_delete = Get-PrismRESTCall -method $method -url $url -credential $prismCredentials
          Write-Host "$(get-date) [SUCCESS] Successfully deleted VM $($myvar_vm_to_delete.name) from $($cluster)!" -ForegroundColor Cyan
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