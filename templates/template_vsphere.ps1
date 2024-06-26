<#
.SYNOPSIS
  This is a summary of what the script is.
.DESCRIPTION
  This is a detailed description of what the script does and how it is used.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER vcenter
  VMware vCenter server hostname. Default is localhost. You can specify several hostnames by separating entries with commas.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\template.ps1 -vcenter myvcenter.local
Connect to a vCenter server of your choice.
 
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 19th 2015
#>

#region parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$log,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$vcenter,
      [parameter(mandatory = $false)] [string]$vcenterCreds
  )
#endregion

#region functions

#endregion

#region prepwork
  # get rid of annoying error messages
  if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
  if ($debugme) {$VerbosePreference = "Continue"}

  #check if we need to display help and/or history
  $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/19/2015 sb   Initial release.
################################################################################
'@
  $myvarScriptName = ".\template.ps1"
  
  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

  #check PoSH version
  if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

  #check if we have all the required PoSH modules
  Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

  #region Load/Install VMware.PowerCLI
      if (!(Get-Module VMware.PowerCLI)) 
      {#module VMware.PowerCLI is not loaded
          try 
          {#load module VMware.PowerCLI
              Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
              Import-Module VMware.PowerCLI -ErrorAction Stop
              Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
          }
          catch 
          {#couldn't load module VMware.PowerCLI
              Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
              try 
              {#install module VMware.PowerCLI
                  Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
                  Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
                  Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
                  try 
                  {#loading module VMware.PowerCLI
                      Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                      Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                      Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
                  }
                  catch 
                  {#couldn't load module VMware.PowerCLI
                      throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
                  }
              }
              catch 
              {#couldn't install module VMware.PowerCLI
                  throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"
              }
          }
      }
      
      if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
      {#check PowerCLI version
          try 
          {#update module VMware.PowerCLI
              Update-Module -Name VMware.PowerCLI -ErrorAction Stop
          } 
          catch 
          {#couldn't update module VMware.PowerCLI
              throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"
          }
      }
  #endregion
  if ((Get-PowerCLIConfiguration | where-object {$_.Scope -eq "User"}).InvalidCertificateAction -ne "Ignore") {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false
  }
#endregion

#region variables
  #misc variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
  $myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
#endregion

#region parameters validation
  #let's initialize parameters if they haven't been specified
  if (!$vcenter) {$vcenter = read-host "Enter vCenter server name or IP address"}#prompt for vcenter server name
  $myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
  if ($vcenterCreds) 
  {#vcenterCreds was specified
      try 
      {
          $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop 
      }
      catch 
      {
          Set-CustomCredentials -credname $vcenterCreds
          $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
      }
  }
	else 
	{#no vcenter creds were given
		$vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
	}
  $vcenterUsername = $vcenterCredentials.UserName
  $vcenterSecurePassword = $vcenterCredentials.Password
  $vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword
#endregion

#region processing
    #* foreach vcenter loop
	foreach ($myvarvCenter in $myvarvCenterServers)	
	{
        try {
            Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
            $myvarvCenterObject = Connect-VIServer $myvarvCenter -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter" -ForegroundColor Cyan
        }
        catch {throw "$(get-date) [ERROR] Could not connect to vCenter server $myvarvCenter : $($_.Exception.Message)"}

        Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
		Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
	}#end foreach vCenter
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
	Remove-Variable vcenter -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion