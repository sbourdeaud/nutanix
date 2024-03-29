<#
.SYNOPSIS
  This script retrieves the list of protection domains from a given Nutanix cluster.
.DESCRIPTION
  The script uses v2 REST API in Prism to GET the list of protection_domains from Prism Element.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER email
  Specifies that you want to email the output. This requires that you set up variables inside the script for smtp gateway and recipients.

.EXAMPLE
.\get-ProtectionDomainsReport.ps1 -cluster ntnxc1.local
Retrieve the list of unprotected VMs from cluster ntnxc1.local

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
      [parameter(mandatory = $true)] [string]$cluster,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [switch]$email
  )
#endregion

#region prepwork
  # get rid of annoying error messages
  if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
  #check if we need to display help and/or history
  $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 03/25/2020 sb   Initial release.
 04/14/2020 sb   Do over with sbourdeaud module.
 02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
  $myvarScriptName = ".\get-ProtectionDomainsReport.ps1"
 
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
  #! Constants (for -email)
  $smtp_gateway = "" #add your smtp gateway address here
  $smtp_port = 25 #customize the smtp port here if necessary
  $recipients = "" #add a comma separated value of valid email addresses here
  $from = "" #add the from email address here
  $subject = "WARNING: Protection domains in Nutanix cluster $cluster" #customize the subject here
  $body = "Please open the attached csv file and review protection domains on cluster $cluster"

  #initialize variables
	$ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

  [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
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
          $username = $prismCredentials.UserName
          $PrismSecurePassword = $prismCredentials.Password
      }
      catch 
      {
          Set-CustomCredentials -credname $prismCreds
          $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
          $username = $prismCredentials.UserName
          $PrismSecurePassword = $prismCredentials.Password
      }
      $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
  } 
#endregion

#region processing	
    #retrieving all protection domains
    Write-Host "$(get-date) [INFO] Retrieving list of protection domains..." -ForegroundColor Green
    $url = "https://$($cluster):9440/api/nutanix/v2.0/protection_domains"
    $method = "GET"
    $pdList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains list from $cluster!" -ForegroundColor Cyan

    
    Foreach ($entity in $pdList.entities) {
        $myvarPdInfo = [ordered]@{
            "name" = $entity.name;
            "metro_avail" = $entity.metro_avail;
            "total_user_written_bytes" = $entity.total_user_written_bytes;
            "exclusive_snapshot_usage_bytes" = $entity.usage_stats."dr.exclusive_snapshot_usage_bytes";
            "vms" = (($entity.vms | Select-Object -Property vm_name).vm_name) -join ',';
            "remote_site_names" = $entity.remote_site_names -join ',';
            "cron_schedules" = (($entity.cron_schedules | Select-Object -Property type).type) -join ',';
            "schedules_suspended" = $entity.schedules_suspended;
        }
        #store the results for this entity in our overall result variable
        $myvarResults.Add((New-Object PSObject -Property $myvarPdInfo)) | Out-Null
    }#end foreach vm

    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")PdList.csv" -ForegroundColor Green
    $myvarResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"PdList.csv")

    if ($email -and ($pdList.metadata.count -ge 1))
    {#user wants to send email and we have results
        Write-Host "$(get-date) [INFO] Emailing unprotected-vms.csv..." -ForegroundColor Green
        if ((!$smtp_gateway) -and (!$recipients) -and (!$from))
        {#user hasn't customized the script to enable email
            Write-Host "$(get-date) [ERROR] You must configure the smtp_gateway, recipients and from constants in the script (search for Constants in the script source code)!" -ForegroundColor Red
            Exit
        }
        else 
        {
            $attachment = ".\$($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"PdList.csv")"
            Send-MailMessage -From $from -to $recipients -Subject $subject -Body $body -SmtpServer $smtp_gateway -port $smtp_port -Attachments $attachment 
        }
    }


#endregion

#region cleanup
	  #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
#endregion