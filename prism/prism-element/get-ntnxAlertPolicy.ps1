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
  Revision: December 19th 2019
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
################################################################################
'@
$myvarScriptName = ".\get-ntnxAlertPolicy.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#let's get ready to use the Nutanix REST API
Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates" -ForegroundColor Green
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore()

# add Tls12 support
Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
[Net.ServicePointManager]::SecurityProtocol = `
    ([Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12)

#endregion

#region functions
  #this function is used to create saved credentials for the current user
  function Set-CustomCredentials 
  {
  #input: path, credname
    #output: saved credentials file
  <#
  .SYNOPSIS
    Creates a saved credential file using DAPI for the current user on the local machine.
  .DESCRIPTION
    This function is used to create a saved credential file using DAPI for the current user on the local machine.
  .NOTES
    Author: Stephane Bourdeaud
  .PARAMETER path
    Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
  .PARAMETER credname
    Specifies the credential file name.
  .EXAMPLE
  .\Set-CustomCredentials -path c:\creds -credname prism-apiuser
  Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
  #>
    param
    (
      [parameter(mandatory = $false)]
          [string] 
          $path,
      
          [parameter(mandatory = $true)]
          [string] 
          $credname
    )

      begin
      {
          if (!$path)
          {
              if ($IsLinux -or $IsMacOS) 
              {
                  $path = $home
              }
              else 
              {
                  $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
              }
              Write-Host "$(get-date) [INFO] Set path to $path" -ForegroundColor Green
          } 
      }
      process
      {
          #prompt for credentials
          $credentialsFilePath = "$path\$credname.txt"
      $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
      
      #put details in hashed format
      $user = $credentials.UserName
      $securePassword = $credentials.Password
          
          #convert secureString to text
          try 
          {
              $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
          }
          catch 
          {
              throw "$(get-date) [ERROR] Could not convert password : $($_.Exception.Message)"
          }

          #create directory to store creds if it does not already exist
          if(!(Test-Path $path))
      {
              try 
              {
                  $result = New-Item -type Directory $path -ErrorAction Stop
              } 
              catch 
              {
                  throw "$(get-date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
              }
      }

          #save creds to file
          try 
          {
              Set-Content $credentialsFilePath $user -ErrorAction Stop
          } 
          catch 
          {
              throw "$(get-date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
          }
          try 
          {
              Add-Content $credentialsFilePath $password -ErrorAction Stop
          } 
          catch 
          {
              throw "$(get-date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
          }

          Write-Host "$(get-date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan                
      }
      end
      {}
  }

  #this function is used to retrieve saved credentials for the current user
  function Get-CustomCredentials 
  {
  #input: path, credname
    #output: credential object
  <#
  .SYNOPSIS
    Retrieves saved credential file using DAPI for the current user on the local machine.
  .DESCRIPTION
    This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
  .NOTES
    Author: Stephane Bourdeaud
  .PARAMETER path
    Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
  .PARAMETER credname
    Specifies the credential file name.
  .EXAMPLE
  .\Get-CustomCredentials -path c:\creds -credname prism-apiuser
  Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
  #>
    param
    (
          [parameter(mandatory = $false)]
      [string] 
          $path,
      
          [parameter(mandatory = $true)]
          [string] 
          $credname
    )

      begin
      {
          if (!$path)
          {
              if ($IsLinux -or $IsMacOS) 
              {
                  $path = $home
              }
              else 
              {
                  $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
              }
              Write-Host "$(get-date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
          } 
      }
      process
      {
          $credentialsFilePath = "$path\$credname.txt"
          if(!(Test-Path $credentialsFilePath))
        {
              throw "$(get-date) [ERROR] Could not access file $credentialsFilePath : $($_.Exception.Message)"
          }

          $credFile = Get-Content $credentialsFilePath
      $user = $credFile[0]
      $securePassword = $credFile[1] | ConvertTo-SecureString

          $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

          Write-Host "$(get-date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan 
      }
      end
      {
          return $customCredentials
      }
  }
#endregion

#region variables
  #initialize variables
  #misc variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
  $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
  $myvarOutputLogFile += "OutputLog.log"

  [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all entries.  This is what will be exported to csv
    
  ############################################################################
  # command line arguments initialization
  ############################################################################	
  #let's initialize parameters if they haven't been specified
  if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism"}
  if (!$prismCreds) {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
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
  } 
  else { #we are using custom credentials, so let's grab the username and password from that
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
  }
  if (!$csv) {$csv = "prism-alerts-report.csv"}
#endregion

#region processing

  #region prepare api call
    $api_server = $prism
    $api_server_port = "9440"
    $api_server_endpoint = "/PrismGateway/services/rest/v1/health_checks/?includeInternalChecks=true"
    $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
        $api_server_endpoint
    $method = "GET"
    $headers = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
        "Content-Type"="application/json";
        "Accept"="application/json"
    }
  #endregion

  #region make the api call
    Write-Host "$(Get-Date) [INFO] Retrieving alert definitions from $prism..." -ForegroundColor Green
    try {
      Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
      #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
      if ($PSVersionTable.PSVersion.Major -gt 5) {
        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
      } else {
          $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
      }
    }
    catch {
      $saved_error = $_.Exception.Message
      throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
    }

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
