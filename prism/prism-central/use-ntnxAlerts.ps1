<#
.SYNOPSIS
  This script can be used to manage alerts in Prism Central (get, acknowledge and resolve).
.DESCRIPTION
  Given a Prism Central IP or FQDN, get, acknowledge or resolve alerts.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER username
  Prism Central username.
.PARAMETER password
  Prism Central username password.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
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
.\get-ntnxAlerts.ps1 -prism 10.10.10.1 -prismCreds myuser -get -severity Critical
Get all critical alerts which are neither acknowledged nor resolved from Prism Central 10.10.10.1.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: January 17th 2020
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
    [parameter(mandatory = $false)] [switch]$get,
    [parameter(mandatory = $false)] [string]$uuid,
    [parameter(mandatory = $false)] [switch]$acknowledge,
    [parameter(mandatory = $false)] [switch]$resolve,
    [parameter(mandatory = $false)] [ValidateSet("critical","warning","info")][string]$severity,
    [parameter(mandatory = $false)] [string]$csv
)
#endregion

#region prep-work
#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
01/15/2020 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\add-AhvNetwork.ps1"
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
  
############################################################################
# command line arguments initialization
############################################################################	
#let's initialize parameters if they haven't been specified
if ((!$get) -and !($acknowledge) -and !($resolve)) {throw "You must specify either get, acknowledge or resolve!"}
if ($acknowledge -and $resolve) {throw "You must specify either acknowledge or resolve but not both!"}
if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
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

[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all entries.  This is what will be exported to csv
#endregion

#region processing

    #! -get
    #region -get
    if ($get) {
        #region prepare api call
        $api_server = $prism
        $api_server_port = "9440"
        $api_server_endpoint = "/api/nutanix/v3/alerts/list"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "POST"
        $length = 500
        $headers = @{
            "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
            "Content-Type"="application/json";
            "Accept"="application/json"
        }
        $filter = "resolved!=true"
        if ($severity) {$filter += ";severity==$($severity)"}
        $content = @{
            kind= "alert";
            length= $length;
            filter= $filter
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #todo process multiple pages
        #region make the api call
        Write-Host "$(Get-Date) [INFO] Getting alerts from $prism..." -ForegroundColor Green
        try {
            Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Body $payload -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            }
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved alerts from $prism" -ForegroundColor Cyan
            if ($resp -is [string]) {
                $alerts = $resp | ConvertFrom-Json -AsHashTable -Depth 20
            } else {
                $alerts = $resp
            }
            if ($alerts.entities.count -eq 0) {
                Write-Host "$(get-date) [WARNING] There are no active alerts of the specified type." -ForegroundColor Yellow
            } else {
                Write-Host "$(Get-Date) [INFO] Processing results..." -ForegroundColor Green
                ForEach ($alert in $alerts.entities) {
                    #substituting parameter values in the default message (as this varies for every alert)
                    $alert_message = $alert.status.resources.default_message
                    if ($resp -is [string]) {
                        $alert.status.resources.default_message | Select-String -Pattern "{(.*?)}" -AllMatches | % {$_.Matches} | % {$alert_message = $alert_message -replace $_.Groups[0].Value,$alert.status.resources.parameters.$($_.Groups[1].Value).Values}
                    } else {
                        $alert.status.resources.default_message | Select-String -Pattern "{(.*?)}" -AllMatches | % {$_.Matches} | % {$alert_message = $alert_message -replace $_.Groups[0].Value,$alert.status.resources.parameters.$($_.Groups[1].Value).$((Get-Member -InputObject $alert.status.resources.parameters.$($_.Groups[1].Value) -MemberType NoteProperty).Name)}
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
                        "source_entity_type"= $alert.status.resources.source_entity.entity.type;
                        "source_entity_name"= $alert.status.resources.source_entity.entity.name;
                        "uuid"= $alert.metadata.uuid
                    }
                    #adding the captured details to the final result
                    $myvarResults.Add((New-Object PSObject -Property $myvarAlert)) | Out-Null
                }
                if ($csv) {
                    Write-Host "$(Get-Date) [INFO] Exporting results to $csv..." -ForegroundColor Green
                    $myvarResults | export-csv -NoTypeInformation $csv
                } else {
                    $myvarResults | Sort-Object -Property latest_occurrence_time
                }
            }
        }
        catch {
            $saved_error = $_.Exception.Message
            throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
        }
        #endregion
    }
    #endregion

    #! -acknowledge
    #region -acknowledge
    if ($acknowledge) {
        #region prepare api call
        $api_server = $prism
        $api_server_port = "9440"
        $api_server_endpoint = "/api/nutanix/v3/alerts/action/ACKNOWLEDGE"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "POST"
        $length = 500
        $headers = @{
            "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
            "Content-Type"="application/json";
            "Accept"="application/json"
        }
        $filter = "resolved!=true"
        if ($severity) {$filter += ";severity==$($severity)"}
        $content = @{
            alert_uuid_list= @($uuid)
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make the api call
        Write-Host "$(Get-Date) [INFO] Acknowledging alert $uuid in $prism..." -ForegroundColor Green
        try {
            Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Body $payload -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            }
            Write-Host "$(Get-Date) [SUCCESS] Successfully triggered acknowledgement of alert $uuid in $prism" -ForegroundColor Cyan
        }
        catch {
            $saved_error = $_.Exception.Message
            throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
        }
        #endregion
    }
    #endregion

    #! -resolve
    #region -resolve
    if ($resolve) {
        #region prepare api call
        $api_server = $prism
        $api_server_port = "9440"
        $api_server_endpoint = "/api/nutanix/v3/alerts/action/RESOLVE"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "POST"
        $length = 500
        $headers = @{
            "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
            "Content-Type"="application/json";
            "Accept"="application/json"
        }
        $filter = "resolved!=true"
        if ($severity) {$filter += ";severity==$($severity)"}
        $content = @{
            alert_uuid_list= @($uuid)
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make the api call
        Write-Host "$(Get-Date) [INFO] Resolving alert $uuid in $prism..." -ForegroundColor Green
        try {
            Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Body $payload -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            }
            Write-Host "$(Get-Date) [SUCCESS] Successfully triggered resolution of alert $uuid in $prism" -ForegroundColor Cyan
        }
        catch {
            $saved_error = $_.Exception.Message
            throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
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
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable prism -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
Remove-Variable prismCreds -ErrorAction SilentlyContinue
#endregion