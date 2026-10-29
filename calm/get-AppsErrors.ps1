<#
.SYNOPSIS
  Use this script to get all Calm application instances in error state along with their error code and message.
.DESCRIPTION
  Use this script to get all Calm application instances in error state along with their error code and message.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER retry
  Indicates you want to retry those failed apps. This can be either "all" or an integer value to match the apps that failed with that error code.
.EXAMPLE
.\get-AppsErrors.ps1 -prismcentral ntnxc1.local
Fetch all apps in error state from ntnxc1.local
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>


#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $false)] [string]$prismcentral,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [string]$retry
    )
#endregion parameters


#region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $false)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string] 
            $method,
            
            [parameter(mandatory = $false)]
            [string] 
            $url,

            [parameter(mandatory = $false)]
            [string] 
            $payload,
            
            [parameter(mandatory = $false)]
            [System.Management.Automation.PSCredential]
            $credential
        )

        begin
        {
            
        }
        process
        {
            if ($debugme) {Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green}
            try {
                #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
                if ($PSVersionTable.PSVersion.Major -gt 5) {
                    $headers = @{
                        "Content-Type"="application/json";
                        "Accept"="application/json"
                    }
                    if ($payload) {
                        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                    } else {
                        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                    }
                } else {
                    $username = $credential.UserName
                    $password = $credential.Password
                    $headers = @{
                        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                        "Content-Type"="application/json";
                        "Accept"="application/json"
                    }
                    if ($payload) {
                        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                    } else {
                        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                    }
                }
                if ($debugme) {
                  Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
                  Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White
                }
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
        end
        {
            return $resp
        }    
    }

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
    		
            [parameter(mandatory = $false)]
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
    		
            [parameter(mandatory = $false)]
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

    function Set-PoshTls
    {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            # PowerShell 7+ already defaults to TLS 1.2+; Invoke-PrismAPICall also sets -SslProtocol Tls12
            return
        }
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = (
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        )
    }

    function Set-PoSHSSLCerts {
        # PowerShell 6+ uses -SkipCertificateCheck on Invoke-RestMethod (see Invoke-PrismAPICall).
        # The old ServicePointManager Add-Type path is obsolete on modern .NET and fails to compile (SYSLIB0014).
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates (SkipCertificateCheck)" -ForegroundColor Green
            return
        }

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
        if (ServicePointManager.ServerCertificateValidationCallback == null)
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                delegate (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
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
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter and Write-LogOutput function; converted from UTF-16 to UTF-8
02/05/2025 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-AppsErrors.ps1"

    if ($help) {
        $helpContent = Get-Content $PSCommandPath -Raw
        $inHelp = $false
        $helpLines = @()
        foreach ($line in $helpContent -split "`n") {
            if ($line -match '^<#') { $inHelp = $true; continue }
            if ($line -match '^#>') { break }
            if ($inHelp) { $helpLines += $line }
        }
        $helpLines -join "`n" | Write-Host
        exit
    }
    if ($History) {$HistoryText; exit}
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}
#endregion prepwork


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = 9440
#endregion variables


#region parameters validation
    if (!$prismcentral) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral!"
    }
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
#endregion parameters validation


#region processing

    #region GET apps in ERROR state
      Write-Host "$(Get-Date) [INFO] Retrieving list of NCM Self Service applications in ERROR state..." -ForegroundColor Green
      #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/apps/list"
        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
        $method = "POST"

        # this is used to capture the content of the payload
        $offset = 0
        $content = @{
          kind = "app";
          length = 250;
          offset = $offset;
          filter = "_state==error;(name!=Infrastructure;name!=Self%20Service)"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
      #endregion
      #region make api call
        [System.Collections.ArrayList]$myvarAppsResults = New-Object System.Collections.ArrayList($null)
        Do {
            try {
                $error_state_app_list = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                
                #grab the information we need in each entity
                ForEach ($entity in $error_state_app_list.entities) {
                      $myvarAppInfo = [ordered]@{
                          "name" = $entity.status.name;
                          "uuid" = $entity.status.uuid;
                      }
                      #store the results for this entity in our overall result variable
                      $myvarAppsResults.Add((New-Object PSObject -Property $myvarAppInfo)) | Out-Null
                }
                if ($debugme) {write-host "count: $($myvarAppsResults.Count) out of $($error_state_app_list.metadata.total_matches)"}

                #prepare the json payload for the next batch of entities/response
                $offset += ($error_state_app_list.entities).Count
                $content = @{
                  kind = "app";
                  length = 250;
                  offset = $offset;
                  filter = "_state==error;(name!=Infrastructure;name!=Self%20Service)"
                }
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            catch {
                $saved_error = $_.Exception.Message
                # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                Throw "$(get-date) [ERROR] $saved_error"
            }
        }
        While ($error_state_app_list.metadata.total_matches -gt $myvarAppsResults.Count)

        if ($debugme) {
            Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
            $myvarAppsResults
        }
      #endregion
    #endregion GET apps in ERROR state

    #region process each app
    [System.Collections.ArrayList]$myvarErrorResults = New-Object System.Collections.ArrayList($null)
    $app_count = 1
    foreach ($app in $myvarAppsResults) {
      #* get app runlogs
      Write-Host "$(Get-Date) [INFO] Retrieving app runlogs for application $($app.name) ($($app_count) of $($myvarAppsResults.Count))" -ForegroundColor Green
      #region prepare api call
        $api_server_endpoint = "/api/calm/v3.0/apps/{0}/app_runlogs/list" -f $app.uuid
        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
        $method = "POST"

        # this is used to capture the content of the payload
        $group_member_offset = 0
        $content = @{
          filter = "application_reference==$($app.uuid);(type==action_runlog,type==audit_runlog,type==ngt_runlog,type==clone_action_runlog,type==platform_sync_runlog,type==patch_runlog)"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
      #endregion prepare api call
      #region make api call
        try {
          $app_runlog_list = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
          
          #grab the information we need in each entity
          ForEach ($runlog in ($app_runlog_list.entities | Where-Object {$_.status.state -EQ "FAILURE"})) {
                if ($retry -ieq "all") {
                  #* kicking off a retry for all failed apps
                }
                else {#we're not retrying all apps or we're not retrying at all
                  #* getting error details
                  #region prepare api call
                    $api_server_endpoint = "/api/calm/v3.0/apps/{0}/app_runlogs/list" -f $app.uuid
                    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                    $method = "POST"

                    # this is used to capture the content of the payload
                    $group_member_offset = 0
                    $content = @{
                      filter = "root_reference==$($runlog.metadata.uuid)"
                    }
                    $payload = (ConvertTo-Json $content -Depth 4)
                  #endregion prepare api call
                  #region make api call
                  try {
                    $runlog_details_list = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    #grab the information we need in each entity
                    $runlog_detail = ($runlog_details_list.entities | Where-Object {$_.status.state -EQ "FAILURE"})[0]
                  }
                  catch {
                      $saved_error = $_.Exception.Message
                      # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                      Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                      Throw "$(get-date) [ERROR] $saved_error"
                  }
                  #endregion make api call
                  if ($retry) {#we are retrying some apps based on their error code
                    #* filter list of apps with the matching error code
                    #* kicking off a retry for those failed apps
                  }
                }
                $myvarRunlogDetails = [ordered]@{
                    "app_name" = $app.name;
                    "action" = $runlog.status.action_reference.name;
                    "task" = $runlog_detail.status.task_reference.name;
                    "uuid" = $runlog.metadata.uuid;
                    "error_message" = $runlog_detail.status.reason_list[0];
                    "error_code" = $runlog_detail.status.exit_code;
                }
                #store the results for this entity in our overall result variable
                $myvarErrorResults.Add((New-Object PSObject -Property $myvarRunlogDetails)) | Out-Null
          }
        }
        catch {
            $saved_error = $_.Exception.Message
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            Throw "$(get-date) [ERROR] $saved_error"
        }
      #endregion make api call
      ++$app_count
    }
    #endregion process each app
    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($prismcentral)_AppsErrors.csv" -ForegroundColor Green
    $myvarErrorResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($prismcentral)+"_AppsErrors.csv")
#endregion processing


#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable retry -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
#endregion cleanup