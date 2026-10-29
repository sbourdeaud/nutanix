<#
.SYNOPSIS
  Use this script to delete Calm application instances and blueprints based on a name pattern.
.DESCRIPTION
  Use this script to delete Calm application instances based on a name pattern.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\remove-calmApps.ps1 -prismcentral ntnxc1.local -apps myapp*
Delete all Calm application instances starting with "myapp" from Prism Central ntnxc1.local
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
        [parameter(mandatory = $false)] [string]$apps,
        [parameter(mandatory = $false)] [switch]$soft,
        [parameter(mandatory = $false)] [string]$bps,
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion

#region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $false)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string]$method,

            [parameter(mandatory = $false)]
            [string]$url,

            [parameter(mandatory = $false)]
            [string]$payload,

            [parameter(mandatory = $false)]
            [System.Management.Automation.PSCredential]$credential
        )

        Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
        try {
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json"
                    "Accept"       = "application/json"
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
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))))
                    "Content-Type"  = "application/json"
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                } else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
            Write-Host "$(Get-Date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White }
        }
        catch {
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            throw "$(Get-Date) [ERROR] $($_.Exception.Message)"
        }
        return $resp
    }

    function Set-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $false)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Set path to $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
        $user = $credentials.UserName
        $securePassword = $credentials.Password

        try {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        if (!(Test-Path $path)) {
            try {
                New-Item -Type Directory $path -ErrorAction Stop | Out-Null
            }
            catch {
                throw "$(Get-Date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
        }

        try {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(Get-Date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan
    }

    function Get-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $false)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        if (!(Test-Path $credentialsFilePath)) {
            throw "$(Get-Date) [ERROR] Could not access file $credentialsFilePath"
        }

        $credFile = Get-Content $credentialsFilePath
        $user = $credFile[0]
        $securePassword = $credFile[1] | ConvertTo-SecureString
        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(Get-Date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan
        return $customCredentials
    }

    function Set-PoshTls {
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
04/02/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\remove-calmApps.ps1"

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

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = 9440
    $length = 250
#endregion

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

  if (!$apps -and !$bps) 
  {
    Write-Host "$(Get-Date) [ERROR] You must specify either an application name or a blueprint name! Exiting." -ForegroundColor Red
    Exit 1
  }

  $myvar_apps = $apps.Split(",") #make sure we parse the argument in case it contains several entries
  $myvar_bps = $bps.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#region processing

    #region delete app
      if ($apps)
      {
        #region GET apps
          Write-Host "$(Get-Date) [INFO] Retrieving list of NCM Self Service applications..." -ForegroundColor Green

          #region get total number of entities
            $url = "https://{0}:9440/api/nutanix/v3/apps/list" -f $prismcentral
            $method = "POST"
            $content = @{
                kind= "app";
                length = 1;
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Write-Host "$(Get-Date) [INFO] Retrieving total number of Apps available from $prismcentral..." -ForegroundColor Green
            $total_entities = (Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials).metadata.total_matches
          #endregion get total number of entities
          #region retrieve all entities
            $page_size = 250
            $total_pages = [Math]::Ceiling($total_entities / $page_size)
            $offsets = 0..($total_pages - 1) | ForEach-Object { $_ * $page_size }
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            Write-Host "$(Get-Date) [INFO] Retrieving $total_entities entities from $prismcentral..." -ForegroundColor Green
            $results = $offsets | ForEach-Object -ThrottleLimit 5 -Parallel {
                $offset = $_
                $url = "https://{0}:9440/api/nutanix/v3/apps/list" -f $($using:prismcentral)
                $method = "POST"
                $content = @{
                    kind= "app";
                    length = $($using:page_size);
                    offset = $offset;
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                
                try {
                    $response = Invoke-RestMethod -Method $method -Uri $url -Headers $($using:headers) -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $($using:prismCredentials) -ErrorAction Stop
                    $response.entities
                }
                catch {
                    $saved_error = $_.Exception
                    Write-Host "$(Get-Date) [ERROR] $saved_error" -ForegroundColor Red
                }
            }
          #endregion retrieve all entities
        #endregion GET apps in ERROR state

        #region build list of apps to delete
          [array]$myvar_app_list_to_delete=@()
          ForEach ($myvar_app in $myvar_apps)
          {
            if ($myvar_item = $results | Where-Object {$_.status.name -like $myvar_app})
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
            Write-Host "$(Get-Date) [INFO] Deleting Calm application $($myvar_app.status.name)..." -ForegroundColor Green
            #region prepare api call
              if ($soft)
              {
                $api_server_endpoint = "/api/nutanix/v3/apps/{0}?type=soft" -f $myvar_app.metadata.uuid
              }
              else 
              {
                $api_server_endpoint = "/api/nutanix/v3/apps/{0}" -f $myvar_app.metadata.uuid
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
            Write-Host "$(Get-Date) [SUCCESS] Successfully deleted Calm application $($myvar_app.status.name) from $prismcentral!" -ForegroundColor Cyan
        }
      }
    #endregion

    #region delete bp
      if ($bps)
      {
        #POST blueprints/list to retrieve app uuid
          Write-Host "$(Get-Date) [INFO] Retrieving list of Calm blueprints..." -ForegroundColor Green
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
              While ($content.offset -lt $resp.metadata.total_matches)

              if ($debugme) 
              {
                  Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
                  $myvarBlueprintsResults
              }
          #endregion
          Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved list of Calm blueprints from $prismcentral!" -ForegroundColor Cyan
        
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
          Write-Host "$(Get-Date) [INFO] Deleting Calm blueprint $($myvar_bp.name)..." -ForegroundColor Green
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
          Write-Host "$(Get-Date) [SUCCESS] Successfully deleted Calm blueprint $($myvar_bp.name) from $prismcentral!" -ForegroundColor Cyan
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable apps -ErrorAction SilentlyContinue
    Remove-Variable soft -ErrorAction SilentlyContinue
    Remove-Variable bps -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion