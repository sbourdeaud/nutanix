<#
.SYNOPSIS
  This script can be used to create categories in Prism Central. It can take csv as input for mass creation.
.DESCRIPTION
  Given a Nutanix cluster and a list of category:value pairs, create that category:value in Prism Central.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER sourcecsv
  Indicates the path of a comma separated file including a list of VMs to modify. The format of each line (with headers) is: category_name,category_value.
.PARAMETER categories
  List of category:value pairs to create. This is case sensitive.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\new-category.ps1 -prism 10.10.10.1 -prismCreds myuser -categories "my_category:my_value1,my_category:my_value2,my_other_category:my_other_value1"
Creates the specified category:value pairs.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region Parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$prism,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] [string]$sourcecsv,
    [parameter(mandatory = $false)] [string]$categories
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
01/31/2025 sb   Initial release.
################################################################################
'
    $myvarScriptName = ".\new-category.ps1"
    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $true)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string]$method,

            [parameter(mandatory = $true)]
            [string]$url,

            [parameter(mandatory = $false)]
            [string]$payload,

            [parameter(mandatory = $true)]
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

            [parameter(mandatory = $true)]
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

            [parameter(mandatory = $true)]
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


#region variables
    #initialize variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvarListToProcess = New-Object System.Collections.ArrayList($null)
    $myvarCategories = @()

    $api_server_port = "9440"
    $api_server = $prism
    $length = 500
   
    #let's initialize parameters if they haven't been specified
    if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
    if ($categories -and $sourcecsv) {throw "You must specify -categories OR -sourcecsv but NOT BOTH!"}
    if ((!$categories) -and !($sourcecsv)) {$categories = read-host "Enter a list of category:value pairs to create"}
    if ($categories) {
        $categories.Split(",")
        foreach ($pair in $categories) {
            #build dict with provided values
            $myvarItem = [ordered]@{
              "category_name" = $($pair.Split(":"))[0];
              "category_value" = $($pair.Split(":"))[1]
            }
            #store the results for this entity in our overall result variable
            $myvarListToProcess.Add((New-Object PSObject -Property $myvarItem)) | Out-Null
        }
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
#endregion


#region processing
    #region get categories once
    Write-Host "$(Get-Date) [INFO] Retrieving existing categories from $prism..." -ForegroundColor Green
    $myvarCategories = @()
    $url = "https://{0}:{1}/api/nutanix/v3/categories/list" -f $api_server,$api_server_port
    $method = "POST"
    $content = @{
        kind = "category";
        length = $length
    }
    $payload = (ConvertTo-Json $content -Depth 4)

    Do {
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            
            $myvarCategories += $resp.entities
            
            $content.offset = $content.offset + $content.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        catch {
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            Throw "$(get-date) [ERROR] $($_.Exception.Message)"
        }
    }
    While ($resp.metadata.length -eq $length)

    Write-Host "$(Get-Date) [SUCCESS] Retrieved $($myvarCategories.count) existing categories" -ForegroundColor Cyan
    #endregion get categories

    ForEach ($item in $myvarListToProcess) {
        $myvar_already_tagged = $false
        $category = $item.category_name
        $value = $item.category_value

        #region check category:value pair exists
            #region prepare api call
              $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
              $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
              $method = "GET"
            #endregion

            #region make the api call
              Write-Host "$(Get-Date) [INFO] Checking $($category):$($value) exists in $prism..." -ForegroundColor Green
              try {
                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] The category:value pair $($category):$($value) already exists in $prism" -ForegroundColor Cyan
                Continue
              }
              catch {
                $saved_error = $_.Exception.Message
                # Check if it's a 404 error
                if ($_.Exception.Response.StatusCode -eq "NotFound" -or $saved_error -like "*404*") {
                    #region check if category exists, if not create it
                    #* create category if required
                        if ($category -notin $myvarCategories.name) {
                            $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                            $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
                            $method = "PUT"
                            $content = @{
                                name = $category
                            }
                            $payload = (ConvertTo-Json $content -Depth 4)
                            try {
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                Write-Host "$(get-date) [SUCCESS] Created category key $($category)." -ForegroundColor Cyan
                            }
                            catch {
                                Write-Host "$(get-date) [WARNING] Could not create category key $($category)!" -ForegroundColor Yellow
                            }
                        }
                        else {Write-Host "$(get-date) [INFO] The category key $($category) already exists." -ForegroundColor Green}
                    #endregion check if category exists, if not create it

                    #region: create category:value
                        $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
                        $method = "PUT"
                        $content = @{
                          value = $value
                        }
                        $payload = (ConvertTo-Json $content -Depth 4)
                        try {
                          $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                          Write-Host "$(get-date) [SUCCESS] Created value $($value) in category key $($category)." -ForegroundColor Cyan
                        }
                        catch {
                          Write-Host "$(get-date) [WARNING] Could not create value $($value) in category key $($category)!" -ForegroundColor Yellow
                        }
                    #endregion create category:value
                }
                else {
                    Write-Host "$(get-date) [WARNING] $saved_error" -ForegroundColor Yellow
                    Continue
                }
              }
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable sourcecsv -ErrorAction SilentlyContinue
    Remove-Variable categories -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
    Remove-Variable api_server -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion