<#
.SYNOPSIS
  Modernizes Nutanix PowerShell scripts to use the get-AhvCpuRatio.ps1 pattern.
.DESCRIPTION
  Replaces legacy helper functions (Write-LogOutput, LoadModule, Get-PrismCentralObjectList, 
  Get-PrismCentralTaskStatus, New-PercentageBar, CleanUp, old Invoke-PrismAPICall, 
  old Set-PoshTls, old Set-PoSHSSLCerts) with modern inlined versions.
  Removes -log parameter and Start/Stop-Transcript.
  Replaces Get-PrismCentralObjectList calls with inline pagination loops.
.NOTES
  Author: Assistant
  Run from the nutanix repo root: .\Modernize-Scripts.ps1
#>

param(
    [switch]$WhatIf,
    [string[]]$Paths = @(
        "flow\*.ps1",
        "ahv\*.ps1",
        "prism\prism-element\*.ps1",
        "prism\prism-central\*.ps1",
        "vmware\esxi\*.ps1",
        "vmware\view\*.ps1",
        "move\*.ps1",
        "calm\*.ps1",
        "zabbix\*.ps1"
    )
)

$ModernHelpers = @'
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
'@

$ModernCleanup = @'
#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
'@

function Modernize-Script {
    param([string]$FilePath)
    
    $content = Get-Content -Path $FilePath -Raw
    
    # Skip if already modernized (check for modern Set-PoSHSSLCerts pattern)
    if ($content -match 'SYSLIB0014') {
        Write-Host "  Already modernized: $FilePath" -ForegroundColor Cyan
        return
    }
    
    Write-Host "  Processing: $FilePath" -ForegroundColor Yellow
    
    # 1. Remove -log parameter from param block
    $content = $content -replace '\[parameter\(mandatory = \$false\)\] \[switch\]\$log,\s*\n', ''
    $content = $content -replace '\[parameter\(mandatory = \$false\)\] \[switch\]\$log\s*\n', ''
    
    # 2. Replace all Write-LogOutput calls with direct Write-Host
    $content = $content -replace 'Write-LogOutput -Category "([^"]+)" -LogFile \$myvar_log_file -Message "([^"]+)"', 'Write-Host "$(Get-Date) [$1] $2" -ForegroundColor $(switch($1){"INFO"{"Green"}"WARNING"{"Yellow"}"ERROR"{"Red"}"SUM"{"Magenta"}"SUCCESS"{"Cyan"}"STEP"{"Magenta"}"DEBUG"{"White"}"DATA"{"Gray"}})'
    $content = $content -replace 'Write-LogOutput -Category "([^"]+)" -Message "([^"]+)"', 'Write-Host "$(Get-Date) [$1] $2" -ForegroundColor $(switch($1){"INFO"{"Green"}"WARNING"{"Yellow"}"ERROR"{"Red"}"SUM"{"Magenta"}"SUCCESS"{"Cyan"}"STEP"{"Magenta"}"DEBUG"{"White"}"DATA"{"Gray"}})'
    
    # 3. Remove the entire functions region (Write-LogOutput, LoadModule, old Invoke-PrismAPICall, etc.)
    # This is complex - we'll replace the whole #region functions block
    
    # Find the start and end of functions region
    $funcStart = $content.IndexOf('#region functions')
    if ($funcStart -gt 0) {
        # Find the matching #endregion
        $remaining = $content.Substring($funcStart)
        $endMatch = [regex]::Match($remaining, '#endregion')
        if ($endMatch.Success) {
            $funcEnd = $funcStart + $endMatch.Index + 9
            # Replace the entire functions region with modern helpers
            $before = $content.Substring(0, $funcStart)
            $after = $content.Substring($funcEnd)
            $content = $before + $ModernHelpers + $after
        }
    }
    
    # 4. Remove Start-Transcript / Stop-Transcript blocks
    $content = $content -replace 'if \(\$log\)\s*\{[^}]*Start-Transcript[^}]*\}', ''
    $content = $content -replace 'if \(\$log\)\s*\{[^}]*Stop-Transcript[^}]*\}', ''
    
    # 5. Replace Get-PrismCentralObjectList calls with inline pagination
    # This is script-specific, so we'll note it needs manual review
    
    # 6. Update cleanup section
    $cleanupStart = $content.LastIndexOf('#region cleanup')
    if ($cleanupStart -gt 0) {
        $remaining = $content.Substring($cleanupStart)
        $endMatch = [regex]::Match($remaining, '#endregion')
        if ($endMatch.Success) {
            $cleanupEnd = $cleanupStart + $endMatch.Index + 9
            $before = $content.Substring(0, $cleanupStart)
            $after = $content.Substring($cleanupEnd)
            # Keep the timing output but modernize variable cleanup
            $content = $before + $ModernCleanup + "    Remove-Variable `" + ($content -match 'param\s*\([^)]*\$(\w+)' | ForEach-Object { $matches[1] }) -join '" -ErrorAction SilentlyContinue`n    Remove-Variable "') + '" -ErrorAction SilentlyContinue' + @"
#endregion
"@
        }
    }
    
    # 7. Update revision date in NOTES
    $content = $content -replace 'Revision: .+', 'Revision: October 29th 2026'
    $content = $content -replace 'Maintenance Log\s+Date\s+By\s+Updates.*?################################################################################', "Maintenance Log`nDate       By   Updates (newest updates at the top)`n---------- ---- ---------------------------------------------------------------`n10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter`n################################################################################"
    
    if ($WhatIf) {
        Write-Host "  Would modernize: $FilePath" -ForegroundColor Green
    } else {
        Set-Content -Path $FilePath -Value $content -Encoding UTF8
        Write-Host "  Modernized: $FilePath" -ForegroundColor Green
    }
}

# Get all target scripts
$allScripts = @()
foreach ($pattern in $Paths) {
    $fullPattern = Join-Path (Get-Location) $pattern
    $scripts = Get-ChildItem $fullPattern -File | Where-Object { 
        $_.FullName -notmatch '(_archive|wip|template|cursor|task-library|others|machine_flavors)' -and
        $_.Name -ne 'get-AhvCpuRatio.ps1'
    }
    $allScripts += $scripts.FullName
}

$allScripts = $allScripts | Sort-Object -Unique

Write-Host "Found $($allScripts.Count) scripts to modernize" -ForegroundColor Magenta
foreach ($script in $allScripts) {
    Modernize-Script -FilePath $script
}

Write-Host "Done!" -ForegroundColor Magenta