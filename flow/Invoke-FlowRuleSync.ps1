<#
.SYNOPSIS
  Use this script to synchronize Nutanix Flow rules between two Prism Central instances.
.DESCRIPTION
  Given a source and target Prism Central, a category and a rule prefix, script will synchronize Nutanix Flow rules between both Prism Central (from source to target).
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER sourcePc
  Source Prism Central fully qualified domain name or IP address.
.PARAMETER targetPc
  Target Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER action
  Can be either scan (to view changes only) or sync (to synchronize changes from source to target).
.PARAMETER prefix
  Prefix of Flow rule names on source to consider (this prevents deleting rules that need to exist only on target).
.PARAMETER securedCalls
  Use if you want to check SSL certificates with every API call (default is to skip SSL certs checks).
.EXAMPLE
.\Invoke-FlowRuleSync.ps1 -sourcePc pc1.local -targetPc pc2.local -prismCreds myadcreds -action sync -prefix flowPc1
Synchronize all rules starting with flowPc1 from pc1 to pc2:
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
        [parameter(mandatory = $true)] [string]$sourcePc,
        [parameter(mandatory = $true)] [string]$targetPc,
        [parameter(mandatory = $true)] [string]$prefix,
        [parameter(mandatory = $false)][ValidateSet("scan","sync")] [string]$action="scan",
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [switch]$securedCalls
    )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
03/20/2024 sb   Making service groups and address groups name matches case sensitive to avoid errors when groups have the same name but use different case.
03/12/2024 sb   Retrieving target address groups and service groups before processing each rule to avoid issue when trying to create groups that already exist.
10/04/2023 sb   Adding -securedCalls parameter to enable checking SSL certs with every API call. Modified Invoke-PrismAPICall function to handle http errors correctly and show the exact error message.
09/10/2021 sb   Initial release.
09/13/2021 sb   Added processing for rule(s) deletion.
09/17/2021 sb   Adding -log parameter to redirect output to log file in working directory as well as the console.
09/22/2021 sb   Adding service and address groups sync (issue #9).
09/23/2021 sb   Fixed an issue when categories were added to a rule in outbound and/or outbound.
09/26/2021 sb   Moved syncing of categories, address and service groups to functions to avoid code duplication between the add and update actions.
10/11/2021 sb   Adding processing for multiple rules with the same name (issue #21)
10/11/2021 sb   Closing issue #21 for remove and update of rules.
10/18/2021 sb   Fixing an issue where a rule needed both adding and removing but had different target groups.
10/19/2021 sb   Fixing an issue where the wrong rule would sometime get removed.
################################################################################
'
    $myvarScriptName = ".\Invoke-FlowRuleSync.ps1"

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
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
    $length = 500
#endregion


#region parameters validation
    if (!$prismCreds) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
        $prismCredentials = Get-Credential -Message "Please enter Prism credentials"
    } 
    else 
    {#we are using custom credentials, so let's grab the username and password from that
        $myvar_type = $($prismCreds.GetType().Name)
        if ($myvar_type -ne "PSCredential")
        {
            try 
            {#retrieve credentials
                $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            }
            catch 
            {#could not retrieve credentials
                Set-CustomCredentials -credname $prismCreds
                $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            }
        }
        else 
        {
            $prismCredentials = $prismCreds
        }
    }
    if ($securedCalls) 
    {#we want to check ssl certs with every API call
        # Note: securedCalls parameter is deprecated; modern PS7+ always uses -SkipCertificateCheck
        # For PS 5.1, Set-PoSHSSLCerts already ignores invalid certs
    }
#endregion


#todo: what about service and address groups in target group?
#todo: complete scan section (does nothing at the moment)
#todo: bug: dealing with multiple apps in target group
#todo: improve: rule add/update/delete returns task uuid: check on task status: no task uuid is returned... check on status later?
#todo: improve: add export action for rules from source to json (for backup purposes)
#todo: improve: move code to figure out categories to a function
#todo: improve: implement category:value pair delete
#! does not process correctly if rule has been updated on target (exp tested: service group)

#region main

    #TODO: replace code in this region with v4 API calls
    #region GET Flow rules
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting Flow rules" -ForegroundColor Magenta
        #region process source
            Write-Host "$(get-date) [INFO] Retrieving list of Flow rules from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            $source_rules_response = @()
            $url = "https://{0}:9440/api/nutanix/v3/network_security_rules/list" -f $sourcePc
            $method = "POST"
            $content = @{
                kind="network_security_rule";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Do {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                if ($resp.entities) {
                    $source_rules_response += $resp.entities
                }
                $content.offset = $content.offset + $content.length
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of Flow rules from the source Prism Central instance $($sourcePc)" -ForegroundColor Cyan
            $filtered_source_rules_response = $source_rules_response | Where-Object {$_.spec.name -match "^$prefix"}
            Write-Host "$(get-date) [DATA] There are $($filtered_source_rules_response.count) Flow rules which match prefix $($prefix) on source Prism Central $($sourcePc)..." -ForegroundColor White
        #endregion

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of Flow rules from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_rules_response = @()
            $url = "https://{0}:9440/api/nutanix/v3/network_security_rules/list" -f $targetPc
            $method = "POST"
            $content = @{
                kind="network_security_rule";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Do {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                if ($resp.entities) {
                    $target_rules_response += $resp.entities
                }
                $content.offset = $content.offset + $content.length
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of Flow rules from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            $filtered_target_rules_response = $target_rules_response | Where-Object {$_.spec.name -match "^$prefix"}
            Write-Host "$(get-date) [DATA] There are $($filtered_target_rules_response.count) Flow rules which match prefix $($prefix) on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion

        if (!$filtered_source_rules_response -and !$filtered_target_rules_response)
        {#we didn't find any matching rules
            Throw "$(get-date) [ERROR] There are no Flow rules on $($sourcePc) or $($targetPc) which match prefix $($prefix)!"
        }
    #endregion

    #region GET service groups from target
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting service groups..." -ForegroundColor Magenta

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of service groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_service_groups = @()
            $url = "https://{0}:9440/api/nutanix/v3/service_groups/list" -f $targetPc
            $method = "POST"
            $content = @{
                kind="service_group";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Do {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                if ($resp.entities) {
                    $target_service_groups += $resp.entities
                }
                $content.offset = $content.offset + $content.length
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of service groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($target_service_groups.count) service groups on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion
    #endregion

    #region GET address groups from target
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting address groups..." -ForegroundColor Magenta

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of address groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_address_groups = @()
            $url = "https://{0}:9440/api/nutanix/v3/address_groups/list" -f $targetPc
            $method = "POST"
            $content = @{
                kind="address_group";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Do {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                if ($resp.entities) {
                    $target_address_groups += $resp.entities
                }
                $content.offset = $content.offset + $content.length
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of address groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($target_address_groups.count) address groups on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion
    #endregion

    #region COMPARE Flow rules
        Write-Host ""
        Write-Host "$(get-date) [STEP] Comparing Flow rules" -ForegroundColor Magenta

        #* rules to add ($add_rules_list)
        [System.Collections.ArrayList]$add_rules_list = New-Object System.Collections.ArrayList($null)
        $compared_rules = @()
        foreach ($rule in $filtered_source_rules_response) 
        {#compare source with target
            
            $source_rules_list = $filtered_source_rules_response | Where-Object {$_.spec.name -eq $rule.spec.name}
            $target_rules_list = $filtered_target_rules_response | Where-Object {$_.spec.name -eq $rule.spec.name}
            if ($rule.spec.name -notin $compared_rules)
            {#we haven't processed that rule yet
                if ($source_rules_list.count -gt 1)
                {#we have multiple rules with the same name   
                    Foreach ($source_rule_item in $source_rules_list)
                    {#process each rule with a duplicate name
                        $found_match = $false
                        Foreach ($target_rule_item in $target_rules_list)
                        {#compare with all rules with similar name on target
                            if (([String]::Compare(($source_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                            {#we found a match for the target group
                                $found_match = $true
                                continue
                            }
                        }
                        if (!$found_match)
                        {#there is a rule with the same name, but not the same target group
                            Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) does not exist with that specific target group on target Prism Central $($targetPc)" -ForegroundColor Green
                            $add_rules_list.Add($source_rule_item) | Out-Null
                        }
                    }
                }
                elseif ($rule.spec.name -notin $filtered_target_rules_response.spec.name)
                {#rule exists on source but not on target
                    Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) does not exist yet on target Prism Central $($targetPc)" -ForegroundColor Green
                    $add_rules_list.Add($rule) | Out-Null
                }
                else 
                {#rule is on target and source, but the target group could be different
                    Foreach ($source_rule_item in $source_rules_list)
                    {#process each rule with a duplicate name
                        $found_match = $false
                        Foreach ($target_rule_item in $target_rules_list)
                        {#compare with all rules with similar name on target
                            if (([String]::Compare(($source_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                            {#we found a match for the target group
                                $found_match = $true
                                continue
                            }
                        }
                        if (!$found_match)
                        {#there is a rule with the same name, but not the same target group
                            Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) does not exist with that specific target group on target Prism Central $($targetPc)" -ForegroundColor Green
                            $add_rules_list.Add($source_rule_item) | Out-Null
                        }
                    }
                }
                $compared_rules += $rule.spec.name
            }
        }
        Write-Host "$(get-date) [DATA] There are $($add_rules_list.count) Flow rules to add on target Prism Central $($targetPc)" -ForegroundColor White

        #* rules to remove ($remove_rules_list)
        [System.Collections.ArrayList]$remove_rules_list = New-Object System.Collections.ArrayList($null)
        $compared_rules = @()
        foreach ($rule in $filtered_target_rules_response) 
        {#compare target with source
            $source_rules_list = $filtered_source_rules_response | Where-Object {$_.spec.name -eq $rule.spec.name}
            $target_rules_list = $filtered_target_rules_response | Where-Object {$_.spec.name -eq $rule.spec.name}

            if ($rule.spec.name -notin $compared_rules)
            {#we haven't processed that rule yet
                if ($target_rules_list.count -gt 1)
                {#we have multiple rules with the same name   
                    Foreach ($target_rule_item in $target_rules_list)
                    {#process each rule with a duplicate name
                        $found_match = $false
                        Foreach ($source_rule_item in $source_rules_list)
                        {#compare with all rules with similar name on source
                            if (([String]::Compare(($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($source_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                            {#we found a match for the target group
                                $found_match = $true
                                continue
                            }
                        }
                        if (!$found_match)
                        {#there is a rule with the same name, but not the same target group
                            Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) does not exist with that specific target group on target Prism Central $($sourcePc)" -ForegroundColor Green
                            $remove_rules_list.Add($target_rule_item) | Out-Null
                        }
                    }
                }
                elseif ($rule.spec.name -notin $filtered_source_rules_response.spec.name)
                {#rule exists on target but not on source
                    Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) no longer exists on source Prism Central $($sourcePc)" -ForegroundColor Green
                    $remove_rules_list.Add($rule) | Out-Null
                }
                else 
                {#rule is on target and source, but the target group could be different
                    Foreach ($target_rule_item in $target_rules_list)
                    {#process each rule with a duplicate name
                        $found_match = $false
                        Foreach ($source_rule_item in $source_rules_list)
                        {#compare with all rules with similar name on source
                            if (([String]::Compare(($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($source_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                            {#we found a match for the target group
                                $found_match = $true
                            }
                        }
                        if (!$found_match)
                        {#there is a rule with the same name, but not the same target group
                            Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) does not exist with that specific target group on target Prism Central $($sourcePc)" -ForegroundColor Green
                            $remove_rules_list.Add($target_rule_item) | Out-Null
                        }
                    }
                }
                $compared_rules += $rule.spec.name
            }
        }
        Write-Host "$(get-date) [DATA] There are $($remove_rules_list.count) Flow rules to remove on target Prism Central $($targetPc)" -ForegroundColor White

        #* rules to update ($update_rules_list)
        [System.Collections.ArrayList]$update_rules_list = New-Object System.Collections.ArrayList($null)
        $compared_rules = @()
        foreach ($rule in $filtered_source_rules_response) 
        {#compare source with target
            $source_rules_list = $filtered_source_rules_response | Where-Object {$_.spec.name -eq $rule.spec.name}
            $target_rules_list = $filtered_target_rules_response | Where-Object {$_.spec.name -eq $rule.spec.name}

            if ($rule.spec.name -notin $compared_rules)
            {#we haven't processed that rule yet
                #! currently, this will always not match if a service or address group is in use and there is no way to find out if this is a new group or the same since all we're tracking is the uuid...
                if ($source_rules_list.count -gt 1)
                {#we have multiple rules with the same name   
                    Foreach ($source_rule_item in $source_rules_list)
                    {#process each rule with a duplicate name
                        $found_match = $false
                        Foreach ($target_rule_item in $target_rules_list)
                        {#compare with all rules with similar name on target
                            if (([String]::Compare(($source_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                            {#we found a match for the target group
                                if (($($rule.spec.resources | ConvertTo-Json -depth 100) -ne $($target_rule.spec.resources | ConvertTo-Json -depth 100)) -or ($rule.spec.description -ne $target_rule.spec.description))
                                {#rule configuration or description on source does not match rule configuration or description on target
                                    if ($source_rule_item.metadata.uuid -notin $remove_rules_list.metadata.uuid)
                                    {#we haven't marked this rule for removal
                                        Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) needs to be updated on target Prism Central $($targetPc)" -ForegroundColor Green
                                        $update_rules_list.Add($source_rule_item) | Out-Null
                                    }
                                }
                                $found_match = $true
                            }
                        }
                    }
                }
                elseif ($target_rule = $filtered_target_rules_response | Where-Object {$_.spec.Name -eq $rule.spec.Name})
                {#we have a matching rule on target, let's compare
                    if (($($rule.spec.resources | ConvertTo-Json -depth 100) -ne $($target_rule.spec.resources | ConvertTo-Json -depth 100)) -or ($rule.spec.description -ne $target_rule.spec.description))
                    {#rule configuration or description on source does not match rule configuration or description on target
                        if (($rule.metadata.uuid -notin $remove_rules_list.metadata.uuid) -and ($rule.metadata.uuid -notin $add_rules_list.metadata.uuid))
                        {#we haven't marked this rule for removal or addition so it needs to be updated
                            Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) needs to be updated on target Prism Central $($targetPc)" -ForegroundColor Green
                            $update_rules_list.Add($rule) | Out-Null
                        }
                    }
                }
                $compared_rules += $rule.spec.name
            }  
        }
        Write-Host "$(get-date) [DATA] There are $($update_rules_list.count) Flow rules to update on target Prism Central $($targetPc)" -ForegroundColor White

    #endregion

    #region ACTION
        if ($action -eq "scan")
        {#display what we would do

        }

        if ($action -eq "sync")
        {#synchronize (ADD, DELETE, UPDATE)
            
            #region process ADD
                if ($add_rules_list)
                {#there are rules to be added
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Adding Flow rules" -ForegroundColor Magenta
                    foreach ($rule in $add_rules_list)
                    {#process each rule to add
                        
                        #region GET service groups from target
                            Write-Host ""
                            Write-Host "$(get-date) [STEP] Getting service groups..." -ForegroundColor Magenta

                            #region process target
                                Write-Host "$(get-date) [INFO] Retrieving list of service groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
                                $target_service_groups = @()
                                $url = "https://{0}:9440/api/nutanix/v3/service_groups/list" -f $targetPc
                                $method = "POST"
                                $content = @{
                                    kind="service_group";
                                    offset=0;
                                    length=$length
                                }
                                $payload = (ConvertTo-Json $content -Depth 4)
                                Do {
                                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                                    if ($resp.entities) {
                                        $target_service_groups += $resp.entities
                                    }
                                    $content.offset = $content.offset + $content.length
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                }
                                While ($resp.metadata.length -eq $length)
                                Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of service groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
                                Write-Host "$(get-date) [DATA] There are $($target_service_groups.count) service groups on target Prism Central $($targetPc)..." -ForegroundColor White
                            #endregion
                        #endregion

                        #region GET address groups from target
                            Write-Host ""
                            Write-Host "$(get-date) [STEP] Getting address groups..." -ForegroundColor Magenta

                            #region process target
                                Write-Host "$(get-date) [INFO] Retrieving list of address groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
                                $target_address_groups = @()
                                $url = "https://{0}:9440/api/nutanix/v3/address_groups/list" -f $targetPc
                                $method = "POST"
                                $content = @{
                                    kind="address_group";
                                    offset=0;
                                    length=$length
                                }
                                $payload = (ConvertTo-Json $content -Depth 4)
                                Do {
                                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                                    if ($resp.entities) {
                                        $target_address_groups += $resp.entities
                                    }
                                    $content.offset = $content.offset + $content.length
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                }
                                While ($resp.metadata.length -eq $length)
                                Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of address groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
                                Write-Host "$(get-date) [DATA] There are $($target_address_groups.count) address groups on target Prism Central $($targetPc)..." -ForegroundColor White
                            #endregion
                        #endregion

                        Sync-Categories -rule $rule
                        Sync-ServiceGroups -rule $rule
                        Sync-AddressGroups -rule $rule

                        #TODO: replace code in this region with v4 API calls
                        #region add rule on target
                            $api_server_endpoint = "/api/nutanix/v3/network_security_rules"
                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                            $method = "POST"
                            $rule.psobject.members.remove("status")
                            $rule.metadata.psobject.members.remove("uuid")
                            $rule.metadata.psobject.members.remove("owner_reference")
                            if ($rule.spec.resources.app_rule)
                            {#remove rule id references from the payload to avoid API errors
                                $rule.spec.resources.app_rule.outbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                                $rule.spec.resources.app_rule.inbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                            }
                            $payload = (ConvertTo-Json $rule -Depth 100)

                            try 
                            {#create network policy
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                Write-Host "$(Get-Date) [SUCCESS] Added Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan
                                if ($debugme) {$resp}
                                #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc 
                            }
                            catch 
                            {#we couldn't create the network policy
                                if ($_.Exception.Message -match 'rule already exists')
                                {#the isolation rule already exists, let's just warn about this
                                    Write-Host "$(Get-Date) [WARNING] Could not add isolation rule $($rule.spec.Name) to $targetPc" -ForegroundColor Yellow
                                    Write-Host "$($_.Exception.Message)" -ForegroundColor Yellow
                                }
                                else 
                                {
                                    Throw "$($_.Exception.Message)"   
                                }
                            }                            
                        #endregion

                        Write-Host ""
                    }
                }
            #endregion

            
            #region process DELETE
                if ($remove_rules_list)
                {#there are rules to be removed
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Removing Flow rules" -ForegroundColor Magenta
                    foreach ($rule in $remove_rules_list)
                    {#process each rule to remove
                        #todo: for each category, figure out if it is used anywhere else in rules on source: if not, delete the category
                        #todo: replace code in this region with v4 API calls
                        #? delete rule on target
                        $api_server_endpoint = "/api/nutanix/v3/network_security_rules/{0}" -f $rule.metadata.uuid
                        $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                        $method = "DELETE"

                        Write-Host "$(get-date) [STEP] Deleting Flow rule $($rule.spec.Name) on $($targetPc)" -ForegroundColor Green
                        try 
                        {#delete the rule
                            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                            Write-Host "$(Get-Date) [SUCCESS] Deleted Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan
                            
                        }
                        catch 
                        {#we couldn't delete the rule
                            Throw "$($_.Exception.Message)"
                        }
                    }
                }
            #endregion

            
            #region process UPDATE 
                if ($update_rules_list)
                {#there are rules to be updated
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Updating Flow rules" -ForegroundColor Magenta
                    foreach ($rule in $update_rules_list)
                    {#process each rule to update
                        
                        #region GET service groups from target
                            Write-Host ""
                            Write-Host "$(get-date) [STEP] Getting service groups..." -ForegroundColor Magenta

                            #region process target
                                Write-Host "$(get-date) [INFO] Retrieving list of service groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
                                $target_service_groups = @()
                                $url = "https://{0}:9440/api/nutanix/v3/service_groups/list" -f $targetPc
                                $method = "POST"
                                $content = @{
                                    kind="service_group";
                                    offset=0;
                                    length=$length
                                }
                                $payload = (ConvertTo-Json $content -Depth 4)
                                Do {
                                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                                    if ($resp.entities) {
                                        $target_service_groups += $resp.entities
                                    }
                                    $content.offset = $content.offset + $content.length
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                }
                                While ($resp.metadata.length -eq $length)
                                Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of service groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
                                Write-Host "$(get-date) [DATA] There are $($target_service_groups.count) service groups on target Prism Central $($targetPc)..." -ForegroundColor White
                            #endregion
                        #endregion

                        #region GET address groups from target
                            Write-Host ""
                            Write-Host "$(get-date) [STEP] Getting address groups..." -ForegroundColor Magenta

                            #region process target
                                Write-Host "$(get-date) [INFO] Retrieving list of address groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
                                $target_address_groups = @()
                                $url = "https://{0}:9440/api/nutanix/v3/address_groups/list" -f $targetPc
                                $method = "POST"
                                $content = @{
                                    kind="address_group";
                                    offset=0;
                                    length=$length
                                }
                                $payload = (ConvertTo-Json $content -Depth 4)
                                Do {
                                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                                    if ($resp.entities) {
                                        $target_address_groups += $resp.entities
                                    }
                                    $content.offset = $content.offset + $content.length
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                }
                                While ($resp.metadata.length -eq $length)
                                Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of address groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
                                Write-Host "$(get-date) [DATA] There are $($target_address_groups.count) address groups on target Prism Central $($targetPc)..." -ForegroundColor White
                            #endregion
                        #endregion

                        Sync-Categories -rule $rule
                        Sync-ServiceGroups -rule $rule
                        Sync-AddressGroups -rule $rule

                        #region update rule on target
                            $target_rule = $filtered_target_rules_response | Where-Object {$_.spec.Name -eq $rule.spec.Name}
                            #! add code here to deal with the fact that there might be multiple target rules with the same name
                            if ($target_rule.count -gt 1)
                            {#we have multiple rules with the same name on the target, let's identify which ne we are updating based on the target group   
                                Foreach ($target_rule_item in $target_rule)
                                {#compare with all rules with similar name on target
                                    if (([String]::Compare(($rule.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                                    {#we found a match for the target group
                                        $target_rule = $target_rule_item
                                        continue
                                    }
                                }
                            }

                            #TODO: replace code in this region with v4 API calls
                            $api_server_endpoint = "/api/nutanix/v3/network_security_rules/{0}" -f $target_rule.metadata.uuid
                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                            $method = "PUT"
                            $rule.psobject.members.remove("status")
                            $rule.metadata.psobject.members.remove("uuid")
                            $rule.metadata.psobject.members.remove("owner_reference")
                            $rule.metadata.spec_version = $target_rule.metadata.spec_version
                            if ($rule.spec.resources.app_rule)
                            {#remove rule id references from the payload to avoid API errors
                                $rule.spec.resources.app_rule.outbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                                $rule.spec.resources.app_rule.inbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                            }
                            $payload = (ConvertTo-Json $rule -Depth 100)

                            try 
                            {#update the network policy
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                Write-Host "$(Get-Date) [SUCCESS] Updated Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan   
                            }
                            catch 
                            {#we couldn't update the network policy
                                Throw "$($_.Exception.Message)"
                            }                            
                        #endregion
                    }
                }
            #endregion
        }
    #endregion

#endregion


#region Sync-Categories
function Sync-Categories
{#syncs Prism categories used in a given network policy
    param
    (
        [Parameter(Mandatory)]
        $rule
    )

    begin {}

    process 
    {
        #region which categories are used?
        #* figure out categories used in this rule
        Write-Host "$(get-date) [INFO] Examining categories..." -ForegroundColor Green
        [System.Collections.ArrayList]$used_categories_list = New-Object System.Collections.ArrayList($null)
        #types of rules (where categories are listed varies depending on the type of rule): 
        if ($rule.spec.resources.quarantine_rule)
        {#this is a quarantine rule
            Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is a Quarantine rule..." -ForegroundColor Green
            foreach ($category in ($rule.spec.resources.quarantine_rule.target_group.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in target_group
                foreach ($value in ($rule.spec.resources.quarantine_rule.target_group.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
        }
        elseif ($rule.spec.resources.isolation_rule) 
        {#this is an isolation rule
            Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Isolation rule..." -ForegroundColor Green
            foreach ($category in ($rule.spec.resources.isolation_rule.first_entity_filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in first_entity_filter
                foreach ($value in ($rule.spec.resources.isolation_rule.first_entity_filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
            foreach ($category in ($rule.spec.resources.isolation_rule.second_entity_filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in second_entity_filter
                foreach ($value in ($rule.spec.resources.isolation_rule.second_entity_filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
        }
        elseif ($rule.spec.resources.app_rule) 
        {#this is an app policy/rule
            Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Application rule..." -ForegroundColor Green
            foreach ($category in ($rule.spec.resources.app_rule.outbound_allow_list.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in outbound_allow_list
                foreach ($value in ($rule.spec.resources.app_rule.outbound_allow_list.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
            foreach ($category in ($rule.spec.resources.app_rule.target_group.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in target_group
                foreach ($value in ($rule.spec.resources.app_rule.target_group.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
            foreach ($category in ($rule.spec.resources.app_rule.inbound_allow_list.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in inbound_allow_list
                foreach ($value in ($rule.spec.resources.app_rule.inbound_allow_list.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
        }
        else 
        {#we don't know what type of rule this is
            Write-Host "$(get-date) [WARNING] Rule $($rule.spec.Name) is not a supported rule type for replication!" -ForegroundColor Yellow
        }

        Write-Host "$(get-date) [DATA] Flow rule $($rule.spec.Name) uses the following category:value pairs:" -ForegroundColor White
        $used_categories_list | Select-Object -Unique
        #endregion
        
        #region are all used category:value pairs on target?
            #* check each used category:value pair exists on target
            [System.Collections.ArrayList]$missing_categories_list = New-Object System.Collections.ArrayList($null)
            foreach ($category_value_pair in ($used_categories_list | Select-Object -Unique))
            {#process each used category
                $category = ($category_value_pair -split ":")[0]
                $value = ($category_value_pair -split ":")[1]

                $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                $method = "GET"

                Write-Host "$(Get-Date) [INFO] Checking category:value pair $($category):$($value) exists in $targetPc..." -ForegroundColor Green
                try 
                {
                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $targetPc" -ForegroundColor Cyan
                }
                catch 
                {
                    $saved_error = $_.Exception.Message
                    $error_code = ($saved_error -split " ")[3]
                    if ($error_code -eq "404") 
                    {
                        Write-Host "$(get-date) [WARNING] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
                        $missing_categories_list.Add($category_value_pair) | Out-Null
                        Continue
                    }
                    else 
                    {
                        Write-Host "$saved_error" -ForegroundColor Yellow
                        Continue
                    }
                }
            }

            if ($missing_categories_list)
            {#there are missing categories on target
                Write-Host "$(get-date) [DATA] The following category:value pairs need to be added on $($targetPc):" -ForegroundColor White
                $missing_categories_list
            }
        #endregion
        
        #region create missing category:value pairs on target
            [System.Collections.ArrayList]$processed_categories_list = New-Object System.Collections.ArrayList($null)
            foreach ($category_value_pair in $missing_categories_list)
            {#process all missing categories and values
                #check if category exists
                $category = ($category_value_pair -split ":")[0]
                $value = ($category_value_pair -split ":")[1]

                if (!$processed_categories_list)
                {#we havent processed any category yet
                    if ($category -notin $processed_categories_list)
                    {#this category has not been found or added yet
                        $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                        $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                        $method = "GET"

                        Write-Host "$(Get-Date) [INFO] Checking category $($category) exists in $targetPc..." -ForegroundColor Green
                        try 
                        {#get the category
                            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                            Write-Host "$(Get-Date) [SUCCESS] Found the category $($category) in $targetPc" -ForegroundColor Cyan
                            $processed_categories_list.Add($category) | Out-Null
                        }
                        catch 
                        {#get category failed, or category was not found
                            $saved_error = $_.Exception.Message
                            $error_code = ($saved_error -split " ")[3]
                            if ($error_code -eq "404") 
                            {#category was not found
                                Write-Host "$(get-date) [WARNING] The category specified $($category) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
                                #add category
                                $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                                $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                $method = "PUT"
                                $content = @{
                                    api_version="3.1.0";
                                    description="added by Invoke-FlowRuleSync.ps1 script";
                                    name="$category"
                                }
                                $payload = (ConvertTo-Json $content -Depth 4)
                                try 
                                {#add the category
                                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                    Write-Host "$(Get-Date) [SUCCESS] Added category $($category) in $targetPc" -ForegroundColor Cyan
                                    if ($debugme) {$resp}
                                    #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                                    $processed_categories_list.Add($category) | Out-Null     
                                }
                                catch 
                                {#we couldn't add the category
                                    Throw "$($_.Exception.Message)"
                                }  
                            }
                            else 
                            {#we couldn't get the category
                                Throw "$($_.Exception.Message)"
                            }
                        }
                    }
                }
                
                #add value
                $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                $method = "PUT"
                $content = @{
                    api_version="3.1.0";
                    description="added by Invoke-FlowRuleSync.ps1 script";
                    value="$value"
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                try 
                {#add the value
                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                    Write-Host "$(Get-Date) [SUCCESS] Added value $($value) to category $($category) in $targetPc" -ForegroundColor Cyan
                    if ($debugme) {$resp}
                    #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                }
                catch 
                {#we couldn't add the value
                    Throw "$($_.Exception.Message)"
                }
            }
        #endregion
    }

    end {}
}

#endregion


#region Sync-AddressGroups
function Sync-AddressGroups
{#syncs Prism address groups used in a given network policy
    param
    (
        [Parameter(Mandatory)]
        $rule
    )

    begin {}

    process 
    {
        #region which address groups are used?
            #* figure out address groups used in this rule
            Write-Host "$(get-date) [INFO] Examining address groups..." -ForegroundColor Green
            [System.Collections.ArrayList]$used_address_group_list = New-Object System.Collections.ArrayList($null)
            #types of rules (where categories are listed varies depending on the type of rule): 
            if ($rule.spec.resources.app_rule) 
            {#this is an app rule
                foreach ($address_group in $rule.spec.resources.app_rule.outbound_allow_list.address_group_inclusion_list)
                {#process each address group used in outbound_allow_list
                    $used_address_group_list.Add($address_group) | Out-Null
                }
                foreach ($address_group in $rule.spec.resources.app_rule.inbound_allow_list.address_group_inclusion_list)
                {#process each address group used in inbound_allow_list
                    $used_address_group_list.Add($address_group) | Out-Null
                }
            }
        #endregion

        #region are all used address groups on the target?

            [System.Collections.ArrayList]$missing_address_groups_list = New-Object System.Collections.ArrayList($null)
            foreach ($address_group in ($used_address_group_list | Select-Object -Property uuid -Unique))
            {#process each used address group

                #find out what the address group name is (only uuid is kept in rule definition)
                $api_server_endpoint = "/api/nutanix/v3/address_groups/{0}" -f $address_group.uuid
                $url = "https://{0}:9440{1}" -f $sourcePc,$api_server_endpoint
                $method = "GET"

                $source_address_group = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

                if ($source_address_group.address_group.name -notin $target_address_groups.address_group.name)
                {#based on its name, that address group does not exist on the target
                    $missing_address_groups_list.Add($source_address_group) | Out-Null
                }
                else 
                {#the address group already exists on target, let's update the uuid reference in that rule
                    $target_address_group_uuid = ($target_address_groups | Where-Object {$_.address_group.Name -ceq $source_address_group.address_group.name}).uuid
                    if ($address_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $source_address_group.uuid})
                    {#that address group is used in inbound allow list
                        ForEach ($address_group_item in $address_group_inbound)
                        {
                            $address_group_item.uuid = $target_address_group_uuid
                        }
                    }
                    if ($address_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $source_address_group.uuid})
                    {#that address group is used in outbound allow list
                        ForEach ($address_group_item in $address_group_outbound)
                        {
                            $address_group_item.uuid = $target_address_group_uuid
                        }
                    }
                }
            }

            if ($missing_address_groups_list)
            {#there are missing address groups
                Write-Host "$(get-date) [DATA] The following address groups need to be added on $($targetPc):" -ForegroundColor White
                $missing_address_groups_list.address_group.name
            }
        #endregion

        #region create missing address groups on target
            [System.Collections.ArrayList]$processed_address_groups_list = New-Object System.Collections.ArrayList($null)
            foreach ($address_group in $missing_address_groups_list)
            {#process all missing address groups
                #add address group
                $api_server_endpoint = "/api/nutanix/v3/address_groups" -f $category,$value
                $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                $method = "POST"
                $payload = (ConvertTo-Json $address_group.address_group -Depth 10)
                Write-Host "$(Get-Date) [INFO] Adding address group $($address_group.address_group.name) to $targetPc" -ForegroundColor Green
                try 
                {#add address group
                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                    Write-Host "$(Get-Date) [SUCCESS] Added address group $($address_group.address_group.name) to $targetPc" -ForegroundColor Cyan
                    if ($debugme) {$resp}
                    #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                    if ($address_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $address_group.uuid})
                    {#that address group is used in inbound allow list, let's update the uuid with that of the newly created address group
                        ForEach ($address_group_item in $address_group_inbound)
                        {
                            $address_group_item.uuid = $resp.uuid
                        }
                    }
                    if ($address_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $address_group.uuid})
                    {#that address group is used in outbound allow list, let's update the uuid with that of the newly created address group
                        ForEach ($address_group_item in $address_group_outbound)
                        {
                            $address_group_item.uuid = $resp.uuid
                        }
                    }
                }
                catch 
                {#we couldn't add the address group
                    Throw "$($_.Exception.Message)"
                }
            }
        #endregion
    }

    end {}
}

#endregion


#region Sync-ServiceGroups
function Sync-ServiceGroups
{#syncs Prism service groups used in a given network policy
    param
    (
        [Parameter(Mandatory)]
        $rule
    )

    begin {}

    process 
    {
        #region which service groups are used?
            #* figure out service groups used in this rule
            Write-Host "$(get-date) [INFO] Examining service groups..." -ForegroundColor Green
            [System.Collections.ArrayList]$used_service_group_list = New-Object System.Collections.ArrayList($null)
            #types of rules (where categories are listed varies depending on the type of rule): 
            if ($rule.spec.resources.app_rule) 
            {#this is an app rule
                foreach ($service_group in $rule.spec.resources.app_rule.outbound_allow_list.service_group_list)
                {#process each service group used in outbound_allow_list
                    $used_service_group_list.Add($service_group) | Out-Null
                }
                foreach ($service_group in $rule.spec.resources.app_rule.inbound_allow_list.service_group_list)
                {#process each service group used in inbound_allow_list
                    $used_service_group_list.Add($service_group) | Out-Null
                }
            }
        #endregion

        #region are all used service groups on the target?

            [System.Collections.ArrayList]$missing_service_groups_list = New-Object System.Collections.ArrayList($null)
            foreach ($service_group in ($used_service_group_list | Select-Object -Property uuid -Unique))
            {#process each used service group

                #find out what the service group name is (only uuid is kept in rule definition)
                $api_server_endpoint = "/api/nutanix/v3/service_groups/{0}" -f $service_group.uuid
                $url = "https://{0}:9440{1}" -f $sourcePc,$api_server_endpoint
                $method = "GET"

                $source_service_group = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

                #Write-Host "$(Get-Date) [INFO] Checking service group $($source_service_group.service_group.name) exists in $targetPc..." -ForegroundColor Green
                if ($source_service_group.service_group.name -notin $target_service_groups.service_group.name)
                {#based on its name, that service group does not exist on the target
                    $missing_service_groups_list.Add($source_service_group) | Out-Null
                }
                else 
                {#the service group already exists on target, let's update the uuid reference in that rule
                    $target_service_group_uuid = ($target_service_groups | Where-Object {$_.service_group.Name -ceq $source_service_group.service_group.name}).uuid
                    if ($service_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                    {#that service group is used in inbound allow list
                        ForEach ($service_group_item in $service_group_inbound)
                        {
                            $service_group_item.uuid = $target_service_group_uuid
                        } 
                    }
                    if ($service_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                    {#that service group is used in outbound allow list
                        ForEach ($service_group_item in $service_group_outbound)
                        {
                            $service_group_item.uuid = $target_service_group_uuid
                        }
                    }
                }
            }

            if ($missing_service_groups_list)
            {#there are missing service groups
                Write-Host "$(get-date) [DATA] The following service groups need to be added on $($targetPc):" -ForegroundColor White
                $missing_service_groups_list.service_group.name
            }
        #endregion

        #region create missing service groups on target
            [System.Collections.ArrayList]$processed_service_groups_list = New-Object System.Collections.ArrayList($null)
            foreach ($service_group in $missing_service_groups_list)
            {#process all missing service groups
                #add service group
                $api_server_endpoint = "/api/nutanix/v3/service_groups" -f $category,$value
                $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                $method = "POST"
                $payload = (ConvertTo-Json $service_group.service_group -Depth 10)
                Write-Host "$(Get-Date) [INFO] Adding service group $($service_group.service_group.name) to $targetPc" -ForegroundColor Green
                try 
                {#add service group
                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                    Write-Host "$(Get-Date) [SUCCESS] Added service group $($service_group.service_group.name) to $targetPc" -ForegroundColor Cyan
                    if ($debugme) {$resp}
                    if ($service_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                    {#that service group is used in inbound allow list
                        ForEach ($service_group_item in $service_group_inbound)
                        {
                            $service_group_item.uuid = $resp.uuid
                        } 
                    }
                    if ($service_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                    {#that service group is used in outbound allow list
                        ForEach ($service_group_item in $service_group_outbound)
                        {
                            $service_group_item.uuid = $resp.uuid
                        }
                    }
                }
                catch 
                {#we couldn't add the service group
                    Throw "$($_.Exception.Message)"
                }
            }
        #endregion
    }

    end {}
}

#endregion


#region Get-SecurityPolicies
function Get-SecurityPolicies
{#gets FNS >3.0 security policies using API v4
    param
    (
        [Parameter(Mandatory)][string]$prism_central_address,
        [Parameter(Mandatory)][pscredential]$prism_central_credentials_object
    )

    begin 
    {
        $url = "https://{0}:9440/api/microseg/v4.0.a1/config/policies" -f $prism_central_address
        $method = 'GET'
    }

    process 
    {
        $api_response = Invoke-PrismAPICall -method $method -url $url -credential $prism_central_credentials_object
    }

    end 
    {
        return $api_response
    }
}

#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable sourcePc -ErrorAction SilentlyContinue
    Remove-Variable targetPc -ErrorAction SilentlyContinue
    Remove-Variable prefix -ErrorAction SilentlyContinue
    Remove-Variable action -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable securedCalls -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion