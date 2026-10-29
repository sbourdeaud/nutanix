<#
.SYNOPSIS
  This script can be used to manage alerts in Prism Central (get, acknowledge and resolve).
.DESCRIPTION
  Given a Prism Central IP or FQDN, get, acknowledge or resolve alerts.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
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
.PARAMETER csv
  Name of csv file to export to. By default results are only printed to the default output.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\use-ntnxAlerts.ps1 -prism 10.10.10.1 -prismCreds myuser -get -severity Critical
Get all critical alerts which are neither acknowledged nor resolved from Prism Central 10.10.10.1.
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
    [parameter(mandatory = $false)] [switch]$get,
    [parameter(mandatory = $false)] [string]$uuid,
    [parameter(mandatory = $false)] [switch]$acknowledge,
    [parameter(mandatory = $false)] [switch]$resolve,
    [parameter(mandatory = $false)] [ValidateSet("critical","warning","info")][string]$severity,
    [parameter(mandatory = $false)] [string]$csv
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
01/15/2020 sb   Initial release.
04/15/2020 sb   Do over with sbourdeaud module
02/06/2021 sb   Replaced username with get-credential
02/07/2022 sb   Adding cluster name, possible cause and resolution to alert data
                Adding Nutanix KB link (when there is one available)
07/13/2022 sb   Forcing PoSH core as -AsHashTable is not recognized by PoSH 5.1
################################################################################
'
    $myvarScriptName = ".\use-ntnxAlerts.ps1"
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

    function New-PercentageBar {
        [CmdletBinding(DefaultParameterSetName = 'PERCENT')]
        Param (
            [Parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName = 'PERCENT')]
            [ValidateRange(0, 100)]
            [int]$Percent
            ,
            [Parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName = 'VALUE')]
            [ValidateRange(0, [double]::MaxValue)]
            [double]$Value
            ,
            [Parameter(Mandatory, Position = 2, ParameterSetName = 'VALUE')]
            [ValidateRange(1, [double]::MaxValue)]
            [double]$MaxValue
            ,
            [Parameter(Mandatory = $false, Position = 3)]
            [Alias("BarSize", "Length")]
            [ValidateRange(10, 100)]
            [int]$BarLength = 20
            ,
            [Parameter(Mandatory = $false, Position = 4)]
            [ValidateSet("SimpleThin", "SimpleThick1", "SimpleThick2", "AdvancedThin1", "AdvancedThin2", "AdvancedThick")]
            [string]$BarView = "SimpleThin"
            ,
            [Parameter(Mandatory = $false, Position = 5)]
            [ValidateRange(50, 80)]
            [int]$GreenBorder = 60
            ,
            [Parameter(Mandatory = $false, Position = 6)]
            [ValidateRange(80, 90)]
            [int]$YellowBorder = 80
            ,
            [Parameter(Mandatory = $false)]
            [switch]$NoPercent
            ,
            [Parameter(Mandatory = $false)]
            [switch]$DrawBar
        )
        
        Begin
        {
            If ($PSBoundParameters.ContainsKey('VALUE'))
            {
                If ($Value -gt $MaxValue) { Throw "The [-Value] parameter cannot be greater than [-MaxValue]!" }
                Else { $Percent = $Value/$MaxValue * 100 -as [int] }
            }
            If ($YellowBorder -le $GreenBorder) { Throw "The [-YellowBorder] value must be greater than [-GreenBorder]!" }
            
            Function Set-BarView ($View)
            {
                Switch -exact ($View)
                {
                    "SimpleThin"    { $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = "-"; Break }
                    "SimpleThick1"  { $GreenChar = [char]9608; $YellowChar = [char]9608; $RedChar = [char]9608; $EmptyChar = "-"; Break }
                    "SimpleThick2"  { $GreenChar = [char]9612; $YellowChar = [char]9612; $RedChar = [char]9612; $EmptyChar = "-"; Break }
                    "AdvancedThin1" { $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = [char]9476; Break }
                    "AdvancedThin2" { $GreenChar = [char]9642; $YellowChar = [char]9642; $RedChar = [char]9642; $EmptyChar = [char]9643; Break }
                    "AdvancedThick" { $GreenChar = [char]9617; $YellowChar = [char]9618; $RedChar = [char]9619; $EmptyChar = [char]9482; Break }
                }
                $Properties = [ordered]@{ Char1 = $GreenChar; Char2 = $YellowChar; Char3 = $RedChar; Char4 = $EmptyChar }
                $Object = New-Object PSObject -Property $Properties
                $Object
            }
            
            $BarChars = Set-BarView -View $BarView
            $Bar = $null
            
            Function Draw-Bar
            {
                Param ([Parameter(Mandatory)][string]$Char, [Parameter(Mandatory = $false)][string]$Color = 'White', [Parameter(Mandatory = $false)][boolean]$Draw)
                If ($Draw) { Write-Host -NoNewline -ForegroundColor ([System.ConsoleColor]$Color) $Char }
                Else { return $Char }
            }
        }
        
        Process
        {
            If ($NoPercent) { $Bar += Draw-Bar -Char "[ " -Draw $DrawBar }
            Else {
                If ($Percent -eq 100) { $Bar += Draw-Bar -Char "$Percent% [ " -Draw $DrawBar }
                ElseIf ($Percent -ge 10) { $Bar += Draw-Bar -Char " $Percent% [ " -Draw $DrawBar }
                Else { $Bar += Draw-Bar -Char "  $Percent% [ " -Draw $DrawBar }
            }
            For ($i = 1; $i -le ($BarValue = ([Math]::Round($Percent * $BarLength / 100))); $i++)
            {
                If ($i -le ($GreenBorder * $BarLength / 100)) { $Bar += Draw-Bar -Char ($BarChars.Char1) -Color 'DarkGreen' -Draw $DrawBar }
                ElseIf ($i -le ($YellowBorder * $BarLength / 100)) { $Bar += Draw-Bar -Char ($BarChars.Char2) -Color 'Yellow' -Draw $DrawBar }
                Else { $Bar += Draw-Bar -Char ($BarChars.Char3) -Color 'Red' -Draw $DrawBar }
            }
            For ($i = 1; $i -le ($EmptyValue = $BarLength - $BarValue); $i++) { $Bar += Draw-Bar -Char ($BarChars.Char4) -Draw $DrawBar }
            $Bar += Draw-Bar -Char " ]" -Draw $DrawBar
        }
        End { If (!$DrawBar) { return $Bar } }
    }

    function Get-PrismCentralTaskStatus {
        param (
            [Parameter(Mandatory)]
            $task,
            
            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]
            $credential,

            [parameter(mandatory = $true)]
            [String]
            $cluster
        )

        $url = "https://$($cluster):9440/api/nutanix/v3/tasks/$task"
        $method = "GET"
        
        Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
        $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
                $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 2,$Host.UI.RawUI.CursorPosition.Y
                Sleep 5
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.status -ne "running") 
                {
                    if ($taskDetails.status -ne "succeeded") 
                    {
                        Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) failed with the following status and error code : $($taskDetails.status) : $($taskDetails.progress_message)" -ForegroundColor Yellow
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
            Write-Host ""
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            if ($taskDetails.status -ine "succeeded") {
                Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) status is $($taskDetails.status): $($taskDetails.progress_message)" -ForegroundColor Yellow
            } else {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
                Write-Host ""
                Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
            }
        }
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    #initialize variables
    #misc variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all entries.  This is what will be exported to csv
    [System.Collections.ArrayList]$myvarClustersResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarAlertPolicy = New-Object System.Collections.ArrayList($null)
    $api_server = $prism
    $api_server_port = "9440"
    $length = 200
#endregion


#region parameters validation
    #let's initialize parameters if they haven't been specified
    if ((!$get) -and !($acknowledge) -and !($resolve)) {throw "You must specify either get, acknowledge or resolve!"}
    if ($acknowledge -and $resolve) {throw "You must specify either acknowledge or resolve but not both!"}
    if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
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

    #region get clusters using inline pagination
    Write-Host "$(get-date) [INFO] Retrieving list of clusters managed by Prism Central..." -ForegroundColor Green
    $content = @{
        kind = "cluster";
        offset = 0;
        length = $length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    $url = "https://{0}:{1}/api/nutanix/v3/clusters/list" -f $api_server,$api_server_port
    $method = "POST"

    Do {
        try {
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
                if ($entity.status.resources.nodes.hypervisor_server_list) {
                    $myvarClusterInfo = [ordered]@{
                        "name" = $entity.status.name;
                        "uuid" = $entity.metadata.uuid;
                        "nos_version" = $entity.status.resources.config.software_map.NOS.version;
                        "redundancy_factor" = $entity.status.resources.config.redundancy_factor;
                        "domain_awareness_level" = $entity.status.resources.config.domain_awareness_level;
                        "is_long_term_support" = $entity.status.resources.config.build.is_long_term_support;
                        "timezone" = $entity.status.resources.config.timezone;
                        "external_ip" = $entity.status.resources.network.external_ip;
                        "hypervisor" = $entity.status.resources.nodes.hypervisor_server_list.type | Select-Object -Unique
                    }
                    #store the results for this entity in our overall result variable
                    $myvarClustersResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
                }
            }

            #prepare the json payload for the next batch of entities/response
            $content.offset = $content.offset + $content.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            Throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
    }
    While ($resp.metadata.length -eq $length)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarClustersResults
    }
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved clusters list from $prism!" -ForegroundColor Cyan
    #endregion get clusters

    #region get alert policy
    $api_server_endpoint = "/api/nutanix/v3/groups"
    $alert_policy_url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
    $content = @{
        "entity_type" = "alert_check_schema";
        "group_member_attributes" = @(
            @{"attribute" = "alert_uid"};
            @{"attribute" = "kb_num_list"});
        "query_name" = "prism:AlertPolicyGroupsModel";
    }
    $alert_policy_payload = (ConvertTo-Json $content -Depth 4)
    $alert_policy = Invoke-PrismAPICall -method 'POST' -url $alert_policy_url -payload $alert_policy_payload -credential $prismCredentials

    Foreach ($entry in $alert_policy.group_results.entity_results)
    {
        if (($entry.data | where {$_.name -eq "alert_uid"}).values.values -and ($entry.data | where {$_.name -eq "kb_num_list"}).values.values)
        {
            $alert_policy_info = [ordered]@{
                "alert_id" = ($entry.data | where {$_.name -eq "alert_uid"}).values.values;
                "kb_id" = ($entry.data | where {$_.name -eq "kb_num_list"}).values.values;
            }
            $myvarAlertPolicy.Add((New-Object PSObject -Property $alert_policy_info)) | Out-Null
        }
    }
    #endregion get alert policy

    #! -get
    #region -get
    if ($get) 
    {
        #region get alerts using inline pagination
        Write-Host "$(Get-Date) [INFO] Getting alerts from $prism..." -ForegroundColor Green
        $filter = "resolved!=true"
        if ($severity) {$filter += ";severity==$($severity)"}
        $content = @{
            kind = "alert";
            length = 500;
            filter = $filter
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        $url = "https://{0}:{1}/api/nutanix/v3/alerts/list" -f $api_server,$api_server_port
        $method = "POST"

        Do {
            try {
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

                if ($resp.entities.count -eq 0) {
                    Write-Host "$(get-date) [WARNING] There are no active alerts of the specified type." -ForegroundColor Yellow
                } else {
                    ForEach ($alert in $resp.entities) {
                        #substituting parameter values in the default message (as this varies for every alert)
                        $alert_message = $alert.status.resources.default_message
                        $alert.status.resources.default_message | Select-String -Pattern "{(.*?)}" -AllMatches | % {$_.Matches} | % {$alert_message = $alert_message -replace $_.Groups[0].Value, $alert.status.resources.parameters.$($_.Groups[1].Value).$((Get-Member -InputObject $alert.status.resources.parameters.$($_.Groups[1].Value) -MemberType NoteProperty).Name)}
                        
                        $kb_id = ($myvarAlertPolicy | where {$_.alert_id -eq $alert.status.resources.type}).kb_id
                        if ($kb_id)
                        {
                            $kb_url = "https://portal.nutanix.com/kb/{0}" -f $kb_id
                        }
                        else 
                        {
                            $kb_url = ""  
                        }

                        #populating the details we want to capture for each alert
                        $myvarAlert = [ordered]@{
                            "type" = $alert.status.resources.type;
                            "acknowledged" = $alert.status.resources.acknowledged_status.is_true;
                            "latest_occurrence_time" = $alert.status.resources.latest_occurrence_time;
                            "severity" = $alert.status.resources.severity;
                            "creation_time" = $alert.status.resources.creation_time;
                            "title" = $alert.status.resources.title;
                            "alert_message" = $alert_message;
                            "possible_cause" = $alert.status.resources.possible_cause_list.cause_list -join ',';
                            "resolution" = $alert.status.resources.possible_cause_list.resolution_list -join ',';
                            "source_entity_type" = $alert.status.resources.source_entity.entity.type;
                            "source_entity_name" = $alert.status.resources.source_entity.entity.name;
                            "uuid" = $alert.metadata.uuid;
                            "cluster_uuid" = $alert.status.resources.parameters.cluster_uuid.string_value;
                            "cluster_name" = ($myvarClustersResults | Where {$_.uuid -eq $alert.status.resources.parameters.cluster_uuid.string_value}).name;
                            "nutanix_kb" = $kb_url;
                        }
                        #adding the captured details to the final result
                        $myvarResults.Add((New-Object PSObject -Property $myvarAlert)) | Out-Null
                    }
                }

                #prepare the json payload for the next batch of entities/response
                $content.offset = $content.offset + $content.length
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            catch {
                $saved_error = $_.Exception.Message
                Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                Throw "$(get-date) [ERROR] $saved_error"
            }
            finally {
                #add any last words here; this gets processed no matter what
            }
        }
        While ($resp.metadata.length -eq 500)
        #endregion get alerts

        if ($csv) 
        {
            Write-Host "$(Get-Date) [INFO] Exporting results to $csv..." -ForegroundColor Green
            $myvarResults | export-csv -NoTypeInformation $csv -Delimiter ";"
        } 
        else 
        {
            $myvarResults | Sort-Object -Property latest_occurrence_time
        }
    }
    #endregion

    #! -acknowledge
    #region -acknowledge
    if ($acknowledge) 
    {
        #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/alerts/action/ACKNOWLEDGE"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
        $method = "POST"
        $length = 500

        if (!$uuid) 
        {
            #retrieve alerts (as if -get)
            $filter = "resolved!=true"
            if ($severity) {$filter += ";severity==$($severity)"}
            $content = @{
                kind = "alert";
                length = 500;
                filter = $filter
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $url_get = "https://{0}:{1}/api/nutanix/v3/alerts/list" -f $api_server,$api_server_port
            $method_get = "POST"
            
            $resp = Invoke-PrismAPICall -method $method_get -url $url_get -payload $payload -credential $prismCredentials
            $uuid_list = @()
            Foreach ($alert in $resp.entities) 
            {
                if ($severity) 
                {
                    if ($alert.status.resources.severity -eq $severity) { $uuid_list += $alert.metadata.uuid }
                } 
                else 
                {
                    $uuid_list += $alert.metadata.uuid
                }
            }
            $content = @{
                alert_uuid_list = @($uuid_list)
            }
        } 
        else 
        {
            $content = @{
                alert_uuid_list = @($uuid)
            }
        }
        
        $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make the api call
        Write-Host "$(Get-Date) [INFO] Acknowledging alert $uuid in $prism..." -ForegroundColor Green
        try 
        {
            $ack_task_uuid = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            $task_status = Get-PrismCentralTaskStatus -task $ack_task_uuid.task_uuid -credential $prismCredentials -cluster $prism
        }
        catch 
        {
            $saved_error = $_.Exception.Message
            throw "$(get-date) [ERROR] $saved_error"
        }
        finally 
        {
        }
        #endregion
    }
    #endregion

    #! -resolve
    #region -resolve
    if ($resolve) 
    {
        #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/alerts/action/RESOLVE"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
        $method = "POST"
        $length = 500
        
        if (!$uuid) 
        {
            #retrieve alerts (as if -get)
            $filter = "resolved!=true"
            if ($severity) {$filter += ";severity==$($severity)"}
            $content = @{
                kind = "alert";
                length = 500;
                filter = $filter
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $url_get = "https://{0}:{1}/api/nutanix/v3/alerts/list" -f $api_server,$api_server_port
            $method_get = "POST"
            
            $resp = Invoke-PrismAPICall -method $method_get -url $url_get -payload $payload -credential $prismCredentials
            $uuid_list = @()
            Foreach ($alert in $resp.entities) 
            {
                if ($severity) 
                {
                    if ($alert.status.resources.severity -eq $severity) { $uuid_list += $alert.metadata.uuid }
                } 
                else 
                {
                    $uuid_list += $alert.metadata.uuid
                }
            }
            $content = @{
                alert_uuid_list = @($uuid_list)
            }
        } 
        else 
        {
            $content = @{
                alert_uuid_list = @($uuid)
            }
        }

        $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make the api call
        Write-Host "$(Get-Date) [INFO] Resolving alert $uuid in $prism..." -ForegroundColor Green
        try 
        {
            $resolve_task_uuid = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            $task_status = Get-PrismCentralTaskStatus -task $resolve_task_uuid.task_uuid -credential $prismCredentials -cluster $prism
        }
        catch 
        {
            $saved_error = $_.Exception.Message
            Throw "$(get-date) [ERROR] $saved_error"
        }
        finally 
        {
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable get -ErrorAction SilentlyContinue
    Remove-Variable acknowledge -ErrorAction SilentlyContinue
    Remove-Variable resolve -ErrorAction SilentlyContinue
    Remove-Variable severity -ErrorAction SilentlyContinue
    Remove-Variable uuid -ErrorAction SilentlyContinue
    Remove-Variable csv -ErrorAction SilentlyContinue
    Remove-Variable api_server -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion