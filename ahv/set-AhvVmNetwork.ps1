<#
.SYNOPSIS
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network using v4 API for reads, v3/v2 for writes.
.DESCRIPTION
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
  Uses Nutanix Prism Central v4 APIs for read operations (VMM for VMs, Networking for subnets)
  and v3/v2 APIs for write operations (v4 VM PUT with ETag has known 412 PRECONDITION_FAILED issue).
.PARAMETER help
  Displays a help message.
.PARAMETER history
  Displays a release history for this script.
.PARAMETER debugme
  Turns on debug output.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER vms
  One or more vm name(s) (comma separated).
.PARAMETER ahv_network
  AHV network name you want to connect the specified vm(s) to. Can't be used with -vpc_subnet.
.PARAMETER vpc_subnet
  VPC subnet name you want to connect the specified vm(s) to. Can't be used with -ahv_network.
.PARAMETER skiptaskstatuscheck
  Do not check each vm update task status.
.PARAMETER dontkeepip
  When attaching to a vpc subnet, don't try to preserve the ip configuration.
.EXAMPLE
.\set-AhvVmNetwork.ps1 -prismcentral ntnxc1.local -vms myvm -ahv_network mynetwork
Connect myvm to the mynetwork AHV network:
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 30th 2026 - Hybrid: v4 reads (VMM, Networking), v3/v2 writes (v4 VM PUT ETag issue)
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
        [parameter(mandatory = $false)] $vms,
        [parameter(mandatory = $false)] [string]$ahv_network,
        [parameter(mandatory = $false)] [string]$vpc_subnet,
        [parameter(mandatory = $false)] [switch]$skiptaskstatuscheck,
        [parameter(mandatory = $false)] [switch]$dontkeepip
    )
#endregion


#region prepwork

    $myvar_history_text = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/30/2026 sb   Hybrid: v4 reads (VMM, Networking, Prism), v3/v2 writes (v4 VM PUT ETag 412 issue)
10/30/2026 sb   Attempted full v4 but hit v4 VM PUT ETag PRECONDITION_FAILED (PLAT-10005)
10/30/2026 sb   Migrated reads to Prism Central v4 API (VMM for VMs, Networking for subnets); writes use v3/v2 API
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
04/27/2021 sb   Initial release.
06/24/2022 sb   Adding vpc_subnet option.  Replacing external module dependency with local functions.
################################################################################
'@
    $myvar_script_name = ".\set-AhvVmNetwork.ps1"

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
    if ($History) {$myvar_history_text; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $false)]
            [ValidateSet("POST","GET","DELETE","PUT","PATCH")]
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

    function Invoke-PrismAPICallWithRetry {
        param (
            [parameter(mandatory = $true)]
            [hashtable]$InvokeParams,

            [parameter(mandatory = $false)]
            [int]$MaxRetries = 3,

            [parameter(mandatory = $false)]
            [string]$RequestId = (New-Guid).ToString()
        )
        $attempt = 0
        $delayMs = 1000
        # For PS7+, add SSL certificate bypass parameters and capture headers
        $sslParams = @{
            SkipCertificateCheck = $true
            SslProtocol          = 'Tls12'
        }
        while ($true) {
            try {
                $respHeaders = $null
                # Add ResponseHeadersVariable to capture headers
                $invokeParamsWithHeaders = $InvokeParams.Clone()
                $invokeParamsWithHeaders.ResponseHeadersVariable = 'respHeaders'
                $response = Invoke-RestMethod @invokeParamsWithHeaders @sslParams
                # Add headers to response object (ETag is array, get first element)
                $etagValue = $respHeaders.ETag
                if ($etagValue -is [array]) { $etagValue = $etagValue[0] }
                $response | Add-Member -MemberType NoteProperty -Name 'ResponseHeaders' -Value $respHeaders -Force
                $response | Add-Member -MemberType NoteProperty -Name 'ResponseETag' -Value $etagValue -Force
                return $response
            }
            catch {
                $statusCode = $null
                if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                    try { $statusCode = [int][System.Net.HttpStatusCode]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
                }
                if (($statusCode -in 429, 503) -and ($attempt -lt $MaxRetries)) {
                    $attempt++
                    Write-Host "$(Get-Date) [WARN] Transient error (HTTP $statusCode), retry $attempt/$MaxRetries in ${delayMs}ms" -ForegroundColor Yellow
                    Start-Sleep -Milliseconds $delayMs
                    $delayMs = [Math]::Min($delayMs * 2, 30000)
                    continue
                }
                if ($statusCode -eq 412) {
                    Write-Host "$(Get-Date) [ERROR] Precondition failed (ETag mismatch). The resource was modified by another process." -ForegroundColor Red
                    throw "ETag mismatch - resource was modified by another process. Please retry."
                }
                if ($statusCode -eq 428) {
                    Write-Host "$(Get-Date) [ERROR] Precondition required. If-Match header is mandatory for mutations." -ForegroundColor Red
                    throw "If-Match header required for this mutation."
                }
                Write-Host "$(Get-Date) [ERROR] API call failed: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }
        }
    }

    function Invoke-PrismV4Get {
        param (
            [parameter(mandatory = $true)]
            [string]$Url,

            [parameter(mandatory = $true)]
            [hashtable]$Headers,

            [parameter(mandatory = $false)]
            [int]$TimeoutSec = 60
        )
        $invokeParams = @{
            Uri        = $Url
            Method     = 'GET'
            Headers    = $Headers
            TimeoutSec = $TimeoutSec
        }
        return Invoke-PrismAPICallWithRetry -InvokeParams $invokeParams
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
            
            [parameter(mandatory = $false)]
            [System.Management.Automation.PSCredential]
            $credential,

            [parameter(mandatory = $false)]
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

    function Get-PrismTaskStatus {
        param (
            [Parameter(Mandatory)]
            $task,
            
            [parameter(mandatory = $false)]
            [System.Management.Automation.PSCredential]
            $credential,

            [parameter(mandatory = $false)]
            [String]
            $cluster
        )

        Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
        $method = "GET"
        $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Sleep 5
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                $method = "GET"
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.progress_status -ine "running") 
                {
                    if ($taskDetails.progress_status -ine "succeeded") 
                    {
                        Throw "$(Get-Date) [INFO] Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        }
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    $myvar_elapsed_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_api_server_port = "9440"
    $myvar_length = 100
#endregion


#region parameters validation
    if (!$prismcentral -or !$vms -or (!$ahv_network -and !$vpc_subnet)) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral, -vms, and either -ahv_network or -vpc_subnet!"
    }
    if ($ahv_network -and $vpc_subnet) {Throw "$(get-date) [ERROR] You can only specify an ahv_network OR a vpc_subnet but not both! Exiting."}

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

    # Build auth header for v4 API calls
    $pair = "$($prismCredentials.UserName):$($prismCredentials.GetNetworkCredential().Password)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $base64 = [Convert]::ToBase64String($bytes)
    $v4Headers = @{
        'Content-Type' = 'application/json'
        'Accept'       = 'application/json'
        'Authorization' = "Basic $base64"
    }
    $baseUri = "https://${prismcentral}:${myvar_api_server_port}/api"

    #assume vms is a list
    $myvar_vms = $vms.Split(",")
#endregion


#region processing

    if ($ahv_network)
    {#we're updating an ahv network (VLAN)

        Write-Host "$(Get-Date) [INFO] Mode: AHV Network (VLAN) - $ahv_network" -ForegroundColor Green

        #region get subnet details from v4 Networking API
            Write-Host "$(Get-Date) [INFO] Retrieving subnet information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $subnetFilter = [uri]::EscapeDataString("name eq '$ahv_network'")
            $subnetsUri = "${baseUri}/networking/v4.0/config/subnets?`$filter=$subnetFilter"
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $subnetsUri" -ForegroundColor White }
            
            $resp = Invoke-PrismV4Get -Url $subnetsUri -Headers $v4Headers
            
            if (-not $resp.data -or $resp.data.Count -eq 0) {
                Write-Host "$(Get-Date) [ERROR] Network '$ahv_network' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                exit 1
            }
            $subnet = $resp.data[0]
            $subnetExtId = $subnet.extId
            $subnetName = $subnet.name
            $subnetType = $subnet.subnetType
            Write-Host "$(Get-Date) [SUCCESS] Found subnet '$subnetName' (extId: $subnetExtId, type: $subnetType)" -ForegroundColor Cyan
        #endregion

        #region get vms from v4 VMM API
            Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $page = 0
            $allVms = @()
            
            Do 
            {
                try 
                {
                    $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$myvar_length"
                    if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $vmsUri" -ForegroundColor White }
                    
                    $resp = Invoke-PrismV4Get -Url $vmsUri -Headers $v4Headers
                    
                    if ($resp.data) {
                        $allVms += $resp.data
                    }
                    
                    if (-not $resp.data -or (@($resp.data)).Count -eq 0) { break }
                    $page++
                }
                catch 
                {
                    Write-Host "$(Get-Date) [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                    Throw "$(get-date) [ERROR] $($_.Exception.Message)"
                }
            }
            While ($resp.data -and $resp.data.Count -eq $myvar_length)

            Write-Host "$(Get-Date) [SUCCESS] Retrieved $($allVms.Count) VMs from Prism Central" -ForegroundColor Cyan

            # Find specified VMs
            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($vmName in $myvar_vms) {
                $vm = $allVms | Where-Object { $_.name -eq $vmName }
                if (-not $vm) {
                    Write-Host "$(Get-Date) [ERROR] VM '$vmName' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                    exit 1
                }
                $myvar_vms_details.Add($vm) | Out-Null
                Write-Host "$(Get-Date) [DATA] Found VM '$vmName' (extId: $($vm.extId))" -ForegroundColor White
            }
        #endregion

        #region process each vm - update NIC using v3 API (Prism Element v2)
            ForEach ($vm in $myvar_vms_details)
            {
                Write-Host "$(Get-Date) [INFO] Connecting VM '$($vm.name)' to network '$subnetName'..." -ForegroundColor Green
                
                # For VLAN networks, we need to use the Prism Element v2 API
                # Find which cluster the VM is on
                $clusterExtId = $vm.cluster.extId
                
                # Get cluster external IP from v3 clusters API
                Write-Host "$(Get-Date) [INFO] Retrieving cluster external IP for VM cluster..." -ForegroundColor Green
                $v3ClustersUrl = "https://${prismcentral}:${myvar_api_server_port}/api/nutanix/v3/clusters/list"
                $v3Payload = '{"kind":"cluster","offset":0,"length":100}'
                $clusterResp = Invoke-PrismAPICall -method "POST" -url $v3ClustersUrl -payload $v3Payload -credential $prismCredentials
                
                $clusterIp = $null
                if ($clusterResp.entities) {
                    foreach ($cluster in $clusterResp.entities) {
                        if ($cluster.metadata.uuid -eq $clusterExtId) {
                            $clusterIp = $cluster.spec.resources.network.external_ip
                            break
                        }
                    }
                }
                
                if (-not $clusterIp) {
                    Write-Host "$(Get-Date) [ERROR] Could not find external IP for cluster $clusterExtId" -ForegroundColor Red
                    exit 1
                }
                
                Write-Host "$(Get-Date) [INFO] Cluster IP: $clusterIp" -ForegroundColor Green
                
                # Get VM details from Prism Element v2 API (for NIC update)
                $pePort = $myvar_api_server_port
                $peUrl = "https://" + $clusterIp + ":" + $pePort + "/PrismGateway/services/rest/v2.0/vms/?include_vm_nic_config=true&filterCriteria=vm_uuid==" + $vm.extId
                $peResp = Invoke-PrismAPICall -method "GET" -url $peUrl -credential $prismCredentials
                
                if (-not $peResp.entities -or $peResp.entities.Count -eq 0) {
                    Write-Host "$(Get-Date) [ERROR] VM not found on Prism Element $clusterIp" -ForegroundColor Red
                    exit 1
                }
                
                $peVm = $peResp.entities[0]
                $peVmUuid = $peVm.uuid
                
                # Get network UUID from Prism Element v2 API
                $netUrl = "https://" + $clusterIp + ":" + $pePort + "/PrismGateway/services/rest/v2.0/networks/"
                $netResp = Invoke-PrismAPICall -method "GET" -url $netUrl -credential $prismCredentials
                
                $netUuid = $null
                if ($netResp.entities) {
                    foreach ($net in $netResp.entities) {
                        if ($net.name -eq $subnetName) {
                            $netUuid = $net.uuid
                            break
                        }
                    }
                }
                
                if (-not $netUuid) {
                    Write-Host "$(Get-Date) [ERROR] Network '$subnetName' not found on Prism Element $clusterIp" -ForegroundColor Red
                    exit 1
                }
                
                Write-Host "$(Get-Date) [INFO] Network UUID: $netUuid" -ForegroundColor Green
                
                # Update NIC using Prism Element v2 API
                $nicMac = $peVm.vm_nics[0].mac_address
                $nicMacUrl = $nicMac -replace ":","%3A"
                
                $nicPayload = @{
                    nic_spec = @{
                        is_connected = $true
                        network_uuid = $netUuid
                    }
                }
                $nicPayloadJson = $nicPayload | ConvertTo-Json -Depth 9
                
                $updateUrl = "https://" + $clusterIp + ":" + $pePort + "/PrismGateway/services/rest/v2.0/vms/" + $peVmUuid + "/nics/" + $nicMacUrl
                $updateResp = Invoke-PrismAPICall -method "PUT" -url $updateUrl -credential $prismCredentials -payload $nicPayloadJson
                
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested connection of VM '$($vm.name)' to network '$subnetName'!" -ForegroundColor Cyan
                Write-Host "$(Get-Date) [INFO] Task UUID: $($updateResp.task_uuid)" -ForegroundColor Green
                
                # Task status check
                if (-not $skiptaskstatuscheck) {
                    Get-PrismTaskStatus -task $updateResp.task_uuid -credential $prismCredentials -cluster $clusterIp
                }
            }
        #endregion
    }

    if ($vpc_subnet)
    {#we're attaching a vnic to a subnet in a vpc (OVERLAY)

        Write-Host "$(Get-Date) [INFO] Mode: VPC Subnet (OVERLAY) - $vpc_subnet" -ForegroundColor Green

        #region get subnet details from v4 Networking API
            Write-Host "$(Get-Date) [INFO] Retrieving VPC subnet information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $subnetFilter = [uri]::EscapeDataString("name eq '$vpc_subnet'")
            $subnetsUri = "${baseUri}/networking/v4.0/config/subnets?`$filter=$subnetFilter"
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $subnetsUri" -ForegroundColor White }
            
            $resp = Invoke-PrismV4Get -Url $subnetsUri -Headers $v4Headers
            
            if (-not $resp.data -or $resp.data.Count -eq 0) {
                Write-Host "$(Get-Date) [ERROR] VPC subnet '$vpc_subnet' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                exit 1
            }
            $subnet = $resp.data[0]
            $subnetExtId = $subnet.extId
            $subnetName = $subnet.name
            $subnetType = $subnet.subnetType
            $vpcRef = $subnet.vpcReference
            Write-Host "$(Get-Date) [SUCCESS] Found VPC subnet '$subnetName' (extId: $subnetExtId, type: $subnetType, VPC: $vpcRef)" -ForegroundColor Cyan
            
            if ($subnetType -ne "OVERLAY") {
                Write-Host "$(Get-Date) [WARNING] Subnet '$subnetName' is not an OVERLAY (VPC) subnet (type: $subnetType)" -ForegroundColor Yellow
            }
        #endregion

        #region get vms from v4 VMM API
            Write-Host "$(Get-Date) [INFO] Retrieving VM information from Prism Central $($prismcentral) (v4 API)..." -ForegroundColor Green
            $page = 0
            $allVms = @()
            
            Do 
            {
                try 
                {
                    $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$myvar_length"
                    if ($debugme) { Write-Host "$(Get-Date) [DEBUG] URL: $vmsUri" -ForegroundColor White }
                    
                    $resp = Invoke-PrismV4Get -Url $vmsUri -Headers $v4Headers
                    
                    if ($resp.data) {
                        $allVms += $resp.data
                    }
                    
                    if (-not $resp.data -or (@($resp.data)).Count -eq 0) { break }
                    $page++
                }
                catch 
                {
                    Write-Host "$(Get-Date) [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                    Throw "$(get-date) [ERROR] $($_.Exception.Message)"
                }
            }
            While ($resp.data -and $resp.data.Count -eq $myvar_length)

            Write-Host "$(Get-Date) [SUCCESS] Retrieved $($allVms.Count) VMs from Prism Central" -ForegroundColor Cyan

            # Find specified VMs
            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($vmName in $myvar_vms) {
                $vm = $allVms | Where-Object { $_.name -eq $vmName }
                if (-not $vm) {
                    Write-Host "$(Get-Date) [ERROR] VM '$vmName' not found on Prism Central $($prismcentral)!" -ForegroundColor Red
                    exit 1
                }
                $myvar_vms_details.Add($vm) | Out-Null
                Write-Host "$(Get-Date) [DATA] Found VM '$vmName' (extId: $($vm.extId))" -ForegroundColor White
            }
        #endregion

        #region process each vm - use v3 API for VPC subnet attachment
            ForEach ($vm in $myvar_vms_details)
            {
                Write-Host "$(Get-Date) [INFO] Processing VM '$($vm.name)' for VPC subnet '$subnetName'..." -ForegroundColor Green
                
                # Use v3 API for VPC subnet operations (as in original script)
                $content = @{
                    kind = "vm";
                    offset = 0;
                    length = $myvar_length
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                $v3VmsUrl = "https://${prismcentral}:${myvar_api_server_port}/api/nutanix/v3/vms/list"
                $method = "POST"
                
                $v3Resp = Invoke-PrismAPICall -method $method -url $v3VmsUrl -payload $payload -credential $prismCredentials
                
                $v3Vm = $null
                if ($v3Resp.entities) {
                    foreach ($entity in $v3Resp.entities) {
                        if ($entity.metadata.uuid -eq $vm.extId) {
                            $v3Vm = $entity
                            break
                        }
                    }
                }
                
                if (-not $v3Vm) {
                    Write-Host "$(Get-Date) [ERROR] VM not found in v3 API" -ForegroundColor Red
                    exit 1
                }
                
                # Get VPC subnet details from v3 API
                $subnetContent = @{
                    kind = "subnet";
                    offset = 0;
                    length = $myvar_length
                }
                $subnetPayload = (ConvertTo-Json $subnetContent -Depth 4)
                $v3SubnetsUrl = "https://${prismcentral}:${myvar_api_server_port}/api/nutanix/v3/subnets/list"
                $subnetResp = Invoke-PrismAPICall -method "POST" -url $v3SubnetsUrl -payload $subnetPayload -credential $prismCredentials
                
                $v3Subnet = $null
                if ($subnetResp.entities) {
                    foreach ($entity in $subnetResp.entities) {
                        if ($entity.spec.name -eq $subnetName) {
                            $v3Subnet = $entity
                            break
                        }
                    }
                }
                
                if (-not $v3Subnet) {
                    Write-Host "$(Get-Date) [ERROR] VPC subnet '$subnetName' not found in v3 API" -ForegroundColor Red
                    exit 1
                }
                
                Write-Host "$(Get-Date) [INFO] Removing first vnic from vm $($vm.name)..." -ForegroundColor Green
                
                $v3Vm.PSObject.Properties.Remove('status') #removing status section from the vm payload
                if ($v3Vm.spec.resources.nic_list[0].subnet_reference.uuid -eq $v3Subnet.metadata.uuid)
                {
                    Write-Host "$(Get-Date) [WARNING] vnic0 on vm $($v3Vm.spec.name) is already connected to subnet $($vpc_subnet)! Skipping..." -ForegroundColor Yellow
                    Continue
                }
                $v3Vm_nic0_config = $v3Vm.spec.resources.nic_list[0] #saving vnic0 configuration
                if ($v3Vm.spec.resources.nic_list.count -eq 0)
                {#there are no vnics on this vm
                    Write-Host "$(Get-Date) [WARNING] There is no vnic to update on vm $($v3Vm.spec.name)! Skipping..." -ForegroundColor Yellow
                    Continue
                }
                elseif ($v3Vm.spec.resources.nic_list.count -gt 1)
                {#we have more than 1 vnic
                    $v3Vm.spec.resources.nic_list[0] = "" #removing existing vnic0
                }
                else 
                {
                    $v3Vm.spec.resources.nic_list = @()
                }
                $v3Vm.metadata.spec_version += 1 #increasing spec version
                $v3UpdateUrl = "https://${prismcentral}:${myvar_api_server_port}/api/nutanix/v3/vms/$($v3Vm.metadata.uuid)"
                $v3Method = "PUT"
                $v3Payload = (ConvertTo-Json $v3Vm -Depth 9)
                $v3UpdateResp = Invoke-PrismAPICall -method $v3Method -url $v3UpdateUrl -credential $prismCredentials -payload $v3Payload
                
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested removal of vnic0 from vm $($v3Vm.spec.name)!" -ForegroundColor Cyan
                Get-PrismCentralTaskStatus -task $v3UpdateResp.status.execution_context.task_uuid -credential $prismCredentials -cluster $prismcentral
                
                Write-Host "$(Get-Date) [INFO] Connecting vm $($v3Vm.spec.name) to subnet $($vpc_subnet)..." -ForegroundColor Green

                $v3Vm_nic0_config.subnet_reference.name = $v3Subnet.spec.name #updating subnet name reference
                $v3Vm_nic0_config.subnet_reference.uuid = $v3Subnet.metadata.uuid #updating subnet uuid reference
                $v3Vm_nic0_config.PSObject.Properties.Remove('uuid') #removing uuid (this is a new vnic after all)
                
                # Get fresh VM payload
                $v3GetUrl = "https://${prismcentral}:${myvar_api_server_port}/api/nutanix/v3/vms/$($v3Vm.metadata.uuid)"
                $v3GetResp = Invoke-PrismAPICall -method "GET" -url $v3GetUrl -credential $prismCredentials
                $v3Vm_payload_without_vnic0 = $v3GetResp
                $v3Vm_payload_without_vnic0.PSObject.Properties.Remove('status') #removing status section from the vm payload
                $v3Vm_payload_without_vnic0.metadata.spec_version += 1 #increasing spec version
                
                if ($dontkeepip)
                {#remove the ip configuration
                    $v3Vm_nic0_config.ip_endpoint_list = @()
                }
                $v3Vm_payload_without_vnic0.spec.resources.nic_list += $v3Vm_nic0_config #adding new vnic connected to vpc subnet
                $v3Payload2 = (ConvertTo-Json $v3Vm_payload_without_vnic0 -Depth 9)
                $v3UpdateResp2 = Invoke-PrismAPICall -method "PUT" -url $v3GetUrl -credential $prismCredentials -payload $v3Payload2
                
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested connection of vm $($v3Vm.spec.name) to subnet $($vpc_subnet)!" -ForegroundColor Cyan
                if (-not $skiptaskstatuscheck)
                {
                    Get-PrismCentralTaskStatus -task $v3UpdateResp2.status.execution_context.task_uuid -credential $prismCredentials -cluster $prismcentral
                }
            }
        #endregion
    }
#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvar_elapsed_time.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vms -ErrorAction SilentlyContinue
    Remove-Variable ahv_network -ErrorAction SilentlyContinue
    Remove-Variable vpc_subnet -ErrorAction SilentlyContinue
    Remove-Variable skiptaskstatuscheck -ErrorAction SilentlyContinue
    Remove-Variable dontkeepip -ErrorAction SilentlyContinue
    Remove-Variable myvar_api_server_port -ErrorAction SilentlyContinue
    Remove-Variable myvar_length -ErrorAction SilentlyContinue
    Remove-Variable v4Headers -ErrorAction SilentlyContinue
    Remove-Variable baseUri -ErrorAction SilentlyContinue
#endregion