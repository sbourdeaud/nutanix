#Requires -Version 6.0
<#
.SYNOPSIS
  Returns the capacity runway for all clusters managed by Prism Central.
.DESCRIPTION
  Returns the capacity runway for all clusters managed by Prism Central by using the undocumented groups API endpoint.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER html
  Produces an html output in addition to console output.
.PARAMETER viewnow
  Means you want the script to open the html report in your default browser immediately after creation.
.PARAMETER dir
  Directory/path where to save the html report.  By default, it will be created in the current directory. Note that the name of the report is always capacity_report.html and that you can change this in the script variables section.
.PARAMETER influxdb
  Specifies you want to send data to influxdb server. You will need to configure the influxdb server URL and database instance in the variables section of this script.  The timeseries created by default is called capacity_runway.
.PARAMETER influxdbCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$influxdbCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER email
  Specifies that you want to send an email with the html report attached. This will require that you add smtp configuration in the variables section.
.PARAMETER emailCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$emailCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\get-CapacityRunway.ps1 -prism ntnxpc1.local
Grabs the capacity runway for all managed clusters from ntnxpc1.local:
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
        [parameter(mandatory = $false)] [string]$prism,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [switch]$html,
        [parameter(mandatory = $false)] [switch]$viewnow,
        [parameter(mandatory = $false)] [string]$dir,
        [parameter(mandatory = $false)] [switch]$influxdb,
        [parameter(mandatory = $false)] $influxdbCreds,
        [parameter(mandatory = $false)] [switch]$email,
        [parameter(mandatory = $false)] $emailCreds
    )
#endregion parameters


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
06/19/2015 sb   Initial release.
################################################################################
'@
    $myvar_ScriptName = ".\get-CapacityRunway.ps1"

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
    if ($PSVersionTable.PSVersion.Major -lt 6) {throw "$(get-date) [ERROR] This script requires PowerShell 6.0 or above!"}

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
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    $myvar_ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvar_capacity_results = New-Object System.Collections.ArrayList($null)
    
    #* html configuration
    $myvar_desired_runway = 30

    #* email configuration   
    $myvar_smtp_server = "smtp.office365.com"
    $myvar_smtp_server_port = 587
    $myvar_smtp_to = "stephane.bourdeaud@nutanix.com"
    
    #* influxdb configuration 
    $myvar_influxdb_url = "http://localhost:8086"
    $myvar_influxdb_database = "prism"
#endregion


#region parameters validation
    if (!$prism) {
        Throw "$(Get-Date) [ERROR] You must specify -prism!"
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

    if (!$influxdbCreds -and $influxdb) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
       $influxdbCredentials = Get-Credential -Message "Please enter InfluxDB credentials"
    } 
    elseif ($influxdb) 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {#Get-CustomCredentials
            $influxdbCredentials = Get-CustomCredentials -credname $influxdbCreds -ErrorAction Stop
            $username = $influxdbCredentials.UserName
            $InfluxDBSecurePassword = $influxdbCredentials.Password
        }
        catch 
        {#could not Get-CustomeCredentials, so Set-CustomCredentials
            Set-CustomCredentials -credname $influxdbCreds
            $influxdbCredentials = Get-CustomCredentials -credname $influxdbCreds -ErrorAction Stop
            $username = $influxdbCredentials.UserName
            $InfluxDBSecurePassword = $influxdbCredentials.Password
        }
        $influxdbCredentials = New-Object PSCredential $username, $InfluxDBSecurePassword
    }

    if (!$emailCreds -and $email)
    {#we want to send email
        $emailCredentials = Get-Credential -Message "Please enter email credentials"
    }
    elseif ($email) 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {#Get-CustomCredentials
            $emailCredentials = Get-CustomCredentials -credname $emailCreds -ErrorAction Stop
            $username = $emailCredentials.UserName
            $emailSecurePassword = $emailCredentials.Password
        }
        catch 
        {#could not Get-CustomeCredentials, so Set-CustomCredentials
            Set-CustomCredentials -credname $emailCreds
            $emailCredentials = Get-CustomCredentials -credname $emailCreds -ErrorAction Stop
            $username = $emailCredentials.UserName
            $emailSecurePassword = $emailCredentials.Password
        }
        $emailCredentials = New-Object PSCredential $username, $emailSecurePassword

        #make sure we'll use html
        $html = $true
    }

    if (!$dir)
    {#no report directory was specified, so we'll use the current directory
        $dir = Get-Location | Select-Object -ExpandProperty Path
    }

    if (!$dir.EndsWith("\")) 
    {#make sure given log path has a trailing \
        if ($IsMacOS -or $IsLinux)
        {#we are on Mac or Linux
            $dir += "/"
        }
        else 
        {#we are on Windows
            $dir += "\"
        }
    }
    if (Test-Path -path $dir)
    {#specified path exists
        $myvar_html_report_name = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvar_html_report_name += "$($prism)_capacity_report.html"
        $myvar_html_report_name = $dir + $myvar_html_report_name
    }
    else 
    {#specified path does not exist
        Write-Host "$(get-date) [ERROR] Specified log path $($dir) does not exist! Exiting." -ForegroundColor Red
        Exit 1
    }
#endregion


#region main processing	
    #* get data
    #region retrieve the information we need
        Write-Host "$(get-date) [INFO] Retrieving capacity runway values from $($prism)..." -ForegroundColor Green
        
        #configuring the API call
        $url = "https://$($prism):9440/api/nutanix/v3/groups"
        $method = "POST"
        $content = @{
            entity_type="cluster";
            group_member_sort_attribute="cluster_name";
            group_member_sort_order="ASCENDING";
            group_member_attributes=@(
                @{attribute="cluster_name"};
                @{attribute="capacity.runway"};
                @{attribute="capacity.cpu_runway"};
                @{attribute="capacity.memory_runway"};
                @{attribute="capacity.storage_runway"};
                @{attribute="version"};
                @{attribute="num_cpus"};
                @{attribute="memory_capacity_bytes"};
                @{attribute="disk_size_bytes"};
                @{attribute="num_vms"};
                @{attribute="cluster_uuid"}
            )
            query_name="prism:EBQueryModel";
            filter_criteria="feature_name==CAPACITY_FORECAST"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        
        #making the API call
        $myvar_capacity_runway_results = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
        
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved capacity runway values from $($prism)!" -ForegroundColor Cyan

        ForEach ($myvar_cluster in $myvar_capacity_runway_results.group_results)
        {
            ForEach ($entity in $myvar_cluster.entity_results)
            {
                $myvar_cluster_capacity_info = [ordered]@{
                    "cluster" = ($entity.data | Where-Object {$_.name -eq "cluster_name"}).values[0].values[0];
                    "capacity_runway" = if (($entity.data | Where-Object {$_.name -eq "capacity.runway"}).values) {($entity.data | Where-Object {$_.name -eq "capacity.runway"}).values[0].values[0]} else {"no_data"};
                    "cpu_runway" = if (($entity.data | Where-Object {$_.name -eq "capacity.runway"}).values) {($entity.data | Where-Object {$_.name -eq "capacity.cpu_runway"}).values[0].values[0]} else {"no_data"};
                    "memory_runway" = if (($entity.data | Where-Object {$_.name -eq "capacity.runway"}).values) {($entity.data | Where-Object {$_.name -eq "capacity.memory_runway"}).values[0].values[0]} else {"no_data"};
                    "storage_runway" = if (($entity.data | Where-Object {$_.name -eq "capacity.runway"}).values) {($entity.data | Where-Object {$_.name -eq "capacity.storage_runway"}).values[0].values[0]} else {"no_data"};
                    "aos_version" = ($entity.data | Where-Object {$_.name -eq "version"}).values[0].values[0];
                    "num_cpus" = ($entity.data | Where-Object {$_.name -eq "num_cpus"}).values[0].values[0];
                    "memory_capacity_bytes" = ($entity.data | Where-Object {$_.name -eq "memory_capacity_bytes"}).values[0].values[0];
                    "disk_size_bytes" = ($entity.data | Where-Object {$_.name -eq "memory_capacity_bytes"}).values[0].values[0];
                    "num_vms" = ($entity.data | Where-Object {$_.name -eq "num_vms"}).values[0].values[0];
                }
                #store the results for this entity in our overall result variable
                $myvar_capacity_results.Add((New-Object PSObject -Property $myvar_cluster_capacity_info)) | Out-Null
            }
        }
        
    #endregion retrieve the information we need
    
    #* output data
    #region process retrieved data for output
        #* console output
        #region console output  
            Write-Host "-----------------------------------" -ForegroundColor White
            ForEach ($myvar_cluster in $myvar_capacity_results)
            {
                Write-Host "$(get-date) [DATA] Cluster: $($myvar_cluster.cluster)" -ForegroundColor White
                if ($myvar_cluster.capacity_runway -eq "no_data") 
                {
                    Write-Host "$(get-date) [WARNING] Runway (days): $($myvar_cluster.capacity_runway)" -ForegroundColor Yellow
                } 
                else 
                {
                    Write-Host "$(get-date) [DATA] Runway (days): $($myvar_cluster.capacity_runway)" -ForegroundColor $(if ($myvar_cluster.capacity_runway -le $myvar_desired_runway) {"Red"} else {"White"})
                }
                if ($myvar_cluster.cpu_runway -eq "no_data") 
                {
                    Write-Host "$(get-date) [WARNING] CPU Runway (days): $($myvar_cluster.cpu_runway)" -ForegroundColor Yellow
                } 
                else 
                {
                    Write-Host "$(get-date) [DATA] CPU Runway (days): $($myvar_cluster.cpu_runway)" -ForegroundColor $(if ($myvar_cluster.cpu_runway -le $myvar_desired_runway) {"Red"} else {"White"})
                }
                if ($myvar_cluster.memory_runway -eq "no_data") {
                    Write-Host "$(get-date) [WARNING] Memory Runway (days): $($myvar_cluster.memory_runway)" -ForegroundColor Yellow
                } 
                else 
                {
                    Write-Host "$(get-date) [DATA] Memory Runway (days): $($myvar_cluster.memory_runway)" -ForegroundColor $(if ($myvar_cluster.memory_runway -le $myvar_desired_runway) {"Red"} else {"White"})
                }
                if ($myvar_cluster.storage_runway -eq "no_data") 
                {
                    Write-Host "$(get-date) [WARNING] Storage Runway (days): $($myvar_cluster.storage_runway)" -ForegroundColor Yellow
                } 
                else 
                {
                    Write-Host "$(get-date) [DATA] Storage Runway (days): $($myvar_cluster.storage_runway)" -ForegroundColor $(if ($myvar_cluster.storage_runway -le $myvar_desired_runway) {"Red"} else {"White"})
                }
                Write-Host "$(get-date) [DATA] AOS Version: $($myvar_cluster.aos_version)" -ForegroundColor White
                Write-Host "$(get-date) [DATA] CPU Cores Qty: $($myvar_cluster.num_cpus)" -ForegroundColor White
                Write-Host "$(get-date) [DATA] Memory Size in Bytes: $($myvar_cluster.memory_capacity_bytes)" -ForegroundColor White
                Write-Host "$(get-date) [DATA] Storage Size in Bytes: $($myvar_cluster.disk_size_bytes)" -ForegroundColor White
                Write-Host "$(get-date) [DATA] Number of hosted VMs: $($myvar_cluster.num_vms)" -ForegroundColor White
                Write-Host "-----------------------------------" -ForegroundColor White
            }
        #endregion console output
        
        #* html output
        #region html output
            if ($html) 
            {#we need html output
                #check if we have PSWriteHTML module
                if (!(Get-Module -Name PSWriteHTML)) 
                {
                    try
                    {
                        Write-Host "$(get-date) [INFO] Installing module 'PSWriteHTML' from the Powershell Gallery..." -ForegroundColor Green
                        Install-Module -Name PSWriteHTML -Scope CurrentUser -Force -ErrorAction Stop
                        Import-Module -Name PSWriteHTML -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not install module 'PSWriteHTML': $($_.Exception.Message)" -ForegroundColor Red
                    }
                }

                Write-Host "$(get-date) [INFO] Creating HTML report in file $($myvar_html_report_name)..." -ForegroundColor Green

                #* html report creation/formatting starts here
                $myvar_html_report = New-HTML -TitleText "Capacity Runway Report" -Online {
                    New-HTMLTableStyle -BackgroundColor Black -TextColor White -Type Button
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#4C4C4E" -TextColor White -TextAlign center -Type Header
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#4C4C4E" -TextColor White -TextAlign center -Type Footer
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor White -TextColor Black -TextAlign center -Type RowOdd
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor WhiteSmoke -TextColor Black -TextAlign center -Type RowEven
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowSelected
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowHoverSelected
                    New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#76787A" -TextColor WhiteSmoke -TextAlign center -Type RowHover
                    New-HTMLTableStyle -Type Header -BorderLeftStyle dashed -BorderLeftColor "#4C4C4E" -BorderLeftWidthSize 1px
                    New-HTMLTableStyle -Type Footer -BorderLeftStyle dotted -BorderLeftColor "#4C4C4E" -BorderleftWidthSize 1px
                    New-HTMLTableStyle -Type Footer -BorderTopStyle none -BorderTopColor Black -BorderTopWidthSize 5px -BorderBottomColor "#4C4C4E" -BorderBottomStyle solid
                    
                    New-HTMLTable -DataTable ($myvar_capacity_results) -HideFooter {
                        New-HTMLTableCondition -Name 'capacity_runway' -Type number -Operator gt -Value $myvar_desired_runway -BackgroundColor Green -Color White
                        New-HTMLTableCondition -Name 'capacity_runway' -Type number -Operator le -Value $myvar_desired_runway -BackgroundColor Red -Color White
                        New-HTMLTableCondition -Name 'cpu_runway' -Type number -Operator gt -Value $myvar_desired_runway -BackgroundColor Green -Color White
                        New-HTMLTableCondition -Name 'cpu_runway' -Type number -Operator le -Value $myvar_desired_runway -BackgroundColor Red -Color White
                        New-HTMLTableCondition -Name 'memory_runway' -Type number -Operator gt -Value $myvar_desired_runway -BackgroundColor Green -Color White
                        New-HTMLTableCondition -Name 'memory_runway' -Type number -Operator le -Value $myvar_desired_runway -BackgroundColor Red -Color White
                        New-HTMLTableCondition -Name 'storage_runway' -Type number -Operator gt -Value $myvar_desired_runway -BackgroundColor Green -Color White
                        New-HTMLTableCondition -Name 'storage_runway' -Type number -Operator le -Value $myvar_desired_runway -BackgroundColor Red -Color White
                    }
                }
                $myvar_html_report | Out-File -FilePath $($myvar_html_report_name)

                if ($viewnow)
                {#open the html report now in the default browser
                    Invoke-Item $myvar_html_report_name
                }
            }
        #endregion html output

        #* influxdb output
        #region influxdb output
            if ($influxdb)
            {#we need to insert data into influxdb database
                if (!(Get-Module -Name Influx)) 
                {
                    try
                    {
                        Write-Host "$(get-date) [INFO] Installing module 'Influx' from the Powershell Gallery..." -ForegroundColor Green
                        Install-Module -Name Influx -Scope CurrentUser -Force -ErrorAction Stop
                        Import-Module -Name Influx -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Imported module 'Influx'!" -ForegroundColor Cyan
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not install module 'Influx': $($_.Exception.Message)" -ForegroundColor Red
                    }
                }

                ForEach ($myvar_cluster in $myvar_capacity_results)
                {
                    if ($myvar_cluster.capacity_runway -ne "no_data") 
                    {#there is available data for that cluster
                        try 
                        {#sending data to influxdb
                            Write-Host "$(get-date) [INFO] Sending capacity runway data for cluster $($myvar_cluster.cluster) to InfluxDB server $($myvar_influxdb_url) in database $($myvar_influxdb_database) as time series capacity_runway..." -ForegroundColor Green
                            Write-Influx -Measure capacity_runway -Tags @{cluster=$myvar_cluster.cluster} -Metrics @{
                                capacity_runway=$myvar_cluster.capacity_runway;
                                cpu_runway=$myvar_cluster.cpu_runway;
                                memory_runway=$myvar_cluster.memory_runway;
                                storage_runway=$myvar_cluster.storage_runway;
                                num_cpus=$myvar_cluster.num_cpus;
                                memory_capacity_bytes=$myvar_cluster.memory_capacity_bytes;
                                disk_size_bytes=$myvar_cluster.disk_size_bytes;
                                num_vms=$myvar_cluster.num_vms;
                            } -Database $myvar_influxdb_database -Credential $influxdbCredentials -Server $myvar_influxdb_url -ErrorAction Stop
                        }
                        catch 
                        {#could not send data to influxdb
                            Write-Host "$(get-date) [WARNING] Could not send data to influxdb: $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    }
                }
            }
        #endregion influxdb output

        #* email output
        #region email output
            if ($email)
            {#we need to send email
                if (!(Get-Module -Name MailKit)) 
                {
                    try
                    {
                        Write-Host "$(get-date) [INFO] Installing module 'MailKit' from the Powershell Gallery..." -ForegroundColor Green
                        Install-Module -Name MailKit -Scope CurrentUser -Force -ErrorAction Stop
                        Import-Module -Name MailKit -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Imported module 'MailKit'!" -ForegroundColor Cyan
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not install module 'MailKit': $($_.Exception.Message)" -ForegroundColor Red
                    }
                }

                #sender ([MimeKit.MailboxAddress] http://www.mimekit.net/docs/html/T_MimeKit_MailboxAddress.htm, required)
                $From=[MimeKit.MailboxAddress]$emailCredentials.UserName

                #recipient list ([MimeKit.InternetAddressList] http://www.mimekit.net/docs/html/T_MimeKit_InternetAddressList.htm, required)
                $RecipientList=[MimeKit.InternetAddressList]::new()
                $RecipientList.Add([MimeKit.InternetAddress]$myvar_smtp_to)

                #attachment list ([System.Collections.Generic.List[string]], optional)
                $AttachmentList=[System.Collections.Generic.List[string]]::new()
                $AttachmentList.Add($myvar_html_report_name)

                #* putting together mail content (as html)
                $myvar_smtp_subject = "Capacity Runway Report for $($prism)"
                $myvar_smtp_html_body = EmailBody {
                    EmailTextBox -FontFamily 'Calibri' -Size 22 -TextDecoration underline -Color Blue -Alignment center {
                        'Capacity Runway Report'
                    }
                    EmailText -LineBreak
                    EmailText -FontSize 20 -Text "Capacity Runway" -Color Blue -FontFamily 'Calibri'
                    EmailTable -Table $myvar_capacity_results -HideFooter -Title "Capacity Runway"
                    EmailText -LineBreak
                }

                #send message
                Write-Host "$(get-date) [INFO] Sending email message to $($myvar_smtp_to)..." -ForegroundColor Green
                try
                {#sending mail
                    Send-MailKitMessage -UseSecureConnectionIfAvailable -Credential $emailCredentials -SMTPServer $myvar_smtp_server -Port $myvar_smtp_server_port -From $From -RecipientList $RecipientList -Subject $myvar_smtp_subject -HtmlBody $myvar_smtp_html_body -AttachmentList $AttachmentList -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Successfully sent email message to $($myvar_smtp_to)" -ForegroundColor Cyan
                }
                catch
                {#could not send mail
                    Write-Host "$(get-date) [ERROR] Could not send email message to $($myvar_smtp_to): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        #endregion email output

        #* csv output
        Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")capacity_runway.csv" -ForegroundColor Green
        $myvar_capacity_results | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"capacity_runway.csv")
    #endregion process retrieved data for output
#endregion main processing


#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvar_ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable html -ErrorAction SilentlyContinue
    Remove-Variable viewnow -ErrorAction SilentlyContinue
    Remove-Variable dir -ErrorAction SilentlyContinue
    Remove-Variable influxdb -ErrorAction SilentlyContinue
    Remove-Variable influxdbCreds -ErrorAction SilentlyContinue
    Remove-Variable email -ErrorAction SilentlyContinue
    Remove-Variable emailCreds -ErrorAction SilentlyContinue
    Remove-Variable myvar_desired_runway -ErrorAction SilentlyContinue
    Remove-Variable myvar_smtp_server -ErrorAction SilentlyContinue
    Remove-Variable myvar_smtp_server_port -ErrorAction SilentlyContinue
    Remove-Variable myvar_smtp_to -ErrorAction SilentlyContinue
    Remove-Variable myvar_influxdb_url -ErrorAction SilentlyContinue
    Remove-Variable myvar_influxdb_database -ErrorAction SilentlyContinue
    Remove-Variable myvar_html_report_name -ErrorAction SilentlyContinue
#endregion cleanup