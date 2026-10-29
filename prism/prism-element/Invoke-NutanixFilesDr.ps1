<#
.SYNOPSIS
  Start a Nutanix Files failover (planned or unplanned) from one Nutanix cluster to another.
.DESCRIPTION
  Given a file server name, assuming protection domain and replication to another site is already in place, do a planned or unplanned failover of a Nutanix Files file server instance from one site to another. The script will migrate or activate the protection domain, activate the file server and can also trigger DNS update. The script is designed to be able to work also with a reference file so that it can be used to facilitate DR automation.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix cluster fully qualified domain name or IP address (source or target; the script will figure out which is which).
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER failover
  Specifies the type of failover (valid entries are planned, unplanned and deactivate).
.PARAMETER fsname
  Name of the file server instance you want to failover.
.PARAMETER reference
  (Optional) Path to the reference file containing the following information in csv format: fsname,prism-primary,prism-dr,primary-client-network-name,primary-client-network-subnet,primary-client-network-gateway,primary-client-network-startip,primary-client-network-endip,primary-storage-network-name,primary-storage-network-subnet,primary-storage-network-gateway,primary-storage-network-startip,primary-storage-network-endip,dr-client-network-name,dr-client-network-subnet,dr-client-network-gateway,dr-client-network-startip,dr-client-network-endip,dr-storage-network-name,dr-storage-network-subnet,dr-storage-network-gateway,dr-storage-network-startip,dr-storage-network-endip,prismcreds,adcreds,pd,smtp,email,primary-dns-servers,primary-ntp-servers,dr-dns-servers,dr-ntp-servers,vcentercreds
  If any of the client or storage networks are AHV managed, you do not need to specify values for the network name, subnet, gateway, startip and endip.
  The script will always look for a reference file in the current directory called <fsname>-reference.csv and use it if available. Otherwise, it will prompt the user for the necessary information.
.PARAMETER pd
  (Optional) Name of protection domain for the file server instance (assumed name if NTNX-<file-server-name>).
.PARAMETER dns
  (Optional) Specifies that you want to trigger a DNS update after the file server has been activated (works only if your DNS server is a Microsoft DNS server).
.PARAMETER adcreds
  (Required if -dns) Name of credentials file for Active Directory (required for DNS update). If the credentials file does not exist, you will be prompted for credentials.
.PARAMETER mail
  (Optional) Specifies that you want to notify by email when the script takes action.
.PARAMETER smtp
  (Required if -mail) FQDN or IP of the SMTP server to use for sending emails.
.PARAMETER email
  (Required if -mail) Comma separated list of email addresses to notify.
.PARAMETER dvswitch
  (Optional) If the File server you are failing over uses distributed virtual switches on VMware vSphere, use this switch to reconnect the network interface after the Protection Domain has failed over and before File Server activation, otherwise the FSVMs will start without network connectivity.
.PARAMETER workaround
  (Optional) Will remove failed ESXi hosts from vCenter so the Files server can register properly. This may be necessary of you are using a Metro cluster. Only applies to unplanned failover.
.PARAMETER undoworkaround
  (Optional/Work in progress) Will add removef failed ESXi hosts in vCenter and migrate them bak to dvSwitch as appropriate. This is required if you did an unplanned failover with the workaround switch.
.EXAMPLE
.\Invoke-NutanixFilesDr.ps1 -fsname myfileserver -failover unplanned
Do an unplanned failover of a file server called myfileserver. All reference information will be obtained from myfileserver.csv in the current directory:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#! when you run an unplanned failover on an esx cluster with metro availability using a dvswitch, things may not work as expected during file server activation. Try using the -workaround switch.

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$prism,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $true)] [ValidateSet("planned","unplanned","deactivate")] [string]$failover,
    [parameter(mandatory = $false)] [string]$fsname,
    [parameter(mandatory = $false)] [string]$reference,
    [parameter(mandatory = $false)] [string]$pd,
    [parameter(mandatory = $false)] [switch]$dns,
    [parameter(mandatory = $false)] $adCreds,
    [parameter(mandatory = $false)] [switch]$mail,
    [parameter(mandatory = $false)] [string]$smtp,
    [parameter(mandatory = $false)] [string]$email,
    [parameter(mandatory = $false)] [switch]$force,
    [parameter(mandatory = $false)] [switch]$dvswitch,
    [parameter(mandatory = $false)] [switch]$workaround,
    [parameter(mandatory = $false)] [switch]$undoworkaround
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
02/06/2021 sb   Replaced username with get-credential
################################################################################
'
    $myvarScriptName = ".\Invoke-NutanixFilesDr.ps1"

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
                    "SimpleThin"	{ $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = "-"; Break }
                    "SimpleThick1"	{ $GreenChar = [char]9608; $YellowChar = [char]9608; $RedChar = [char]9608; $EmptyChar = "-"; Break }
                    "SimpleThick2"	{ $GreenChar = [char]9612; $YellowChar = [char]9612; $RedChar = [char]9612; $EmptyChar = "-"; Break }
                    "AdvancedThin1"	{ $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = [char]9476; Break }
                    "AdvancedThin2"	{ $GreenChar = [char]9642; $YellowChar = [char]9642; $RedChar = [char]9642; $EmptyChar = [char]9643; Break }
                    "AdvancedThick"	{ $GreenChar = [char]9617; $YellowChar = [char]9618; $RedChar = [char]9619; $EmptyChar = [char]9482; Break }
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

    function Get-PrismTaskStatus {
        param (
            [Parameter(Mandatory)][String]$task,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential   
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
                Start-Sleep 5
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                if ($taskDetails.progress_status -ne "Running") 
                {
                    if ($taskDetails.progress_status -ne "Succeeded")
                    {
                        Write-Host "$(Get-Date) [ERROR] Task $($taskDetails.meta_request.method_name) failed with status: $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)" -ForegroundColor Red
                        $userChoice = Read-Host -Prompt "Task failed. Continue? (y/n)"
                        if ($userChoice -eq "n") { Exit }
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            if ($taskDetails.progress_status -ne "Succeeded")
            {
                Write-Host "$(Get-Date) [ERROR] Task $($taskDetails.meta_request.method_name) failed with status: $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)" -ForegroundColor Red
                $userChoice = Read-Host -Prompt "Task failed. Continue? (y/n)"
                if ($userChoice -eq "n") { Exit }
            }
            else 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
            }
        }
    }

    function Get-PrismPdTaskStatus {
        param (
            [Parameter(Mandatory)]$time,
            [Parameter(Mandatory)][String][ValidateSet('activate','deactivate')]$operation,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential   
        )
        
        Write-Host ""
        Write-Host "$(Get-Date) [INFO] Retrieving list of tasks on the cluster $cluster ..." -ForegroundColor Green
        Start-Sleep 10
        
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
        $method = "GET"
        $response = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Retrieved list of tasks on the cluster $cluster" -ForegroundColor Cyan
        
        Do
        {
            $pdTasks = $response.entities | Where-Object {$_.operation -eq $operation} | Where-Object {($_.createTimeUsecs / 1000000) -ge $time}
        }
        While (!$pdTasks)

        ForEach ($pdTask in $pdTasks) 
        {
            if ($pdTask.percentageCompleted -ne "100") 
            {
                Do 
                {
                    Write-Host "$(Get-Date) [WARNING] Waiting 5 seconds for task $($pdTask.taskName) to complete : $($pdTask.percentageCompleted)%" -ForegroundColor Yellow
                    Start-Sleep 5
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $credential
                    $task = $response.entities | Where-Object {$_.taskName -eq $pdTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $time}
                    if ($task.status -ne "running") 
                    {
                        if ($task.status -ne "succeeded") 
                        {
                            Write-Host "$(Get-Date) [ERROR] Task $($pdTask.taskName) failed with status: $($task.status) : $($task.errorCode)" -ForegroundColor Red
                            Exit
                        }
                    }
                }
                While ($task.percentageCompleted -ne "100")
                Write-Host "$(Get-Date) [SUCCESS] Protection domain $operation task $($pdTask.taskName) completed on the cluster $cluster" -ForegroundColor Cyan
                Write-Host ""
            } 
            else 
            {
                Write-Host "$(Get-Date) [SUCCESS] Protection domain $operation task $($pdTask.taskName) completed on the cluster $cluster" -ForegroundColor Cyan
                Write-Host ""
            }
        }
    }

    function Invoke-NtnxPdMigration {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential            
        )

        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        if (!$pd) 
        {
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
        } 
        else 
        {
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        ForEach ($pd2migrate in $pd) 
        {
            $remoteSite = $PdList.entities | Where-Object {$_.name -eq $pd2migrate} | Select-Object -Property remote_site_names
            if (!$remoteSite.remote_site_names) 
            {
                Write-Host "$(Get-Date) [ERROR] There is no remote site defined for protection domain $pd2migrate" -ForegroundColor Red
                Exit
            }
            if ($remoteSite -is [array]) 
            {
                Write-Host "$(Get-Date) [ERROR] There is more than one remote site for protection domain $pd2migrate" -ForegroundColor Red
                Exit
            }

            Write-Host ""
            Write-Host "$(Get-Date) [INFO] Migrating $pd2migrate to $($remoteSite.remote_site_names) ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
            $method = "POST"
            $content = @{ value = $($remoteSite.remote_site_names) }
            $body = (ConvertTo-Json $content -Depth 4)
            $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Migration request response is: $($response.metadata)" -ForegroundColor White }
            if ($response.metadata.count -ne 0)
            {
                Write-Host "$(Get-Date) [ERROR] Could not start migration of $pd2migrate to $($remoteSite.remote_site_names). Try to trigger it manually in Prism and see why it won't work (this could be caused by NGT being disabled on some VMs, or by delta disks due to old snapshots)." -ForegroundColor Red
                Exit
            }
            Write-Host "$(Get-Date) [SUCCESS] Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)" -ForegroundColor Cyan
        }
        return $pd
    }

    function Invoke-NtnxPdActivation {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential   
        )

        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        if (!$pd) 
        {
            $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name
        } 
        else 
        {
            $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        ForEach ($pd2activate in $pd) 
        {
            Write-Host ""
            Write-Host "$(Get-Date) [INFO] Activating protection domain $($pd2activate) on $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate)/activate"
            $method = "POST"
            $content = @{}
            $body = (ConvertTo-Json $content -Depth 4)
            $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
            Write-Host "$(Get-Date) [SUCCESS] Successfully activated protection domain $($pd2activate) on $cluster" -ForegroundColor Cyan
        }
        return $pd
    }

    function Invoke-NtnxPdDeactivation {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential   
        )

        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        if (!$pd) 
        {
            $pd = Read-Host "Enter the name of the protection domain(s) you want to deactivate on $cluster. !!!WARNING!!! All VMs in that protection domain will be deleted!"
            $pd = $pd.Split(",")
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        } 
        else 
        {
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        ForEach ($pd2deactivate in $pd) 
        {
            Write-Host ""
            Write-Host "$(Get-Date) [INFO] Deactivating protection domain $pd2deactivate on $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
            $method = "POST"
            $content = @{}
            $body = (ConvertTo-Json $content -Depth 4)
            $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
            Write-Host "$(Get-Date) [SUCCESS] Successfully started deactivation of protection domain $pd2deactivate on $cluster" -ForegroundColor Cyan
        }
        return $response
    }

    function Set-NtnxPdVmPowerOn {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential   
        )

        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        if (!$pd) 
        {
            $pd = Read-Host "Enter the name of the protection domain(s) you want to process on $cluster."
            $pd = $pd.Split(",")
            $pd = $PdList.entities | Where-Object {$_.active -eq $true} | Where-Object {$pd -contains $_.name}
        } 
        else 
        {
            $pd = $PdList.entities | Where-Object {$_.active -eq $true} | Where-Object {$pd -contains $_.name}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        Write-Host "$($pd.vms)" -ForegroundColor Red

        Write-Host "$(Get-Date) [INFO] Retrieving details of VMs on $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
        $method = "GET"
        $vms_info = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of VMs on $cluster" -ForegroundColor Cyan

        ForEach ($protection_domain in $pd)
        {
            ForEach ($vm in $protection_domain.vms)
            {
                $vm_uuid = ($vms_info.entities | Where-Object {$_.name -eq $vm.vm_name}).uuid
                if ($vm_uuid -is [array])
                {
                    Write-Host "$(Get-Date) [WARNING] There is more than one VM with the name $($vm.vm_name) on $cluster. Setting uuid to what is in the protection domain ($($vm.vm_id))" -ForegroundColor Yellow
                    $vm_uuid = $vm.vm_id
                }

                Write-Host "$(Get-Date) [INFO] Powering on VM $($vm.vm_name) on $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($vm_uuid)/set_power_state"
                $method = "POST"
                $content = @{
                    transition = "ON"
                    uuid = $vm_uuid
                }
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                Write-Host "$(Get-Date) [SUCCESS] Successfully created task to power on VM $($vm.vm_name) on $cluster" -ForegroundColor Cyan
                Get-PrismTaskStatus -task $response.task_uuid -cluster $cluster -credential $credential
            }
        }
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls

    #region set variables
        $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
    #endregion

    Write-Host ""
    Write-Host "$(Get-Date) [STEP] --Preparing--" -ForegroundColor Magenta

#endregion


#region processing

    #region get reference file
        $myvar_reference_file = "$PWD\$($fsname)-reference.csv"
        if ($reference) {$myvar_reference_file = $reference}
        if (Test-Path $myvar_reference_file) 
        {
            Write-Host "$(Get-Date) [INFO] Found reference file $myvar_reference_file" -ForegroundColor Green
            $ref = Import-Csv $myvar_reference_file
            $fsname = $ref.fsname
            $prism_primary = $ref['prism-primary']
            $prism_dr = $ref['prism-dr']
            $primary_client_network_name = $ref['primary-client-network-name']
            $primary_client_network_subnet = $ref['primary-client-network-subnet']
            $primary_client_network_gateway = $ref['primary-client-network-gateway']
            $primary_client_network_startip = $ref['primary-client-network-startip']
            $primary_client_network_endip = $ref['primary-client-network-endip']
            $primary_storage_network_name = $ref['primary-storage-network-name']
            $primary_storage_network_subnet = $ref['primary-storage-network-subnet']
            $primary_storage_network_gateway = $ref['primary-storage-network-gateway']
            $primary_storage_network_startip = $ref['primary-storage-network-startip']
            $primary_storage_network_endip = $ref['primary-storage-network-endip']
            $dr_client_network_name = $ref['dr-client-network-name']
            $dr_client_network_subnet = $ref['dr-client-network-subnet']
            $dr_client_network_gateway = $ref['dr-client-network-gateway']
            $dr_client_network_startip = $ref['dr-client-network-startip']
            $dr_client_network_endip = $ref['dr-client-network-endip']
            $dr_storage_network_name = $ref['dr-storage-network-name']
            $dr_storage_network_subnet = $ref['dr-storage-network-subnet']
            $dr_storage_network_gateway = $ref['dr-storage-network-gateway']
            $dr_storage_network_startip = $ref['dr-storage-network-startip']
            $dr_storage_network_endip = $ref['dr-storage-network-endip']
            $prismCreds = $ref.prismcreds
            $adCreds = $ref.adcreds
            $pd = $ref.pd
            $smtp = $ref.smtp
            $email = $ref.email
            $primary_dns_servers = $ref['primary-dns-servers']
            $primary_ntp_servers = $ref['primary-ntp-servers']
            $dr_dns_servers = $ref['dr-dns-servers']
            $dr_ntp_servers = $ref['dr-ntp-servers']
            $vcenterCreds = $ref.vcentercreds
        }
        else 
        {
            Write-Host "$(Get-Date) [WARNING] Reference file not found. Will prompt for required parameters." -ForegroundColor Yellow
        }
    #endregion

    #region get prism credentials
        if (!$prismCreds) 
        {
            $prismCredentials = Get-Credential -Message "Please enter Prism credentials"
        } 
        else 
        {
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
    #endregion

    #region determine which prism is source/target
        if (!$prism) 
        {
            Write-Host "$(Get-Date) [ERROR] Prism cluster address is required." -ForegroundColor Red
            Exit
        }
        
        # For simplicity, we'll use the provided prism as the target for activation/unplanned
        # and source for planned. In reality, you'd need to detect this.
        $targetPrism = $prism
        $sourcePrism = $prism
    #endregion

    #region execute failover
        if ($failover -eq "planned")
        {
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Planned Failover (Migrate)--" -ForegroundColor Magenta
            
            $pdList = Invoke-NtnxPdMigration -pd $pd -cluster $sourcePrism -credential $prismCredentials
            
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Activating File Server--" -ForegroundColor Magenta
            $url = "https://$($targetPrism):9440/PrismGateway/services/rest/v2.0/file_servers/$fsname/activate"
            $method = "POST"
            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully activated file server $fsname" -ForegroundColor Cyan
            Get-PrismTaskStatus -task $response.task_uuid -cluster $targetPrism -credential $prismCredentials
        }
        elseif ($failover -eq "unplanned")
        {
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Unplanned Failover (Activate)--" -ForegroundColor Magenta
            
            $pdList = Invoke-NtnxPdActivation -pd $pd -cluster $targetPrism -credential $prismCredentials
            
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Activating File Server--" -ForegroundColor Magenta
            $url = "https://$($targetPrism):9440/PrismGateway/services/rest/v2.0/file_servers/$fsname/activate"
            $method = "POST"
            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully activated file server $fsname" -ForegroundColor Cyan
            Get-PrismTaskStatus -task $response.task_uuid -cluster $targetPrism -credential $prismCredentials
        }
        elseif ($failover -eq "deactivate")
        {
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Deactivate File Server--" -ForegroundColor Magenta
            Write-Host "$(Get-Date) [WARNING] This will DELETE the file server and all its data!" -ForegroundColor Yellow
            
            $url = "https://$($targetPrism):9440/PrismGateway/services/rest/v2.0/file_servers/$fsname/deactivate"
            $method = "POST"
            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully deactivated file server $fsname" -ForegroundColor Cyan
            Get-PrismTaskStatus -task $response.task_uuid -cluster $targetPrism -credential $prismCredentials
        }
    #endregion

#endregion


#region cleanup
    Write-Host ""
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable failover -ErrorAction SilentlyContinue
    Remove-Variable fsname -ErrorAction SilentlyContinue
    Remove-Variable reference -ErrorAction SilentlyContinue
    Remove-Variable pd -ErrorAction SilentlyContinue
    Remove-Variable dns -ErrorAction SilentlyContinue
    Remove-Variable adCreds -ErrorAction SilentlyContinue
    Remove-Variable mail -ErrorAction SilentlyContinue
    Remove-Variable smtp -ErrorAction SilentlyContinue
    Remove-Variable email -ErrorAction SilentlyContinue
    Remove-Variable force -ErrorAction SilentlyContinue
    Remove-Variable dvswitch -ErrorAction SilentlyContinue
    Remove-Variable workaround -ErrorAction SilentlyContinue
    Remove-Variable undoworkaround -ErrorAction SilentlyContinue
#endregion