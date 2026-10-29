<#
.SYNOPSIS
  This script can be used to automate the failover (planned or unplanned) of Nutanix asynchronous or near-sync protection domains.
.DESCRIPTION
  This script can be used to automate the failover (planned or unplanned) of Nutanix asynchronous or near-sync protection domains.
  The script has three main workflows: (1)planned failover (migrate), (2)unplanned failover (activate) and (3)deactivate.

  A planned failover will (migrate):
    (1)Initiate migrate on the matching protection domains on the source Nutanix cluster, which will shutdown all the VMs and replicate them to the target site
    (2)Optionally, start VMs on the target cluster.
  
  An unplanned failover (activate) will:
    (1)Activate the specified protection domains on the target Nutanix cluster
    (2)Optionally, start VMs on the target cluster.

  Deactivate will:
    (1)Disable the matching protection domains on the source Nutanix cluster, which will:
    (2) DELETE ALL VMs on that cluster
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER migrate
  Specifies you want to trigger a planned failover workflow.  See the script description for more information.
.PARAMETER activate
  Specifies you want to trigger an unplanned failover workflow.  See the script description for more information.
.PARAMETER deactivate
  Specifies you want to disable a protection domain and DELETE ALL VMs on that cluster that belong to that protection domain.  See the script description for more information.
.PARAMETER pd
  Lets you specify which protection domain(s) you want to failover. If left blank, all applicable protection domains will be processed.
.PARAMETER prismCreds
  Specifies a custom credentials file name for Prism authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt).
.PARAMETER powerOnVms
  Specifies you want VMs to power on after failover.
.PARAMETER reconnectVnicsOnly
  Specifies you just want to reconnect the virtual NICs of the VMs in the specified protection domain (applies to vSphere cluster only).
.EXAMPLE
.\Invoke-AsyncDr.ps1 -cluster <ip> -migrate -prismCreds prism_api-user -pd <protection domain name>
Trigger a planned failover workflow for the specified protection domain.
.EXAMPLE
.\Invoke-AsyncDr.ps1 -cluster <ip> -activate -username admin -password <secret>
Trigger an uplanned failover for all protection domains.
.EXAMPLE
.\Invoke-AsyncDr.ps1 -cluster <ip> -deactivate -pd <protection domain name>
Disable the specified protection domain and delete VMs.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
  Version: 0.2
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [switch]$migrate,
    [parameter(mandatory = $false)] [switch]$activate,
    [parameter(mandatory = $false)] [switch]$deactivate,
    [parameter(mandatory = $false)] [string]$cluster,
    [parameter(mandatory = $false)] $pd, #don't specify type as this is sometimes a string, sometimes an array in the script
    [parameter(mandatory = $false)] $prismCreds, #don't specify type as this is sometimes a string, sometimes secure credentials
    [parameter(mandatory = $false)] [switch]$powerOnVms,
    [parameter(mandatory = $false)] [switch]$reconnectVnicsOnly
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
02/06/2021 sb   Replaced username with get-credential
06/09/2020 sb   Do over with new sbourdeaud module
10/08/2018 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\Invoke-AsyncDr.ps1"

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
    if ($History) 
    {
        $HistoryText
        exit
    }

    #region parameter validation
        if (($activate -and $migrate) -or ($activate -and $deactivate) -or ($migrate -and $deactivate) -or ($activate -and $reconnectVnicsOnly) -or ($deactivate -and $reconnectVnicsOnly) -or ($reconnectVnicsOnly -and $migrate))
        {#multiple actions
            Write-Host "$(Get-Date) [ERROR] You can only use -activate OR -deactivate OR -migrate OR -reconnectVnicsOnly. Don't try to combine them together." -ForegroundColor Red
            Exit
        }

        if ($deactivate -and $powerOnVms)
        {#invalid power on request
            Write-Host "$(Get-Date) [ERROR] You have used -powerOnVms and -deactivate together which is not a valid combination." -ForegroundColor Red
            Exit
        }

        if (!$activate -and !$migrate -and !$deactivate -and !$reconnectVnicsOnly)
        {#no action specified
            Write-Host "$(Get-Date) [ERROR] You must specify an action: -migrate, -activate, -deactivate or -reconnectVnicsOnly." -ForegroundColor Red
            Exit
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
            $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
        }

    #endregion

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 6)
    {#PoSH version <6
        Write-Host "$(Get-Date) [ERROR] Your version of Powershell is too old, please update to Powershell Core version 6 or above!" -ForegroundColor Red
        Exit
    }

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
            [parameter(mandatory = $false)][System.Management.Automation.PSCredential]$credential   
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
            [parameter(mandatory = $false)][System.Management.Automation.PSCredential]$credential   
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
            [parameter(mandatory = $false)][System.Management.Automation.PSCredential]$credential            
        )

        #let's retrieve the list of protection domains
        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
        if (!$pd) 
        {#no pd specified
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
        } 
        else 
        {#fetch specified pd
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        #region process
            #now let's call the migrate workflow
            ForEach ($pd2migrate in $pd) 
            {
                #figure out if there is more than one remote site defined for the protection domain
                $remoteSite = $PdList.entities | Where-Object {$_.name -eq $pd2migrate} | Select-Object -Property remote_site_names
                if (!$remoteSite.remote_site_names) 
                {#no remote site defined or no schedule on the pd with a remote site
                    Write-Host "$(Get-Date) [ERROR] There is no remote site defined for protection domain $pd2migrate" -ForegroundColor Red
                    Exit
                }
                if ($remoteSite -is [array]) 
                {#more than 1 remote site target defined on the pd schedule
                    Write-Host "$(Get-Date) [ERROR] There is more than one remote site for protection domain $pd2migrate" -ForegroundColor Red
                    Exit
                }

                #region migrate the protection domain
                    Write-Host ""
                    Write-Host "$(Get-Date) [INFO] Migrating $pd2migrate to $($remoteSite.remote_site_names) ..." -ForegroundColor Green
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                    $method = "POST"
                    $content = @{ value = $($remoteSite.remote_site_names) }
                    $body = (ConvertTo-Json $content -Depth 4)
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                    if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Migration request response is: $($response.metadata)" -ForegroundColor White }
                    if ($response.metadata.count -ne 0)
                    {#something went wrong with our migration request
                        Write-Host "$(Get-Date) [ERROR] Could not start migration of $pd2migrate to $($remoteSite.remote_site_names). Try to trigger it manually in Prism and see why it won't work (this could be caused by NGT being disabled on some VMs, or by delta disks due to old snapshots)." -ForegroundColor Red
                        Exit
                    }
                    Write-Host "$(Get-Date) [SUCCESS] Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)" -ForegroundColor Cyan
                #endregion
            }
        #endregion
        return $pd #list of protection domains which were processed 
    }

    function Invoke-NtnxPdActivation {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $false)][System.Management.Automation.PSCredential]$credential   
        )

        #let's retrieve the list of protection domains
        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
        if (!$pd) 
        {#no pd specified
            $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name
        } 
        else 
        {#fetch specified pd
            $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        #now let's call the activate workflow
        ForEach ($pd2activate in $pd) 
        {#activate each pd
            #region activate the protection domain
                Write-Host ""
                Write-Host "$(Get-Date) [INFO] Activating protection domain $($pd2activate) on $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate)/activate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                Write-Host "$(Get-Date) [SUCCESS] Successfully activated protection domain $($pd2activate) on $cluster" -ForegroundColor Cyan
            #endregion    
        }
        return $pd #list of protection domains which were processed
    }

    function Invoke-NtnxPdDeactivation {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $false)][System.Management.Automation.PSCredential]$credential   
        )

        #let's retrieve the list of protection domains
        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        #first, we need to figure out which protection domains need to be deactivated. If none have been specified, we'll assume all of them which are active.
        if (!$pd) 
        {#no pd specified
            $pd = Read-Host "Enter the name of the protection domain(s) you want to deactivate on $cluster. !!!WARNING!!! All VMs in that protection domain will be deleted!"
            $pd = $pd.Split(",") #make sure we process protection_domains as an array
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        } 
        else 
        {#fetch specified pd
            $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        #region process
            ForEach ($pd2deactivate in $pd) 
            {#now let's call the deactivate workflow for each pd
                Write-Host ""
                Write-Host "$(Get-Date) [INFO] Deactivating protection domain $pd2deactivate on $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                Write-Host "$(Get-Date) [SUCCESS] Successfully started deactivation of protection domain $pd2deactivate on $cluster" -ForegroundColor Cyan
            }
        #endregion
        return $response #this is the task uuid as sent back from the API
    }

    function Set-NtnxPdVmPowerOn {
        param (
            $pd,
            [Parameter(Mandatory)][String]$cluster,
            [parameter(mandatory = $false)][System.Management.Automation.PSCredential]$credential   
        )

        #let's retrieve the list of protection domains
        Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

        #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
        if (!$pd) 
        {#no pd specified
            $pd = Read-Host "Enter the name of the protection domain(s) you want to process on $cluster."
            $pd = $pd.Split(",") #make sure we process protection_domains as an array
            $pd = $PdList.entities | Where-Object {$_.active -eq $true} | Where-Object {$pd -contains $_.name}
        } 
        else 
        {#fetch specified pd
            $pd = $PdList.entities | Where-Object {$_.active -eq $true} | Where-Object {$pd -contains $_.name}
        }

        if (!$pd) 
        {
            Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
            Exit
        }

        Write-Host "$($pd.vms)" -ForegroundColor Red

        #region get vms
            Write-Host "$(Get-Date) [INFO] Retrieving details of VMs on $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
            $method = "GET"
            $vms_info = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of VMs on $cluster" -ForegroundColor Cyan
        #endregion

        ForEach ($protection_domain in $pd)
        {
            ForEach ($vm in $protection_domain.vms)
            {
                #region get the vm uuid
                    $vm_uuid = ($vms_info.entities | Where-Object {$_.name -eq $vm.vm_name}).uuid
                    if ($vm_uuid -is [array])
                    {#we have multiple vms with the same name...
                        Write-Host "$(Get-Date) [WARNING] There is more than one VM with the name $($vm.vm_name) on $cluster. Setting uuid to what is in the protection domain ($($vm.vm_id))" -ForegroundColor Yellow
                        $vm_uuid = $vm.vm_id
                    }
                #endregion

                #region power the vm on
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
                #endregion
            }
        }
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls

    #region set variables
        $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
        $StartEpochSeconds = Get-Date (Get-Date).ToUniversalTime() -UFormat %s #used to get tasks generated in Prism after the script was invoked
    #endregion

    Write-Host ""
    Write-Host "$(Get-Date) [STEP] --Preparing--" -ForegroundColor Magenta

#endregion


#region processing

    #region get stuff we'll need regardless
        
        #get cluster information
        Write-Host "$(Get-Date) [INFO] Retrieving details of Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $cluster_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of Nutanix cluster $cluster" -ForegroundColor Cyan

        Write-Host "$(Get-Date) [INFO] Hypervisor on Nutanix cluster $cluster is of type $($cluster_details.hypervisor_types)." -ForegroundColor Green

    #endregion

    #TODO: if the cluster hypervisor is vSphere, check for the presence of VM snapshots as this prevents pd migration.
    #TODO: also check that NGT is enabled (not sure how to do that in the API)
    
    #region migrate
        if ($migrate)
        {   
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Triggering protection domain migration workflow--" -ForegroundColor Magenta

            #get vms and networks if AHV (for later when we will try to reconnect to dvportgroups)
            if ($cluster_details.hypervisor_types -eq "kKvm")
            {
                Write-Host "$(Get-Date) [INFO] Retrieving VMs from cluster $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
                $method = "GET"
                $vms_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved VMs from $cluster" -ForegroundColor Cyan

                Write-Host "$(Get-Date) [INFO] Retrieving networks from cluster $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/networks/"
                $method = "GET"
                $networks_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved networks from $cluster" -ForegroundColor Cyan
            }

            $pdList = Invoke-NtnxPdMigration -pd $pd -cluster $cluster -credential $prismCredentials

            if ($powerOnVms)
            {
                Write-Host ""
                Write-Host "$(Get-Date) [STEP] --Powering on VMs on remote site--" -ForegroundColor Magenta
                Set-NtnxPdVmPowerOn -pd $pdList -cluster $cluster -credential $prismCredentials
            }

            Write-Host ""
            Write-Host "$(Get-Date) [INFO] Retrieving list of tasks on the cluster $cluster ..." -ForegroundColor Green
            Start-Sleep 10
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Retrieved list of tasks on the cluster $cluster" -ForegroundColor Cyan
            Get-PrismPdTaskStatus -time $StartEpochSeconds -operation migrate -cluster $cluster -credential $prismCredentials
        }
    #endregion

    #region activate
        if ($activate)
        {   
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Triggering protection domain activation workflow--" -ForegroundColor Magenta

            #get vms and networks if AHV (for later when we will try to reconnect to dvportgroups)
            if ($cluster_details.hypervisor_types -eq "kKvm")
            {
                Write-Host "$(Get-Date) [INFO] Retrieving VMs from cluster $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
                $method = "GET"
                $vms_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved VMs from $cluster" -ForegroundColor Cyan

                Write-Host "$(Get-Date) [INFO] Retrieving networks from cluster $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/networks/"
                $method = "GET"
                $networks_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved networks from $cluster" -ForegroundColor Cyan
            }

            $pdList = Invoke-NtnxPdActivation -pd $pd -cluster $cluster -credential $prismCredentials

            if ($powerOnVms)
            {
                Write-Host ""
                Write-Host "$(Get-Date) [STEP] --Powering on VMs--" -ForegroundColor Magenta
                Set-NtnxPdVmPowerOn -pd $pdList -cluster $cluster -credential $prismCredentials
            }

            Write-Host ""
            Write-Host "$(Get-Date) [INFO] Retrieving list of tasks on the cluster $cluster ..." -ForegroundColor Green
            Start-Sleep 10
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Retrieved list of tasks on the cluster $cluster" -ForegroundColor Cyan
            Get-PrismPdTaskStatus -time $StartEpochSeconds -operation activate -cluster $cluster -credential $prismCredentials
        }
    #endregion

    #region deactivate
        if ($deactivate)
        {   
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Triggering protection domain deactivation workflow--" -ForegroundColor Magenta
            Write-Host "$(Get-Date) [WARNING] This will DELETE ALL VMs in the specified protection domain(s)!" -ForegroundColor Yellow

            $response = Invoke-NtnxPdDeactivation -pd $pd -cluster $cluster -credential $prismCredentials

            Write-Host ""
            Write-Host "$(Get-Date) [INFO] Retrieving list of tasks on the cluster $cluster ..." -ForegroundColor Green
            Start-Sleep 10
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Retrieved list of tasks on the cluster $cluster" -ForegroundColor Cyan
            Get-PrismPdTaskStatus -time $StartEpochSeconds -operation deactivate -cluster $cluster -credential $prismCredentials
        }
    #endregion

    #region reconnectVnicsOnly
        if ($reconnectVnicsOnly)
        {   
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Reconnecting virtual NICs--" -ForegroundColor Magenta
            
            Write-Host "$(Get-Date) [INFO] Retrieving VMs from cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
            $method = "GET"
            $vms_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved VMs from $cluster" -ForegroundColor Cyan

            Write-Host "$(Get-Date) [INFO] Retrieving networks from cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/networks/"
            $method = "GET"
            $networks_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved networks from $cluster" -ForegroundColor Cyan

            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
            Write-Host "$(Get-Date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $PdList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

            if (!$pd) 
            {#no pd specified
                $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
            } 
            else 
            {#fetch specified pd
                $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
            }

            if (!$pd) 
            {
                Write-Host "$(Get-Date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
                Exit
            }

            ForEach ($pd2reconnect in $pd) 
            {#reconnect vnics for each pd
                Write-Host ""
                Write-Host "$(Get-Date) [INFO] Reconnecting virtual NICs for protection domain $($pd2reconnect) on $cluster ..." -ForegroundColor Green
                
                #get the vms in this pd
                $pdVms = $PdList.entities | Where-Object {$_.name -eq $pd2reconnect} | Select-Object -ExpandProperty vms
                
                ForEach ($vm in $pdVms) 
                {
                    $vm_uuid = ($vms_info.entities | Where-Object {$_.name -eq $vm.vm_name}).uuid
                    if ($vm_uuid -is [array])
                    {#we have multiple vms with the same name...
                        Write-Host "$(Get-Date) [WARNING] There is more than one VM with the name $($vm.vm_name) on $cluster. Using uuid from protection domain ($($vm.vm_id))" -ForegroundColor Yellow
                        $vm_uuid = $vm.vm_id
                    }
                    
                    #get the network uuid for each nic
                    ForEach ($nic in $vm.vnics)
                    {
                        $network_uuid = ($networks_info.entities | Where-Object {$_.name -eq $nic.network_name}).uuid
                        if ($network_uuid)
                        {
                            Write-Host "$(Get-Date) [INFO] Reconnecting NIC $($nic.mac_address) of VM $($vm.vm_name) to network $($nic.network_name) ..." -ForegroundColor Green
                            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($vm_uuid)/nics/$($nic.mac_address)/connect"
                            $method = "POST"
                            $content = @{ network_uuid = $network_uuid }
                            $body = (ConvertTo-Json $content -Depth 4)
                            $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
                            Write-Host "$(Get-Date) [SUCCESS] Successfully reconnected NIC $($nic.mac_address) of VM $($vm.vm_name) to network $($nic.network_name)" -ForegroundColor Cyan
                        }
                    }
                }
            }
        }
    #endregion

#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    
    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable pd -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable migrate -ErrorAction SilentlyContinue
    Remove-Variable activate -ErrorAction SilentlyContinue
    Remove-Variable deactivate -ErrorAction SilentlyContinue
    Remove-Variable powerOnVms -ErrorAction SilentlyContinue
    Remove-Variable reconnectVnicsOnly -ErrorAction SilentlyContinue
    Remove-Variable StartEpochSeconds -ErrorAction SilentlyContinue
#endregion