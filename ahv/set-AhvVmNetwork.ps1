<#
.SYNOPSIS
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
.DESCRIPTION
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix cluster Prism Element fully qualified domain name or IP address.  If you are using vpc_subnet, then this should be a Prism Central instance.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vms
  One or more vm name(s) (comma separated).
.PARAMETER ahv_network
  AHV network name you want to connect the specified vm(s) to.  Can't be used with -vpc_subnet.
.PARAMETER vpc_subnet
  VPC subnet name you want to connect the specified vm(s) to.  Can't be used with -ahv_network.  Note that this will remove the existing vnic and create a new one to replace it which will be connected to the specified vpc subnet.
.PARAMETER skiptaskstatuscheck
  Do not check each vm update task status.
.PARAMETER dontkeepip
  When attaching to a vpc subnet, don't try to preserve the ip configuration.
.EXAMPLE
.\set-AhvVmNetwork.ps1 -cluster ntnxc1.local -vm myvm -ahv_network mynetwork
Connect myvm to the mynetwork AHV network:
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
    if (!$prismcentral -or !$vmname -or !$networkname) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral -vmname -networkname!"
    }
    if ($ahv_network -and $vpc_subnet) {Throw "$(get-date) [ERROR] You can only specify an ahv_network OR a vpc_subnet but not both! Exiting."}
    if (!$ahv_network -and !$vpc_subnet) {Throw "$(get-date) [ERROR] You must specify either an ahv_network OR a vpc_subnet! Exiting."}
    if ($ahv_network) 
    {#renamed the network variable when I added vpc subnet so to make things more simple, doing this :)
        $network = $ahv_network
        $cluster = $prism
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

    #assume vms is a list
    $myvar_vms = $vms.Split("{,}")
#endregion


#region processing
    
    if ($network) 
    {#we're updating an ahv network

        #region get cluster info, check it is AHV
            Write-Host "$(Get-Date) [INFO] Retrieving cluster information from $($cluster)..." -ForegroundColor Green
            $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/cluster/" -f $cluster,$myvar_api_server_port
            $myvar_method = "GET"
            $myvar_cluster = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved cluster information from $($cluster)!" -ForegroundColor Cyan
            if ($myvar_cluster.hypervisor_types -eq "kKvm")
            {
                Write-Host "$(Get-Date) [DATA] Cluster $($cluster) is an AHV cluster." -ForegroundColor White
            }
            else 
            {
                Write-Host "$(Get-Date) [ERROR] Cluster $($cluster) is not an AHV cluster!" -ForegroundColor Red
                exit 1
            }
        #endregion

        #region get vms, make sure all specified vms exist, gather information about each vm to process
            Write-Host "$(Get-Date) [INFO] Retrieving list of VMs from AHV cluster $($cluster)..." -ForegroundColor Green
            $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/vms/?include_vm_nic_config=true" -f $cluster,$myvar_api_server_port
            $myvar_method = "GET"
            $myvar_vm_list = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved VMs list from $($cluster)!" -ForegroundColor Cyan

            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_vm in (Compare-Object -ReferenceObject $myvar_vm_list.entities.name -DifferenceObject $myvar_vms -IncludeEqual))
            {#make sure all specified vms exist
                if ($myvar_vm.SideIndicator -eq "=>")
                {#this vm does not exist
                    Write-Host "$(Get-Date) [ERROR] VM $($myvar_vm.InputObject) does not exist on AHV cluster $($cluster)!" -ForegroundColor Red
                    exit 1
                }
                if ($myvar_vm.SideIndicator -eq "==")
                {#vm matches
                    $myvar_vm_info = $myvar_vm_list.entities | Where-Object -Property name -eq $myvar_vm.InputObject | Select-Object -Property name,uuid,vm_nics
                    #store the results for this entity in our overall result variable
                    $myvar_vms_details.Add($myvar_vm_info) | Out-Null
                    Write-Host "$(Get-Date) [DATA] Grabbed information for vm $($myvar_vm.InputObject)..." -ForegroundColor White
                }
            }
        #endregion

        #region get networks, make sure the specified network exists, get information about that network
        
            Write-Host "$(Get-Date) [INFO] Retrieving list of networks from AHV cluster $($cluster)..." -ForegroundColor Green
            $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/networks/" -f $cluster,$myvar_api_server_port
            $myvar_method = "GET"
            $myvar_network_list = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved network list from $($cluster)!" -ForegroundColor Cyan
            
            if ($network -notin $myvar_network_list.entities.name)
            {
                Write-Host "$(Get-Date) [ERROR] Network $($network) does not exist on AHV cluster $($cluster)!" -ForegroundColor Red
                exit 1
            }
            #grab the uuid of the network
            $myvar_network_details = $myvar_network_list.entities | Where-Object -Property name -eq $network | Select-Object -Property name,uuid    

        #endregion

        #region process each vm
            ForEach ($myvar_vm in $myvar_vms_details)
            {
                Write-Host "$(Get-Date) [INFO] Connecting vm $($myvar_vm.name) to network $($network)..." -ForegroundColor Green
                #figuring out vnic mac address and formatting associated url string
                $myvar_vnic_mac = ($myvar_vm.vm_nics[0]).mac_address
                $myvar_vnic_mac_url = $myvar_vnic_mac -replace ":","%3A"
                #figure out payload
                $myvar_content = @{
                    nic_spec = @{
                        is_connected = $true;
                        network_uuid = "$($myvar_network_details.uuid)"
                    }
                }
                $myvar_payload = (ConvertTo-Json $myvar_content -Depth 9)
                $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/vms/{2}/nics/{3}" -f $cluster,$myvar_api_server_port,$myvar_vm.uuid,$myvar_vnic_mac_url
                $myvar_method = "PUT"
                $myvar_vm_update_task = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
                Write-Host "$(Get-Date) [SUCCESS] Successfully requested connection of vm $($myvar_vm.name) to network $($network)!" -ForegroundColor Cyan

                #task status check
                if (!$skiptaskstatuscheck)
                {
                    Get-PrismTaskStatus -task $myvar_vm_update_task.task_uuid -credential $prismCredentials -cluster $cluster
                }
            }
        #endregion
    }

    if ($vpc_subnet)
    {#we're attaching a vnic to a subnet in a vpc

        #region get vms, make sure all specified vms exist, gather information about each vm to process
            Write-Host "$(Get-Date) [INFO] Retrieving list of VMs from Prism Central..." -ForegroundColor Green
            $content = @{
                kind = "vm";
                offset = 0;
                length = $myvar_length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $url = "https://{0}:{1}/api/nutanix/v3/vms/list" -f $prism,$myvar_api_server_port
            $method = "POST"
            $myvar_vm_list = @()
            $total = 0
            $cumulated = 0
            $page_offset = 0

            Do {
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    if ($total -eq 0) {$total = $resp.metadata.total_matches}
                    $cumulated += $resp.entities.count
                    
                    Write-Host "$(Get-Date) [INFO] Processing results from $($page_offset) to $($cumulated) out of $($total)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            
                    ForEach ($entity in $resp.entities) {                
                        $myvar_vm_list += $entity
                    }
                    
                    $page_offset += $myvar_length
                    $content.offset = $page_offset
                    $payload = (ConvertTo-Json $content -Depth 4)
                }
                catch {
                    $saved_error = $_.Exception.Message
                    Throw "$(get-date) [ERROR] $saved_error"
                }
            }
            While ($cumulated -lt $total)
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved VMs list from Prism Central!" -ForegroundColor Cyan

            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_vm in (Compare-Object -ReferenceObject $myvar_vm_list.spec.name -DifferenceObject $myvar_vms -IncludeEqual))
            {#make sure all specified vms exist
                if ($myvar_vm.SideIndicator -eq "=>")
                {#this vm does not exist
                    Write-Host "$(Get-Date) [ERROR] VM $($myvar_vm.InputObject) does not exist on AHV cluster $($cluster)!" -ForegroundColor Red
                    exit 1
                }
                if ($myvar_vm.SideIndicator -eq "==")
                {#vm matches
                    $myvar_vm_info = $myvar_vm_list | Where-Object -FilterScript {$_.spec.name -eq $myvar_vm.InputObject}
                    #store the results for this entity in our overall result variable
                    $myvar_vms_details.Add($myvar_vm_info) | Out-Null
                    Write-Host "$(Get-Date) [DATA] Grabbed payload for vm $($myvar_vm.InputObject)..." -ForegroundColor White
                }
            }
        #endregion

        #region get vpc subnets and make sure the one specified by the user exists

            Write-Host "$(Get-Date) [INFO] Retrieving list of subnets from Prism Central..." -ForegroundColor Green
            $content = @{
                kind = "subnet";
                offset = 0;
                length = $myvar_length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $url = "https://{0}:{1}/api/nutanix/v3/subnets/list" -f $prism,$myvar_api_server_port
            $method = "POST"
            $myvar_subnet_list = @()
            $total = 0
            $cumulated = 0
            $page_offset = 0

            Do {
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    if ($total -eq 0) {$total = $resp.metadata.total_matches}
                    $cumulated += $resp.entities.count
                    
                    Write-Host "$(Get-Date) [INFO] Processing results from $($page_offset) to $($cumulated) out of $($total)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            
                    ForEach ($entity in $resp.entities) {                
                        $myvar_subnet_list += $entity
                    }
                    
                    $page_offset += $myvar_length
                    $content.offset = $page_offset
                    $payload = (ConvertTo-Json $content -Depth 4)
                }
                catch {
                    $saved_error = $_.Exception.Message
                    Throw "$(get-date) [ERROR] $saved_error"
                }
            }
            While ($cumulated -lt $total)
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved subnets list from Prism Central!" -ForegroundColor Cyan
            
            if ($vpc_subnet -notin $myvar_subnet_list.spec.name)
            {
                Write-Host "$(Get-Date) [ERROR] Subnet $($vpc_subnet) does not exist on Prism Central $($prism)!" -ForegroundColor Red
                exit 1
            }
            #grab the uuid of the subnet
            $myvar_subnet_details = $myvar_subnet_list | Where-Object -FilterScript {$_.spec.name -eq $vpc_subnet}

        #endregion get vpc subnets

        #region process each vm
            #region process each vm
                ForEach ($myvar_vm in $myvar_vms_details)
                {
                    Write-Host "$(Get-Date) [INFO] Removing first vnic from vm $($myvar_vm.spec.name)..." -ForegroundColor Green

                    $myvar_vm.PSObject.Properties.Remove('status') #removing status section from the vm payload
                    if ($myvar_vm.spec.resources.nic_list[0].subnet_reference.uuid -eq $myvar_subnet_details.metadata.uuid)
                    {
                        Write-Host "$(Get-Date) [WARNING] vnic0 on vm $($myvar_vm.spec.name) is already connected to subnet $($vpc_subnet)! Skipping..." -ForegroundColor Yellow
                        Continue
                    }
                    $myvar_vm_nic0_config = $myvar_vm.spec.resources.nic_list[0] #saving vnic0 configuration
                    if ($myvar_vm.spec.resources.nic_list.count -eq 0)
                    {#there are no vnics on this vm
                        Write-Host "$(Get-Date) [WARNING] There is no vnic to update on vm $($myvar_vm.spec.name)! Skipping..." -ForegroundColor Yellow
                        Continue
                    }
                    elseif ($myvar_vm.spec.resources.nic_list.count -gt 1)
                    {#we have more than 1 vnic
                        $myvar_vm.spec.resources.nic_list[0] = "" #removing existing vnic0
                    }
                    else 
                    {
                        $myvar_vm.spec.resources.nic_list = @()
                    }
                    $myvar_vm.metadata.spec_version += 1 #increasing spec version
                    $myvar_url = "https://{0}:{1}/api/nutanix/v3/vms/{2}" -f $prism,$myvar_api_server_port,$myvar_vm.metadata.uuid
                    $myvar_method = "PUT"
                    $myvar_payload = (ConvertTo-Json $myvar_vm -Depth 9)
                    $myvar_vm_update_task = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
                    
                    Write-Host "$(Get-Date) [SUCCESS] Successfully requested removal of vnic0 from vm $($myvar_vm.spec.name)!" -ForegroundColor Cyan
                    $myvar_vm_update_task_status = Get-PrismCentralTaskStatus -task $myvar_vm_update_task.status.execution_context.task_uuid -credential $prismCredentials -cluster $prism

                   
                    Write-Host "$(Get-Date) [INFO] Connecting vm $($myvar_vm.spec.name) to subnet $($vpc_subnet)..." -ForegroundColor Green

                    $myvar_vm_nic0_config.subnet_reference.name = $myvar_subnet_details.spec.name #updating subnet name reference
                    $myvar_vm_nic0_config.subnet_reference.uuid = $myvar_subnet_details.metadata.uuid #updating subnet uuid reference
                    $myvar_vm_nic0_config.PSObject.Properties.Remove('uuid') #removing uuid (this is a new vnic after all)
                    $myvar_url = "https://{0}:{1}/api/nutanix/v3/vms/{2}" -f $prism,$myvar_api_server_port,$myvar_vm.metadata.uuid
                    $myvar_method = "GET"
                    $myvar_vm_payload_without_vnic0 = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
                    $myvar_vm_payload_without_vnic0.PSObject.Properties.Remove('status') #removing status section from the vm payload
                    $myvar_vm_payload_without_vnic0.metadata.spec_version += 1 #increasing spec version
                    if ($dontkeepip)
                    {#remove the ip configuration
                        $myvar_vm_nic0_config.ip_endpoint_list = @()
                    }
                    $myvar_vm_payload_without_vnic0.spec.resources.nic_list += $myvar_vm_nic0_config #adding new vnic connected to vpc subnet
                    $myvar_method = "PUT"
                    $myvar_payload = (ConvertTo-Json $myvar_vm_payload_without_vnic0 -Depth 9)
                    $myvar_vm_update_task = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
                    
                    Write-Host "$(Get-Date) [SUCCESS] Successfully requested connection of vm $($myvar_vm.spec.name) to subnet $($vpc_subnet)!" -ForegroundColor Cyan
                    if (!$skiptaskstatuscheck)
                    {
                        $myvar_vm_update_task_status = Get-PrismCentralTaskStatus -task $myvar_vm_update_task.status.execution_context.task_uuid -credential $prismCredentials -cluster $prism
                    }
                }
            #endregion
        #endregion process vms
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
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vms -ErrorAction SilentlyContinue
    Remove-Variable ahv_network -ErrorAction SilentlyContinue
    Remove-Variable vpc_subnet -ErrorAction SilentlyContinue
    Remove-Variable skiptaskstatuscheck -ErrorAction SilentlyContinue
    Remove-Variable dontkeepip -ErrorAction SilentlyContinue
    Remove-Variable myvar_api_server_port -ErrorAction SilentlyContinue
    Remove-Variable myvar_length -ErrorAction SilentlyContinue
#endregion