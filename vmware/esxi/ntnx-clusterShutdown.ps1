<#
.SYNOPSIS
  This script can be used to start/stop fully a Nutanix cluster running the vSphere hypervisor.
.DESCRIPTION
  The script does the following steps: (1)Makes sure that redundancy status is greater than or equal to 2; (2)Makes sure there is no cluster upgrade in progress; (3)Figures out the vCenter VM, connects to it and cleanly shuts down VMs (except the vCenter VM and CVMs); (4)Forcibly shuts down any remaining user VMs after 5 minutes; (5)Stops the vCenter Server VM if it is hosted on the Nutanix cluster; (6)Stops the Nutanix cluster; (7)Powers off all the ESXi hosts cleanly.  With its start parameter, it can also (1)Start the Nutanix cluster and (2)Power on the vCenter VM if it is hosted on Nutanix.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER start
  Use this parameter to start a Nutanix cluster (after its hosts and CVMs have been powered on).
.PARAMETER cvm
  A CVM IP. Used with start to start the Nutanix cluster. The script will prompt for this information if it is not specified.
.PARAMETER vcentervmname
  Used with start to specify which VM is the vCenter VM. The script will prompt for this information if it is not specified.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\ntnx-clusterShutdown.ps1 -cluster ntnxc1.local -username admin -password admin
Stop the Nutanix cluster of your choice
.EXAMPLE
.\ntnx-clusterShutdown.ps1 -cluster ntnxc1.local -username admin -password admin -start
Start the Nutanix cluster of your choice
.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
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
        [parameter(mandatory = $false)] [string]$cluster,
        [parameter(mandatory = $false)] [switch]$start,
        [parameter(mandatory = $false)] [string]$cvm,
        [parameter(mandatory = $false)] [string]$vcentervmname,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] $vcenterCreds
    )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
02/05/2021 sb   Multiple updates and fixes based on API and AOS updates.
05/11/2020 sb   Multiple fixes in params and help.
04/17/2018 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\ntnx-clusterShutdown.ps1"
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

    #check if we have all the required PoSH modules
    Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

    #region Load/Install VMware.PowerCLI
        if (!(Get-Module VMware.PowerCLI)) 
        {
            try 
            {
                Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                Import-Module VMware.PowerCLI -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
            }
            catch 
            {
                Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
                try 
                {
                    Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
                    Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
                    Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
                }
                catch 
                {
                    throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
                }
            }
        }
        
        if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
        {
            try { Update-Module -Name VMware.PowerCLI -ErrorAction Stop }
            catch { throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)" }
        }
    #endregion
    if ((Get-PowerCLIConfiguration | where-object {$_.Scope -eq "User"}).InvalidCertificateAction -ne "Ignore") {
      Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false
    }

    #region Load/Install SSHSessions
        if (!(Get-Module SSHSessions)) {
            try { Import-Module SSHSessions }
            catch {
                Write-Host "$(get-date) [WARNING] We need to install the SSHSessions module!" -ForegroundColor Yellow
                try { Install-Module SSHSessions -ErrorAction Stop -Scope CurrentUser }
                catch { throw "Could not install the SSHSessions module : $($_.Exception.Message)" }
                try { Import-Module SSHSessions }
                catch { throw "Could not load the SSHSessions module : $($_.Exception.Message)" }
            }
        }
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


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvarvCenterServers = @()
    $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_") + "OutputLog.log"
#endregion


#region parameters validation
    if (!$cluster) {
        Throw "$(Get-Date) [ERROR] You must specify -cluster!"
    }
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
    $username = $prismCredentials.UserName
    $PrismSecurePassword = $prismCredentials.Password
    $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword

    if ($vcenterCreds) 
    {
        try 
        {
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop 
        }
        catch 
        {
            Set-CustomCredentials -credname $vcenterCreds
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
        }
    }
    else 
    {
        $vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
    }
    $vcenterUsername = $vcenterCredentials.UserName
    $vcenterSecurePassword = $vcenterCredentials.Password
    $vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword
#endregion


#region processing

    if ($start)
    {
        #region START NUTANIX CLUSTER
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Starting Nutanix Cluster--" -ForegroundColor Magenta
            
            if (!$cvm) { $cvm = Read-Host "Enter the CVM IP address to start the cluster" }
            if (!$vcentervmname) { $vcentervmname = Read-Host "Enter the vCenter VM name (if hosted on this cluster)" }
            
            #region start cluster via CVM SSH
                Write-Host "$(Get-Date) [INFO] Starting Nutanix cluster via CVM $cvm..." -ForegroundColor Green
                $ssh = New-SSHSessions -ComputerName $cvm -Credential $prismCredentials
                if ($ssh) {
                    $result = Invoke-SSHCommand -Session $ssh -Command "cluster start" -TimeOut 300
                    Write-Host "$(Get-Date) [SUCCESS] Cluster start command sent" -ForegroundColor Cyan
                    Remove-SSHSessions -Session $ssh
                }
            #endregion
            
            #region start vCenter VM
                if ($vcentervmname) {
                    Write-Host "$(Get-Date) [INFO] Starting vCenter VM $vcentervmname..." -ForegroundColor Green
                    Connect-VIServer -Server $cluster -Credential $vcenterCredentials -WarningAction SilentlyContinue | Out-Null
                    Start-VM -VM $vcentervmname -Confirm:$false
                    Write-Host "$(Get-Date) [SUCCESS] Started vCenter VM" -ForegroundColor Cyan
                    Disconnect-VIServer -Server $cluster -Confirm:$false
                }
            #endregion
        #endregion
    }
    else
    {
        #region STOP NUTANIX CLUSTER
            Write-Host ""
            Write-Host "$(Get-Date) [STEP] --Stopping Nutanix Cluster--" -ForegroundColor Magenta
            
            #region check cluster health
                Write-Host "$(Get-Date) [INFO] Checking cluster health..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
                $method = "GET"
                $clusterInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                
                if ($clusterInfo.cluster_redundancy_state.current_redundancy_factor -lt 2) {
                    Write-Host "$(Get-Date) [ERROR] Cluster redundancy factor is less than 2. Cannot safely shut down." -ForegroundColor Red
                    Exit 1
                }
                Write-Host "$(Get-Date) [SUCCESS] Cluster redundancy factor: $($clusterInfo.cluster_redundancy_state.current_redundancy_factor)" -ForegroundColor Cyan
            #endregion
            
            #region check for upgrades
                Write-Host "$(Get-Date) [INFO] Checking for cluster upgrades..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/upgrades"
                $method = "GET"
                $upgrades = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                if ($upgrades.entities | Where-Object {$_.status -eq "IN_PROGRESS"}) {
                    Write-Host "$(Get-Date) [ERROR] Cluster upgrade in progress. Cannot shut down." -ForegroundColor Red
                    Exit 1
                }
                Write-Host "$(Get-Date) [SUCCESS] No upgrades in progress" -ForegroundColor Cyan
            #endregion
            
            #region get vCenter VM
                Write-Host "$(Get-Date) [INFO] Retrieving VMs to identify vCenter VM..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
                $method = "GET"
                $vms = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                
                $vCenterVM = $vms.entities | Where-Object {$_.vm_name -like "*vcenter*" -or $_.vm_name -like "*vcsa*"}
                if (!$vCenterVM) {
                    $vCenterVM = $vms.entities | Where-Object {$_.vm_name -like "*center*" -and $_.vm_nics.ip_address}
                }
                if ($vCenterVM) {
                    Write-Host "$(Get-Date) [INFO] Found potential vCenter VM: $($vCenterVM.vm_name)" -ForegroundColor Green
                }
            #endregion
            
            #region connect to vCenter and shutdown VMs
                Write-Host "$(Get-Date) [INFO] Connecting to vCenter..." -ForegroundColor Green
                Connect-VIServer -Server $cluster -Credential $vcenterCredentials -WarningAction SilentlyContinue | Out-Null
                
                #get all powered on VMs except CVMs and vCenter
                $cvmIps = ($vms.entities | Where-Object {$_.vm_name -like "*CVM*"} | Select-Object -ExpandProperty vm_nics.ip_address) -join ","
                $vmsToShutdown = Get-VM | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.Name -notlike "*CVM*" -and $_.Name -notlike "*vcenter*" -and $_.Name -notlike "*vcsa*"}
                
                Write-Host "$(Get-Date) [INFO] Shutting down $($vmsToShutdown.Count) user VMs..." -ForegroundColor Green
                ForEach ($vm in $vmsToShutdown) {
                    Write-Host "$(Get-Date) [INFO] Shutting down VM $($vm.Name)..." -ForegroundColor Green
                    Shutdown-VMGuest -VM $vm -Confirm:$false
                }
                
                #wait for graceful shutdown
                Write-Host "$(Get-Date) [INFO] Waiting 5 minutes for graceful shutdown..." -ForegroundColor Green
                Start-Sleep -Seconds 300
                
                #force shutdown remaining VMs
                $remainingVMs = Get-VM | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.Name -notlike "*CVM*" -and $_.Name -notlike "*vcenter*" -and $_.Name -notlike "*vcsa*"}
                if ($remainingVMs) {
                    Write-Host "$(Get-Date) [WARNING] Force powering off $($remainingVMs.Count) remaining VMs..." -ForegroundColor Yellow
                    ForEach ($vm in $remainingVMs) {
                        Stop-VM -VM $vm -Confirm:$false
                    }
                }
                
                #shutdown vCenter VM if found
                if ($vCenterVM) {
                    Write-Host "$(Get-Date) [INFO] Shutting down vCenter VM $($vCenterVM.vm_name)..." -ForegroundColor Green
                    Shutdown-VMGuest -VM $vCenterVM.vm_name -Confirm:$false
                    Start-Sleep -Seconds 120
                    $vc = Get-VM -Name $vCenterVM.vm_name
                    if ($vc.PowerState -eq "PoweredOn") {
                        Stop-VM -VM $vCenterVM.vm_name -Confirm:$false
                    }
                }
                
                Disconnect-VIServer -Server $cluster -Confirm:$false
            #endregion
            
            #region stop nutanix cluster
                Write-Host "$(Get-Date) [INFO] Stopping Nutanix cluster..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/stop"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
                Write-Host "$(Get-Date) [SUCCESS] Cluster stop initiated" -ForegroundColor Cyan
                
                #wait for cluster to stop
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$($response.task_uuid)"
                $method = "GET"
                do {
                    $task = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    if ($task.progress_status -ne "Succeeded") { Start-Sleep -Seconds 30 }
                } while ($task.progress_status -ne "Succeeded")
                Write-Host "$(Get-Date) [SUCCESS] Cluster stopped" -ForegroundColor Cyan
            #endregion
            
            #region power off ESXi hosts
                Write-Host "$(Get-Date) [INFO] Powering off ESXi hosts..." -ForegroundColor Green
                $hosts = Get-VMHost
                ForEach ($host in $hosts) {
                    Write-Host "$(Get-Date) [INFO] Powering off host $($host.Name)..." -ForegroundColor Green
                    $host | Set-VMHost -State Maintenance -Confirm:$false
                    Stop-VMHost -VMHost $host -Confirm:$false
                }
                Write-Host "$(Get-Date) [SUCCESS] All hosts powered off" -ForegroundColor Cyan
            #endregion
        #endregion
    }

#endregion


#region cleanup
    Write-Host ""
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    
    Disconnect-VIServer -Server $cluster -Confirm:$false -WarningAction SilentlyContinue
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable start -ErrorAction SilentlyContinue
    Remove-Variable cvm -ErrorAction SilentlyContinue
    Remove-Variable vcentervmname -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vcenterCreds -ErrorAction SilentlyContinue
#endregion