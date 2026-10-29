<#
.SYNOPSIS
  This script is used to create DRS affinity groups and rules based on the Nutanix Metro Availability setup of a vSphere cluster.
.DESCRIPTION
  The script will look at the Metro Availability setup for a pair of given Nutanix clusters and will create DRS affinity groups and rules so that VMs will run on hosts which hold the active copy of a given replicated datastore. This is to avoid I/O going over two sites in normal conditions.  If DRS groups and rules already exist that match the naming convention used in this script, then it will update those groups and rules (unless you use the -noruleupdate switch in which case only groups will be updated).  This script requires having both the Nutanix cmdlets and PowerCLI installed.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER ntnx_cluster1
  First Nutanix cluster fully qualified domain name or IP address.
.PARAMETER ntnx_cluster2
  Second Nutanix cluster fully qualified domain name or IP address.
.PARAMETER vcenter
  Hostname or IP address of the vCenter Server.
.PARAMETER noruleupdate
  Use this switch if you do NOT want to update DRS rules. Only groups will be updated. This can be useful when using the script within the context of a failback.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
.PARAMETER vcenterCreds
  Specifies a custom credentials file name for vCenter authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$vcenterCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
  If you do not specify a credential file, the script will prompt you for this information, unless your logged in user already has access to vCenter.
.EXAMPLE
.\add-DRSAffinityRulesForMA.ps1 -ntnx_cluster1 ntnxc1.local -ntnx_cluster2 ntnxc2.local -vcenter vcenter1.local
Create DRS affinity groups and rules for ntnxc1 and ntnxc2 on vcenter1:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region A - parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$ntnx_cluster1,
	[parameter(mandatory = $false)] [string]$ntnx_cluster2,
    [parameter(mandatory = $false)] [string]$vcenter,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] $vcenterCreds,
    [parameter(mandatory = $false)] [switch]$noruleupdate
)
#endregion

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

#region B - functions
#this function is used to create a DRS host group
Function New-DrsHostGroup
{
<#
.SYNOPSIS
  Creates a new DRS host group
.DESCRIPTION
  This function creates a new DRS host group in the DRS Group Manager
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VMHost
  The hosts to add to the group. Supports objects from the pipeline.
.PARAMETER Cluster
  The cluster to create the new group on.
.PARAMETER Name
  The name for the new group.
.EXAMPLE
  PS> Get-VMHost ESX001,ESX002 | New-DrsHostGroup -Name "HostGroup01" -Cluster CL01
.EXAMPLE
  PS> New-DrsHostGroup -Host ESX001,ESX002 -Name "HostGroup01" -Cluster (Get-CLuster CL01)
#>

    Param(
        [parameter(valuefrompipeline = $true, mandatory = $true,
        HelpMessage = "Enter a host entity")]
            [PSObject]$VMHost,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name)

    begin {
        switch ($Cluster.gettype().name) {
            "String" {$cluster = Get-Cluster $cluster | Get-View}
            "ClusterImpl" {$cluster = $cluster | Get-View}
            "Cluster" {}
            default {throw "No valid type for parameter -Cluster specified"}
        }
        $spec = New-Object VMware.Vim.ClusterConfigSpecEx
        $group = New-Object VMware.Vim.ClusterGroupSpec
        $group.operation = "add"
        $group.Info = New-Object VMware.Vim.ClusterHostGroup
        $group.Info.Name = $Name
    }

    Process {
        switch ($VMHost.gettype().name) {
            "String[]" {Get-VMHost -Name $VMHost | ForEach-Object {$group.Info.Host += $_.Extensiondata.MoRef}}
            "String" {Get-VMHost -Name $VMHost | ForEach-Object {$group.Info.Host += $_.Extensiondata.MoRef}}
            "VMHostImpl" {$group.Info.Host += $VMHost.Extensiondata.MoRef}
            "HostSystem" {$group.Info.Host += $VMHost.MoRef}
            default {throw "No valid type for parameter -VMHost specified"}
        }
    }

    End {
        if ($group.Info.Host) {
            $spec.GroupSpec += $group
            $cluster.ReconfigureComputeResource_Task($spec,$true) | Out-Null
        }
        else {
            throw "No valid hosts specified"
        }
    }
}

#this function is used to create a DRS VM group
Function New-DrsVmGroup
{
<#
.SYNOPSIS
  Creates a new DRS VM group
.DESCRIPTION
  This function creates a new DRS VM group in the DRS Group Manager
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VM
  The VMs to add to the group. Supports objects from the pipeline.
.PARAMETER Cluster
  The cluster to create the new group on.
.PARAMETER Name
  The name for the new group.
.EXAMPLE
  PS> Get-VM VM001,VM002 | New-DrsVmGroup -Name "VmGroup01" -Cluster CL01
.EXAMPLE
  PS> New-DrsVmGroup -VM VM001,VM002 -Name "VmGroup01" -Cluster (Get-CLuster CL01)
#>

    Param(
        [parameter(valuefrompipeline = $true, mandatory = $true,
        HelpMessage = "Enter a vm entity")]
            [PSObject]$VM,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name)

    begin {
        switch ($Cluster.gettype().name) {
            "String" {$cluster = Get-Cluster $cluster | Get-View}
            "ClusterImpl" {$cluster = $cluster | Get-View}
            "Cluster" {}
            default {throw "No valid type for parameter -Cluster specified"}
        }
        $spec = New-Object VMware.Vim.ClusterConfigSpecEx
        $group = New-Object VMware.Vim.ClusterGroupSpec
        $group.operation = "add"
        $group.Info = New-Object VMware.Vim.ClusterVmGroup
        $group.Info.Name = $Name
    }

    Process {
        switch ($VM.gettype().name) {
            "String[]" {Get-VM -Name $VM | ForEach-Object {$group.Info.VM += $_.Extensiondata.MoRef}}
            "String" {Get-VM -Name $VM | ForEach-Object {$group.Info.VM += $_.Extensiondata.MoRef}}
            "VirtualMachineImpl" {$group.Info.VM += $VM.Extensiondata.MoRef}
            "VirtualMachine" {$group.Info.VM += $VM.MoRef}
            default {throw "No valid type for parameter -VM specified"}
        }
    }

    End {
        if ($group.Info.VM) {
            $spec.GroupSpec += $group
            $cluster.ReconfigureComputeResource_Task($spec,$true) | Out-Null
        }
        else {
            throw "No valid VMs specified"
        }
    }
}

#this function is used to create a VM to host DRS rule
Function New-DRSVMToHostRule
{
<#
.SYNOPSIS
  Creates a new DRS VM to host rule
.DESCRIPTION
  This function creates a new DRS vm to host rule
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VMGroup
  The VMGroup name to include in the rule.
.PARAMETER HostGroup
  The VMHostGroup name to include in the rule.
.PARAMETER Cluster
  The cluster to create the new rule on.
.PARAMETER Name
  The name for the new rule.
.PARAMETER AntiAffine
  Switch to make the rule an AntiAffine rule. Default rule type is Affine.
.PARAMETER Mandatory
  Switch to make the rule mandatory (Must run rule). Default rule is not mandatory (Should run rule)
.EXAMPLE
  PS> New-DrsVMToHostRule -VMGroup "VMGroup01" -HostGroup "HostGroup01" -Name "VMToHostRule01" -Cluster CL01 -AntiAffine -Mandatory
#>

    Param(
        [parameter(mandatory = $true,
        HelpMessage = "Enter a VM DRS group name")]
            [String]$VMGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a host DRS group name")]
            [String]$HostGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name,
            [Switch]$AntiAffine,
            [Switch]$Mandatory)

    switch ($Cluster.gettype().name) {
        "String" {$cluster = Get-Cluster $cluster | Get-View}
        "ClusterImpl" {$cluster = $cluster | Get-View}
        "Cluster" {}
        default {throw "No valid type for parameter -Cluster specified"}
    }

    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $rule = New-Object VMware.Vim.ClusterRuleSpec
    $rule.operation = "add"
    $rule.info = New-Object VMware.Vim.ClusterVmHostRuleInfo
    $rule.info.enabled = $true
    $rule.info.name = $Name
    $rule.info.mandatory = $Mandatory
    $rule.info.vmGroupName = $VMGroup
    if ($AntiAffine) {
        $rule.info.antiAffineHostGroupName = $HostGroup
    }
    else {
        $rule.info.affineHostGroupName = $HostGroup
    }
    $spec.RulesSpec += $rule
    $cluster.ReconfigureComputeResource_Task($spec,$true) | Out-Null
}

#this function is used to edit an existing DRS rule
Function Update-DrsVMGroup
{
<#
.SYNOPSIS
Update DRS VM group with a new collection of VM´s

.DESCRIPTION
Use this function to update the ClusterVMgroup with VMs that are sent in by parameters

.PARAMETER  xyz

.NOTES
Author: Niklas Akerlund / RTS (most of the code came from http://communities.vmware.com/message/1667279 @LucD22 and GotMoo)
Date: 2012-06-28
#>
	param
    (
	    $cluster,
	    $VMs,
	    $groupVMName
    )

    $cluster = Get-Cluster $cluster
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $groupVM = New-Object VMware.Vim.ClusterGroupSpec
    #Operation edit will replace the contents of the GroupVMName with the new contents seleced below.
    $groupVM.operation = "edit"

    $groupVM.Info = New-Object VMware.Vim.ClusterVmGroup
    $groupVM.Info.Name = $groupVMName

    Get-VM $VMs | ForEach-Object {$groupVM.Info.VM += $_.Extensiondata.MoRef}
    $spec.GroupSpec += $groupVM

    #Apply the settings to the cluster
    $cluster.ExtensionData.ReconfigureComputeResource($spec,$true)
}

#this function is used to edit an existing DRS rule
Function Update-DrsHostGroup
{
<#
.SYNOPSIS
Update DRS Host group with a new collection of Hosts

.DESCRIPTION
Use this function to update the ClusterHostgroup with Hosts that are sent in by parameters

.PARAMETER  xyz

.NOTES
Author: Niklas Akerlund / RTS (most of the code came from http://communities.vmware.com/message/1667279 @LucD22 and GotMoo)
Date: 2012-06-28
#>
	param
    (
	    $cluster,
	    $Hosts,
	    $groupHostName
    )

    $cluster = Get-Cluster $cluster
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $groupHost = New-Object VMware.Vim.ClusterGroupSpec
    #Operation edit will replace the contents of the GroupVMName with the new contents seleced below.
    $groupHost.operation = "edit"

    $groupHost.Info = New-Object VMware.Vim.ClusterHostGroup
    $groupHost.Info.Name = $groupHostName

    Get-VMHost $Hosts | ForEach-Object {$groupHost.Info.Host += $_.Extensiondata.MoRef}
    $spec.GroupSpec += $groupHost

    #Apply the settings to the cluster
    $cluster.ExtensionData.ReconfigureComputeResource($spec,$true)
}

#this function is used to create a VM to host DRS rule
Function Update-DRSVMToHostRule
{
<#
.SYNOPSIS
  Creates a new DRS VM to host rule
.DESCRIPTION
  This function creates a new DRS vm to host rule
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VMGroup
  The VMGroup name to include in the rule.
.PARAMETER HostGroup
  The VMHostGroup name to include in the rule.
.PARAMETER Cluster
  The cluster to create the new rule on.
.PARAMETER Name
  The name for the new rule.
.PARAMETER AntiAffine
  Switch to make the rule an AntiAffine rule. Default rule type is Affine.
.PARAMETER Mandatory
  Switch to make the rule mandatory (Must run rule). Default rule is not mandatory (Should run rule)
.EXAMPLE
  PS> New-DrsVMToHostRule -VMGroup "VMGroup01" -HostGroup "HostGroup01" -Name "VMToHostRule01" -Cluster CL01 -AntiAffine -Mandatory
#>

    Param(
        [parameter(mandatory = $true,
        HelpMessage = "Enter a VM DRS group name")]
            [String]$VMGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a DRS rule key")]
            [String]$RuleKey,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a DRS rule uuid")]
            [String]$RuleUuid,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a host DRS group name")]
            [String]$HostGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name,
            [Switch]$AntiAffine,
            [Switch]$Mandatory)

    switch ($Cluster.gettype().name) {
        "String" {$cluster = Get-Cluster $cluster | Get-View}
        "ClusterImpl" {$cluster = $cluster | Get-View}
        "Cluster" {}
        default {throw "No valid type for parameter -Cluster specified"}
    }

    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $rule = New-Object VMware.Vim.ClusterRuleSpec
    $rule.operation = "edit"
    $rule.info = New-Object VMware.Vim.ClusterVmHostRuleInfo
    $rule.info.enabled = $true
    $rule.info.name = $Name
    $rule.info.mandatory = $Mandatory
    $rule.info.vmGroupName = $VMGroup
    $rule.info.Key = $RuleKey
    $rule.info.RuleUuid = $RuleUuid
    if ($AntiAffine) {
        $rule.info.antiAffineHostGroupName = $HostGroup
    }
    else {
        $rule.info.affineHostGroupName = $HostGroup
    }
    $spec.RulesSpec += $rule
    $cluster.ReconfigureComputeResource_Task($spec,$true) | Out-Null
}
#endregion

#region C - prepwork
    #region C1 - misc preparation
        # get rid of annoying error messages
        #if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter and OutputLogData function
10/06/2015 sb   Initial release.
06/21/2016 sb   Updated code to support refresh of existing rules as well as
                 partial groups and rules creation.  Changed default groups and
                 rule naming to simplify them.  Added the -noruleupdate switch.
09/15/2016 sb   Changed password input to secure string
06/05/2018 sb   Updated script to use REST API instead of NTNX cmdlets
06/27/2018 sb   Added BetterTls module for Tls 1.2
07/17/2018 sb   Added check for PoSH version and removed silentlycontinue as
                 default for erroractionpreference
09/03/2019 sb   Added yet additional error control.  Removed dependencies on
                 sbourdeaud and BetterTls modules.
02/06/2021 sb   Replaced username with get-credential
################################################################################
'
        $myvarScriptName = ".\add-DRSAffinityRulesForMA.ps1"

        if ($help) 
        {
            get-help $myvarScriptName
            exit
        }
        if ($History) {
        $HistoryText
        exit
    }
    
        if ($PSVersionTable.PSVersion.Major -lt 5) 
        {#check PoSH version
            throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
        }
    #endregion

    #check if we have all the required PoSH modules
    Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

    #region C4 - Load/Install VMware.PowerCLI
        if (!(Get-Module VMware.PowerCLI)) 
        {#module VMware.PowerCLI is not loaded
            try 
            {#load module VMware.PowerCLI
                Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                Import-Module VMware.PowerCLI -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
            }
            catch 
            {#couldn't load module VMware.PowerCLI
                Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
                try 
                {#install module VMware.PowerCLI
                    Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
                    Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
                    try 
                    {#loading module VMware.PowerCLI
                        Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                        Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
                    }
                    catch 
                    {#couldn't load module VMware.PowerCLI
                        throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
                    }
                }
                catch 
                {#couldn't install module VMware.PowerCLI
                    throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"
                }
            }
        }
        
        if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
        {#check PowerCLI version
            try 
            {#update module VMware.PowerCLI
                Update-Module -Name VMware.PowerCLI -ErrorAction Stop
            } 
            catch 
            {#couldn't update module VMware.PowerCLI
                throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"
            }
        }
    #endregion
#endregion

#region D - parameters validation	
    if (!$vcenter) 
    {#prompt for vcenter server name
        $vcenter = read-host "Enter vCenter server name or IP address"
    }
	$myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
    
    if (!$ntnx_cluster1) 
    {#prompt for the first Nutanix cluster name
        $ntnx_cluster1 = read-host "Enter the hostname or IP address of the first Nutanix cluster"
    }
    if (!$ntnx_cluster2) 
    {#prompt for the second Nutanix cluster name
        $ntnx_cluster2 = read-host "Enter the hostname or IP address of the second Nutanix cluster"
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

    if ($vcenterCreds) 
    {#vcenterCreds was specified
        try 
        {
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
            $vcenterUsername = $vcenterCredentials.UserName
            $vcenterSecurePassword = $vcenterCredentials.Password
        }
        catch 
        {
            Set-CustomCredentials -credname $vcenterCreds
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
            $vcenterUsername = $vcenterCredentials.UserName
            $vcenterSecurePassword = $vcenterCredentials.Password
        }
        $vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword
    }
	else 
	{#no vcenter creds were given
		$vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
	}
#endregion

#region E - processing
    #region Prism Element
	#building a variable containing the Nutanix cluster names
	$myvarNutanixClusters = @($ntnx_cluster1,$ntnx_cluster2)
	#initialize variables we'll need to store information about the Nutanix clusters
	$myvarNtnxC1_hosts, $myvarNtnxC2_hosts, $myvarNtnxC1_MaActiveCtrs, $myvarNtnxC2_MaActiveCtrs = @()
	$myvarCounter = 1 #we use this to store results differently for cluster 1 and 2
    
	foreach ($myvarNutanixCluster in $myvarNutanixClusters)
	{#connect to each Nutanix cluster to figure out the info we need
		if ($myvarCounter -eq 1) 
		{#we're processing data from cluster 1    
            Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
            $url = "https://$($myvarNutanixCluster):9440/PrismGateway/services/rest/v2.0/cluster/"
            $method = "GET"
            try 
            {
                $myvarNTNXCluster1Info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve cluster information from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
            $myvarNTNXCluster1Name = $myvarNTNXCluster1Info.name

            Write-Host "$(get-date) [INFO] Retrieving hosts information from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
            $url = "https://$($myvarNutanixCluster):9440/PrismGateway/services/rest/v2.0/hosts/"
            $method = "GET"
            try 
            {
                $NTNXHosts = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve hosts information from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
            $myvarNtnxC1_hosts = ($NTNXHosts.entities).hypervisor_address

            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
            $url = "https://$($myvarNutanixCluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            try 
            {
                $myvarMaActivePDs = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve protection domains from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
            }
            $myvarNtnxC1_MaActiveCtrs = ($myvarMaActivePDs.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
		}
		if ($myvarCounter -eq 2) 
		{#we're processing data from cluster 2
            Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
            $url = "https://$($myvarNutanixCluster):9440/PrismGateway/services/rest/v2.0/cluster/"
            $method = "GET"
            try 
            {
                $myvarNTNXCluster2Info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve cluster information from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
            $myvarNTNXCluster2Name = $myvarNTNXCluster2Info.name

            Write-Host "$(get-date) [INFO] Retrieving hosts information from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
            $url = "https://$($myvarNutanixCluster):9440/PrismGateway/services/rest/v2.0/hosts/"
            $method = "GET"
            try
            {
                $NTNXHosts = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch 
            {
                throw "$(get-date) [ERROR] Could not retrieve hosts information from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
            $myvarNtnxC2_hosts = ($NTNXHosts.entities).hypervisor_address

            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
            $url = "https://$($myvarNutanixCluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            try 
            {
                $myvarMaActivePDs = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch 
            {
                throw "$(get-date) [ERROR] Could not retrieve protection domains from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
            }
            $myvarNtnxC2_MaActiveCtrs = ($myvarMaActivePDs.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
        }

		#increment the counter
		++$myvarCounter
    }#end foreach Nutanix cluster loop
    #endregion

    #region vCenter
    #$result = Disconnect-viserver * -Confirm:$False -ErrorAction SilentlyContinue #making sure we are not already connected to a vCenter server
    
    #* CUSTOMIZATION: if you want to edit the object names, check out the section below
    if ($myvarNTNXCluster1Name)
    {
        $myvarNutanixCluster_1_HostGroupName = "DRS_HG_MA_" + $myvarNTNXCluster1Name
    }
    else 
    {
        $myvarNutanixCluster_1_HostGroupName = "DRS_HG_MA_" + $ntnx_cluster1
    }
    
    if ($myvarNTNXCluster2Name)
    {
        $myvarNutanixCluster_2_HostGroupName = "DRS_HG_MA_" + $myvarNTNXCluster2Name
    }
    else 
    {
        $myvarNutanixCluster_2_HostGroupName = "DRS_HG_MA_" + $ntnx_cluster2
    }
    #! for vm group names, search for multiple instances of $myvarDRSVMGroupName =
    #! for DRS rule names, search for multiple instances of $myvarDRSRuleName =

	foreach ($myvarvCenter in $myvarvCenterServers)
    {#connect to vcenter now
        #region connect
		Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
		if (!($myvarvCenterObject = Connect-VIServer $myvarvCenter -Credential $vcenterCredentials))
		{#make sure we can connect to the vCenter server
			$myvarerror = $error[0].Exception.Message
			Write-Host "$(get-date) [ERROR] $myvarerror" -ForegroundColor Red
			return
		}
		else 
		{#...otherwise show the error message
			Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter." -ForegroundColor Cyan
        }#endelse
        #endregion

        #region process
		if ($myvarvCenterObject)
		{#process vcenter

            #region process hosts
                #let's match host IP addresses we got from the Nutanix clusters to VMHost objects in vCenter
                $myvarNtnxC1_vmhosts = @() #this is where we will save the hostnames of the hosts which make up the first Nutanix cluster
                $myvarNtnxC2_vmhosts = @() #this is where we will save the hostnames of the hosts which make up the second Nutanix cluster
                Write-Host "$(get-date) [INFO] Getting hosts registered in vCenter server $myvarvCenter..." -ForegroundColor Green
                try 
                {#get all the vmhosts registered in vCenter
                    $myvarVMHosts = Get-VMHost -ErrorAction Stop 
                    Write-Host "$(get-date) [SUCCESS] Successfully retrieved vmhosts from vCenter server $myvarvCenter" -ForegroundColor Cyan
                }
                catch
                {#couldn't get all the vmhosts registered in vCenter
                    throw "$(get-date) [ERROR] Could not retrieve vmhosts from vCenter server $myvarvCenter : $($_.Exception.Message)"
                }
                foreach ($myvarVMHost in $myvarVMHosts) 
                {#let's look at each host and determine which is which
                    Write-Host "$(get-date) [INFO] Retrieving vmk interfaces for host $myvarVMHost..." -ForegroundColor Green
                    try 
                    {#retrieve all vmk NICs for that host
                        $myvarHostVmks = $myvarVMHost | Get-VMHostNetworkAdapter -ErrorAction Stop | Where-Object {$_.DeviceName -like "vmk*"} 
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved vmk interfaces for host $myvarVMHost" -ForegroundColor Cyan
                    }
                    catch
                    {#couldn't retrieve all vmk NICs for that host
                        throw "$(get-date) [ERROR] Could not retrieve vmk interfaces for host $myvarVMHost : $($_.Exception.Message)"
                    }
                    foreach ($myvarHostVmk in $myvarHostVmks) 
                    {#examine all VMKs
                        foreach ($myvarHostIP in $myvarNtnxC1_hosts) 
                        {#compare to the host IP addresses we got from the Nutanix cluster 1
                            if ($myvarHostVmk.IP -eq $myvarHostIP)
                            {#if we get a match, that vcenter host is in cluster 1
                                Write-Host "$(get-date) [INFO] $($myvarVMHost.Name) is a host in Nutanix cluster $ntnx_cluster1..." -ForegroundColor Green
                                $myvarNtnxC1_vmhosts += $myvarVMHost
                            }
                        }#end foreach IP C1 loop
                        foreach ($myvarHostIP in $myvarNtnxC2_hosts) 
                        {#compare to the host IP addresses we got from the Nutanix cluster 2
                            if ($myvarHostVmk.IP -eq $myvarHostIP)
                            {#if we get a match, that vcenter host is in cluster 2
                                Write-Host "$(get-date) [INFO] $($myvarVMHost.Name) is a host in Nutanix cluster $ntnx_cluster2..." -ForegroundColor Green
                                $myvarNtnxC2_vmhosts += $myvarVMHost 
                            }
                        }#end foreacch IP C2 loop
                    }#end foreach VMK loop
                }#end foreach VMhost loop

                if (!$myvarNtnxC1_vmhosts) 
                {#couldn't find hosts in cluster1
                    throw "$(get-date) [ERROR] No vmhosts were found for Nutanix cluster $ntnx_cluster1 in vCenter server $myvarvCenter"
                }
                if (!$myvarNtnxC2_vmhosts) 
                {#couldn't find hosts in cluster2
                    throw "$(get-date) [ERROR] No vmhosts were found for Nutanix cluster $ntnx_cluster2 in vCenter server $myvarvCenter"
                }

                #check all vmhosts are part of the same vSphere cluster
                Write-Host "$(get-date) [INFO] Checking that all hosts are part of the same compute cluster..." -ForegroundColor Green
                try 
                {#we look at which cluster the first vmhost in cluster 1 belongs to.
                    $myvarvSphereCluster = $myvarNtnxC1_vmhosts[0] | Get-Cluster -ErrorAction Stop 
                }
                catch 
                {
                    throw "$(get-date) [ERROR] Could not retrieve vSphere cluster for host $($myvarNtnxC1_vmhosts[0].Name) : $($_.Exception.Message)"
                }
                
                $myvarvSphereClusterName = $myvarvSphereCluster.Name
                $myvarvSphereClusterVMHosts = $myvarNtnxC1_vmhosts + $myvarNtnxC2_vmhosts #let's create an array with all vmhosts that should be in the compute cluster

                
                try 
                {#get existing DRS groups
                    $myvarClusterObject = get-cluster $myvarvSphereClusterName -ErrorAction Stop
                    $myvarDRSGroups = $myvarClusterObject.ExtensionData.ConfigurationEx.group
                }
                catch 
                {#couldn't get existing DRS groups
                    throw "$(get-date) [ERROR] Could not retrieve vSphere object for cluster $myvarvSphereClusterName : $($_.Exception.Message)"
                }
                
                #get existing DRS rules
                try 
                {
                    $myvarClusterComputeResourceView = Get-View -ErrorAction Stop -ViewType ClusterComputeResource -Property Name, ConfigurationEx | where-object {$_.Name -eq $myvarvSphereClusterName}
                    $myvarClusterDRSRules = $myvarClusterComputeResourceView.ConfigurationEx.Rule
                }
                catch 
                {
                    throw "$(get-date) [ERROR] Could not retrieve existing DRS rules for cluster $myvarvSphereClusterName : $($_.Exception.Message)"
                }
                
                foreach ($myvarvSphereClusterVMHost in $myvarvSphereClusterVMHosts) 
                {#let's now look at each vmhost and which cluster they belong to
                    try 
                    {#which cluster does this host belong to?
                        $myvarVMHostCluster = $myvarvSphereClusterVMHost | Get-Cluster -ErrorAction Stop 
                    }
                    catch 
                    {
                        throw "$(get-date) [ERROR] Could not retrieve vSphere cluster object for vmhost $myvarvSphereClusterVMHost : $($_.Exception.Message)"
                    }
                    
                    if ($myvarVMHostCluster -ne $myvarvSphereCluster) 
                    {#let's check if it's the same cluster as our first host
                        $myvarVMHostName = $myvarvSphereClusterVMHost.Name
                        $myvarVMHostClusterName = $myvarVMHostCluster.Name
                        Write-Host "$(get-date) [ERROR] $myvarVMHostName belongs to vSphere cluster $myvarVMHostClusterName when it should be in $myvarvSphereClusterName..." -ForegroundColor Red
                        break #we'l stop right here since at least one vmhost is not in the right compute cluster
                    }
                }#end foreach cluster vmhost loop

                #check that vSphere cluster has HA and DRS enabled
                Write-Host "$(get-date) [INFO] Checking HA is enabled on vSphere cluster $myvarvSphereClusterName..." -ForegroundColor Green
                if ($myvarvSphereCluster.HaEnabled -ne $true) {Write-Host "$(get-date) [WARNING] HA is not enabled on vSphere cluster $myvarvSphereClusterName!" -ForegroundColor Yellow}
                Write-Host "$(get-date) [INFO] Checking DRS is enabled on vSphere cluster $myvarvSphereClusterName..." -ForegroundColor Green
                if ($myvarvSphereCluster.DrsEnabled -ne $true)
                {
                    Write-Host "$(get-date) [ERROR] DRS is not enabled on vSphere cluster $myvarvSphereClusterName!" -ForegroundColor Red
                    break #exit since DRS is not enabled
                }

                #check to see if the host group already exists
                $myvarDRSHostGroups = $myvarDRSGroups | Where-Object {$_.host} #keep host groups

                #CREATE DRS affinity groups for hosts in each nutanix cluster
                $myvarNtnxC1_DRSHostGroupName = $myvarNutanixCluster_1_HostGroupName
                $myvarNtnxC2_DRSHostGroupName = $myvarNutanixCluster_2_HostGroupName

                #do we have an existing DRS host group for c1 already?
                if ($myvarDRSHostGroups | Where-Object {$_.Name -eq $myvarNtnxC1_DRSHostGroupName})
                { #yes, so let's update it
                    Write-Host "$(get-date) [INFO] Updating DRS Host Group $myvarNtnxC1_DRSHostGroupName on cluster $myvarvSphereCluster" -ForegroundColor Green
                    Update-DrsHostGroup -cluster $myvarvSphereCluster -Hosts $myvarNtnxC1_vmhosts -groupHostName $myvarNtnxC1_DRSHostGroupName
                }
                else
                { #no, so let's create it
                    Write-Host "$(get-date) [INFO] Creating DRS Host Group $myvarNtnxC1_DRSHostGroupName on cluster $myvarvSphereClusterName for $ntnx_cluster1..." -ForegroundColor Green
                    $myvarNtnxC1_vmhosts | New-DrsHostGroup -Name $myvarNtnxC1_DRSHostGroupName -Cluster $myvarvSphereCluster
                }

                #do we have an existing DRS host group for c2 already?
                if ($myvarDRSHostGroups | Where-Object {$_.Name -eq $myvarNtnxC2_DRSHostGroupName})
                { #yes, so let's update it
                    Write-Host "$(get-date) [INFO] Updating DRS Host Group $myvarNtnxC2_DRSHostGroupName on cluster $myvarvSphereCluster" -ForegroundColor Green
                    Update-DrsHostGroup -cluster $myvarvSphereCluster -Hosts $myvarNtnxC2_vmhosts -groupHostName $myvarNtnxC2_DRSHostGroupName
                }
                else
                { #no, so let's create it
                    Write-Host "$(get-date) [INFO] Creating DRS Host Group $myvarNtnxC2_DRSHostGroupName on cluster $myvarvSphereClusterName for $ntnx_cluster2..." -ForegroundColor Green
                    $myvarNtnxC2_vmhosts | New-DrsHostGroup -Name $myvarNtnxC2_DRSHostGroupName -Cluster $myvarvSphereCluster
                }

                #now let's process the datastores
                Write-Host "$(get-date) [INFO] Getting datastores registered in vCenter server $myvarvCenter..." -ForegroundColor Green
                try 
                {#get all the datastores registered in vCenter
                    $myvarDatastores = Get-Datastore -ErrorAction Stop 
                    Write-Host "$(get-date) [SUCCESS] Successfully retrieved datastores from vCenter server $myvarvCenter" -ForegroundColor Cyan
                }
                catch
                {#couldn't get all the datastores registered in vCenter
                    throw "$(get-date) [ERROR] Could not retrieve datastores from vCenter server $myvarvCenter : $($_.Exception.Message)"
                }

                #let's match datastore names we got from the Nutanix clusters to Datastore objects in vCenter
                $myvarNtnxC1_Datastores = @() #this is where we will save the datastores which make up the first Nutanix cluster
                $myvarNtnxC2_Datastores = @() #this is where we will save the datastores which make up the second Nutanix cluster
                foreach ($myvarDatastore in $myvarDatastores) 
                {#let's look at each datastore and determine which is which
                    foreach ($myvarCtrName in $myvarNtnxC1_MaActiveCtrs) 
                    {#compare to the container names we got from the Nutanix cluster 1
                        if ($myvarDatastore.Name -eq $myvarCtrName)
                        {#if we get a match, that datastore is in cluster 1
                            Write-Host "$(get-date) [INFO] $($myvarDatastore.Name) is a container in Nutanix cluster $ntnx_cluster1..." -ForegroundColor Green
                            $myvarNtnxC1_Datastores += $myvarDatastore
                        }
                    }#end foreach container C1 loop
                    foreach ($myvarCtrName in $myvarNtnxC2_MaActiveCtrs) 
                    {#compare to the container names we got from the Nutanix cluster 2
                        if ($myvarDatastore.Name -eq $myvarCtrName)
                        {#if we get a match, that datastore is in cluster 2
                            Write-Host "$(get-date) [INFO] $($myvarDatastore.Name) is a container in Nutanix cluster $ntnx_cluster2..." -ForegroundColor Green
                            $myvarNtnxC2_Datastores += $myvarDatastore 
                        }
                    }#end foreach container C2 loop
                }#end foreach datastore loop

                if (!$myvarNtnxC1_Datastores) 
                {#couldn't find containers in cluster1
                    throw "$(get-date) [ERROR] No metro availability datastores were found for Nutanix cluster $ntnx_cluster1 in vCenter server $myvarvCenter"
                }
                if (!$myvarNtnxC2_Datastores) 
                {#couldn't find containers in cluster2
                    throw "$(get-date) [ERROR] No metro availability datastores were found for Nutanix cluster $ntnx_cluster2 in vCenter server $myvarvCenter"
                }

                #now let's create VM groups and rules for each datastore
                foreach ($myvarDatastore in $myvarNtnxC1_Datastores) 
                {#process each datastore from cluster 1
                    #CUSTOMIZATION: if you want to edit the object names, check out the section below
                    $myvarDRSVMGroupName = "DRS_VMG_MA_" + $myvarDatastore.Name
                    $myvarDRSRuleName = "MA_" + $myvarDatastore.Name + "_Should_Run_On_" + $myvarNTNXCluster1Name

                    Write-Host "$(get-date) [INFO] Getting VMs running on datastore $($myvarDatastore.Name)..." -ForegroundColor Green
                    $myvarDatastoreVMs = $myvarDatastore | Get-VM -ErrorAction Stop
                    
                    #do we have an existing DRS VM group already?
                    $myvarDRSVMGroups = $myvarDRSGroups | Where-Object {$_.VM} #keep VM groups
                    if ($myvarDRSVMGroups | Where-Object {$_.Name -eq $myvarDRSVMGroupName})
                    { #yes, so let's update it
                        Write-Host "$(get-date) [INFO] Updating DRS VM Group $myvarDRSVMGroupName on cluster $myvarvSphereCluster" -ForegroundColor Green
                        Update-DrsVMGroup -cluster $myvarvSphereCluster -VMs $myvarDatastoreVMs -groupVMName $myvarDRSVMGroupName
                    }
                    else
                    { #no, so let's create it
                        Write-Host "$(get-date) [INFO] Creating DRS VM Group $myvarDRSVMGroupName on cluster $myvarvSphereClusterName for datastore $($myvarDatastore.Name)..." -ForegroundColor Green
                        $myvarDatastoreVMs | New-DrsVmGroup -Name $myvarDRSVMGroupName -Cluster $myvarvSphereCluster
                    }

                    #do we have an existing DRS rule already?
                    if (!$noruleupdate)
                    {
                        if ($myvarClusterDRSRules | Where-Object {$_.Name -eq $myvarDRSRuleName})
                        { #yes, so let's update it
                            $myvarExistingRule = $myvarClusterDRSRules | Where-Object {$_.Name -eq $myvarDRSRuleName}
                            Write-Host "$(get-date) [INFO] Updating DRS Rule $myvarDRSRuleName on cluster $myvarvSphereCluster" -ForegroundColor Green
                            Update-DRSVMToHostRule -VMGroup $myvarDRSVMGroupName -HostGroup $myvarNtnxC1_DRSHostGroupName -RuleKey $myvarExistingRule.Key -RuleUuid $myvarExistingRule.RuleUuid -Name $myvarDRSRuleName -Cluster $myvarvSphereCluster -Mandatory
                        }
                        else
                        { #no, so let's create it
                            Write-Host "$(get-date) [INFO] Creating DRS Rule $myvarDRSRuleName on cluster $myvarvSphereClusterName..." -ForegroundColor Green
                            New-DRSVMToHostRule -VMGroup $myvarDRSVMGroupName -HostGroup $myvarNtnxC1_DRSHostGroupName -Name $myvarDRSRuleName -Cluster $myvarvSphereCluster -Mandatory
                        }
                    }
                }#end foreach datastore C1 loop

                foreach ($myvarDatastore in $myvarNtnxC2_Datastores) 
                {#process each datastore from cluster 2
                    #CUSTOMIZATION: if you want to edit the object names, check out the section below
                    $myvarDRSVMGroupName = "DRS_VMG_MA_" + $myvarDatastore.Name
                    $myvarDRSRuleName = "MA_" + $myvarDatastore.Name + "_Should_Run_On_" + $myvarNTNXCluster2Name

                    Write-Host "$(get-date) [INFO] Getting VMs running on datastore $($myvarDatastore.Name)..." -ForegroundColor Green
                    $myvarDatastoreVMs = $myvarDatastore | Get-VM -ErrorAction Stop
                    
                    #do we have an existing DRS VM group already?
                    $myvarDRSVMGroups = $myvarDRSGroups | Where-Object {$_.VM} #keep VM groups
                    if ($myvarDRSVMGroups | Where-Object {$_.Name -eq $myvarDRSVMGroupName})
                    { #yes, so let's update it
                        Write-Host "$(get-date) [INFO] Updating DRS VM Group $myvarDRSVMGroupName on cluster $myvarvSphereCluster" -ForegroundColor Green
                        Update-DrsVMGroup -cluster $myvarvSphereCluster -VMs $myvarDatastoreVMs -groupVMName $myvarDRSVMGroupName
                    }
                    else
                    { #no, so let's create it
                        Write-Host "$(get-date) [INFO] Creating DRS VM Group $myvarDRSVMGroupName on cluster $myvarvSphereClusterName for datastore $($myvarDatastore.Name)..." -ForegroundColor Green
                        $myvarDatastoreVMs | New-DrsVmGroup -Name $myvarDRSVMGroupName -Cluster $myvarvSphereCluster
                    }

                    #do we have an existing DRS rule already?
                    if (!$noruleupdate)
                    {
                        if ($myvarClusterDRSRules | Where-Object {$_.Name -eq $myvarDRSRuleName})
                        { #yes, so let's update it
                            $myvarExistingRule = $myvarClusterDRSRules | Where-Object {$_.Name -eq $myvarDRSRuleName}
                            Write-Host "$(get-date) [INFO] Updating DRS Rule $myvarDRSRuleName on cluster $myvarvSphereCluster" -ForegroundColor Green
                            Update-DRSVMToHostRule -VMGroup $myvarDRSVMGroupName -HostGroup $myvarNtnxC2_DRSHostGroupName -RuleKey $myvarExistingRule.Key -RuleUuid $myvarExistingRule.RuleUuid -Name $myvarDRSRuleName -Cluster $myvarvSphereCluster -Mandatory
                        }
                        else
                        { #no, so let's create it
                            Write-Host "$(get-date) [INFO] Creating DRS Rule $myvarDRSRuleName on cluster $myvarvSphereClusterName..." -ForegroundColor Green
                            New-DRSVMToHostRule -VMGroup $myvarDRSVMGroupName -HostGroup $myvarNtnxC2_DRSHostGroupName -Name $myvarDRSRuleName -Cluster $myvarvSphereCluster -Mandatory
                        }
                    }
                }#end foreach datastore C2 loop

        #endregion
        }#endelse process vcenter
        Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
		Disconnect-viserver -Confirm:$False #cleanup after ourselves and disconnect from vcenter
    }#end foreach vCenter
#endregion

#region cleanup
	#let's figure out how much time this all took
	Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable debugme -ErrorAction SilentlyContinue
	Remove-Variable ntnx_cluster1 -ErrorAction SilentlyContinue
    Remove-Variable ntnx_cluster2 -ErrorAction SilentlyContinue
    Remove-Variable vcenter -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vcenterCreds -ErrorAction SilentlyContinue
    Remove-Variable noruleupdate -ErrorAction SilentlyContinue
#endregion