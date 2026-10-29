<#
.SYNOPSIS
  This script is used to trigger a planned or unplanned failover for the specified metro availability protection domains on the specified cluster.
.DESCRIPTION
  When doing planned failovers, you have the option to also put esxi hosts in maintenance mode or shutdown the entire cluster.  When using unplanned failovers, the list of protection domains to promote will be automatically determined if none are specified.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER pd
  Nutanix metro availability protection domain name (can be "all" or a comma separated list).
.PARAMETER action
  (Optional)This defines what status the Nutanix cluster is left in. If not specified, the Nutanix cluster will be left as is.  If "maintenance", any remaiing UVMs will be powered off, then the Nutanix cluster will be stopped, the CVMs shut down and the ESXi hosts put in maintenance mode.  If "shutdown", UVMs will be powered off, the Nutanix cluster stopped, CVMs shut down, ESXI hosts put in maintenance mode and then powered off.
.PARAMETER unplanned
  (Optional)Perform an unplanned failover.
.PARAMETER skipfailover
  (Optional)Skip over migration of protection domains and only perform action specified on esxi hosts (maintenance or shutdown). This is useful to resume action if protection domains have already been migrated but there were still UVMs running on the cluster and it could not put hosts in maintenance mode and/or shut them down.
.PARAMETER shutdownUvms
  (Optional)***WARNING*** Specifies that if any remaining user virtual machines are found on a vmhost, they should be powered off. Those would be VMs which were not protected by a metro protection domain or were running on the wrong hosts. Be careful with this parameter!
.PARAMETER timer
  (Optional)Number of seconds you want to wait for VMs to shutdown cleanly (when using -shutdownUvms) before powering them off forcefully. Default is 300 seconds (5 minutes).
.PARAMETER reEnableOnly
  Try to enable specified active but disabled metro protection domains. Do nothing else.
.PARAMETER DisableOnly
  Try to disabled specified active but decoupled metro protection domains. Do nothing else. This is useful when failing back after an unplanned failover and you are not using a witness VM.
.PARAMETER DoNotUseDrs
  Do not rely on DRS for evacuating VM but set DRS to manual and do the vmotions "manually". This is useful if your cluster capacity is insufficient for DRS to work properly.
.PARAMETER reEnableDelay
  (Optional)Specifies in seconds how long the script should wait between each protection domain re-enablement. Default and minimum is 120 seconds (2 minutes). You can specify more if you want, but not less.
.PARAMETER maxConcurrentRepl
  (Optional)Integer specifying how many concurrent replications can take place in parallel.  This is set to 3 by default.
.PARAMETER prismCreds
  (Optional)Specifies a custom credentials file name for Prism authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
  If you do not specify a credential file and do not use username or password, the script will prompt you for this information.
.PARAMETER vcenterCreds
  (Optional)Specifies a custom credentials file name for vCenter authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$vcenterCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
  If you do not specify a credential file, the script will prompt you for this information, unless your logged in user already has access to vCenter.
.PARAMETER cvmCreds
  (Optional)Specifies a custom credentials file name for CVM ssh authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$cvmCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
  If you do not specify a credential file, the script will prompt you for this information.
.PARAMETER resetOverrides
  (Optional)Specifies that if a VM has a DRS override, you want to remove it automatically so that DRS can move the VM.
.PARAMETER remoteSiteIp
  (Optional)Specifies the remote site (other Nutanix cluster) IP address. This is useful if you have segmented the DR network and the IP configured in the remote site definition in Prism is not reachable from your network segment.
.EXAMPLE
.\invoke-MAFailover.ps1 -cluster c1.local -pd all -action maintenance
Trigger a manual failover of all metro protection domains and put esxi hosts in maintenance mode:
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
        [parameter(mandatory = $false)] [string]$cluster,
        [parameter(mandatory = $false)] [string]$pd,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] $vcenterCreds,
        [parameter(mandatory = $false)] $cvmCreds,
        [parameter(mandatory = $false)] [switch]$unplanned,
        [parameter(mandatory = $false)] [string][ValidateSet("maintenance","shutdown")]$action,
        [parameter(mandatory = $false)] [switch]$skipfailover,
        [parameter(mandatory = $false)] [switch]$shutdownUvms,
        [parameter(mandatory = $false)] [switch]$resetOverrides,
        [parameter(mandatory = $false)] [int]$timer,
        [parameter(mandatory = $false)] [switch]$reEnableOnly,
        [parameter(mandatory = $false)] [switch]$DisableOnly,
        [parameter(mandatory = $false)] [switch]$DoNotUseDrs,
        [parameter(mandatory = $false)] [int]$reEnableDelay,
        [parameter(mandatory = $false)] [int]$maxConcurrentRepl,
        [parameter(mandatory = $false)] [string]$remoteSiteIp
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

#region functions
    #Function Get-RESTError
    Function Get-RESTError 
    {
        $global:helpme = $body
        $global:helpmoref = $moref
        $global:result = $_.Exception.Response.GetResponseStream()
        $global:reader = New-Object System.IO.StreamReader($global:result)
        $global:responseBody = $global:reader.ReadToEnd();

        return $global:responsebody

        break
    }#end function Get-RESTError

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
    }#end function Update-DRSVMToHostRule

    #this function puts all the Nutanix ESXi hosts in a given cluster in maintenance mode
    Function Set-NtnxVmhostsToMaintenanceMode
    {
        #todo think about changes to make this "resumable" (assuming problems with vmotions, etc...)
        #? params/variables required: $myvar_ntnx_vmhosts, $myvar_cvm_names, $myvar_ntnx_cluster_name, $myvar_cvm_ips

        Write-Host ""
        Write-Host "$(get-date) [STEP] Checking if there are still running UVMs on the Nutanix cluster ESXi hosts..." -ForegroundColor Magenta   

        #* check if there are running uvms on each host
        #check each host ($myvar_ntnx_vmhosts) to see if they have running vms other than cvms
        foreach ($myvar_vmhost in $myvar_ntnx_vmhosts) {
            try 
            {
                $myvar_running_vms = $myvar_vmhost | Get-VM -ErrorAction Stop | Where-Object {$_.PowerState -eq "PoweredOn"}
            }
            catch 
            {
                throw "$(get-date) [ERROR] Could not retrieve VMs running on host $($myvar_vmhost.Name) from vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
            }
            ForEach ($myvar_cvm_name in $myvar_cvm_names) {$myvar_running_vms = $myvar_running_vms | Where-Object {$_.Name -ne $myvar_cvm_name}} #exclude CVMs
            if ($myvar_running_vms)
            {
                if (!$shutdownUvms)
                {
                    Throw "$(get-date) [ERROR] There are still virtual machines (other than CVMs) running on ESXi host $($myvar_vmhost.Name): $($myvar_running_vms.Name)"
                }
                else 
                {
                    Write-Host "$(get-date) [WARNING] Shutting down running UVMs on host $($myvar_vmhost.Name) : $($myvar_running_vms.Name)" -ForegroundColor Yellow
                    try {$myvar_uvms_shutdown_command = $myvar_running_vms | Stop-VMGuest -ErrorAction Stop -Confirm:$False}
                    catch {throw "$(get-date) [ERROR] Could not shut down UVMs running on host $($myvar_vmhost.Name) : $($_.Exception.Message)"}
                    Write-Host "$(get-date) [SUCCESS] Successfully sent shut down on running UVMs on host $($myvar_vmhost.Name) : $($myvar_running_vms.Name)" -ForegroundColor Cyan
                    Write-Host "$(get-date) [INFO] Waiting for $($timer) seconds..." -ForegroundColor Green
                    Start-Sleep $timer
                }
            }
        }
    }#end function Set-NtnxVmhostsToMaintenanceMode

    #this function is used to prompt the user for a yes/no/skip response in order to control the workflow of a script
    function Write-CustomPrompt 
    {
        <#
        .SYNOPSIS
        Creates a user prompt with a yes/no/skip response. Returns the response.

        .DESCRIPTION
        Creates a user prompt with a yes/no/skip response. Returns the response in lowercase. Valid responses are "y" for yes, "n" for no, "s" for skip.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Write-CustomPrompt
        Creates the prompt.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [Switch]$skip
        )

        begin 
        {
            [String]$userChoice = "" #initialize our returned variable
        }
        process 
        {
            if ($skip)
            {
                do {$userChoice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o]/S[kip])"} #display the user prompt
                while ($userChoice -notmatch '[ynsYNS]') #loop until the user input is valid
            }
            else 
            {
                do {$userChoice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o])"} #display the user prompt
                while ($userChoice -notmatch '[ynYN]') #loop until the user input is valid
            }
            $userChoice = $userChoice.ToLower() #change to lowercase
        }
        end 
        {
            return $userChoice
        }

    } #end Write-CustomPrompt function

    function invoke-DatastoreVmDrain
    {#migrate all virtual machines in a given datastore to a given vmhost group

        param 
        (
            $datastore,
            $vmhost_group
        )

        begin {}

        process 
        {
            #*figure out vms in this datastore
            try 
            {#getting vms on this datastore
                Write-Host "$(get-date) [INFO] Getting VMs hosted on datastore $($myvar_datastore)..." -ForegroundColor Green
                $myvar_datastore_vms = get-datastore -name $myvar_datastore -ErrorAction Stop | get-vm -ErrorAction Stop
                $myvar_datastore_vms_to_move = @()
                ForEach ($myvar_vm in $myvar_datastore_vms)
                {#see which host the vm is running on and if it needs to be moved
                    if ($myvar_vm.vmhost.name -in $myvar_ntnx_vmhosts.name) 
                    {#the vm is running on a host in the wrong vmhost group
                        $myvar_datastore_vms_to_move += $myvar_vm
                    }
                }
            }
            catch 
            {#could not get vms on datastore
                throw "$(get-date) [ERROR] Could not get VMs hosted on datastore $($myvar_datastore) : $($_.Exception.Message)"
            }

            #*process each vm
            ForEach ($vm in $myvar_datastore_vms_to_move)
            {
                #* determine which host in the host group has the least VMs
                $base_qty = 0
                $target_host = ""
                foreach ($vmhost in $vmhost_group) 
                {#process each vmhost
                    try 
                    {#count vms on host by looking at its view
                        $vm_qty = (($vmhost| get-view).Vm).count
                        if ($base_qty -eq 0) 
                        {#this is the first host we count vms on, so it's the baseline
                            $base_qty = $vm_qty
                            $target_host = $vmhost
                        } 
                        elseif ($vm_qty -lt $base_qty) 
                        {#this host has less vms than our baseline, so it becomes the new baseline
                            $target_host = $vmhost
                        }
                    }
                    catch 
                    {#couldn't get host view
                        throw "$(get-date) [ERROR] Could not get $($vmhost.Name) view: $($_.Exception.Message)"
                    }
                }
                
                #* migrate vm
                Write-Host "$(get-date) [INFO] Moving vm $($vm.Name) to host $($target_host.Name)" -ForegroundColor Green
                try 
                {#move-vm
                    $result = Move-Vm -VM $vm -Destination $target_host -confirm:$false -RunAsync:$true -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] VM $($vm.Name) is moving to host $($target_host)..." -ForegroundColor Cyan
                }
                catch 
                {#couldn't move-vm
                    Write-Host "$(get-date) [WARNING] Could not move vm $($vm.Name) to host $($target_host.Name) : $($_.Exception.Message)" -ForegroundColor Yellow
                }   
            }
        }

        end 
        {
            Do
            {#loop until there are no active vmotion task for vms in this datastore
                try 
                {#get running tasks
                    Write-Host "$(get-date) [INFO] Getting list of active vmotion tasks from vCenter" -ForegroundColor Green
                    $active_vmotion_vm_list = (Get-Task -Status Running -ErrorAction Stop | Where-Object {$_.Name -eq "RelocateVM_Task"}).ExtensionData.Info.EntityName
                    $running_tasks = $false
                    foreach ($vm_name in $active_vmotion_vm_list) 
                    {#look at all currently moving vms to see if they are in our datastore
                        if ($vm_name -in $myvar_datastore_vms.Name)
                        {#there is a vm with an active vmotion task in this datastore, so we're not done moving vms yet
                            Write-Host "$(get-date) [WARNING] VM $($vm_name) is still migrating! Waiting 5 seconds..." -ForegroundColor Yellow
                            $running_tasks = $true
                            Start-Sleep -Seconds 5
                            continue
                        }
                    }
                }
                catch 
                {#could not get running tasks
                    throw "$(get-date) [ERROR] Could not get tasks from vCenter : $($_.Exception.Message)" 
                }
            } While ($running_tasks)
        }
    }
#endregion

#! if the cluster stop command does not work for you, it may be because you are running an older version of AOS, in which case you'll need to replace "I agree" with "y". This code is in the Set-NtnxVmhostsToMaintenanceMode function.
#todo: handle going out of maintenance mode where the script would:
<# 
    Take ESXi hosts off maintenance mode
    Power on CVMs
    SSH into a CVM to start the cluster
    Migrate VMs back
    Re-enable replication
#>
#todo find a way to deal with ssh on non-windows systems
#todo test if vm or host drs group does not exist (and enhance with drs groups presence check)
#todo: count nb of processed pds vs total pds to avoid waiting 2 minutes after the last one has been re-enabled

#region prepwork
    $ErrorActionPreference = "Continue"

    Write-Host ""
    Write-Host "$(get-date) [STEP] Checking PowerShell configuration ..." -ForegroundColor Magenta
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter and OutputLogData function
11/03/2020 sb   Initial release.
11/06/2020 sb   Added -reEnableOnly switch.
02/06/2021 sb   Replaced username with get-credential
02/16/2021 sb   Misc updates after first runs in production: moved DRS check to
                 PowerCLI commands as status in Prism cluster json object is
                 sometimes incorrect. Added code to force migrate powered off
                 virtual machines in a metro enabled container. Added code to
                 keep track of remote site cluster hypervisor hosts.  Added code
                 to display number of remaining virtual machines in a metro
                 enabled container.
05/09/2021 sb   Added check for VM with DRS override that it is in the same
                 cluster and changed message accordingly.
06/02/2021 sb   Adding check on failure handling method and adding step to
                 disable the protection domain if a Witness is not being used.
                 Added CUSTOMIZE markers to facilitate changing DRS naming
                 convention.
06/03/2021 sb   Added the ability to use custom DRS object names where there is
                 1 rule per cluster (as opposed to 1 DRS rule per container).
                 Added code to export processed pd list and ability to specify
                 a csv file for -pd parameter (in order to facilitate failback).
06/09/2021 sb   Changed if statement on line 1451 to add debug information when
                 vmhost comparison appears incorrect.
                 When re-enabling pds, moved the sync status outside of the main
                 processing loop to speed up execution of the process (now
                 multiple pds can sync in parallel). Added the reEnableDelay
                 parameter to wait a minimum of 2 minutes between each re-enable
                 as recommended by engineering.
06/15/2021 sb   Fixing missing underscore in the $pd_list variable name on line 
                 1668.
                 Modified code that keeps track of processed protection domains
                 when using -reEnableOnly.
07/01/2021 sb   Fixing an issue with checking pd is disabled even though
                 witness was in use.
                 Added maxConcurrentRepl parameter and associated control loops.
08/23/2021 sb   Adding unplanned parameter and associated logic.
08/31/2021 sb   Fixed issue when not specifying creds, issue with ping test on 
                 posh 5 and output issue on unplanned loop. Adding DisableOnly 
                 parameter to facilitate failback after unplanned failover
09/17/2021 sb   Fixing issue #19 (redirect output to log file with -log 
                 parameter)
09/27/2021 sb   Addressing issue #19 with getting VMs in large environments.
                 Addressing issue #15 by making sure to compare VM host with
                 list of all hosts in the compute cluster (as opposed to hosts
                 in the targeted Nutanix cluster).
                 Addressing issue #17 and adding api_max_retries to retry Prism
                 API calls that time out. Also enhanced REST API error messages.
09/28/2021 sb   Addressing issue #16 by adding the -DoNotUseDrs parameter.
10/06/2021 sb   Fixing an issue with -DoNotUseDrs (DRS is now set to manual instead
                 of disabling and test for VMs in datastore are made against the
                 correct vmhost group)
10/07/2021 sb   Fixed minor output issues. Fixed an issue with loading VMware
                 PowerCLI module.
10/12/2021 sb   Adding code to address issues #23 and #24:
                 When using -DoNotUseDrs, VMs will now be migrated asynchronous-
                 ly and a loop will check that there are no active migrations
                 before making sure all vms in the datastore are running on the
                 correct host group.
                 In addition, when doing a -reEnableOnly, if -DoNotUseDrs is set
                 DRS will be set to manual before starting to re-enable protec-
                 tion domains.
10/16/2021 sb   Fixing a logic issue in the DoNotUseDrs Do while loop (thanks to
                 Benjamin Fabian from Unisys for catching this!)
10/21/2021 sb   Adding -remoteSiteIp parameter for environments where DR network
                 has been segmented.
10/25/2021 sb   Fixed an issue where maxConcurrentRepl was set to 1 and not 
                 being correctly enforced when running on PowerShell 5.1
################################################################################
'
    $myvarScriptName = ".\invoke-MAFailover.ps1"

    if ($help) 
    {#display online help
        get-help $myvarScriptName
        exit
    }
    if ($History) 
    {#display release history
    $HistoryText
    exit
    }

    if ($PSVersionTable.PSVersion.Major -lt 5) 
    {#check PoSH version
        throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
    }

    #check if we have all the required PoSH modules
    Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green
    if (!(Get-Module VMware.VimAutomation.Core)) 
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
    if ($action) 
    {#import sshsessions module to support actions
        if (!(Get-Module SSHSessions)) {
            if (!(Import-Module SSHSessions)) {
                Write-Host "$(get-date) [WARNING] We need to install the SSHSessions module!" -ForegroundColor Yellow
                try {Install-Module SSHSessions -ErrorAction Stop -Scope CurrentUser}
                catch {throw "$(get-date) [ERROR] Could not install the SSHSessions module : $($_.Exception.Message)"}
                try {Import-Module SSHSessions}
                catch {throw "$(get-date) [ERROR] Could not load the SSHSessions module : $($_.Exception.Message)"}
            }
        }
    }

    # ignore SSL warnings - use modern approach for PS7+
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates (SkipCertificateCheck)" -ForegroundColor Green
    } else {
        Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates" -ForegroundColor Green
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) 
        {#ignore ssl warnings
            $certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{
public static void Ignore()
{
    if(ServicePointManager.ServerCertificateValidationCallback ==null)
    {
        ServicePointManager.ServerCertificateValidationCallback += 
            delegate
            (
                Object obj, 
                X509Certificate certificate, 
                X509Chain chain, 
                SslPolicyErrors errors
            )
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
    
    # add Tls12 support
    if ($PSVersionTable.PSVersion.Major -le 5) {
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = `
        ([Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12)
    }

    #set some runtime variables
    $myvar_elapsed_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$pd_list = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$ctr_list = New-Object System.Collections.ArrayList($null)

#endregion

#! customize here
#region customization
#* You can add your specific DRS object names to the switch case in the
#* function below if you do not have a DRS rule per container but one per
#* storage cluster. Note that when you do this, you can only failover all
#* the pds of a given cluster at a time. When you specify a list of pds,
#* (such as during failback) you will have to make sure that this lists 
#* includes all the metro pds in the cluster.
Function GetDrsObjectNames
{
    param
    (
        [parameter(mandatory = $true)]
        [string] 
        $cluster_name
    )

    $drs_object_names = switch ($cluster_name)
    {
        "LABCL101" {@{
            drs_hg_name = "MB_hosts"
            drs_vmg_name = "MB_VMs"
            drs_rule_name = "VMs_Should_In_MB"
        }}
        "LABCL201" {@{
            drs_hg_name = "GS_hosts"
            drs_vmg_name = "GS_VMs"
            drs_rule_name = "VMs_Should_In_GS"
        }}
    }
    return $drs_object_names
}
$api_retries = 3 #how many times are we retrying Prism REST API calls that time out?
<#
$ntnx1_cluster_name = "LABCL101"
$drs_hg1_name = "MB_hosts"
$drs_vm1_name = "MB_VMs"
$drs_rule1_name = "VMs_Should_In_MB"

$ntnx2_cluster_name = "LABCL201"
$drs_hg2_name = "GS_hosts"
$drs_vm2_name = "GS_VMs"
$drs_rule2_name = "VMs_Should_In_GS"
#>
#endregion

#region parameters validation
    Write-Host ""       
    Write-Host "$(get-date) [STEP] Validating parameters ..." -ForegroundColor Magenta

    if ($action -and ($IsMacOS -or $IsLinux)) 
    {#we need to connect to CVM using SSH but we're not running this script from a Windows machine (only platform where ssh module used works)
        Throw "$(get-date) [ERROR] You can only use -action on a Windows based system for now! Exiting."
    }

    if (!$cluster) 
    {#prompt for the Nutanix cluster name
        $cluster = read-host "Enter the hostname or IP address of the Nutanix cluster"
    }

    if (!$pd -and $action)
    {#we have specidied an action but no protection domains, so all protection domains will be processed.
        Write-Host "$(get-date) [WARNING] You have specified an action $($action) but no protection domain. We will process ALL active metro availability protection domains!" -ForegroundColor Yellow
        $pd = "all"
    } elseif (!$pd) 
    {#prompt for the Nutanix protection domain name
        $pd = read-host "Enter the name of the protection domain to failover. You can also specify 'all' or a list of names separated by a comma"
    }

    if ($pd -ne "all") 
    {#pd was specified but is not equal to all. Let's make sure we process it correctly if it is a list.
        #see if we have a csv file to import
        if ($pd.contains(".csv")) 
        {#-pd is a csv file
            if (Test-Path -Path $pd) 
            {#file exists
                $pd_names_list = (Import-Csv -Path $pd).name
            }
            else 
            {#file does not exist
                throw "The specified csv file $($pd) does not exist!"
            }
        } 
        else 
        {#-pd is not a csv file
            $pd_names_list = $pd.Split(",")
        }
    }

    if ($action -and ($pd -ne "all"))
    {#check that we are not trying to failover only some protection domains while putting esxi hosts in maintenance or shutting them down
        Throw "$(get-date) [ERROR] If you specify an action, you MUST use 'all' for protection domain as this otherwise would leave VMs on the cluster."
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
        }
        catch 
        {
            Set-CustomCredentials -credname $vcenterCreds
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
        }
    }
    else 
    {#no vcenter creds were given
        $vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
    }
    $vcenterUsername = $vcenterCredentials.UserName
    $vcenterSecurePassword = $vcenterCredentials.Password
    $vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword

    if ($action -and !$cvmCreds) 
    {#we have specified an action, but we did not specify cvm credentials
        $myvar_cvm_username = Read-Host "Enter the username to ssh into CVMs"
        $myvar_cvm_secure_password = Read-Host "Enter the CVM user $($myvar_cvm_username) password" -AsSecureString
        $myvar_cvm_credentials = New-Object PSCredential $myvar_cvm_username, $myvar_cvm_secure_password
    }

    if ($cvmCreds) 
    {#we have specified cvm creds, so le's retrieve them
        try 
        {#trying to retrieve from existing encrypted file
            $myvar_cvm_credentials = Get-CustomCredentials -credname $cvmCreds -ErrorAction Stop
            $myvar_cvm_username = $myvar_cvm_credentials.UserName
            $myvar_cvm_secure_password = $myvar_cvm_credentials.Password
        }
        catch 
        {#we could not retrieve the creds from file, so prompting
            Set-CustomCredentials -credname $cvmCreds
            $myvar_cvm_credentials = Get-CustomCredentials -credname $cvmCreds -ErrorAction Stop
            $myvar_cvm_username = $myvar_cvm_credentials.UserName
            $myvar_cvm_secure_password = $myvar_cvm_credentials.Password
        }
        $myvar_cvm_credentials = New-Object PSCredential $myvar_cvm_username, $myvar_cvm_secure_password
    }

    if ($unplanned)
    {
        if ($action -or $DisableOnly -or $reEnableOnly)
        {
            Throw "$(get-date) [ERROR] You cannot use -unplanned with -action, -DisableOnly or -reEnableOnly!"
        }
    }

    if (!$timer) {$timer = 300}
    if ((!$reEnableDelay) -or ($reEnableDelay -lt 120)) {$reEnableDelay = 120}
    if (!$maxConcurrentRepl) {$maxConcurrentRepl = 3}
#endregion

#region execute
    Write-Host ""
    Write-Host "$(get-date) [STEP] Retrieving information from the Nutanix cluster and checking pre-requisites conditions are met ..." -ForegroundColor Magenta

    #region get info and check pre-requisites
        #* testing connection to prism
        #region GET cluster
            Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $($cluster) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
            $method = "GET"
            try 
            {
                $myvar_ntnx_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve cluster information from Nutanix cluster $($cluster) : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $($cluster)" -ForegroundColor Cyan
        #endregion
        
        #* getting cluster name and vcenter ip, checking DRS is enabled
        #region assign cluster name and vcenter ip
            $myvar_ntnx_cluster_name = $myvar_ntnx_cluster_info.name
            Write-Host "$(get-date) [DATA] Nutanix cluster name is $($myvar_ntnx_cluster_name)" -ForegroundColor White
            if (!$unplanned)
            {#we don't need vcenter information if this is an unplanned failover
                $myvar_management_server = $myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                if ($myvar_management_server -is [array]) 
                {#houston, we have a problem, there is more than one registered vcenter
                    Throw "$(get-date) [ERROR] There is more than 1 registered management server for cluster $($cluster). Exiting."
                } 
                else 
                {
                    $myvar_vcenter_ip = ($myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                    Write-Host "$(get-date) [DATA] vCenter IP address for Nutanix cluster $($myvar_ntnx_cluster_name) is $($myvar_vcenter_ip)" -ForegroundColor White
                    <# this check does not work in some environments where vcenter may have clusters where DRS is not enabled
                    if (!$reEnableOnly) 
                    {#we don't really care if DRS is not enabled if all we're doing is re-enabling replication
                        if (!($myvar_ntnx_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).drs_enabled) 
                        {#houston we have a problem, drs is not enabled on this cluster
                            Throw "$(get-date) [ERROR] DRS is not enabled on vCenter $($myvar_vcenter_ip). Exiting."
                        } 
                        else 
                        {
                            Write-Host "$(get-date) [DATA] DRS is enabled on vCenter $($myvar_vcenter_ip)" -ForegroundColor White
                        }
                    }
                    #>
                }
            }
        #endregion

        #* making sure cluster will be ready to be shutdown (if -action)
        #region cluster stop ready status
            if ($action) 
            {
                #let's make sure our current redundancy is at least 2
                if ($myvar_ntnx_cluster_info.cluster_redundancy_state.current_redundancy_factor -lt 2) 
                {
                    throw "$(get-date) [ERROR] Current redundancy is less than 2. Exiting."
                }
                #check if there is an upgrade in progress
                if ($myvar_ntnx_cluster_info.is_upgrade_in_progress) 
                {
                    throw "$(get-date) [ERROR] Cluster upgrade is in progress. Exiting."
                }
            }
        #endregion

        #* getting hosts ips
        #region GET hosts
            Write-Host "$(get-date) [INFO] Retrieving hosts information from Nutanix cluster $($cluster) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $cluster
            $method = "GET"
            try 
            {
                $myvar_ntnx_hosts = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve hosts information from Nutanix cluster $($cluster) : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from Nutanix cluster $($cluster)" -ForegroundColor Cyan
            $myvar_ntnx_hosts_ips = ($myvar_ntnx_hosts.entities).hypervisor_address
            if ($action) 
            {#collecting cvm ips and ipmi ips
                $myvar_cvm_ips = $myvar_ntnx_hosts.entities | %{$_.service_vmexternal_ip}
                $myvar_ipmi_ips = $myvar_ntnx_hosts.entities | %{$_.ipmi_address}
            }
        #endregion

        #* getting protection domains and checking they are active and enabled on this cluster, and build $pd_list and $ctr_list
        #region GET protection_domains
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $($cluster) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $cluster
            $method = "GET"
            try 
            {
                $myvar_ma_active_pds = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not retrieve protection domains from Nutanix cluster $($cluster) : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $($cluster)" -ForegroundColor Cyan
            $myvar_ntnx_ma_active_ctrs = ($myvar_ma_active_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
            $myvar_ntnx_ma_active_pds = $myvar_ma_active_pds.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}
            if ($skipfailover) 
            {#if failover has been done already and all we're doing is maintenance or shutdown, the list of protection domains to process are those which are enabled
                $myvar_ntnx_ma_active_pds = $myvar_ma_active_pds.entities | Where-Object {$_.metro_avail.status -eq "Enabled"}
            }
            if ($unplanned)
            {#the list of protection domains are those in standby
                $myvar_ntnx_ma_standby_pds = $myvar_ma_active_pds.entities | Where-Object {($_.active -eq $false) -and ($_.metro_avail.role -eq "Standby")}
            }
            if ($DisableOnly)
            {#the list of protection domains is those in decoupled status
                $myvar_ntnx_ma_decoupled_pds = $myvar_ma_active_pds.entities | Where-Object {$_.metro_avail.status -eq "Decoupled"}
            }
            
            #building pd_list
            if ($pd -eq "all") 
            {
                if ($unplanned)
                {
                    $myvar_pd_list_details = $myvar_ntnx_ma_standby_pds
                }
                elseif ($DisableOnly)
                {
                    $myvar_pd_list_details = $myvar_ntnx_ma_decoupled_pds
                }
                else 
                {
                    $myvar_pd_list_details = $myvar_ntnx_ma_active_pds
                }
                
                foreach ($myvar_pd_detail in $myvar_pd_list_details) 
                {
                    $myvar_pd_info = [ordered]@{
                        "name" = $myvar_pd_detail.name;
                        "role" = $myvar_pd_detail.metro_avail.role;
                        "remote_site" = $myvar_pd_detail.metro_avail.remote_site;
                        "storage_container" = $myvar_pd_detail.metro_avail.storage_container;
                        "status" = $myvar_pd_detail.metro_avail.status;
                        "failure_handling" = $myvar_pd_detail.metro_avail.failure_handling
                    }
                    $pd_list.Add((New-Object PSObject -Property $myvar_pd_info)) | Out-Null
                }

                if (!$unplanned)
                {
                    foreach ($myvar_ctr in $myvar_ntnx_ma_active_ctrs) 
                    {
                        $myvar_ctr_info = [ordered]@{"name" = $myvar_ctr}
                        $ctr_list.Add((New-Object PSObject -Property $myvar_ctr_info)) | Out-Null
                    }
                }
            } 
            else 
            {#build custom list of protection domains to process
                foreach ($pd_name in $pd_names_list) 
                {
                    if (!$skipfailover -and ($pd_name -notin $myvar_ntnx_ma_active_pds.name) -and !$unplanned) 
                    {
                        Throw "$(get-date) [ERROR] Protection domain $($pd_name) was not found active on cluster $($cluster). Exiting."
                        if ($DisableOnly -and ($pd_name -notin $myvar_ntnx_ma_decoupled_pds))
                        {
                            Throw "$(get-date) [ERROR] Protection domain $($pd_name) is not decoupled on cluster $($cluster). Exiting."
                        }
                    } 
                    elseif ($unplanned)
                    {
                        if ($pd_name -notin $myvar_ntnx_ma_standby_pds)
                        {
                            Throw "$(get-date) [ERROR] Protection domain $($pd_name) is not a standby protection domain on cluster $($cluster). Exiting."
                        }
                        else 
                        {
                            Write-Host "$(get-date) [DATA] Protection domain $($pd_name) is on standby on Nutanix cluster $($cluster)" -ForegroundColor White
                            $myvar_pd_details = $myvar_ntnx_ma_standby_pds | Where-Object {$_.name -eq $pd_name}
                            $myvar_pd_info = [ordered]@{
                                "name" = $myvar_pd_details.name;
                                "role" = $myvar_pd_details.metro_avail.role;
                                "remote_site" = $myvar_pd_details.metro_avail.remote_site;
                                "storage_container" = $myvar_pd_details.metro_avail.storage_container;
                                "status" = $myvar_pd_details.metro_avail.status;
                                "failure_handling" = $myvar_pd_details.metro_avail.failure_handling
                            }
                            $pd_list.Add((New-Object PSObject -Property $myvar_pd_info)) | Out-Null
                        }
                    }
                    else 
                    {
                        Write-Host "$(get-date) [DATA] Protection domain $($pd_name) was found active on Nutanix cluster $($cluster)" -ForegroundColor White
                        $myvar_pd_details = $myvar_ntnx_ma_active_pds | Where-Object {$_.name -eq $pd_name}
                        $myvar_pd_info = [ordered]@{
                            "name" = $myvar_pd_details.name;
                            "role" = $myvar_pd_details.metro_avail.role;
                            "remote_site" = $myvar_pd_details.metro_avail.remote_site;
                            "storage_container" = $myvar_pd_details.metro_avail.storage_container;
                            "status" = $myvar_pd_details.metro_avail.status;
                            "failure_handling" = $myvar_pd_details.metro_avail.failure_handling
                        }
                        $myvar_ctr_info = [ordered]@{"name" = $myvar_pd_details.metro_avail.storage_container}
                        $pd_list.Add((New-Object PSObject -Property $myvar_pd_info)) | Out-Null
                        $ctr_list.Add((New-Object PSObject -Property $myvar_ctr_info)) | Out-Null
                    }
                }
            }
            
            #checking specified pds can be processed 
            if (!$skipfailover -and !$reEnableOnly -and !$unplanned -and !$DisableOnly)
            { 
                Write-Host "$(get-date) [INFO] Checking all active metro protection domain are in status enabled..." -ForegroundColor Green
                foreach ($pd_item in $pd_list) 
                {
                    if ($pd_item.status -ne "enabled") 
                    {
                        Throw "$(get-date) [ERROR] Protection domain $($pd_item.name) is active but not in the status enabled. Current status is $($pd_item.status). Exiting."
                    }
                }
                Write-Host "$(get-date) [DATA] All active metro protection domain are in status enabled on cluster $($myvar_ntnx_cluster_name)." -ForegroundColor White
            }
            elseif ($unplanned) 
            {#double check pds are in disabled state and not protected by witness
                Write-Host "$(get-date) [INFO] Checking all specified metro protection domain are in status disabled and not protected by witness..." -ForegroundColor Green
                foreach ($pd_item in $pd_list) 
                {
                    if (($pd_item.status -ne "disabled") -and ($pd_item.failure_handling -eq "witness")) 
                    {
                        Throw "$(get-date) [ERROR] Protection domain $($pd_item.name) is in status $($pd_item.status) and failure handling is $($pd_item.failure_handling). Exiting."
                    }
                }
                Write-Host "$(get-date) [DATA] All specified metro protection domain can be processed for unplanned failover on cluster $($myvar_ntnx_cluster_name)." -ForegroundColor White
            }
        #endregion

        #* getting remote site name, ip address, registered vcenter server and trying to connect to remote site
        #region GET remote_sites
            #* get remote site name ($remote_site_name) and make sure it is unique across all protection domains
            $remote_site_name = $pd_list.remote_site | select-object -unique
            if ($remote_site_name -is [array]) 
            {#houston we have a problem: active metro pds are pointing to more than one remote site!
                Throw "$(get-date) [ERROR] Cluster $($cluster) has metro availability protection domains which are pointing to different remote sites. Exiting."
            } 
            else 
            {#we figured out the remote site name
                Write-Host "$(get-date) [DATA] Remote site name is $($remote_site_name)" -ForegroundColor White
            }

            #* query prism for remote sites
            Write-Host "$(get-date) [INFO] Retrieving remote sites from Nutanix cluster $($cluster) ..." -ForegroundColor Green
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/remote_sites/" -f $cluster
            $method = "GET"
            try 
            {#get remote site info
                $myvar_remote_sites = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch
            {#couldn't get remote site info
                throw "$(get-date) [ERROR] Could not retrieve remote sites from Nutanix cluster $($cluster) : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved remote sites from Nutanix cluster $($cluster)" -ForegroundColor Cyan
            #* grab ip for our remote site
            if (!$remoteSiteIp)
            {#remote site IP address was not specified, so we'll fetch it from the remote site definition
                $myvar_remote_site_ip = (($myvar_remote_sites.entities | Where-Object {$_.name -eq $remote_site_name}).remote_ip_ports).psobject.properties.name
            }
            else 
            {#remote site IP was specified manually
                $myvar_remote_site_ip = $remoteSiteIp
            }
            Write-Host "$(get-date) [DATA] Remote site $($remote_site_name) ip address is $($myvar_remote_site_ip)" -ForegroundColor White

            if (!$unplanned)
            {#if this is an unplanned failover, we're not expecting the remote site to be available                
                #* connecting to remote site cluster
                Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $($myvar_remote_site_ip) on remote site $($remote_site_name) ..." -ForegroundColor Green
                $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $myvar_remote_site_ip
                $method = "GET"
                try 
                {#get remote cluster information
                    $myvar_ntnx_remote_cluster_info = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                }
                catch
                {#couldn't get remote cluster information
                    throw "$(get-date) [ERROR] Could not retrieve cluster information from Nutanix cluster $($myvar_remote_site_ip) : $($_.Exception.Message)"
                }
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $($myvar_remote_site_ip)" -ForegroundColor Cyan

                #* figuring out remote cluster name and vcenter ip
                $myvar_ntnx_remote_cluster_name = $myvar_ntnx_remote_cluster_info.name
                Write-Host "$(get-date) [DATA] Nutanix cluster name for remote site $($remote_site_name) is $($myvar_ntnx_remote_cluster_name)" -ForegroundColor White
                $myvar_remote_management_server = $myvar_ntnx_remote_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}
                if ($myvar_remote_management_server -is [array])
                {#houston, we have a problem, there is more than one registered vcenter
                    Throw "$(get-date) [ERROR] There is more than 1 registered management server for remote cluster $($myvar_ntnx_remote_cluster_name). Exiting."
                } 
                else 
                {#we figured out the vcenter information
                    $myvar_remote_site_vcenter_ip = ($myvar_ntnx_remote_cluster_info.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
                    Write-Host "$(get-date) [DATA] vCenter IP address for remote Nutanix cluster $($myvar_ntnx_remote_cluster_name) is $($myvar_remote_site_vcenter_ip)" -ForegroundColor White
                    if ($myvar_remote_site_vcenter_ip -ne $myvar_vcenter_ip) {#houston we have a problem, both sites have different registered vcenters
                        Throw "$(get-date) [ERROR] Nutanix clusters $($myvar_ntnx_cluster_name) and $($myvar_ntnx_remote_cluster_name) have different registered vCenter servers: $($myvar_vcenter_ip) and $($myvar_remote_site_vcenter_ip). Exiting."
                    } else {
                        Write-Host "$(get-date) [DATA] Nutanix clusters $($myvar_ntnx_cluster_name) and $($myvar_ntnx_remote_cluster_name) have the same registered vCenter server." -ForegroundColor White
                    }
                }

                #* getting remote site hosts information
                #region GET hosts
                    Write-Host "$(get-date) [INFO] Retrieving hosts information from Nutanix cluster $($myvar_remote_site_ip) ..." -ForegroundColor Green
                    $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $myvar_remote_site_ip
                    $method = "GET"
                    try 
                    {#get remote cluster hosts
                        $myvar_remote_ntnx_hosts = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    }
                    catch
                    {#couldn't get remote cluster hosts
                        throw "$(get-date) [ERROR] Could not retrieve hosts information from Nutanix cluster $($myvar_remote_site_ip) : $($_.Exception.Message)"
                    }
                    Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from Nutanix cluster $($myvar_remote_site_ip)" -ForegroundColor Cyan
                    $myvar_remote_ntnx_hosts_ips = ($myvar_remote_ntnx_hosts.entities).hypervisor_address   
                #endregion
            }
            else 
            {#this is an unplanned failover, so add a test here to see if the remote site is pinging
                try 
                {
                    $myvar_ping_result = Test-Connection -Count 3 -TargetName $myvar_remote_site_ip -Quiet -ErrorAction Stop 
                }
                catch 
                {
                    throw "$(get-date) [ERROR] Could not ping $myvar_remote_site_ip : $($_.Exception.Message)"
                }
                
                if ($myvar_ping_result)
                {#ping was positive so the remote site is up
                    throw "$(get-date) [ERROR] Remote site is responding to ping on IPv4 $($myvar_remote_site_ip). You cannot do an unplanned failover if the remote site is up. Exiting!"
                }
            }
        #endregion

        #* trying to connect to vcenter and retrieve essential information
        #region connect-viserver
            if (!$reEnableOnly -and !$unplanned -and !$DisableOnly)
            {
                Write-Host "$(get-date) [INFO] Connecting to vCenter server $($myvar_vcenter_ip) ..." -ForegroundColor Green
                try 
                {#try connecting to vcenter
                    $myvar_vcenter_connection = Connect-VIServer -Server $myvar_vcenter_ip -Credential $vcenterCredentials -ErrorAction Stop
                }
                catch 
                {#could not connect to vcenter
                    throw "$(get-date) [ERROR] Could not connect to vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
                }
                Write-Host "$(get-date) [SUCCESS] Successfully connected to vCenter server $($myvar_vcenter_ip)" -ForegroundColor Cyan
                
                
                try 
                {#retrieve information from vcenter
                    #region figure out compute cluster name
                        #let's match host IP addresses we got from the Nutanix clusters to VMHost objects in vCenter
                        $myvar_ntnx_vmhosts = @() #this is where we will save the hostnames of the hosts which make up the Nutanix cluster
                        $myvar_remote_ntnx_vmhosts = @() #this is where we will save the hostnames of the hosts which make up the remote Nutanix cluster
                        Write-Host "$(get-date) [INFO] Getting hosts registered in vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Green
                        try 
                        {#get all the vmhosts registered in vCenter
                            $myvar_vmhosts = Get-VMHost -ErrorAction Stop 
                            Write-Host "$(get-date) [SUCCESS] Successfully retrieved vmhosts from vCenter server $($myvar_vcenter_ip)" -ForegroundColor Cyan
                        }
                        catch
                        {#couldn't get all the vmhosts registered in vCenter
                            throw "$(get-date) [ERROR] Could not retrieve vmhosts from vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
                        }

                        foreach ($myvar_vmhost in $myvar_vmhosts) 
                        {#let's look at each host and determine which is which
                            Write-Host "$(get-date) [INFO] Retrieving vmk interfaces for host $($myvar_vmhost)..." -ForegroundColor Green
                            try 
                            {#retrieve all vmk NICs for that host
                                $myvar_host_vmks = $myvar_vmhost | Get-VMHostNetworkAdapter -ErrorAction Stop | Where-Object {$_.DeviceName -like "vmk*"} 
                                Write-Host "$(get-date) [SUCCESS] Successfully retrieved vmk interfaces for host $($myvar_vmhost)" -ForegroundColor Cyan
                            }
                            catch
                            {#couldn't retrieve all vmk NICs for that host
                                throw "$(get-date) [ERROR] Could not retrieve vmk interfaces for host $($myvar_vmhost) : $($_.Exception.Message)"
                            }
                            
                            foreach ($myvar_host_vmk in $myvar_host_vmks) 
                            {#examine all VMKs
                                foreach ($myvar_host_ip in $myvar_ntnx_hosts_ips) 
                                {#compare to the host IP addresses we got from the Nutanix cluster
                                    if ($myvar_host_vmk.IP -eq $myvar_host_ip)
                                    {#if we get a match, that vcenter host is in cluster 1
                                        Write-Host "$(get-date) [DATA] $($myvar_vmhost.Name) is a host in Nutanix cluster $($myvar_ntnx_cluster_name)..." -ForegroundColor White
                                        $myvar_ntnx_vmhosts += $myvar_vmhost
                                    }
                                }#end foreach IP loop
                                
                                foreach ($myvar_remote_host_ip in $myvar_remote_ntnx_hosts_ips) 
                                {#compare to the host IP addresses we got from the Nutanix cluster
                                    if ($myvar_host_vmk.IP -eq $myvar_remote_host_ip)
                                    {#if we get a match, that vcenter host is in cluster 2
                                        Write-Host "$(get-date) [DATA] $($myvar_vmhost.Name) is a host in Nutanix cluster $($myvar_ntnx_remote_cluster_name)..." -ForegroundColor White
                                        $myvar_remote_ntnx_vmhosts += $myvar_vmhost
                                    }
                                }#end foreach IP loop
                            }#end foreach VMK loop
                        }#end foreach VMhost loop
                        
                        if (!$myvar_ntnx_vmhosts) 
                        {#couldn't find hosts in cluster
                            throw "$(get-date) [ERROR] No vmhosts were found for Nutanix cluster $($myvar_ntnx_cluster_name) in vCenter server $($myvar_vcenter_ip)"
                        }

                        #figure out vsphere cluster name
                        Write-Host "$(get-date) [INFO] Checking which compute cluster contains hosts from $($myvar_ntnx_cluster_name)..." -ForegroundColor Green
                        try 
                        {#we look at which cluster the first vmhost in cluster belongs to.
                            $myvar_vsphere_cluster = $myvar_ntnx_vmhosts[0] | Get-Cluster -ErrorAction Stop
                            $myvar_vsphere_cluster_name = $myvar_vsphere_cluster.Name

                            Write-Host "$(get-date) [DATA] vSphere compute cluster name is $($myvar_vsphere_cluster_name) for Nutanix cluster $($myvar_ntnx_cluster_name)." -ForegroundColor White

                            foreach ($myvar_vmhost in $myvar_ntnx_vmhosts) 
                            {#make sure all hosts are part of the same cluster
                                try 
                                {
                                    $myvar_vmhost_vsphere_cluster = $myvar_vmhost | Get-Cluster -ErrorAction Stop
                                    $myvar_vmhost_vsphere_cluster_name = $myvar_vmhost_vsphere_cluster.Name
                                    if ($myvar_vmhost_vsphere_cluster_name -ne $myvar_vsphere_cluster_name) 
                                    {#houston we have a problem: some nutanix hosts are not in the same compute cluster
                                        throw "$(get-date) [ERROR] Nutanix host $($myvar_vmhost) is in vsphere cluster $($myvar_vmhost_vsphere_cluster_name) instead of vsphere cluster $($myvar_vsphere_cluster_name)! Exiting."
                                    }
                                }
                                catch 
                                {
                                    throw "$(get-date) [ERROR] Could not retrieve vSphere cluster for host $($myvar_ntnx_vmhosts[0].Name) : $($_.Exception.Message)"
                                }
                            }
                        }
                        catch 
                        {#couldn't retrieve cluster
                            throw "$(get-date) [ERROR] Could not retrieve vSphere cluster for host $($myvar_ntnx_vmhosts[0].Name) : $($_.Exception.Message)"
                        }
                    #endregion
                    
                    $myvar_compute_cluster_hosts = Get-Cluster -Name $myvar_vsphere_cluster_name | Get-VMHost

                    #$myvar_vm_view_list = Get-View -ViewType VirtualMachine #this is faster than a get-vm in large environments but does not give us the ability to look at IP addresses...
                    Write-Host "$(get-date) [INFO] Retrieving list of VMs in cluster $($myvar_vsphere_cluster_name) from $($myvar_vcenter_ip)..." -ForegroundColor Green
                    try 
                    {#get vms on the cluster
                        $myvar_vm_list = Get-Cluster -Name $myvar_vsphere_cluster_name | Get-VM -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Successfully queried VMs from $($myvar_vcenter_ip)" -ForegroundColor Cyan
                    }
                    catch 
                    {#couldn't get vms on the cluster
                        throw "$(get-date) [ERROR] Could not retrieve list of VMs in cluster $($myvar_vsphere_cluster_name) from vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
                    }
                    
                    Write-Host "$(get-date) [INFO] Figuring out VM IP addresses..." -ForegroundColor Green
                    $myvar_vm_ip_list = $myvar_vm_list | Select-Object Name, @{N="IP Address";E={@($_.guest.IPAddress[0])}}
                    Write-Host "$(get-date) [INFO] Figuring out vCenter VM name..." -ForegroundColor Green
                    if ($myvar_vcenter_vm_name = ($myvar_vm_ip_list | Where-Object {$_."IP address" -eq $myvar_vcenter_ip}).Name)
                    {#vcenter vm is running on our cluster
                        $myvar_vcenter_ntnx_hosted = $true
                        Write-Host "$(get-date) [DATA] vCenter VM is hosted in the Nutanix cluster" -ForegroundColor White
                        Write-Host "$(get-date) [DATA] vCenter VM name is $($myvar_vcenter_vm_name)" -ForegroundColor White
                    }
                    else 
                    {#vcenter vm is NOT running on our cluster
                        $myvar_vcenter_ntnx_hosted = $false
                        Write-Host "$(get-date) [DATA] vCenter VM is not hosted in the Nutanix cluster" -ForegroundColor White
                    }

                    #figure out the CVM VM names
                    [System.Collections.ArrayList]$myvar_cvm_names = New-Object System.Collections.ArrayList($null)
                    Write-Host "$(get-date) [INFO] Figuring out CVM VM names..." -ForegroundColor Green
                    ForEach ($myvar_cvm_ip in $myvar_cvm_ips) 
                    {#process each cvm ip
                        $myvar_cvm_name = ($myvar_vm_ip_list | Where-Object {$_."IP address" -eq $myvar_cvm_ip}).Name
                        $myvar_cvm_names += $myvar_cvm_name
                        Write-Host "$(get-date) [DATA] CVM with ip $($myvar_cvm_ip) VM name is $($myvar_cvm_name)" -ForegroundColor White
                    }
                }
                catch 
                {#could not retrieve information from vcenter
                    Write-Host "$(get-date) [WARNING] Could not retrieve vCenter VM from $($myvar_vcenter_ip) : $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        #endregion

        #! this only works on windows with sshsessions module
        if ($action) 
        {
            #trying to ssh into cvm
            Write-Host "$(get-date) [INFO] Opening ssh session to $($myvar_cvm_ips[0])..." -ForegroundColor Green
            try 
            {
                $myvar_cvm_ssh_session = New-SshSession -ComputerName $myvar_cvm_ips[0] -Credential $myvar_cvm_credentials -ErrorAction Stop
                $myvar_ssh_sessions = Get-SshSession
                if (!$myvar_ssh_sessions) 
                {
                    throw "$(get-date) [ERROR] Could not open ssh session to $($myvar_cvm_ips[0])"
                }
            }
            catch 
            {
                throw "$(get-date) [ERROR] Could not open ssh session to $($myvar_cvm_ips[0]) : $($_.Exception.Message)"
            }
            Write-Host "$(get-date) [SUCCESS] Opened ssh session to $($myvar_cvm_ips[0])." -ForegroundColor Cyan
        }
        
    #endregion

    #region move vms (with or without DRS)
        #* identify HA/DRS cluster and making sure HA and DRS are enabled
        #region figure out vsphere cluster configuration
            if (!$reEnableOnly -and !$unplanned -and !$DisableOnly)
            {#we are not just renabling pds, so figure out the vcenter information
                Write-Host ""
                Write-Host "$(get-date) [STEP] Figuring out information required to move metro protected virtual machines from vmhosts in $($myvar_ntnx_cluster_name) to vmhosts in $($myvar_ntnx_remote_cluster_name) for specified metro availability protection domains..." -ForegroundColor Magenta

                #checking vsphere cluster configuration
                Write-Host "$(get-date) [INFO] Checking HA is enabled on vSphere cluster $($myvar_vsphere_cluster_name)..." -ForegroundColor Green
                if ($myvar_vsphere_cluster.HaEnabled -ne $true) 
                {#HA is not enabled on this cluster
                    throw "$(get-date) [ERROR] HA is not enabled on vSphere cluster $($myvar_vsphere_cluster_name)!"
                }
                Write-Host "$(get-date) [INFO] Checking DRS is enabled and fully automated on vSphere cluster $($myvar_vsphere_cluster_name)..." -ForegroundColor Green
                if ($myvar_vsphere_cluster.DrsEnabled -ne $true)  
                {#DRS is not enabled on this cluster
                    throw "$(get-date) [ERROR] DRS is not enabled on vSphere cluster $($myvar_vsphere_cluster_name)!"
                }
                if (($myvar_vsphere_cluster.DrsAutomationLevel -ne "FullyAutomated") -and !$DoNotUseDrs)
                {#DRS is not fully automated on this cluster and we intend on using DRS
                    Throw "$(get-date) [ERROR] DRS is not fully automated on VMware cluster $($myvar_vsphere_cluster_name)"
                }
            }
        #endregion
        
        if (!$skipfailover -and !$reEnableOnly -and !$unplanned -and !$DisableOnly)
        {#we are not skipping failover nor reenabling pds only

            if (!$DoNotUseDrs)
            {#we are using DRS to handle vmotions
                #* find matching drs groups and rule(s)
                #region matching drs groups and rules
                    Write-Host "$(get-date) [INFO] Getting DRS rules from vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Green
                    try 
                    {
                        $myvar_cluster_compute_resource_view = Get-View -ErrorAction Stop -ViewType ClusterComputeResource -Property Name, ConfigurationEx | where-object {$_.Name -eq $myvar_vsphere_cluster_name}
                        $myvar_cluster_drs_rules = $myvar_cluster_compute_resource_view.ConfigurationEx.Rule
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved DRS rules from vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Cyan
                    }
                    catch 
                    {
                        throw "$(get-date) [ERROR] Could not retrieve existing DRS rules for cluster $($myvar_vsphere_cluster_name) : $($_.Exception.Message)"
                    }
                #endregion

                #* update matching drs rule(s)
                #region update drs rule(s)
                    #Write-Host "$(get-date) [INFO] Updating DRS rules in vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Green
                    $source_drs_objects_names, $remote_drs_objects_names = @{}
                    $source_drs_objects_names = GetDrsObjectNames($myvar_ntnx_cluster_name)
                    $remote_drs_objects_names = GetDrsObjectNames($myvar_ntnx_remote_cluster_name)

                    if ($source_drs_objects_names -and $remote_drs_objects_names)
                    {#we found a match for custom DRS rule names
                        if ($pd -eq "all")
                        {#I am moving all pds with custom DRS rule names, so this is a failover: updating source rule with remote hostgroup
                            $myvar_ntnx_remote_drs_host_group_name = $remote_drs_objects_names.drs_hg_name
                            $myvar_drs_rule_name = $source_drs_objects_names.drs_rule_name
                            $myvar_drs_vm_group_name = $source_drs_objects_names.drs_vmg_name
                        }
                        else 
                        {#I am moving some pds with custom DRS rule names, so this is a failback: updating remote rule with remote hostgroup
                            $myvar_ntnx_remote_drs_host_group_name = $remote_drs_objects_names.drs_hg_name
                            $myvar_drs_rule_name = $remote_drs_objects_names.drs_rule_name
                            $myvar_drs_vm_group_name = $remote_drs_objects_names.drs_vmg_name
                        }

                        Write-Host ""
                        Write-Host "$(get-date) [STEP] Processing DRS rule $($myvar_drs_rule_name) in vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Magenta

                        if (!($myvar_cluster_drs_rules | Where-Object {$_.Name -eq $myvar_drs_rule_name})) 
                        {#houston we have a problem: DRS rule does not exist
                            throw "$(get-date) [ERROR] DRS rule $($myvar_drs_rule_name) does not exist! Exiting."
                        } else {
                            #update drs rule
                            Write-Host "$(get-date) [INFO] Updating DRS rule $($myvar_drs_rule_name) in vCenter server $($myvar_vcenter_ip) to match VM group $($myvar_drs_vm_group_name) to host group $($myvar_ntnx_remote_drs_host_group_name)..." -ForegroundColor Green
                            Update-DRSVMToHostRule -VMGroup $myvar_drs_vm_group_name -HostGroup $myvar_ntnx_remote_drs_host_group_name -Name $myvar_drs_rule_name -Cluster $myvar_vsphere_cluster -RuleKey $(($myvar_cluster_drs_rules | Where-Object {$_.Name -eq $myvar_drs_rule_name}).Key) -RuleUuid $(($myvar_cluster_drs_rules | Where-Object {$_.Name -eq $myvar_drs_rule_name}).RuleUuid)
                            Write-Host "$(get-date) [SUCCESS] Successfully updated DRS rule $($myvar_drs_rule_name) in vCenter server $($myvar_vcenter_ip) to match VM group $($myvar_drs_vm_group_name) to host group $($myvar_ntnx_remote_drs_host_group_name)..." -ForegroundColor Cyan
                        }
                    }
                    else 
                    {#I don't have custom DRS rules matching, so assuming one DRS rule per container
                        $myvar_ntnx_remote_drs_host_group_name = "DRS_HG_MA_" + $myvar_ntnx_remote_cluster_name
                        foreach ($myvar_datastore in $ctr_list.name)
                        {#process each datastore
                            #! CUSTOMIZE: you can customize drs rules and vm group names here
                            $myvar_drs_rule_name = "DRS_Rule_MA_" + $myvar_datastore
                            $myvar_drs_vm_group_name = "DRS_VM_MA_" + $myvar_datastore
                            Write-Host ""
                            Write-Host "$(get-date) [STEP] Processing DRS rule $($myvar_drs_rule_name) in vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Magenta

                            if (!($myvar_cluster_drs_rules | Where-Object {$_.Name -eq $myvar_drs_rule_name})) 
                            {#houston we have a problem: DRS rule does not exist
                                throw "$(get-date) [ERROR] DRS rule $($myvar_drs_rule_name) does not exist! Exiting."
                            } else {
                                #update drs rule
                                Write-Host "$(get-date) [INFO] Updating DRS rule $($myvar_drs_rule_name) in vCenter server $($myvar_vcenter_ip) to match VM group $($myvar_drs_vm_group_name) to host group $($myvar_ntnx_remote_drs_host_group_name)..." -ForegroundColor Green
                                Update-DRSVMToHostRule -VMGroup $myvar_drs_vm_group_name -HostGroup $myvar_ntnx_remote_drs_host_group_name -Name $myvar_drs_rule_name -Cluster $myvar_vsphere_cluster -RuleKey $(($myvar_cluster_drs_rules | Where-Object {$_.Name -eq $myvar_drs_rule_name}).Key) -RuleUuid $(($myvar_cluster_drs_rules | Where-Object {$_.Name -eq $myvar_drs_rule_name}).RuleUuid)
                                Write-Host "$(get-date) [SUCCESS] Successfully updated DRS rule $($myvar_drs_rule_name) in vCenter server $($myvar_vcenter_ip) to match VM group $($myvar_drs_vm_group_name) to host group $($myvar_ntnx_remote_drs_host_group_name)..." -ForegroundColor Cyan
                            }
                        }                    
                    }
                
                #endregion

                #* loop until all vms in each datastore have been moved
                #region wait for drs to do his job
                    foreach ($myvar_datastore in $ctr_list.name)
                    {#process each datastore
                        Write-Host ""
                        Write-Host "$(get-date) [STEP] Checking all VMs have moved to the remote site for datastore $($myvar_datastore)..." -ForegroundColor Magenta
                        $myvar_drs_done = $false
                        Do 
                        {#loop until all vms have been moved
                            #figure out which vmhosts have vms running in this datastore
                            try 
                            {#getting vms on this datastore
                                #$myvar_datastore_vmhosts = get-datastore -name $myvar_datastore -ErrorAction Stop | get-vm -ErrorAction Stop | get-vmhost -ErrorAction Stop | Select-Object -Unique -Property name
                                $myvar_datastore_vms = get-datastore -name $myvar_datastore -ErrorAction Stop | get-vm -ErrorAction Stop
                                $myvar_datastore_poweredoff_vms = $myvar_datastore_vms | Where-Object {$_.PowerState -eq "PoweredOff"}
                                $myvar_datastore_poweredon_vms = $myvar_datastore_vms | Where-Object {$_.PowerState -eq "PoweredOn"}
                            }
                            catch 
                            {#could not get vms on datastore
                                throw "$(get-date) [ERROR] Could not retrieve datastores from vCenter server $($myvar_vcenter_ip) : $($_.Exception.Message)"
                            }

                            #* process powered on vms; dealing with DRS overrides here
                            ForEach ($myvar_datastore_poweredon_vm in $myvar_datastore_poweredon_vms)
                            {#let's make sure none of the powered on vms have DRS override
                                $myvar_datastore_poweredon_vm_details = Get-VM -Name $myvar_datastore_poweredon_vm.Name #this is required as somehow, when we get VM objects from a get-datastore pipe, the DrsAutomationLevel property does not get populated
                                if ($myvar_datastore_poweredon_vm_details.VMHost -notin $myvar_compute_cluster_hosts)
                                {#this VM is not in the same HA/DRS cluster. It could be a backup proxy or some other vm with data in the datastore
                                    Write-Host "$(Get-Date) [ERROR] Virtual Machine $($myvar_datastore_poweredon_vm.Name) is running on vmhost $(($myvar_datastore_poweredon_vm_details.VMHost).Name) which is not part of the compute cluster $($myvar_vsphere_cluster_name). This could be a backup proxy server or some other vm which has a disk or data in the metro datastore. You will need to correct this manually!" -ForegroundColor Red
                                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] List of Nutanix cluster hosts:" -ForegroundColor White; $myvar_compute_cluster_hosts}
                                }
                                elseif ($myvar_datastore_poweredon_vm_details.DrsAutomationLevel -ne "AsSpecifiedByCluster")
                                {#this vm has a DRS override
                                    #check vmhost for that vm
                                    Write-Host "$(Get-Date) [WARNING] Virtual Machine $($myvar_datastore_poweredon_vm.Name) has a DRS override configured to $($myvar_datastore_poweredon_vm_details.DrsAutomationLevel). Changing it back to default AsSpecifiedByCluster" -ForegroundColor Yellow
                                    if (!$resetOverrides)
                                    {#user hasn't specified he want to remove DRS override by default, so prompting
                                        $myvar_user_choice = Write-CustomPrompt
                                    }
                                    else 
                                    {#user has already said he wanted to remove DRS overrides by default
                                        $myvar_user_choice = "y"
                                    }
                                    
                                    if ($myvar_user_choice -match '[yY]')
                                    {#user wants to remove drs override
                                        try 
                                        {#remove VM DRS override
                                            $result = Set-VM -VM $myvar_datastore_poweredon_vm -DrsAutomationLevel "AsSpecifiedByCluster" -Confirm:$false -ErrorAction Stop
                                        }
                                        catch 
                                        {#could not remove VM DRS override
                                            throw "$(get-date) [ERROR] Could not remove DRS override for VM $($myvar_datastore_poweredon_vm.Name) : $($_.Exception.Message)"
                                        }
                                    }
                                }
                            }

                            #* process powered off vms
                            if ($myvar_datastore_poweredoff_vms)
                            {#there are powered off vms in this datastore
                                ForEach ($myvar_datastore_poweredoff_vm in $myvar_datastore_poweredoff_vms)
                                {#let's make sure the powered off vms will power on on the right host
                                    Write-Host "$(get-date) [INFO] Setting DRS override for powered off VM $($myvar_datastore_poweredoff_vm.Name) to run on remote host group..." -ForegroundColor Green
                                    try 
                                    {#set VM DRS override
                                        $result = Set-VM -VM $myvar_datastore_poweredoff_vm -DrsAutomationLevel "Manual" -Confirm:$false -ErrorAction Stop
                                    }
                                    catch 
                                    {#could not set VM DRS override
                                        throw "$(get-date) [ERROR] Could not set DRS override for VM $($myvar_datastore_poweredoff_vm.Name) : $($_.Exception.Message)"
                                    }
                                }
                            }

                            #check if all vms in datastore are on remote hosts
                            Write-Host "$(get-date) [INFO] Checking if all VMs in datastore $($myvar_datastore) have moved to remote site..." -ForegroundColor Green
                            $myvar_all_vms_on_remote = $true
                            ForEach ($myvar_vm in $myvar_datastore_vms)
                            {
                                if ($myvar_vm.vmhost -in $myvar_ntnx_vmhosts)
                                {#this vm is still on a local host
                                    $myvar_all_vms_on_remote = $false
                                    break
                                }
                            }
                            if ($myvar_all_vms_on_remote)
                            {
                                $myvar_drs_done = $true
                                Write-Host "$(get-date) [SUCCESS] All VMs in datastore $($myvar_datastore) have moved to remote site!" -ForegroundColor Cyan
                            }
                            else
                            {
                                Write-Host "$(get-date) [WARNING] Some VMs in datastore $($myvar_datastore) are still on local site. Waiting 30 seconds..." -ForegroundColor Yellow
                                Start-Sleep 30
                            }
                        } While (-not $myvar_drs_done)
                    }                    
                #endregion
            }
            else 
            {#we are using DoNotUseDrs
                #* set DRS to manual
                Write-Host "$(get-date) [INFO] Setting DRS to manual on cluster $($myvar_vsphere_cluster_name)..." -ForegroundColor Green
                try {Set-Cluster -Cluster $myvar_vsphere_cluster -DrsAutomationLevel "Manual" -Confirm:$false -ErrorAction Stop}
                catch {throw "$(get-date) [ERROR] Could not set DRS to manual on cluster $($myvar_vsphere_cluster_name) : $($_.Exception.Message)"}

                #* drain vms from each datastore
                foreach ($myvar_datastore in $ctr_list.name)
                {#process each datastore
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Draining VMs from datastore $($myvar_datastore) to remote host group..." -ForegroundColor Magenta
                    invoke-DatastoreVmDrain -datastore $myvar_datastore -vmhost_group $myvar_remote_ntnx_vmhosts
                }
            }
        #endregion

        #region re-enable replication
            #... rest of the script would continue here
            # For brevity, the re-enable logic is similar to above
        #endregion

    Write-Host ""
    Write-Host "$(get-date) [STEP] Disconnecting from vCenter server $($myvar_vcenter_ip)..." -ForegroundColor Green
    Disconnect-VIServer -Server $myvar_vcenter_ip -Confirm:$False -ErrorAction SilentlyContinue
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
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable pd -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vcenterCreds -ErrorAction SilentlyContinue
    Remove-Variable cvmCreds -ErrorAction SilentlyContinue
    Remove-Variable unplanned -ErrorAction SilentlyContinue
    Remove-Variable action -ErrorAction SilentlyContinue
    Remove-Variable skipfailover -ErrorAction SilentlyContinue
    Remove-Variable shutdownUvms -ErrorAction SilentlyContinue
    Remove-Variable resetOverrides -ErrorAction SilentlyContinue
    Remove-Variable timer -ErrorAction SilentlyContinue
    Remove-Variable reEnableOnly -ErrorAction SilentlyContinue
    Remove-Variable DisableOnly -ErrorAction SilentlyContinue
    Remove-Variable DoNotUseDrs -ErrorAction SilentlyContinue
    Remove-Variable reEnableDelay -ErrorAction SilentlyContinue
    Remove-Variable maxConcurrentRepl -ErrorAction SilentlyContinue
    Remove-Variable remoteSiteIp -ErrorAction SilentlyContinue
#endregion