<#
.SYNOPSIS
  Use this script to add one or more disks to an existing VM.
.DESCRIPTION
  The script takes a VM, a size (in GiB) and a quantity of disks as input. Optionally, it can also take a storage container as input. It then adds the specified number of disks to the VM, either in the same container as disk scsi0:0, or in the specified container.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vm
  Specifies the name of the VM to add disks to.
.PARAMETER qty
  Quantity of disks to add (default is 1 if qty is not specified).
.PARAMETER size
  Size in GiB of the disk(s) to add.
.PARAMETER container
  Name of the container where you want the disks to be created in. If none is specified, the disks will be added in the same container as disk scsi0:0.
.EXAMPLE
.\new-AhvVmDisk.ps1 -cluster ntnxc1.local -vm myvm -size 100
Adds a single 100 GiB disk to VM myvm.
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
        [parameter(mandatory = $false,HelpMessage = "Enter the Nutanix AHV cluster name or address")] [string]$cluster,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false,HelpMessage = "Enter the name of the VM to add disks to")] [string]$vm,
        [parameter(mandatory = $false,HelpMessage = "Enter the size in GiB of the disks to add")] [int64]$size,
        [parameter(mandatory = $false)] [string]$container,
        [parameter(mandatory = $false)] [int]$qty
    )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
09/11/2018 sb   Initial release.
04/06/2020 sb   Do over with sbourdeaud module
02/06/2021 sb   Replaced username with get-credential
22/10/2021 sb   Removed dependency on external modules; Added Get-NtnxTask to function library; Replaced Invoke-PrismRESTCall references with Invoke-PrismAPICall; made hypervisor comparison case insensitive (thx to Philippe Lima for catching all of those errors)
################################################################################
'@
    $myvarScriptName = ".\new-AhvVmDisk.ps1"

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

    function Get-PrismTaskStatus {
        param (
            [Parameter(Mandatory)]
            $Task,
            [parameter(mandatory = $false)]
            [System.Management.Automation.PSCredential]
            $credential,
            [parameter(mandatory = $false)]
            [String]
            $cluster
        )

        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$Task"
        $method = "GET"
        
        Write-Host "$(Get-Date) [INFO] Retrieving details of task $Task..." -ForegroundColor Green
        $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $Task" -ForegroundColor Cyan

        While ($taskDetails.progress_status -ne "Succeeded")
        {
            if ($taskDetails.progress_status -eq "Failed") 
            {
                Write-Host "$(Get-Date) [ERROR] Task failed with status: $($taskDetails.progress_status)" -ForegroundColor Red
                throw "$(get-date) [ERROR] Task $Task failed. Exiting!"
            }
            else 
            {
                Write-Host "$(get-date) [WARNING] Task $Task status is $($taskDetails.progress_status) with $($taskDetails.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
            $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
        }
        Write-Host "$(Get-Date) [SUCCESS] Task $Task completed successfully!" -ForegroundColor Cyan
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
#endregion


#region parameters validation
    if (!$prismcentral -or !$vmname -or !$disksize) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral -vmname -disksize!"
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

    if (!$qty) {$qty = 1}
    $size = $size * 1024 * 1024 * 1024 
#endregion


#region processing	
    #region check cluster is running AHV
        Write-Host "$(get-date) [INFO] Retrieving details of Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $cluster_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of Nutanix cluster $cluster" -ForegroundColor Cyan

        Write-Host "$(get-date) [INFO] Hypervisor on Nutanix cluster $cluster is of type $($cluster_details.hypervisor_types)." -ForegroundColor Green

        if ($cluster_details.hypervisor_types -ine "kKvm")
        {#this isn't an AHV cluster
            Throw "$(get-date) [ERROR] $cluster is not an AHV cluster!"
        }
    #endregion

    #region check the VM exists
        Write-Host "$(get-date) [INFO] Retrieving VMs from cluster $cluster..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true"
        $method = "GET"
        $vmList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved VMs from $cluster!" -ForegroundColor Cyan
        
        if (!($vmDetails = $vmList.entities | Where-Object {$_.name -eq $vm}))
        {#couldn't find a matching VM
            Throw "$(get-date) [ERROR] Could not find VM $vm on $cluster!"
        }
    #endregion

    #region find the disk labeled scsi.0 if no container has been specified
        if (!$container)
        {#no container has been specified
            ForEach ($vmDisk in $vmDetails.vm_disk_info)
            {#for each vm disk
                if ($vmDisk.disk_address.disk_label -eq "scsi.0")
                {#this is the first scsi disk
                    Write-Host "$(get-date) [INFO] Found disk uuid $($vmDisk.disk_address.vmdisk_uuid) with label scsi.0 for VM $vm on $cluster" -ForegroundColor Green
                    $diskUuid = $vmDisk.disk_address.vmdisk_uuid
                }
            }

            if (!$diskUuid)
            {#couldn't find a disk labeled scsi.0
                Throw "$(get-date) [ERROR] Could not find a disk labeled scsi.0 for VM $vm on $cluster!"
            }

            #region get the disk nfs file path
                Write-Host "$(get-date) [INFO] Retrieving details of disk $diskUuid..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/virtual_disks/$diskUuid"
                $method = "GET"
                $diskDetails = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of disk $diskUuid!" -ForegroundColor Cyan

                $diskContainerUUid = $diskDetails.storage_container_uuid
            #endregion
        }
    #endregion

    #region check the specified container exists
        if ($container)
        {#a container was specified
            Write-Host "$(get-date) [INFO] Retrieving storage containers from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/storage_containers/"
            $method = "GET"
            $storage_containers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved storage containers from Nutanix cluster $cluster" -ForegroundColor Cyan

            if (!($diskContainerUUid = ($storage_containers.entities | Where-Object {$_.name -eq $container}).storage_container_uuid))
            {#couldn't find a matching container
                Throw "$(get-date) [ERROR] Could not find container $container on $cluster!"
            }
        }
    #endregion

    #region add the disks
        Write-Host "$(get-date) [INFO] Adding $qty disk(s) of size $size bytes to $vm in container $diskContainerUUid..." -ForegroundColor Green
        $taskUuids = @()
        While ($qty -ne 0)
        {
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($vmDetails.uuid)/disks/attach"
            $method = "POST"
            $content = @{
                vm_disks = 
                @(
                @{
                is_cdrom = "false"
                vm_disk_create = 
                    @{
                        size = $size
                        "storage_container_uuid" = $diskContainerUUid
                    }
                }           
                )
            }
            $body = (ConvertTo-Json $content -Depth 4)
            if ($debugme) {Write-Host $body -ForegroundColor White}
            $taskUuid = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
            Write-Host "$(get-date) [SUCCESS] Successfully requested 1 disk of size $size bytes to be added to $vm in container $diskContainerUUid!" -ForegroundColor Cyan
            $qty = $qty - 1
            $taskUuids += $taskUuid
        }

        #check on image import task status
        Foreach ($diskAddTask in $taskUuids)
        {
            Write-Host "$(get-date) [INFO] Checking status of the disk creation task $($diskAddTask.task_uuid)..." -ForegroundColor Green
            Get-PrismTaskStatus -Task $diskAddTask.task_uuid -credential $prismCredentials -cluster $cluster
        }

    #endregion
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
	Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vm -ErrorAction SilentlyContinue
    Remove-Variable qty -ErrorAction SilentlyContinue
    Remove-Variable size -ErrorAction SilentlyContinue
    Remove-Variable container -ErrorAction SilentlyContinue
#endregion