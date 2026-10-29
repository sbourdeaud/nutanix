<#
.SYNOPSIS
  This script can be used to clone a volume group attached to a source vm to a target vm.
.DESCRIPTION
  The script checks that the specified source and target VMs exist, then lists the volume groups available on the source VM and prompts the user to choose (assuming there is more than one vg, otherwise it just proceeds), clones the volume group (adding a timestamp to the cloned vg name) and direct attaches it to the target vg. It then displays the disk label of the newly attached volume group.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER sourcevm
  Name of the source virtual machine as displayed in Prism.
.PARAMETER targetvm
  Name of the target virtual machine as displayed in Prism.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.EXAMPLE
  .\clone-ntnxVg.ps1 -cluster ntnxc1.local -sourcevm sqlprod1 -targetvm sqldev1
Display a list of volume groups to clone from sqlprod1 to sqldev1 and proceed with the clone operation.
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
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $true)] [string]$sourcevm,
        [parameter(mandatory = $true)] [string]$targetvm,
        [parameter(mandatory = $false)] [string]$prismCreds
    )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
02/06/2021 sb   Replaced username with get-credential
04/03/2020 sb   Do over with sbourdeaud module.
06/19/2015 sb   Initial release.
################################################################################
'
    $myvarScriptName = ".\clone-ntnxVg.ps1"
    
    if ($help) 
    {
        get-help $myvarScriptName
        exit
    }
    if ($History) 
    {
        $HistoryText
        exit
    }

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) 
    {
        throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
    }

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

    function Get-PrismTaskStatus {
        param (
            [Parameter(Mandatory)]
            $Task,
            
            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]
            $credential,

            [parameter(mandatory = $true)]
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

    function Write-Menu {
        param (
            [Parameter(Mandatory)]
            $Menu,
            
            [Parameter(Mandatory)]
            [string]$PropertyToShow,
            
            [string]$Prompt = "Select an option",
            
            [string]$Header = "Options",
            
            [string]$TextColor = "White",
            
            [string]$HeaderColor = "White",
            
            [int]$Shift = 0
        )

        $items = @($Menu)
        if ($items.Count -eq 0) { throw "Menu is empty" }
        
        Write-Host "$Header" -ForegroundColor $HeaderColor
        for ($i = 0; $i -lt $items.Count; $i++) {
            $display = $items[$i].$PropertyToShow
            Write-Host "  [$($i + 1 + $Shift)] $display" -ForegroundColor $TextColor
        }
        
        do {
            $choice = Read-Host -Prompt "$Prompt [1-$($items.Count + $Shift)]"
        } while ($choice -notmatch '^\d+$' -or [int]$choice -lt 1 -or [int]$choice -gt ($items.Count + $Shift))
        
        return $items[([int]$choice - 1 - $Shift)]
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
#endregion


#region parameters validation	
	#let's initialize parameters if they haven't been specified
    if ($sourcevm -eq $targetvm)
    {#source and target vm are the same
        Write-Host "$(Get-Date) [ERROR] Source VM and target VM cannot be the same!" -ForegroundColor Red
        exit
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
#endregion


#region processing	
    #region getting VMs
        Write-Host "$(Get-Date) [INFO] Retrieving list of VMs..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
        $method = "GET"
        $vmList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved VMs list from $cluster!" -ForegroundColor Cyan
        
        if ($sourceVmObject = $vmList.entities | Where-Object {$_.Name -eq $sourcevm})
        {#checking source vm exists
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of source vm $sourcevm with uuid $($sourceVmObject.uuid)" -ForegroundColor Cyan
        }
        else 
        {#source vm does not exist
            Write-Host "$(Get-Date) [ERROR] Could not find source vm $sourcevm on $cluster!" -ForegroundColor Red   
            exit
        }

        if ($targetVmObject = $vmList.entities | Where-Object {$_.Name -eq $targetvm})
        {#checking target vm exists
            Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of target vm $targetvm with uuid $($targetVmObject.uuid)" -ForegroundColor Cyan
        }
        else 
        {#target vm does not exist
            Write-Host "$(Get-Date) [ERROR] Could not find target vm $targetvm on $cluster!" -ForegroundColor Red    
            exit
        }
    #endregion

    #region getting cluster information
        Write-Host "$(Get-Date) [INFO] Retrieving cluster basic information..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $clusterInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved information from $cluster!" -ForegroundColor Cyan

        if ($clusterInfo.hypervisor_types -eq "kVmware")
        {#cluster is running ESXi
			Write-Host "$(Get-Date) [ERROR] Cluster $cluster is running VMware vSphere which is not compatible yet with this script!" -ForegroundColor Red
			Exit
        }

        if ($clusterInfo.hypervisor_types -eq "kKvm")
        {#cluster is running AHV
            Write-Host "$(Get-Date) [INFO] Cluster $cluster is running AHV" -ForegroundColor Green
		}
		else
		{
			Write-Host "$(Get-Date) [ERROR] The hypervisor running on cluster $cluster is not compatible with this script (only AHV is supported at the moment)!" -ForegroundColor Red
			Exit
		}
    #endregion

    #region getting volume groups attached to source vm        
        Write-Host "$(Get-Date) [INFO] Retrieving cluster volume groups information..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved information cluster volume groups!" -ForegroundColor Cyan

        if ($sourceVmVgs = $vgInfo.entities | Where-Object {$_.attachment_list.vm_uuid -eq $sourceVmObject.uuid})
        {#found one or more volume group(s) attached to the source vm
            if ($sourceVmVgs -is [array])
            {#more than one vg attached
                Write-Host "$(Get-Date) [SUCCESS] Found $($sourceVmVgs.count) volume groups attached to the source vm $sourcevm" -ForegroundColor Cyan
            }
            else 
            {#a single vg attached
                Write-Host "$(Get-Date) [SUCCESS] Found a single volume group attached to the source vm $sourcevm" -ForegroundColor Cyan
            }
        }
        else
        {#could not find volume groups attached to the source vm
            Write-Host "$(Get-Date) [ERROR] There were no volume groups found attached to the source vm $sourcevm on cluster $cluster" -ForegroundColor Red
            exit
        }
    #endregion

    #region prompting user to select volume groups to clone (if more than one vg were found)
        if ($sourceVmVgs -is [array])
        {#more than one vg attached
            $userchoice = Write-Menu -Menu $sourceVmVgs -PropertyToShow Name -Prompt "Select a volume group to clone" -Header "Available Volume Groups" -TextColor Green -HeaderColor Green -Shift 1
		}
		else
		{#only one vg attached
			$userchoice = $sourceVmVgs
		}
    #endregion

    #region cloning volume group
        Write-Host "$(Get-Date) [INFO] Cloning volume group $($userchoice.name) with uuid $($userchoice.uuid)..." -ForegroundColor Green
        $timestamp = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $vgCloneName = "$($userchoice.name)-$($timestamp)clone"
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($userchoice.uuid)/clone"
        $method = "POST"
        $content = @{
            name = $vgCloneName
        }
        $body = (ConvertTo-Json $content)
        $vgCloneTaskResp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
        Write-Host "$(Get-Date) [SUCCESS] Successfully started task to clone volume group $($userchoice.name) with uuid $($userchoice.uuid)!" -ForegroundColor Cyan

        Start-Sleep -Seconds 5
        Get-PrismTaskStatus -Task $vgCloneTaskResp.task_uuid -credential $prismCredentials -cluster $cluster
    #endregion
    
    #region retrieving details about the cloned vg
        Write-Host "$(Get-Date) [INFO] Retrieving cluster volume groups information..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved information cluster volume groups!" -ForegroundColor Cyan

        if ($clonedVg = $vgInfo.entities | Where-Object {$_.name -eq $vgCloneName})
        {#found our cloned vg
            Write-Host "$(Get-Date) [SUCCESS] Found $($clonedVg.name) with uuid $($clonedVg.uuid)" -ForegroundColor Cyan
        }
        else
        {#could not find our cloned vg
            Write-Host "$(Get-Date) [ERROR] Could not find volume group $vgCloneName on cluster $cluster" -ForegroundColor Red
            exit
        }
    #endregion

    #region attaching volume groups to target vm
        Write-Host "$(Get-Date) [INFO] Attaching volume group $($clonedVg.name) with uuid $($clonedVg.uuid) to vm $targetVm with uuid $($targetVmObject.uuid)..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($clonedVg.uuid)/attach"
        $method = "POST"
        $content = @{
            operation = "ATTACH"
            vm_uuid = $($targetVmObject.uuid)
        }
        $body = (ConvertTo-Json $content)
        $vgAttachTaskResp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $body
        Write-Host "$(Get-Date) [SUCCESS] Successfully started task to attach volume group $($clonedVg.name) to vm $targetVm!" -ForegroundColor Cyan

        Start-Sleep -Seconds 5
        Get-PrismTaskStatus -Task $vgAttachTaskResp.task_uuid -credential $prismCredentials -cluster $cluster
    #endregion

    #region retrieving new details of target vm
        Write-Host "$(Get-Date) [INFO] Retrieving new details of vm $targetVm..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($targetVmObject.uuid)?include_vm_disk_config=true"
        $method = "GET"
        $newTargetVmObject = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved new details of vm $targetVm!" -ForegroundColor Cyan

        $disk_label = $newTargetVmObject.vm_disk_info.disk_address | Where-Object {$_.volume_group_uuid -eq $($clonedVg.uuid)}
        Write-Host "$(Get-Date) [SUCCESS] Volume group $($clonedVg.name) has been attached to $targetVm as disk $($disk_label.disk_label)" -ForegroundColor Cyan
        
    #endregion

#endregion


#region cleanup
	#let's figure out how much time this all took
	Write-Host ""
	Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
	Remove-Variable prismCreds -ErrorAction SilentlyContinue
	Remove-Variable sourcevm -ErrorAction SilentlyContinue
	Remove-Variable targetvm -ErrorAction SilentlyContinue
#endregion