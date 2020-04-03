<#
.SYNOPSIS
  This script can be used to clone a volume group attached to a source vm to a target vm.
.DESCRIPTION
  The script checks that the specified source and target VMs exist, then lists the volume groups available on the source VM and prompts the user to choose (assuming there is more than one vg, otherwise it just proceeds), clones the volume group (adding a timestamp to the cloned vg name) and direct attaches it to the target vg. It then displays the disk label of the newly attached volume group.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER sourcevm
  Name of the source virtual machine as displayed in Prism.
.PARAMETER targetvm
  Name of the target virtual machine as displayed in Prism.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
 .\clone-ntnxVg.ps1 -cluster ntnxc1.local -username admin -password admin -sourcevm sqlprod1 -targetvm sqldev1
Display a list of volume groups to clone from sqlprod1 to sqldev1 and proceed with the clone operation.
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 3rd 2020
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $true)] [string]$cluster,
	[parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $true)] [string]$sourcevm,
	[parameter(mandatory = $true)] [string]$targetvm,
	[parameter(mandatory = $false)] [string]$prismCreds
)
#endregion

#region functions
Function Write-LogOutput
{
<#
.SYNOPSIS
Outputs color coded messages to the screen and/or log file based on the category.

.DESCRIPTION
This function is used to produce screen and log output which is categorized, time stamped and color coded.

.PARAMETER Category
This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".

.PARAMETER Message
This is the actual message you want to display.

.PARAMETER LogFile
If you want to log output to a file as well, use logfile to pass the log file full path name.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Write-LogOutput -category "ERROR" -message "You must be kidding!"
Displays an error message.

.LINK
https://github.com/sbourdeaud
#>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		[Parameter(Mandatory)]
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS')]
        [string]
        $Category,

        [string]
		$Message,

        [string]
        $LogFile
	)

    process
    {
        $Date = get-date #getting the date so we can timestamp the output entry
	    $FgColor = "Gray" #resetting the foreground/text color
	    switch ($Category) #we'll change the text color depending on the selected category
	    {
		    "INFO" {$FgColor = "Green"}
		    "WARNING" {$FgColor = "Yellow"}
		    "ERROR" {$FgColor = "Red"}
            "SUM" {$FgColor = "Magenta"}
            "SUCCESS" {$FgColor = "Cyan"}
	    }

	    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
	    if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput
#endregion

#region prepwork
# get rid of annoying error messages
if (!$debugme) 
{
    $ErrorActionPreference = "SilentlyContinue"
}
if ($debugme) 
{
    $VerbosePreference = "Continue"
}

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/19/2015 sb   Initial release.
 04/03/2020 sb   Do over with sbourdeaud module.
################################################################################
'@
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

#check if we have all the required PoSH modules
Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

#region module sbourdeaud is used for facilitating Prism REST calls
if (!(Get-Module -Name sbourdeaud)) {
  Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
  try
  {
      Import-Module -Name sbourdeaud -ErrorAction Stop
      Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
  }#end try
  catch #we couldn't import the module, so let's install it
  {
      Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
      try {Install-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
      catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

      try
      {
          Import-Module -Name sbourdeaud -ErrorAction Stop
          Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
      }#end try
      catch #we couldn't import the module
      {
          Write-Host "$(get-date) [ERROR] Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)" -ForegroundColor Red
          Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/sbourdeaud/1.1" -ForegroundColor Yellow
          Exit
      }#end catch
  }#end catch
}#endif module sbourdeaud
$MyVarModuleVersion = Get-Module -Name sbourdeaud | Select-Object -Property Version
if (($MyVarModuleVersion.Version.Major -lt 3) -or (($MyVarModuleVersion.Version.Major -eq 3) -and ($MyVarModuleVersion.Version.Minor -eq 0) -and ($MyVarModuleVersion.Version.Build -lt 2))) {
  Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
  try {Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
  catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
}
#endregion
Set-PoSHSSLCerts
Set-PoshTls

#endregion

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

#endregion

#region parameters validation	
	#let's initialize parameters if they haven't been specified
    if ($sourcevm -eq $targetvm)
    {#source and target vm are the same
        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Source VM and target VM cannot be the same!"
        exit
	}
	if (!$prismCreds) 
	{#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
		if (!$username) 
		{#if Prism username has not been specified ask for it
			$username = Read-Host "Enter the Prism username"
		} 

		if (!$password) 
		{#if password was not passed as an argument, let's prompt for it
			$PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
		}
		else 
		{#if password was passed as an argument, let's convert the string to a secure string and flush the memory
			$PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
			Remove-Variable password
		}
		$prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
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
			$credname = Read-Host "Enter the credentials name"
			Set-CustomCredentials -credname $credname
			$prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
			$username = $prismCredentials.UserName
			$PrismSecurePassword = $prismCredentials.Password
		}
		$prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
	}
#endregion

#region processing	
    #region getting VMs
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of VMs..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
        $method = "GET"
        $vmList = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved VMs list from $cluster!"
        
        if ($sourceVmObject = $vmList.entities | Where-Object {$_.Name -eq $sourcevm})
        {#checking source vm exists
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details of source vm $sourcevm with uuid $($sourceVmObject.uuid)"
        }
        else 
        {#source vm does not exist
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find source vm $sourcevm on $cluster!"    
            exit
        }

        if ($targetVmObject = $vmList.entities | Where-Object {$_.Name -eq $targetvm})
        {#checking target vm exists
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details of target vm $targetvm with uuid $($targetVmObject.uuid)"
        }
        else 
        {#target vm does not exist
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find target vm $targetvm on $cluster!"    
            exit
        }
    #endregion

    #region getting cluster information
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster basic information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $clusterInfo = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information from $cluster!"

        if ($clusterInfo.hypervisor_types -eq "kVmware")
        {#cluster is running ESXi
			Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Cluster $cluster is running VMware vSphere which is not compatible yet with this script!"
			Exit
        }

        if ($clusterInfo.hypervisor_types -eq "kKvm")
        {#cluster is running ESXi
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Cluster $cluster is running AHV"
		}
		else
		{
			Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "The hypervisor running on cluster $cluster is not compatible with this script (only AHV is supported at the moment)!"
			Exit
		}
    #endregion

    #region getting volume groups attached to source vm        
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster volume groups information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information cluster volume groups!"

        if ($sourceVmVgs = $vgInfo.entities | Where-Object {$_.attachment_list.vm_uuid -eq $sourceVmObject.uuid})
        {#found one or more volume group(s) attached to the source vm
            if ($sourceVmVgs -is [array])
            {#more than one vg attached
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found $($sourceVmVgs.count) volume groups attached to the source vm $sourcevm"
            }
            else 
            {#a single vg attached
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found a single volume group attached to the source vm $sourcevm"
            }
        }
        else
        {#could not find volume groups attached to the source vm
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There were no volume groups found attached to the source vm $sourcevm on cluster $cluster"
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
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Cloning volume group $($userchoice.name) with uuid $($userchoice.uuid)..."
        $timestamp = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $vgCloneName = "$($userchoice.name)-$($timestamp)clone"
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($userchoice.uuid)/clone"
        $method = "POST"
        $content = @{
            name = $vgCloneName
        }
        $body = (ConvertTo-Json $content)
        $vgCloneTaskUuid = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $body
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started task to clone volume group $($userchoice.name) with uuid $($userchoice.uuid)!"

        Start-Sleep -Seconds 5
        Get-PrismTaskStatus -Task $vgCloneTaskUuid.task_uuid -credential $prismCredentials -cluster $cluster
    #endregion
    
    #region retrieving details about the cloned vg
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster volume groups information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information cluster volume groups!"

        if ($clonedVg = $vgInfo.entities | Where-Object {$_.name -eq $vgCloneName})
        {#found our cloned vg
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found $($clonedVg.name) with uuid $($clonedVg.uuid)"
        }
        else
        {#could not find our cloned vg
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find volume group $vgCloneName on cluster $cluster"
            exit
        }
    #endregion

    #region attaching volume groups to target vm
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Attaching volume group $($clonedVg.name) with uuid $($clonedVg.uuid) to vm $targetVm with uuid $($targetVmObject.uuid)..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($clonedVg.uuid)/attach"
        $method = "POST"
        $content = @{
            operation = "ATTACH"
            vm_uuid = $($targetVmObject.uuid)
        }
        $body = (ConvertTo-Json $content)
        $vgAttachTaskUuid = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $body
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started task to attach volume group $($clonedVg.name) to vm $targetVm!"

        Start-Sleep -Seconds 5
        Get-PrismTaskStatus -Task $vgAttachTaskUuid.task_uuid -credential $prismCredentials -cluster $cluster
    #endregion

    #region retrieving new details of target vm
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving new details of vm $targetVm..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($targetVmObject.uuid)?include_vm_disk_config=true"
        $method = "GET"
        $newTargetVmObject = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved new details of vm $targetVm!"

        $disk_label = $newTargetVmObject.vm_disk_info.disk_address | Where-Object {$_.volume_group_uuid -eq $($clonedVg.uuid)}
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Volume group $($clonedVg.name) has been attached to $targetVm as disk $($disk_label.disk_label)"
        
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
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
	Remove-Variable username -ErrorAction SilentlyContinue
	Remove-Variable password -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion