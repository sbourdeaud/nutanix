<#
.SYNOPSIS
  Use this script to create and direct attach a volume group to an existing VM.
.DESCRIPTION
  The script takes a VM, a volume group name, a size (in GiB) and a quantity of disks as input. Optionally, it can also take a storage container as input. It then adds the specified number of disks to the volume group, either in the same container, or in the specified container, and then attaches the volume group to the VM.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vg
  Specifies the name of the volume group to be created.
.PARAMETER vm
  Specifies the name of the VM to attach the volume group to. You can specify multiple vms by separating them with commas and enclosing everything in double quotes.
.PARAMETER qty
  Quantity of disks to add to the volume group (default is 1 if qty is not specified).
.PARAMETER size
  Size in GiB of the disk(s) to add inside the volume group.
.PARAMETER container
  Name of the container where you want the volume group disks to be created in. If none is specified, the disks will be added in the same container as disk scsi0:0 of the VM.
.EXAMPLE
.\new-AhvVmDisk.ps1 -cluster ntnxc1.local -vg myvm_data -vm myvm -size 100 -qty 5
Creates a volume group called myvm_data, adds five 100 GiB disks to it, then attach it to the VM myvm.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true,HelpMessage = "Enter the Nutanix AHV cluster name or address")] [string]$cluster,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true,HelpMessage = "Enter the name of the volume group to create")] [string]$vg,
        [parameter(mandatory = $true,HelpMessage = "Enter the name of the VM to attach the volume group to")] [string]$vm,
        [parameter(mandatory = $true,HelpMessage = "Enter the size in GiB of the disks to add")] [int64]$size,
        [parameter(mandatory = $false)] [string]$container,
        [parameter(mandatory = $false)] [int]$qty
    )
#endregion

#region functions
    function Write-LogOutput
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
            [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG')]
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
                "STEP" {$FgColor = "Magenta"}
                "DEBUG" {$FgColor = "White"}
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
    #check if we need to display help and/or history
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
12/13/2018 sb   Initial release. Happy birthday to my beloved wife, Elodie!
04/03/2020 sb   Do over with sbourdeaud module
01/28/2021 sb   Added ability to specify multiple VMs
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\new-AhvVg.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    #region module sbourdeaud is used for facilitating Prism REST calls
        $required_version = "3.0.8"
        if (!(Get-Module -Name sbourdeaud)) {
        Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
        try
        {
            Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
        }#end try
        catch #we couldn't import the module, so let's install it
        {
            Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
            try {Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop}
            catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

            try
            {
                Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
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
        if (($MyVarModuleVersion.Version.Major -lt $($required_version.split('.')[0])) -or (($MyVarModuleVersion.Version.Major -eq $($required_version.split('.')[0])) -and ($MyVarModuleVersion.Version.Minor -eq $($required_version.split('.')[1])) -and ($MyVarModuleVersion.Version.Build -lt $($required_version.split('.')[2])))) {
        Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
        Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
        Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
        try {
            Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
            Import-Module -Name sbourdeaud -ErrorAction Stop
        }
        catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
        }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_vm_list = @()
#endregion

#region parameters validation
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
    
    $myvar_vm_list = $vm.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#region processing	

    #region check cluster is running AHV
        Write-Host "$(get-date) [INFO] Retrieving details of Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $cluster_details = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of Nutanix cluster $cluster" -ForegroundColor Cyan

        Write-Host "$(get-date) [INFO] Hypervisor on Nutanix cluster $cluster is of type $($cluster_details.hypervisor_types)." -ForegroundColor Green

        if ($cluster_details.hypervisor_types -ne "kKvm")
        {#this isn't an AHV cluster
            Throw "$(get-date) [ERROR] $cluster is not an AHV cluster!"
        }
    #endregion

    #region check the VM exists
        Foreach ($myvar_vm in $myvar_vm_list)
        {
            Write-Host "$(get-date) [INFO] Retrieving VMs from cluster $cluster..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true"
            $method = "GET"
            $vmList = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved VMs from $cluster!" -ForegroundColor Cyan
            
            if (!($vmDetails = $vmList.entities | Where-Object {$_.name -eq $myvar_vm}))
            {#couldn't find a matching VM
                Throw "$(get-date) [ERROR] Could not find VM $myvar_vm on $cluster!"
            }

            #region find the disk labeled scsi.0 if no container has been specified
                if (!$container)
                {#no container has been specified
                    ForEach ($vmDisk in $vmDetails.vm_disk_info)
                    {#for each vm disk
                        if ($vmDisk.disk_address.disk_label -eq "scsi.0")
                        {#this is the first scsi disk
                            Write-Host "$(get-date) [INFO] Found disk uuid $($vmDisk.disk_address.vmdisk_uuid) with label scsi.0 for VM $myvar_vm on $cluster" -ForegroundColor Green
                            $diskUuid = $vmDisk.disk_address.vmdisk_uuid
                        }
                    }

                    if (!$diskUuid)
                    {#couldn't find a disk labeled scsi.0
                        Throw "$(get-date) [ERROR] Could not find a disk labeled scsi.0 for VM $myvar_vm on $cluster!"
                    }

                    #region get the disk nfs file path
                        Write-Host "$(get-date) [INFO] Retrieving details of disk $diskUuid..." -ForegroundColor Green
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/virtual_disks/$diskUuid"
                        $method = "GET"
                        $diskDetails = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of disk $diskUuid!" -ForegroundColor Cyan

                        $diskContainerUUid = $diskDetails.storage_container_uuid
                    #endregion
                }
            #endregion
        }
    #endregion

    #region check the specified container exists
        if ($container)
        {#a container was specified
            Write-Host "$(get-date) [INFO] Retrieving storage containers from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/storage_containers/"
            $method = "GET"
            $storage_containers = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved storage containers from Nutanix cluster $cluster" -ForegroundColor Cyan

            if (!($diskContainerUUid = ($storage_containers.entities | Where-Object {$_.name -eq $container}).storage_container_uuid))
            {#couldn't find a matching container
                Throw "$(get-date) [ERROR] Could not find container $container on $cluster!"
            }
        }
    #endregion

    #region create the volume group, including disks
        Write-Host "$(get-date) [INFO] Creating volume group $vg with $qty disk(s) of size $size bytes to $vm in container $diskContainerUUid..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/"
        $method = "POST"
        $content = @{
            description = "Volume group attached to vm $vm"
            disk_list = 
            @(
                while ($qty -ne 0) {
                    @{
                    create_config = 
                        @{
                            size = $size
                            storage_container_uuid = $diskContainerUUid
                        }
                    }
                    $qty = $qty - 1
                }
            )
            flash_mode_enabled = "false"
            is_shared = "true"
            name = "$vg"
        }
        $body = (ConvertTo-Json $content -Depth 4)
        if ($debugme) {Write-Host $body -ForegroundColor White}
        $taskUuid = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $body
        Write-Host "$(get-date) [SUCCESS] Successfully requested creation of volume group $vg in container $diskContainerUUid!" -ForegroundColor Cyan

        Write-Host "$(get-date) [INFO] Checking status of the volume group creation task $($taskUuid.task_uuid)..." -ForegroundColor Green
        $task = (Get-NTNXTask -TaskId $taskUuid -credential $prismCredentials -cluster $cluster)
        While ($task.progress_status -ne "Succeeded")
        {
            if ($task.progress_status -eq "Failed") 
            {#task failed
                throw "$(get-date) [ERROR] Volume group creation task $($taskUuid.task_uuid) failed. Exiting!"
            }
            else 
            {#task hasn't completed yet
                Write-Host "$(get-date) [WARNING] Volume group creation task $($taskUuid.task_uuid) status is $($task.progress_status) with $($task.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
            $task = (Get-NTNXTask -TaskId $taskUuid -credential $prismCredentials -cluster $cluster)
        } 
        Write-Host "$(get-date) [SUCCESS] Volume group creation task $($taskUuid.task_uuid) has $($task.progress_status)!" -ForegroundColor Cyan
    #endregion

    #region retrieving details about the created vg
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster volume groups information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information cluster volume groups!"

        if ($createdVg = $vgInfo.entities | Where-Object {$_.name -eq $vg})
        {#found our created vg
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found $($vg) with uuid $($createdVg.uuid)"
        }
        else
        {#could not find our created vg
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find volume group $vg on cluster $cluster"
            exit
        }
    #endregion

    #region attach volume group to the vms
        Foreach ($myvar_vm in $myvar_vm_list)
        {
            if (!($vmDetails = $vmList.entities | Where-Object {$_.name -eq $myvar_vm}))
            {#couldn't find a matching VM
                Throw "$(get-date) [ERROR] Could not find VM $myvar_vm on $cluster!"
            }

            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Attaching volume group $($createdVg.name) with uuid $($createdVg.uuid) to vm $myvar_vm with uuid $($vmDetails.uuid)..."
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($createdVg.uuid)/attach"
            $method = "POST"
            $content = @{
                operation = "ATTACH"
                vm_uuid = $($vmDetails.uuid)
            }
            $body = (ConvertTo-Json $content)
            $vgAttachTaskUuid = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials -payload $body
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started task to attach volume group $($createdVg.name) to vm $vm!"

            Start-Sleep -Seconds 5

            Write-Host "$(get-date) [INFO] Checking status of the volume group attach task $($vgAttachTaskUuid.task_uuid)..." -ForegroundColor Green
            $task = (Get-NTNXTask -TaskId $vgAttachTaskUuid -credential $prismCredentials -cluster $cluster)
            While ($task.progress_status -ne "Succeeded")
            {
                if ($task.progress_status -eq "Failed") 
                {#task failed
                    throw "$(get-date) [ERROR] Volume group attach task $($vgAttachTaskUuid.task_uuid) failed. Exiting!"
                }
                else 
                {#task hasn't completed yet
                    Write-Host "$(get-date) [WARNING] Volume group attach task $($vgAttachTaskUuid.task_uuid) status is $($task.progress_status) with $($task.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 5
                }
                $task = (Get-NTNXTask -TaskId $vgAttachTaskUuid -credential $prismCredentials -cluster $cluster)
            } 
            Write-Host "$(get-date) [SUCCESS] Volume group attach task $($vgAttachTaskUuid.task_uuid) has $($task.progress_status)!" -ForegroundColor Cyan
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
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion