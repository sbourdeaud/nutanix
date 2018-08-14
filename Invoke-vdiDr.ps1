<#
.SYNOPSIS
  This script can be used to automate the failover (planned or unplanned) of Horizon View desktop pool(s) using manual assignment and full clones and hosted on a Nutanix cluster.
.DESCRIPTION
  This script can be used to automate the failover (planned or unplanned) of Horizon View desktop pool(s) using manual assignment and full clones and hosted on a Nutanix cluster.
  The script has four main workflows: (1)failover, (2)cleanup, (3)scan and (4)deactivate.

  Failover is either (1)planned or (2)unplanned.
  When planned, failover will:
    (1)Check that the targeted desktop pools on the source Horizon View server are disabled
    (2)Remove all machines from the targeted desktop pools on the source Horizon View server
    (3)Initiate migrate on the matching protection domains on the source Nutanix cluster, which will shutdown all the VMs and replicate them to the target site
    (4)Remove orphaned inventory entries from the source vCenter server
    (5)Move the VMs to the correct folder on the target vCenter server, and reconnect their vNIC to the distributed vSwitch if applicable
    (6)Add VMs to the desktop pools on the target Horizon View server
    (7)Assign users to their VM on the target Horizon View server
  When unplanned, failover will:
    (1)Activate the matching protection domains (for the given desktop pools) on the target Nutanix cluster
    (2)Move the VMs to the correct folder on the target vCenter server, and reconnect their vNIC to the distributed vSwitch if applicable
    (3)Add VMs to the desktop pools on the target Horizon View server
    (4)Assign users to their VM on the target Horizon View server

  Cleanup is either (1)planned or (2)unplanned.
  When planned, cleanup will:
    (1)Remove schedules from all matching protection domains on the source Nutanix cluster
  When unplanned, cleanup will:
    (1)Check that the targeted desktop pools on the source Horizon View server are disabled
    (2)Remove all machines from the targeted desktop pools on the source Horizon View server
    (3)Disable the matching protection domains on the source Nutanix cluster, which will DELETE ALL VMs on that cluster
    (4)Remove orphaned inventory entries from the source vCenter server

  Scan will:
    (1)Retrieve desktop pool information from the specified Horizon View server and save the desktop pool name and assigned user for each VM. A reference file is created in the specified directory.
    (2)Retrieve matching VMs information from the source vCenter server and save the Folder and portgroup name for each VM. A reference file is created in the specified directory.

  Deactivate will:
    (1)Disable the specified protection domain on the specified Nutanix cluster which will DELETE ALL VMs on that cluster

  In order to work properly, the script requires a reference file matching desktop pools to protection domain names. The file should be called poolRef.csv and be either in the script working directory, or the specified reference path.
  That reference file contains the following fields (in that order): desktop_pool,protection_domain. Headers should be specified in the csv file.

  Example:

  desktop_pool,protection_domain
  VDI1,async1
  VDI2,async2
  VDI3,async3
  VDI4,async4

.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER scan
  Specifies you want to create the reference files.  See the script description for more information.
.PARAMETER failover
  Specifies you want to trigger a failover workflow, either planned or unplanned.  See the script description for more information.
.PARAMETER cleanup
  Specifies you want to trigger a cleanup workflow, either planned or unplanned.  See the script description for more information.
.PARAMETER planned
  Used in conjunction with failover or cleanup. When used with failover, planned assumes both the source and target sites are available. See the script description for more information.
.PARAMETER unplanned
  Used in conjunction with failover or cleanup. When used with failover, unplanned assumes only the target site is available. See the script description for more information.
.PARAMETER deactivate
  Specifies you want to disable a protection domain and DELETE ALL VMs on that cluster that belong to that protection domain.  See the script description for more information.
.PARAMETER referentialPath
  Specifies the path where reference files are stored. Reference files are required for the failover and cleanup workflows. If no reference path is specified, the script working directory is used instead.
.PARAMETER target_pg
  Specifies the name of the portgroup you want to reconnect VMs to. If none is specified, the script figures out if there is a single distributed portgroup available, in which case it will use it.  If not, it looks for a matching portgroup name.  If there are none, it sees if there is a single portgroup on vSwitch0. If not, the script will fail. Alternatively, you can create a pgRef.csv file in the referential directory which contains "sourcePg","targetPg" headers and values. The script will then remap the vNIC interface to the target portgroup.
.PARAMETER protection_domains
  Lets you specify which protection domain(s) you want to failover. Only works with planned.
.PARAMETER desktop_pools
  Lets you specify which protection domain(s) you want to failover or cleanup.
.PARAMETER source_cluster
  Specifies the source Nutanix cluster (IP or FQDN).
.PARAMETER source_vc
  Specifies the source vCenter server (IP or FQDN).
.PARAMETER source_hv
  Specifies the source Horizon View server (IP or FQDN).
.PARAMETER target_cluster
  Specifies the target Nutanix cluster (IP or FQDN).
.PARAMETER target_vc
  Specifies the target vCenter server (IP or FQDN).
.PARAMETER target_hv
  Specifies the target Horizon View (IP or FQDN).
.PARAMETER prismCreds
  Specifies a custom credentials file name for Prism authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt).
.PARAMETER vcCreds
  Specifies a custom credentials file name for vCenter authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$vcCreds.txt).
.PARAMETER hvCreds
  Specifies a custom credentials file name for Horizon View authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$hvCreds.txt).
.PARAMETER noprompt
  Specifies that you do not want to be prompted for confirmation at each specific step. If neither prompt nor noprompt are used, the script will prompt once to determine if steps should be confirmed at the beginning of code execution (except for the scan workflow).
.PARAMETER prompt
  Specifies that you want to be prompted for confirmation at each specific step. If neither prompt nor noprompt are used, the script will prompt once to determine if steps should be confirmed at the beginning of code execution (except for the scan workflow).
.EXAMPLE
.\Invoke-vdiDr.ps1 -source_cluster <ip> -source_vc <ip> -source_hv <ip> -referentialPath c:\temp -scan -prismCreds prism_api-user
Trigger a scan of the source environment to create reference file and update protection domains as required. Use the previously stored credentials in the %USERPROFILE%\Documents\WindowsPowerShell\Credentials\prism_api-user.txt file (use the Set-CustomCredentials function in the sbourdeaud module to create the credentials file).
.EXAMPLE
.\Invoke-vdiDr.ps1 -source_cluster <ip> -source_vc <ip> -source_hv <ip> -referentialPath c:\temp -target_cluster <ip> -target_vc <ip> -target_hv <ip> -failover -planned  -username admin -password <secret>
Trigger a planned failover for all disabled desktop pools on the source Horizon View server which contain VMs.
.EXAMPLE
.\Invoke-vdiDr.ps1 -source_cluster <ip> -source_vc <ip> -source_hv <ip> -referentialPath c:\temp -target_cluster <ip> -target_vc <ip> -target_hv <ip> -failover -planned  -username admin -password <secret> -desktop_pools VDI1
Trigger a planned failover for the specified desktop pool on the source Horizon View server which contain VMs.
.EXAMPLE
.\Invoke-vdiDr.ps1 -referentialPath c:\temp -source_cluster <ip> -cleanup -planned  -username admin -password <secret> -desktop_pools VDI1,VDI3
Remove schedules for the matching protection domains (based on desktop pools) at the source Nutanix cluster after a planned failover has completed.
.EXAMPLE
.\Invoke-vdiDr.ps1 -referentialPath c:\temp -target_cluster <ip> -target_vc <ip> -target_hv <ip> -failover -unplanned  -username admin -password <secret> -desktop_pools VDI1,VDI3
Perform an unplanned failover of the designated desktop pools to a target Nutanix cluster.
.EXAMPLE
.\Invoke-vdiDr.ps1 -referentialPath c:\temp -source_cluster <ip> -source_vc <ip> -source_hv <ip> -cleanup -unplanned  -username admin -password <secret> -desktop_pools VDI1,VDI3
Empty desktop pools, disable protection domains, delete VMs and remove them from vCenter inventory on the source Nutanix cluster after an unplanned failover has been done to a target Nutanix cluster.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: August 2nd 2018
  Version: 3.0
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [switch]$scan,
    [parameter(mandatory = $false)] [switch]$failover,
    [parameter(mandatory = $false)] [switch]$deactivate,
    [parameter(mandatory = $false)] [switch]$planned,
    [parameter(mandatory = $false)] [switch]$unplanned,
    [parameter(mandatory = $false)] [switch]$cleanup,
    [parameter(mandatory = $false)] [string]$source_cluster,
    [parameter(mandatory = $false)] [string]$target_cluster,
    [parameter(mandatory = $false)] [string]$source_hv,
    [parameter(mandatory = $false)] [string]$target_hv,
    [parameter(mandatory = $false)] [string]$source_vc,
    [parameter(mandatory = $false)] [string]$target_vc,
    [parameter(mandatory = $false)] [string]$target_pg,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] [string]$referentialPath,
    [parameter(mandatory = $false)] $protection_domains, #don't specify type as this is sometimes a string, sometimes an array in the script
    [parameter(mandatory = $false)] $desktop_pools, #don't specify type as this is sometimes a string, sometimes an array in the script
    [parameter(mandatory = $false)] $prismCreds, #don't specify type as this is sometimes a string, sometimes secure credentials
    [parameter(mandatory = $false)] $vcCreds, #don't specify type as this is sometimes a string, sometimes secure credentials
    [parameter(mandatory = $false)] $hvCreds, #don't specify type as this is sometimes a string, sometimes secure credentials
    [parameter(mandatory = $false)] [switch]$noprompt,
    [parameter(mandatory = $false)] [switch]$prompt
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

#function update protection domain
Function Update-NutanixProtectionDomain
{
	#input: method (add or remove), cluster, username, password, protection domain name, vm name
	#output: POST method result response in json format
<#
.SYNOPSIS
  Adds/removes a VM to/from a Nutanix protection domain.
.DESCRIPTION
  Adds/removes a VM to/from a Nutanix protection domain.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER method
  This can be add or remove.
.PARAMETER cluster
  FQDN or IP of Nutanix cluster.
.PARAMETER username
  Nutanix cluster API username.
.PARAMETER password
  Nutanix cluster API password (passed as a secure string).
.PARAMETER protection_domain
  Protection Domain name.
.PARAMETER vm
  Virtual machine name.
.EXAMPLE
Update-NutanixProtectionDomain -method add -cluster ntnx1.local -username api-user -password $secret -protection_domain pd1 -vm vm1
#>
	[CmdletBinding()]
	param
	(
        [parameter(mandatory = $true)]
        [string]
        [ValidateSet('add','remove')]
        $action,
        [parameter(mandatory = $true)]
        [string]
        $cluster,
        [parameter(mandatory = $true)]
        [secureString]
        $password,
        [parameter(mandatory = $true)]
        [string]
        $username,
        [parameter(mandatory = $true)]
        [string]
        $protection_domain,
        [parameter(mandatory = $true)]
        [string]
        $vm
	)

    begin
    {
        switch ($action) 
        {
            add 
            {
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$protection_domain/protect_vms"
                $content = @{
                                app_consistent_snapshots = "false"
                                names = @(
                                            $vm
                                        )
                            }
            }
            remove 
            {
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$protection_domain/unprotect_vms"
                $content = @($vm)
            }
        }
    }

    process
    {
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Updating $protection_domain to $action $vm on $cluster ..."
        $method = "POST"
        $body = (ConvertTo-Json $content -Depth 4)
        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) -body $body
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully updated $protection_domain to $action $vm on $cluster"
    }

    end
    {
        return $response
    }
}#end function Invoke-HvQuery

#this function is used to control the workflow of the script by prompting the user
Function ConfirmStep
{
    [CmdletBinding()]
	param
	(
      [switch]$skip
	)

    begin
    {}

    process
    {
        if ($skip)
        {
            $promptUser = Write-CustomPrompt -skip
        }
        else
        {
            $promptUser = Write-CustomPrompt
        }
        switch ($promptUser) 
        {
            "y" {}
            "s" {}
            "n" {exit}
        }
    }

    end
    {
        return $promptUser
    }
}

#this function is used to reconnect a vm vnic to a portgroup
Function ConnectVmToPortGroup
{
    [CmdletBinding()]
    param
    (

    )

    begin
    {

    }

    process
    {
        try 
        {#figure out the portgroup name and connect the vnic
            if (!$target_pg) 
            {#no target portgroup has been specified, so we need to figure out where to connect our vnics

                #region see if we have a portgroup mapping reference file
                    If (Test-Path -Path ("$referentialPath\pgRef.csv")) 
                    {#we found a pgRef file
                        try 
                        {#load the pgRef.csv file
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Importing data from $referentialPath\pgRef.csv..."
                            $pgRef = Import-Csv -Path ("$referentialPath\pgRef.csv") -ErrorAction Stop
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported data from $referentialPath\pgRef.csv"

                            #see if we have a matching portgroup mapping in the reference file
                            $vmPortgroup = ($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).portgroup #retrieve the portgroup name at the source for this vm
                            if ($vmTargetPortGroup = ($pgRef | Where-Object {$_.sourcePg -eq $vmPortGroup}).targetPg)
                            {#we found a matching target portgroup using our pgRef file
                                try 
                                {#getting available portgroups on vmhost
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Fetching available portgroups on the vmhost for $($vmObject.Name)..."
                                    $HostAvailablePortgroups = $vmObject | Get-VMHost -ErrorAction Stop | Get-VirtualPortGroup -ErrorAction Stop
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Fetched available portgroups on the vmhost for $($vmObject.Name)."
                                    if ($target_pgObject = $HostAvailablePortGroups | Where-Object {$_.Name -eq $vmTargetPortGroup})
                                    {#found the target portgroup on our vmhost
                                        try 
                                        {#connect the vm to that portgroup
                                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting vm $($vmObject.Name) to $vmTargetPortGroup..."
                                            $result = $vmObject | Get-NetworkAdapter -ErrorAction Stop | Select-Object -First 1 |Set-NetworkAdapter -NetworkName $target_pgObject.Name -Confirm:$false -ErrorAction Stop
                                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected vm $($vmObject.Name) to $vmTargetPortGroup."
                                            return
                                        }
                                        catch 
                                        {#couldn't connect vm to that portgroup
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect vm $($vmObject.Name) to $vmTargetPortGroup : $($_.Exception.Message)"
                                            return
                                        }
                                    }
                                    else 
                                    {
                                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not find the target portgroup $vmTargetPortGroup. This vm will be skipped."                                            
                                    }
                                }
                                catch 
                                {#couldn't get available portgroups on vmhost
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not get available portgroups on vmhost : $($_.Exception.Message)"
                                    return
                                }
                            }
                            else
                            {#we didn't find a matching portgroup in our pgRef file
                                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not find a target portgroup for source portgroup $vmPortGroup in pgRef.csv. Skipping this vm."
                                return
                            }    
                        } 
                        catch 
                        {#we couldn't load the file
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\pgRef.csv : $($_.Exception.Message)"
                            Exit
                        }
                    }    
                #endregion
                    else 
                    {
                       #region automatically identify the best portgroup
                        $standard_portgroup = $false #we use this to track if the vm is laready connected to the correct standard vSwitch portgroup, in which case we won't try to reconnect
                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "No target portgroup was specified, figuring out which one to use..."
                        
                        #first we'll see if there is a portgroup with the same name in the target infrastructure
                        $vmPortgroup = ($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).portgroup #retrieve the portgroup name at the source for this vm
                        $portgroups = $vmObject | Get-VMHost | Get-VirtualPortGroup -Standard #retrieve portgroup names in the target infrastructure on the VMhost running that VM
                        $vSwitch0_portGroups = ($vmObject | Get-VMHost | Get-VirtualSwitch -Name "vSwitch0" | Get-VirtualPortGroup -Standard) # get portgroups only on vSwitch0
                        if ($target_pgObject = $dvPortgroups | Where-Object {$_.Name -eq $vmPortGroup}) 
                        {#we have a matching portgroup on a dvSwitch
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "There is a matching distributed portgroup $($target_pgObject.Name) which will be used."
                        } 
                        elseIf ($target_pgObject = $portgroups | Where-Object {$_.Name -eq $vmPortGroup}) 
                        {#we have a matching portgroup on a standard vSwitch
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "There is a matching standard portgroup $($target_pgObject.Name) which will be used."
                            $standard_portgroup = $true
                        } 
                        elseIf (!($dvPortGroups -is [array])) 
                        {#if not, we'll see if there is a dvswitch, and see if there is only one portgroup on that dvswitch
                            $target_pgObject = $dvPortgroups
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "There is a single distributed portgroup $($target_pgObject.Name) which will be used."
                        } 
                        elseIf (!($vSwitch0_portGroups -is [array])) 
                        {#if not, we'll see if there is a single portgroup on vSwitch0
                            $target_pgObject = $vSwitch0_portGroups
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "There is a single standard portgroup on vSwitch0 $($target_pgObject.Name) which will be used."
                            $standard_portgroup = $true
                        } 
                        else 
                        {#if not, we'll warn the user we could not process that VM
                            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not figure out which portgroup to use, so skipping connecting this VM's vNIC!"
                            continue
                        }
                    #endregion 
                    }
                
            } 
            else 
            { #fetching the specified portgroup
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving the specified target portgroup $target_pg..."
                try 
                {#retrieving the specified portgroup
                    $target_pgObject = Get-VirtualPortGroup -Name $target_pg
                } 
                catch 
                {#we couldn't get the portgroup object
                    Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not retrieve the specified target portgroup : $($_.Exception.Message)"
                    Continue
                }
                if ($target_pgObject -is [array]) 
                {#more than one portgroup with that name was found
                    Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "There is more than one portgroup with the specified name!"
                    Continue
                }
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved the specified target portgroup $target_pg"
            }
            #now that we know which portgroup to connect the vm to, let's connect its vnic to that portgroup
            if (!$standard_portgroup) 
            {
                $result = $vmObject | Get-NetworkAdapter -ErrorAction Stop | Select-Object -First 1 |Set-NetworkAdapter -NetworkName $target_pgObject.Name -Confirm:$false -ErrorAction Stop
            }
        }
        catch 
        {#we failed to connect the vnic
            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not reconnect $($vm.vmName) to the network : $($_.Exception.Message)"
            Continue
        }
        if (!$standard_portgroup) 
        {#we connected to a dvPortGroup
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Re-connected the virtual machine $($vm.vmName) to the network $($target_pgObject.Name)"
        } 
        else 
        {#vm is already connected to the correct portgroup
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Virtual machine $($vm.vmName) is already connected to an existing standard portgroup, so skipping reconnection..."
        }
    }

    end
    {

    }
}

#this function is used to move a vm to a folder
Function MoveVmToFolder
{
    [CmdletBinding()]
    param
    (

    )

    begin
    {

    }

    process
    {
        try 
        {#trying to move the vm
            if ($vmObject.Folder.Name -ne $folder.Name) 
            {#we moved the vm successfully
                $result = $vmObject | Move-VM -InventoryLocation $folder -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Moved $($vm.vmName) to folder $($folder.Name)"
            } 
            else 
            {#vm is already in the correct folder
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "VM $($vm.vmName) is already in folder $($folder.Name)"
            }
        }
        catch 
        {#we failed to move the vm to its folder
            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not move $($vm.vmName) to folder $($folder.Name) : $($_.Exception.Message)"
        }
    }

    end
    {

    }
}

#this function is used to add vms to a desktop pool
Function AddVmsToPool
{
    [CmdletBinding()]
    param
    (

    )

    begin
    {

    }

    process
    {
        #figure out the desktop pool Id
        $desktop_poolId = ($target_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Name -eq $desktop_pool}).Id
        #determine which vms belong to the desktop pool(s) we are processing
        $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}

        #add vms to the desktop pools
        if ($vms) 
        {#there are vms to process
            #process all vms for that desktop pool
            #we start by building the list of vms to add to the pool (this will be more efficient than adding them one by one)
            $vmIds = @()
            ForEach ($vm in $vms) 
            {#figure out the virtual machine id
                $vmId = ($target_hvAvailableVms | Where-Object {$_.Name -eq $vm.vmName}).Id
                $vmIds += $vmId
            }

            if (!$vmIds) 
            {#couldn't find vms ids
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "No Virtual Machines summary information was found from the TARGET Horizon View server $target_hv..."
                Exit
            }

            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Adding virtual machines to desktop pool $desktop_pool..."
            
            #! ACTION 1/3: Add vms to the desktop pool
            try 
            {#add vms
                $result = $target_hvObjectAPI.Desktop.Desktop_AddMachinesToManualDesktop($desktop_poolId,$vmIds)
            } 
            catch 
            {#couldn't add vms
                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not add virtual machines to desktop pool $desktop_pool : $($_.Exception.Message)"
                Continue
            }
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Added virtual machines to desktop pool $desktop_pool."

            #retrieve the list of machines now registered in the TARGET Horizon View server (we need their ids)
            #extract Virtual Machines summary information
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..."
            Sleep 15
            $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv"

            ForEach ($vm in $vms) 
            {#register users to their vms
                #figure out the object id of the assigned user
                if ($vm.assignedUser) 
                {#process the assigned user if there was one  
                    while (!($vmId = ($target_hvVMs | Where-Object {$_.Base.Name -eq $vm.vmName}).Id)) 
                    {#loop to figure out the virtual machine id for the recently added vms
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Waiting 15 seconds and retrieving Virtual Machines summary information from the TARGET Horizon View server $target_hv..."
                        Sleep 15
                        $target_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $target_hvObjectAPI
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Virtual Machines summary information from the TARGET Horizon View server $target_hv"
                    }

                    $vmUserId = ($target_hvADUsers | Where-Object {$_.Base.DisplayName -eq $vm.assignedUser}).Id #grab the user name whose id matches the id of the assigned user on the desktop machine
                    if (!$vmUserId) 
                    {#couldn't find the user in AD
                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not find a matching Active Directory object for user $($vm.AssignedUser) for VM $($vm.vmName)!"
                        continue
                    }

                    #create the MapEntry object required for updating the machine
                    $MapEntry = New-Object "Vmware.Hv.MapEntry"
                    $MapEntry.key = "base.user"
                    $MapEntry.value = $vmUserId

                    #update the machine
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Updating assigned user for $($vm.vmName)..."
                    #! ACTION 2/3: Assign user to the vm
                    try 
                    {#update vm
                        $result = $target_hvObjectAPI.Machine.Machine_Update($vmId,$MapEntry)
                    } 
                    catch 
                    {#couldn't update vm
                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not update assigned user to $($vm.vmName) : $($_.Exception.Message)"
                        Continue
                    }
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Updated assigned user for $($vm.vmName) to $($vm.assignedUser)."
                }

                if ($vm.status -eq "MAINTENANCE")
                {#check if the vm was in maintenance mode before
                    $MapEntry.key = "managedMachineData.inMaintenanceMode"
                    $MapEntry.value = $true

                    #update the machine
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Putting $($vm.vmName) in maintenance mode..."
                    #! ACTION 3/3: putting vm in maintenance mode
                    try 
                    {#update vm
                        $result = $target_hvObjectAPI.Machine.Machine_Update($vmId,$MapEntry)
                    } 
                    catch 
                    {#couldn't update vm
                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not put vm $($vm.vmName) in maintenance mode : $($_.Exception.Message)"
                        Continue
                    }
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Put vm $($vm.vmName) in maintenance mode."
                }
            }
        } 
        else 
        {#no vm in pool
            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "There were no virtual machines to add to desktop pool $desktop_pool..."
        }
    }

    end
    {

    }
}
#endregion

#region prepwork

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 05/11/2018 sb   Initial release.
 05/28/2018 sb   Added checks for PowerCLI version and corrected a parameter check bug with -failover -planned.
 05/31/2018 sb   Added prismCreds parameter.
 06/27/2018 sb   Added BetterTls module for Tls 1.2
 07/27/2018 sb   Multiple enhancements as documented on GitHub (pre-tests @customer site)
 08/01/2018 sb   Replaced prompting with Write-CustomPrompt and ConfirmStep functions.
                 Added ability to skip processing in workflows.
                 Added requirement for sbourdeaud module version 2.1 or above.
                 Replaced all output with Write-LogOutput.
                 Indented code properly for easier readout.
                 Marked specific sections doing actual processing in the code with #! for easier readout.
                 Replaced code in the prepwork region with functions from sbourdeaud module v2.1
 08/02/2018 sb   Fixed pagination in Invoke-HvQuery.
                 Added support for -desktop_pools with the -scan workflow.
                 Moved Invoke-HvQuery to sbourdeaud module.
                 Added ConnectVmToPortGroup, MoveVmToFolder and AddVmsToPool functions to rationalize the code.
                 Added support for a pgRef.csv reference file in order to map portgroups between site manually in the referential.
                 Tested all scan and failover planned workflows in the lab.
 08/14/2018 sb   Added disable of desktop pools in -cleanup -unplanned workflow.
                 Added BasicState property to -scan exported results.
                 Added code for failover workflows (in AddVmsToPool function) to move vms in maintenance mode after failover if that was their previously tracked status.
################################################################################
'@
$myvarScriptName = ".\Invoke-vdiDr.ps1"

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


#check if we have all the required PoSH modules
Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

#region module sbourdeaud is used for facilitating Prism REST calls
    if (!(Get-Module -Name sbourdeaud)) 
    {#module is not loaded
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Importing module 'sbourdeaud'..."
        try
        {#try loading the module
            Import-Module -Name sbourdeaud -ErrorAction Stop
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported module 'sbourdeaud'!"
        }
        catch 
        {#we couldn't import the module, so let's install it
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Installing module 'sbourdeaud' from the Powershell Gallery..."
            try 
            {#install
                Install-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
            }
            catch 
            {#couldn't install
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not install module 'sbourdeaud': $($_.Exception.Message)"
                Exit
            }

            try
            {#import
                Import-Module -Name sbourdeaud -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported module 'sbourdeaud'!"
            }
            catch 
            {#we couldn't import the module
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)"
                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Please download and install from https://www.powershellgallery.com/packages/sbourdeaud/1.1"
                Exit
            }
        }
    }#endif module sbourdeaud
    if (((Get-Module -Name sbourdeaud).Version.Major -le 2) -and ((Get-Module -Name sbourdeaud).Version.Minor -le 0)) 
    {
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Updating module 'sbourdeaud'..."
        try 
        {#update the module
            Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
        }
        catch 
        {#couldn't update
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not update module 'sbourdeaud': $($_.Exception.Message)"
            Exit
        }
    }
#endregion

#region module BetterTls
    $result = Set-PoshTls
#endregion

#region Load/Install VMware.PowerCLI
    $result = Get-PowerCLIModule
#endregion

#region get ready to use the Nutanix REST API
    #Accept self signed certs
    $code = @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    if (!(([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type))
    {#make sure the type isn't already there in order to avoid annoying error messages
        $result = add-type $code -ErrorAction SilentlyContinue
    }
    
    #we also need to use the proper encryption protocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol =  [System.Security.Authentication.SslProtocols] "tls12"

#endregion

#endregion

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$StartEpochSeconds = Get-Date (Get-Date).ToUniversalTime() -UFormat %s
    $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
    $myvarOutputLogFile += "Invoke-VdiDr_OutputLog.log"
    $promptUser = ""
    
    ########## uncomment those if you want to use constants instead of variables for some of the parameters
    #######################################################################################################
    #$source_cluster = "<enter your source Nutanix cluster here>"
    #$source_vc = "<enter your source vCenter server here>"
    #$source_hv = "<enter your source VMware Horizon View here>"
    #$target_cluster = "<enter your target Nutanix cluster here>"
    #$target_vc = "<enter your target vCenter server here>"
    #$target_hv = "<enter your target VMware Horizon View server here>"
    #$username = "<enter your Prism username here>"
    #$referentialPath = "<enter your path to reference files here>"
    #$target_pg = "<enter your target portgroup name here>"
    #$hvCreds = Get-Credential -Message "Please enter the credentials for the Horizon View server(s)"
    #$vcCreds = Get-Credential -Message "Please enter the credentials for the vCenter server(s)"
#endregion

#region parameters validation
	#let's initialize parameters if they haven't been specified

    #region deal with invalid combinations
        if ($prompt -and $noprompt) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only use prompt OR noprompt, not both at the same time!"
            Exit
        }
        if (!$scan -and !$failover -and !$deactivate -and !$cleanup) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You haven't specified any workflow (-scan, -failover, -deactivate or -cleanup)"
            Exit
        }
        if ($scan -and ($failover -or $deactivate -or $cleanup)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"
            Exit
        }
        if ($failover -and ($scan -or $deactivate -or $cleanup)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"
            Exit
        }
        if ($deactivate -and ($failover -or $scan -or $cleanup)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"
            Exit
        }
        if ($cleanup -and ($failover -or $deactivate -or $scan)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only specify a single workflow at a time (-scan, -failover, -deactivate or -cleanup)"
            Exit
        }
    #endregion

    #region check that we have what we need to proceed
        if (!$referentialPath) 
        {
            $referentialPath = (Get-Item -Path ".\").FullName #assume all reference fiels are in the current working directory if a path has not been specified
        } 
        If ((Test-Path -Path $referentialPath) -eq $false) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not access the path where the reference files are: $($_.Exception.Message)"
            Exit
        }
        If ((Test-Path -Path ("$referentialPath\PoolRef.csv")) -eq $false) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not access the PoolRef.csv file in $referentialPath : $($_.Exception.Message)"
            Exit
        }
    #endregion

    #region process credentials
        if (!$prismCreds) 
        {
            if (!$username) 
            {
                $username = "admin"
            } #if Prism username has not been specified, assume we are using admin

            if (!$password) #if it was not passed as an argument, let's prompt for it
            {
                $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
            }
            else #if it was passed as an argument, let's convert the string to a secure string and flush the memory
            {
                $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
                Remove-Variable password
            }
        } 
        else 
        {
            $prismCredentials = Get-CustomCredentials -credname $prismCreds
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }

        if ($vcCreds) 
        {
            $vcCreds = Get-CustomCredentials -credname $vcCreds
        }
        if ($hvCreds) 
        {
            $hvCreds = Get-CustomCredentials -credname $hvCreds
        }
    #endregion
    
    #region get the input we need by prompting if not already specified
        if (!$deactivate -and !$failover -and !$unplanned -and !$cleanup) 
        {
            if (!$source_cluster) 
            {
                $source_cluster = Read-Host "Enter the fully qualified domain name or IP address of the source Nutanix cluster" #prompt for the Nutanix source cluster name/ip if it hasn't been specified already
            } 
            if (!$source_vc) 
            {
                $source_vc = Read-Host "Enter the fully qualified domain name or IP address of the source vCenter server" #prompt for the vCenter server name/ip if it hasn't been specified already
            } 
            if (!$source_hv) 
            {
                $source_hv = Read-Host "Enter the fully qualified domain name or IP address of the source VMware Horizon View server" #prompt for the VMware Horizon View server name/ip if it hasn't been specified already
            } 
        }
        if ($failover -or $deactivate) 
        {
            if (!$target_cluster) 
            {
                $target_cluster = Read-Host "Enter the fully qualified domain name or IP address of the target Nutanix cluster" #prompt for the target Nutanix cluster name/ip if we are trying to failover and it hasn't been specified already
            } 
            if (!$deactivate -and !$target_vc) 
            {
                $target_vc = Read-Host "Enter the fully qualified domain name or IP address of the target vCenter server" #prompt for the target vCenter server name/ip if we are trying to failover and it hasn't been specified already
            } 
            if (!$deactivate -and !$target_hv) 
            {
                $target_hv = Read-Host "Enter the fully qualified domain name or IP address of the target VMware Horizon View server" #prompt for the target vCenter server name/ip if we are trying to failover and it hasn't been specified already
            } 
        }
        if ($failover -and (!$planned -and !$unplanned)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You need to specify -planned or -unplanned with -failover!"
            Exit
        }
        if ($failover -and ($planned -and $unplanned)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only specify -planned or -unplanned with -failover, not both at the same time!"
            Exit
        }
        if ($failover -and ($unplanned -and !$desktop_pools)) 
        {
            $desktop_pools = Read-Host "You must specify which desktop pools you want to failover (unplanned)"
        }
    #endregion

    #region misc cleanup items
        if ($cleanup) 
        {
            if (!$source_cluster) 
            {
                $source_cluster = Read-Host "Enter the fully qualified domain name or IP address of the Nutanix cluster that you want to clean up. This is usually the cluster where the VMs used to be." #prompt for the Nutanix source cluster name/ip if it hasn't been specified already
            } 
            if ($unplanned) 
            {
                if (!$source_vc) 
                {
                    $source_vc = Read-Host "Enter the fully qualified domain name or IP address of the vCenter server you want to cleanup" #prompt for the vCenter server name/ip if it hasn't been specified already
                } 
                if (!$source_hv) 
                {
                    $source_hv = Read-Host "Enter the fully qualified domain name or IP address of the VMware Horizon View server you want to cleanup" #prompt for the VMware Horizon View server name/ip if it hasn't been specified already
                } 
            }
        }
        if ($cleanup -and (!$planned -and !$unplanned)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You need to specify -planned or -unplanned with -cleanup!"
            Exit
        }
        if ($cleanup -and ($planned -and $unplanned)) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only specify -planned or -unplanned with -cleanup, not both at the same time!"
            Exit
        }
    #endregion

    #region process specified parameters as arrays where applicable
        if ($desktop_pools) 
        {
            $desktop_pools = $desktop_pools.Split(",") #make sure we process desktop_pools as an array
        } 
        if ($protection_domains) 
        {
            $protection_domains = $protection_domains.Split(",") #make sure we process protection_domains as an array
        } 
    #endregion

    #region misc prompt items
        if ($prompt) 
        {
            $confirmSteps = $true
        }
        if ($noprompt) 
        {
            $confirmSteps = $false
        }
    #endregion

#endregion

#TODO List
#TODO : 1. add code to control .Net SSL protocols here so that we can connect to View consistently (sometimes the SSL handshake fails for some reason)
#TODO : 2. Add planned connectivity check for target Prism Element in the region prechecks planned failover
#TODO : 3. Add WARNING when one of the specified pool is enabled (otherwise it's hard to catch that it is skipping that pool)
#TODO : 4. Add logic to not go ahead if there is nothing in the reference files (such as when using a pgRef.csv file and having forgotten to do a scan on target before failing back)

#region processing
	################################
	##  Main execution here       ##
	################################

    #region -scan
        if ($scan) 
        {#we're doing a scan
            #region prepare
                #load pool2pd reference
                try 
                {#load the file in $poolRef
                    $poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop
                } 
                catch 
                {#we couldn't load the file
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"
                    Exit
                }
            #endregion

            #region extract Horizon View data
                #region connect
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE Horizon View server $source_hv..."
                    try 
                    {#connect to Horizon View server
                        if ($hvCreds) 
                        {#use specified creds
                            $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                        } 
                        else 
                        {#no creds specified so rely on sso
                            $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                        }
                    }
                    catch
                    {#couldn't connect
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"
                        Exit
                    }
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the SOURCE Horizon View server $source_hv"
                    #create API object
                    $source_hvObjectAPI = $source_hvObject.ExtensionData
                #endregion
                
                #region get
                    [System.Collections.ArrayList]$newHvRef = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect new information from the system (vm name, assigned ad username, desktop pool name, vm folder, portgroup)

                    #region extract desktop pools
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..."
                        $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved desktop pools information from the SOURCE Horizon View server $source_hv"
                    #endregion

                    #region get AD information
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Active Directory user information from the SOURCE Horizon View server $source_hv..."
                        $source_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $source_hvObjectAPI
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Active Directory user information from the SOURCE Horizon View server $source_hv"
                    #endregion

                    #region get machines information
                        #extract Virtual Machines summary information
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..."
                        $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv"
                    #endregion

                    #region figure out the list of VMs to process
                        $vmObjectsToProcess = @() #we use this variable to build the list of vms to process
                        if ($desktop_pools)
                        {#specific pools were specified, let's keep only vms which are in those pools
                            #preserve the list of dekstop pool names for when we process protection domains in Prism
                            $desktopPoolNames = $desktop_pools
                            #turn our flat list of desktop_pools into Hv objects
                            $desktop_pools = $source_hvDesktopPools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
                            ForEach ($desktop_pool in $desktop_pools)
                            {#process each pool
                                #figure out which vms are in that pool
                                $vms = $source_hvVMs | Where-Object {$_.Base.Desktop.id -eq $desktop_pool.Id.Id}
                                #aggregate results in list of vms to process
                                $vmObjectsToProcess += $vms
                            }
                        }
                        else
                        {#we are processing all desktop pools
                            $vmObjectsToProcess = $source_hvVMs
                            #preserve the list of dekstop pool names for when we process protection domains in Prism
                            $desktopPoolNames = $source_hvDesktopPools.DesktopSummaryData.Name
                        }

                        #save the list of VMs to process for later (used when getting info from vCenter)
                        $vmsToProcess = $vmObjectsToProcess.Base.Name
                    #endregion

                    #region figure out the info we need for each VM (VM name, user, desktop pool name, status)
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Figuring out usernames for vms (this can take a while)..."

                        ForEach ($vm in $vmObjectsToProcess) 
                        { #let's process each vm
                            #figure out the vm assigned username
                            $vmUsername = ($source_hvADUsers | Where-Object {$_.Id.Id -eq $vm.Base.User.Id}).Base.DisplayName #grab the user name whose id matches the id of the assigned user on the desktop machine

                            #figure out the desktop pool name
                            $vmDesktopPool = ($source_hvDesktopPools | Where-Object {$_.Id.Id -eq $vm.Base.Desktop.Id}).DesktopSummaryData.Name

                            $vmInfo = @{"vmName" = $vm.Base.Name;"assignedUser" = $vmUsername;"desktop_pool" = "$vmDesktopPool";"status" = $vm.Base.BasicState} #we build the information for that specific machine
                            $result = $newHvRef.Add((New-Object PSObject -Property $vmInfo))
                        }
                    #endregion
                #endregion

                #region disconnect
                    Disconnect-HVServer -Confirm:$false
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the SOURCE Horizon View server $source_hv..."
                #endregion
            #endregion

            #region extract information from vSphere
                #region connect
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE vCenter server $source_vc ..."
                    try 
                    {#connect to the vCenter server
                        if ($vcCreds) 
                        {#use specified creds
                            $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                        } 
                        else 
                        {#no creds specified so rely on sso
                            $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                        }
                    }
                    catch 
                    {#couldn't connect
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"
                        Exit
                    }
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to SOURCE vCenter server $source_vc"
                #endregion

                #region get
                    [System.Collections.ArrayList]$newVcRef = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect new information from the system (vm name, assigned ad username, desktop pool name, vm folder, portgroup)

                    ForEach ($vm in $newHvRef) 
                    {#process each vm and figure out the folder and portgroup name
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving VM $($vm.vmName) ..."
                        try
                        {#get-vm
                            $vmObject = Get-VM $vm.vmName -ErrorAction Stop
                        } 
                        catch
                        {#couldn't get-vm
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not retrieve VM $($vm.vmName) : $($_.Exception.Message)"
                            Exit
                        }
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving portgroup name for VM $($vm.vmName) ..."
                        try 
                        {#get-networkadapter
                            $vmPortGroup = ($vmObject | Get-NetworkAdapter -ErrorAction Stop).NetworkName
                        } 
                        catch 
                        {#couldn't get-networkadapter
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not retrieve portgroup name for VM $($vm.vmName) : $($_.Exception.Message)"
                            Exit
                        }
                        if ($vmPortGroup -is [array]) 
                        {#portgroup is an array (meaning several vnics are connected)
                            $vmPortGroup = $vmPortGroup | Select-Object -First 1
                            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "There is more than one portgroup for $($vm.vmName). Only keeping the first one ($vmPortGroup)."
                        }
                        $vmInfo = @{"vmName" = $vm.vmName;"folder" = $vmObject.Folder.Name;"portgroup" = $vmPortGroup} #we build the information for that specific machine
                        $result = $newVcRef.Add((New-Object PSObject -Property $vmInfo))
                    }
                #endregion

                #region disconnect
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from SOURCE vCenter server $source_vc..."
                    Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
                #endregion
            #endregion

            #region extract Nutanix Prism data
                #extract protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from source Nutanix cluster $source_cluster ..."
                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                $newPrismRef = $sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name,vms
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from source Nutanix cluster $source_cluster"
            #endregion

            #region update reference files and figure out which vms need to be added/removed to protection domain(s)
                #compare reference file with pool & pd content
                [System.Collections.ArrayList]$vms2Add = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect which vms need to be added to which protection domain
                ForEach ($vm in $newHvRef) 
                {#foreach vm in hv, find out if it is already in the right protection domain, otherwise, add it to the list of vms to add to that pd
                    #figure out which protection domain this vm should be based on its current desktop pool and the assigned protection domain for that pool
                    $assignedPd = ($poolRef | Where-Object {$_.desktop_pool -eq $vm.desktop_pool}).protection_domain
                    if (!$assignedPd) 
                    {#no pool to pd in reference file
                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not process protection domain addition for VM $($vm.vmName) because there is no assigned protection domain defined in $referentialPath\poolRef.csv for $($vm.desktop_pool)!"
                    }
                    else 
                    {#process vm to figure out pd membership status
                        #now find out if that vm is already in that protection domain
                        if (!($newPrismRef | Where-Object {$_.name -eq $assignedPd} | Where-Object {$_.vms.vm_name -eq $vm.vmName})) 
                        {#vm is not in pd
                            $vmInfo = @{"vmName" = $vm.vmName;"protection_domain" = $assignedPd}
                            #add vm to name the list fo vms to add to that pd
                            $result = $vms2Add.Add((New-Object PSObject -Property $vmInfo))
                        }
                    }
                }

                #foreach protection domain, figure out if there are vms which are no longer in horizon view and which need to be removed from the protection domain
                [System.Collections.ArrayList]$vms2Remove = New-Object System.Collections.ArrayList($null) #we'll use this variable to collect which vms need to be removed from which protection domain
                $protectedVMs = ($newPrismRef | Where-Object {$poolRef.protection_domain -Contains $_.name}).vms.vm_name
                $vmNames2remove = $protectedVMs | Where-Object {$newHvRef.vmname -notcontains $_}
                ForEach ($vm in $vmNames2remove) 
                { #process each vm identified above
                    $pd = (($newPrismRef | Where-Object {$poolRef.protection_domain -Contains $_.name}) | Where-Object {$_.vms.vm_name -eq $vm}).name
                    #compare the list of desktop pools we are processing with their matching protection domain names in the reference file. This is to ensure we are not touching a pd we're not supposed to.
                    if (($poolRef | Where-Object {$_.desktop_pool -eq $desktopPoolNames}).protection_domain -contains $pd)
                    {#that pd matches a desktop pool we are processing
                        $vmInfo = @{"vmName" = $vm;"protection_domain" = $pd}
                        #add vm to name the list fo vms to add to that pd
                        $result = $vms2Remove.Add((New-Object PSObject -Property $vmInfo))
                    }
                }
            #endregion

            #region update protection domains
                
                ForEach ($vm2add in $vms2add) 
                {#if required, add vms to pds
                    $reponse = Update-NutanixProtectionDomain -action add -cluster $source_cluster -username $username -password $PrismSecurePassword -protection_domain $vm2add.protection_domain -vm $vm2add.vmName
                }
                
                ForEach ($vm2remove in $vms2remove) 
                {#if required, remove vms from pds
                    $reponse = Update-NutanixProtectionDomain -action remove -cluster $source_cluster -username $username -password $PrismSecurePassword -protection_domain $vm2remove.protection_domain -vm $vm2remove.vmName
                }
            #endregion

            #region export
                $newHvRefExport = $newHvRef | Sort-Object -Property vmName | Export-Csv -NoTypeInformation -Path "$referentialPath\hvRef.csv"
                $newVcRefExport = $newVcRef | Sort-Object -Property vmName | Export-Csv -NoTypeInformation -Path "$referentialPath\vcRef.csv"
            #endregion
        } 
    #endregion

    #region -failover
        if ($failover) 
        {#we're doing a failover    
            if ((!$prompt) -and (!$noprompt))
            {#prompt for step by step confirmation
                do {$promptUser = Read-Host -Prompt "Do you want to confirm every step? (y/n)"}
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {
                    "y" {$confirmSteps = $true}
                    "n" {$confirmSteps = $false}
                }
            }

            #region prechecks
                #code to check pre-requisites before starting the workflow. That will prevent us from having a half completed workflow which would require manual recovery
                Write-Host ""
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Performing pre-checks..."

                #region check we have the appropriate references
                    #load pool2pd reference
                    try 
                    {
                        $poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop
                    } 
                    catch 
                    {
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"
                        Exit
                    }
                    #load old references
                    If (Test-Path -Path ("$referentialPath\hvRef.csv")) 
                    {
                        try 
                        {
                            $oldHvRef = Import-Csv -Path ("$referentialPath\hvRef.csv") -ErrorAction Stop
                        } 
                        catch 
                        {
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\hvRef.csv : $($_.Exception.Message)"
                            Exit
                        }
                    }
                    If (Test-Path -Path ("$referentialPath\vcRef.csv")) 
                    {
                        try 
                        {
                            $oldVcRef = Import-Csv -Path ("$referentialPath\vcRef.csv") -ErrorAction Stop
                        } 
                        catch 
                        {
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\vcRef.csv : $($_.Exception.Message)"
                            Exit
                        }
                    }
                #endregion

                #TODO : Add planned connectivity check for target Prism Element in the region below
                #region applies to PLANNED only
                    if ($planned) 
                    {#doing checks for planned failover
                        #region SOURCE HORIZON VIEW SERVER 
                            #? Are there matching desktop pools with VMs to process and which are disabled on the source hv?
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Starting checks on SOURCE Horizon View server $source_hv..."

                            #region connect
                                #start by connecting to the source view server
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE Horizon View server $source_hv..."
                                try 
                                {#connect
                                    if ($hvCreds) 
                                    {#with creds
                                        $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                                    } 
                                    else 
                                    {#no creds so use sso
                                        $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                                    }
                                }
                                catch
                                {#coudln't connect
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"
                                    Exit
                                }
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the SOURCE Horizon View server $source_hv"
                                #create API object
                                $source_hvObjectAPI = $source_hvObject.ExtensionData
                            #endregion

                            #region get
                                #extract desktop pools
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..."
                                $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved desktop pools information from the SOURCE Horizon View server $source_hv"

                                #find out which pool we are working with (assume all which are disabled if none have been specified)
                                if (!$desktop_pools) 
                                {#no pool was specified
                                    if ($protection_domains) 
                                    { #one or more protection domain(s) was/were specified
                                        $test_desktop_pools = @()
                                        ForEach ($protection_domain in $protection_domains) 
                                        {#so let's match those to desktop pools using the reference file
                                            $test_desktop_pools += ($poolRef | Where-Object {$_.protection_domain -eq $protection_domain}).desktop_pool
                                        }
                                        $test_disabled_desktop_pools = $source_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                                        $test_desktop_pools = $test_disabled_desktop_pools | Where-Object {$test_desktop_pools -contains $_.DesktopSummaryData.Name}
                                    } 
                                    else 
                                    { #no pd and no pool were specified, so let's assume we have to process all disabled pools
                                        $test_desktop_pools = $source_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                                    }
                                } 
                                else 
                                { #extract the desktop pools information
                                    $test_disabled_desktop_pools = $source_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                                    $test_desktop_pools = $test_disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
                                }

                                if (!$test_desktop_pools) 
                                {#couldn't find any pool with the right status
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no desktop pool(s) to process on SOURCE horizon view server $source_hv! Make sure the desktop pool(s) you want to failover are disabled and contain VMs."
                                    Exit
                                }

                                Remove-Variable test_desktop_pools -ErrorAction SilentlyContinue
                                Remove-Variable test_disabled_desktop_pools -ErrorAction SilentlyContinue
                            #endregion

                            #region disconnect
                                Disconnect-HVServer * -Confirm:$false
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the SOURCE Horizon View server $source_hv..."
                            #endregion
                        #endregion
                    
                        #region SOURCE NUTANIX PRISM ELEMENT 
                            #? Are there matching protection domains in the correct status and with remote sites defined
                            #let's retrieve the list of protection domains from the source
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from source Nutanix cluster $source_cluster ..."
                            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                            $method = "GET"
                            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from source Nutanix cluster $source_cluster"

                            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                            if (!$protection_domains) 
                            {#no pd specified
                                if ($desktop_pools) 
                                { #one or more dekstop pool(s) was/were specified
                                    $test_protection_domains = @()
                                    ForEach ($desktop_pool in $desktop_pools) 
                                    {#so let's match to protection domains using the reference file
                                        $test_protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                                    }
                                    $test_activeProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                                    $test_protection_domains = $test_activeProtectionDomains | Where-Object {$test_protection_domains -contains $_}
                                } 
                                else 
                                { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains
                                    $test_protection_domains = ($poolRef | Select-Object -Property protection_domain -Unique).protection_domain
                                    $test_protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$test_protection_domains -contains $_}
                                }
                            } 
                            else 
                            {#get pd info
                                $test_protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                            }

                            if (!$test_protection_domains) 
                            {#couldn't find a pd in the correct status
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $source_cluster!"
                                ConfirmStep
                            }

                            ForEach ($test_pd2migrate in $test_protection_domains) 
                            {#figure out if there is more than one remote site defined for the protection domain                                
                                $test_remoteSite = $sourceClusterPd.entities | Where-Object {$_.name -eq $test_pd2migrate} | Select-Object -Property remote_site_names
                                if (!$test_remoteSite.remote_site_names) 
                                {#no remote site
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no remote site defined for protection domain $test_pd2migrate"
                                    Exit
                                }
                                if ($test_remoteSite -is [array]) 
                                {#more than one remote site
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one remote site for protection domain $test_pd2migrate"
                                    Exit
                                }
                            }

                            Remove-Variable test_protection_domains -ErrorAction SilentlyContinue
                            Remove-Variable test_activeProtectionDomains -ErrorAction SilentlyContinue
                        #endregion

                        #region SOURCE VCENTER
                            #? Can we connect to source vc?
                            #region connect
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE vCenter server $source_vc ..."
                                try 
                                {#connect
                                    if ($vcCreds) 
                                    {#with creds
                                        $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                                    } 
                                    else 
                                    {#no creds so use sso
                                        $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                                    }
                                }
                                catch 
                                {#couldn't connect
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"
                                    Exit
                                }
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to SOURCE vCenter server $source_vc"
                            #endregion

                            #region disconnect
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from SOURCE vCenter server $source_vc..."
                                Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
                            #endregion
                        #endregion    
                    }  
                #endregion

                #region applies to UNPLANNED only
                    if ($unplanned) 
                    {#doing checks for unplanned failover
                        #region TARGET NUTANIX PRISM ELEMENT
                            #? Are there matching protection domains in the correct status on the target prism
                            #let's retrieve the list of protection domains from the target
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from target Nutanix cluster $target_cluster ..."
                            $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                            $method = "GET"
                            $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from target Nutanix cluster $target_cluster"

                            $test_matching_protection_domains = @()
                            $test_pds2activate = @()
                            ForEach ($desktop_pool in $desktop_pools) 
                            {#match pool to pd
                                $test_matching_protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                            }

                            ForEach ($test_matching_protection_domain in $test_matching_protection_domains) 
                            {#make sure the matching protection domains are not active already on the target Prism, then build the list of protection domains to process
                                if (($targetClusterPd.entities | Where-Object {$_.name -eq $test_matching_protection_domain}).active -eq $true) 
                                {#pd already active
                                    Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Protection domain $test_matching_protection_domain is already active on target Prism $target_cluster. Skipping."
                                } 
                                else 
                                {#add pd to process list
                                    $test_pds2activate += $targetClusterPd.entities | Where-Object {$_.name -eq $test_matching_protection_domain}
                                }
                            }

                            if (!$test_pds2activate) 
                            {#no pd to process
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There were no matching protection domain(s) to process. Make sure the selected desktop pools have a matching protection domain in the reference file and that those protection domains exist on the target Prism cluster and are in standby status."
                                Exit
                            }

                            Remove-Variable pds2activate -ErrorAction SilentlyContinue
                        #endregion
                    }   
                #endregion

                #region applies to BOTH (planned and unplanned)

                    #region TARGET HORIZON VIEW
                        #? Can we connect to the target hv?
                        #region connect
                            #connect to the target view server
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the TARGET Horizon View server $target_hv..."
                            try 
                            {#connect
                                if ($hvCreds) 
                                {#with creds
                                    $target_hvObject = Connect-HVServer -Server $target_hv -Credential $hvCreds -ErrorAction Stop
                                } 
                                else 
                                {#no creds, so use sso
                                    $target_hvObject = Connect-HVServer -Server $target_hv -ErrorAction Stop
                                }
                            }
                            catch
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the TARGET Horizon View server $target_hv"
                        #endregion

                        #region disconnect
                            Disconnect-HVServer * -Confirm:$false
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the TARGET Horizon View server $target_hv..."
                        #endregion
                    #endregion

                    #region TARGET VC
                        #? Can we connect to the target vc?
                        #region connect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the TARGET vCenter server $target_vc ..."
                            try 
                            {#connect
                                if ($vcCreds) 
                                {#with creds
                                    $target_vcObject = Connect-VIServer $target_vc -Credential $vcCreds -ErrorAction Stop
                                } 
                                else 
                                {#no creds so use sso
                                    $target_vcObject = Connect-VIServer $target_vc -ErrorAction Stop
                                }
                            }
                            catch 
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to TARGET vCenter server $target_vc"
                        #endregion

                        #region disconnect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from TARGET vCenter server $source_vc..."
                            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
                        #endregion
                    #endregion    
                #endregion

                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Performed pre-checks."
                Write-Host ""
            #endregion

            #region -planned
                if ($planned) { #we're doing a planned failover

                    #region deal with the source view bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing items on SOURCE Horizon View server $source_hv..."
                        if ($confirmSteps) 
                        {#offer the opportunity to stop here
                            $promptUser = ConfirmStep
                        }
                        
                        #region connect
                            #start by connecting to the source view server
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE Horizon View server $source_hv..."
                            try 
                            {
                                if ($hvCreds) 
                                {
                                    $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                                } 
                                else 
                                {
                                    $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                                }
                            }
                            catch
                            {
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the SOURCE Horizon View server $source_hv"
                            #create API object
                            $source_hvObjectAPI = $source_hvObject.ExtensionData
                        #endregion

                        #region get data
                            #extract desktop pools
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..."
                            $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved desktop pools information from the SOURCE Horizon View server $source_hv"

                            #extract Virtual Machines summary information
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..."
                            $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv"

                            #find out which pool we are working with (assume all which are disabled if none have been specified)
                            if (!$desktop_pools) 
                            {#no pd specified
                                if ($protection_domains) 
                                { #one or more protection domain(s) was/were specified
                                    $desktop_pools = @()
                                    ForEach ($protection_domain in $protection_domains) 
                                    {#so let's match those to desktop pools using the reference file
                                        $desktop_pools += ($poolRef | Where-Object {$_.protection_domain -eq $protection_domain}).desktop_pool
                                    }
                                    $disabled_desktop_pools = $source_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                                    $desktop_pools = $disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
                                } 
                                else 
                                { #no pd and no pool were specified, so let's assume we have to process all disabled pools
                                    $desktop_pools = $source_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                                }
                            } 
                            else 
                            { #extract the desktop pools information
                                $disabled_desktop_pools = $source_hvDesktopPools | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                                $desktop_pools = $disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
                            }

                            if (!$desktop_pools) 
                            {#no valid pool
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no desktop pool(s) to process on SOURCE horizon view server $source_hv!"
                                Exit
                            }
                        #endregion

                        #! processing here
                        #region process
                            $poolProcessed = $false #we'll use this to make sure we've touched at least one pool
                            ForEach ($desktop_pool in $desktop_pools) 
                            {#process each desktop pool
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing the desktop pool $($desktop_pool.DesktopSummaryData.Name) on the source Horizon View Connection server $source_hv..."
                                if ($confirmSteps) 
                                {#giving the opportunity to skip this pool
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    if ($desktop_pool.DesktopSummaryData.Enabled -eq $true) 
                                    {#check that the pool is disabled
                                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Skipping $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv because the desktop pool is enabled"
                                        continue
                                    }
                                    #figure out which machines are in that desktop pool
                                    $vms = $source_hvVMs | Where-Object {$_.Base.Desktop.id -eq $desktop_pool.Id.Id}
                                    
                                    #remove machines from the desktop pool
                                    if ($vms -is [array]) 
                                    {#we use different methods based on the number of vms in the pool
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..."
                                        try 
                                        {#removing vms from the pool
                                            $result = $source_hvObjectAPI.Machine.Machine_DeleteMachines($vms.Id,$null)
                                        } 
                                        catch 
                                        {#failed to remove vms from the pool
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"
                                            Exit
                                        }
                                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv"
                                        $poolProcessed = $true
                                    } 
                                    else 
                                    {#there was only one vm in the pool
                                        if ($vms -ne $null) 
                                        {#there is only a single vm in the pool to remove, so we use a different method
                                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..."
                                            try 
                                            {#remove vm from the pool
                                                $result = $source_hvObjectAPI.Machine.Machine_Delete($vms.Id,$null)
                                            } 
                                            catch 
                                            {#failed to remove vm from the pool
                                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"
                                                Exit
                                            }
                                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv"
                                            $poolProcessed = $true
                                        } 
                                        else 
                                        {#there were no vms in the pool
                                            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "There were no vms to remove from pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv!"
                                        }
                                    }
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..."
                                    $poolProcessed = $true
                                }
                            }

                            if (!$poolProcessed) 
                            {#no pool was processed
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There were no disabled desktop pools with VMs in their inventory. Stopping execution here."
                                Exit
                            }

                            #save the desktop pool names we processed for later
                            $desktop_pool_names = $desktop_pools.DesktopSummaryData.Name
                        #endregion

                        #region disconnect
                            #disconnect from the source view server
                            Disconnect-HVServer * -Confirm:$false
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the SOURCE Horizon View server $source_hv..."

                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done processing items on SOURCE Horizon View server $source_hv"
                            Write-Host ""
                        #endregion
                    
                    #endregion

                    #region deal with the source Prism bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing items on SOURCE Nutanix cluster $source_cluster..."
                        if ($confirmSteps) 
                        {#offer the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #region get data
                            #let's retrieve the list of protection domains from the source
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from source Nutanix cluster $source_cluster ..."
                            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                            $method = "GET"
                            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from source Nutanix cluster $source_cluster"

                            #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                            if (!$protection_domains) 
                            {#no pd specified
                                if ($desktop_pools) 
                                { #one or more dekstop pool(s) was/were specified
                                    $protection_domains = @()
                                    ForEach ($desktop_pool in $desktop_pools) 
                                    {#so let's match to protection domains using the reference file
                                        $protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool.DesktopSummaryData.Name}).protection_domain
                                    }
                                    $activeProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                                    $protection_domains = $activeProtectionDomains | Where-Object {$protection_domains -contains $_}
                                } 
                                else 
                                { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains
                                    $protection_domains = ($poolRef | Select-Object -Property protection_domain -Unique).protection_domain
                                    $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                                }
                            } 
                            else 
                            {#fetch specified pd
                                $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                            }

                            if (!$protection_domains) 
                            {
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $source_cluster!"
                                ConfirmStep
                            }
                        #endregion

                        #! processing here
                        #region process
                            #now let's call the migrate workflow
                            ForEach ($pd2migrate in $protection_domains) 
                            {
                                #figure out if there is more than one remote site defined for the protection domain
                                $remoteSite = $sourceClusterPd.entities | Where-Object {$_.name -eq $pd2migrate} | Select-Object -Property remote_site_names
                                if (!$remoteSite.remote_site_names) 
                                {
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no remote site defined for protection domain $pd2migrate"
                                    Exit
                                }
                                if ($remoteSite -is [array]) 
                                {
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one remote site for protection domain $pd2migrate"
                                    Exit
                                }

                                #migrate the protection domain
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Migrating $pd2migrate to $($remoteSite.remote_site_names) ..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                                    $method = "POST"
                                    $content = @{
                                                    value = $($remoteSite.remote_site_names)
                                                }
                                    $body = (ConvertTo-Json $content -Depth 4)
                                    $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)"
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping migrating $pd2migrate to $($remoteSite.remote_site_names) ..."
                                }
                            }

                            #let's make sure all protection domain migrations have been processed successfully
                            #retrieve the list of tasks in the cluster
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of tasks on the SOURCE cluster $source_cluster ..."
                            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                            $method = "GET"
                            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved list of tasks on the SOURCE cluster $source_cluster"
                            #select only the tasks of operation type "deactivate" which were created after this script was started
                            $pdMigrateTasks = $response.entities | Where-Object {$_.operation -eq "deactivate"} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                            #let's loop now until the tasks status are completed and successfull. If a task fails, we'll throw an exception.
                            ForEach ($pdMigrateTask in $pdMigrateTasks) 
                            {
                                if ($pdMigrateTask.percentageCompleted -ne "100") 
                                {
                                    Do 
                                    {
                                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Waiting 5 seconds for task $($pdMigrateTask.taskName) to complete : $($pdMigrateTask.percentageCompleted)%"
                                        Sleep 5
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of tasks on the SOURCE cluster $source_cluster ..."
                                        $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                                        $method = "GET"
                                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved list of tasks on the SOURCE cluster $source_cluster"
                                        $task = $response.entities | Where-Object {$_.taskName -eq $pdMigrateTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                                        if ($task.status -ne "running") 
                                        {
                                            if ($task.status -ne "succeeded") 
                                            {
                                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Task $($pdMigrateTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)"
                                                Exit
                                            }
                                        }
                                    }
                                    While ($task.percentageCompleted -ne "100")
                                    
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Protection domain migration task $($pdMigrateTask.taskName) completed on the SOURCE cluster $source_cluster"
                                } 
                                else 
                                {
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Protection domain migration task $($pdMigrateTask.taskName) completed on the SOURCE cluster $source_cluster"
                                }
                            }

                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "All protection domain migration tasks have completed. Moving on to vCenter."

                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done processing items on SOURCE Nutanix server $source_cluster"
                            Write-Host ""
                        #endregion
                    #endregion

                    #region deal with the source vCenter bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing items on SOURCE vCenter server $source_vc..."
                        if ($confirmSteps) 
                        {#offer the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #region connect
                            #connect to the source vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE vCenter server $source_vc ..."
                            try 
                            {#connect
                                if ($vcCreds) 
                                {#with creds
                                    $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                                } 
                                else 
                                {#no creds, so use sso
                                    $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                                }
                            }
                            catch 
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to SOURCE vCenter server $source_vc"
                        #endregion

                        #! processing here
                        #region process
                            
                            #our reference point is the desktop pool, so let's process vms in each desktop pool
                            ForEach ($desktop_pool in $desktop_pool_names) 
                            {#remove orphaned entries from SOURCE vCenter
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing vms in desktop pool $desktop_pool on $source_vc ..."
                                if ($confirmSteps)
                                {
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    #determine which vms belong to the desktop pool(s) we are processing
                                    $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                                    #process all vms for that desktop pool
                                    ForEach ($vm in $vms) 
                                    {
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing $($vm.vmName) from inventory in $source_vc ..."
                                        try 
                                        {
                                            $result = Get-VM -Name $vm.vmName | Where-Object {$_.ExtensionData.Summary.OverallStatus -eq 'gray'} | remove-vm -Confirm:$false
                                        } 
                                        catch 
                                        {
                                            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not remove VM $($vm.vmName): $($_.Exception.Message)"
                                        }
                                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Removed $($vm.vmName) from inventory in $source_vc."
                                    }
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping processing vms in desktop pool $desktop_pool on $source_vc ..."
                                }
                            }
                        #endregion

                        #region disconnect
                            #disconnect from vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from SOURCE vCenter server $source_vc..."
                            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter

                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done processing items on SOURCE vCenter server $source_vc"
                            Write-Host ""
                        #endregion
                    #endregion

                    #region deal with the target vCenter bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Waiting 30 seconds before processing items on TARGET vCenter server $target_vc..."
                        Sleep 30 #adding sleep here because sometimes the vSphere API does not return the objects immediately for some reason
                        if ($confirmSteps) 
                        {#offer the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }

                        #region connect
                            #connect to the target vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the TARGET vCenter server $target_vc ..."
                            try 
                            {
                                if ($vcCreds) 
                                {
                                    $target_vcObject = Connect-VIServer $target_vc -Credential $vcCreds -ErrorAction Stop
                                } else {
                                    $target_vcObject = Connect-VIServer $target_vc -ErrorAction Stop
                                }
                            }
                            catch 
                            {
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to TARGET vCenter server $target_vc"
                        #endregion

                        #! processing here
                        #region process
                            #our reference point is the desktop pool, so let's process vms in each desktop pool
                            ForEach ($desktop_pool in $desktop_pool_names) 
                            {
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing vms in desktop pool $desktop_pool on $target_vc..."
                                if ($confirmSteps) 
                                {#offer the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    #determine which vms belong to the desktop pool(s) we are processing
                                    $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                                    
                                    #! processing here
                                    #process all vms for that desktop pool
                                    $dvPortgroups = Get-VDPortGroup | Where-Object {$_.IsUplink -eq $false} #retrieve distributed portgroup names in the target infrastructure which are not uplinks
                                    ForEach ($vm in $vms) 
                                    {
                                        try 
                                        {#getting vm object
                                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving vm object for $($vm.vmName) from $target_vc"
                                            $vmObject = Get-VM -Name $vm.vmName -ErrorAction Stop    
                                        }
                                        catch 
                                        {#couldn't get vm object so skipping to next vm
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not retrieve vm object for $($vm.vmName) from $target_vc : $($_.Exception.Message)"
                                            Continue
                                        }

                                        #! ACTION 1/2: move vms to their correct folder
                                        $folder = Get-Folder -Name (($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).folder) #figure out which folder this vm was in and move it
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Trying to move $($vm.vmName) to folder $($folder.Name)..."
                                        MoveVmToFolder

                                        #! ACTION 2/2: connect vms to the portgroup
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Re-connecting the virtual machine $($vm.vmName) virtual NIC..."
                                        ConnectVmToPortGroup
                                    }
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping processing vms in desktop pool $desktop_pool on $target_vc..."
                                }
                            }
                        #endregion

                        #region disconnect
                            #disconnect from vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from TARGET vCenter server $target_vc..."
                            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter

                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done processing items on TARGET vCenter server $target_vc"
                            Write-Host ""
                        #endregion
                    #endregion

                    #region deal with the target view bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing items on TARGET Horizon View server $target_hv..."
                        if ($confirmSteps) 
                        {#give the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #region connect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the TARGET Horizon View server $target_hv..."
                            try 
                            {#connect
                                if ($hvCreds) 
                                {#with creds
                                    $target_hvObject = Connect-HVServer -Server $target_hv -Credential $hvCreds -ErrorAction Stop
                                } 
                                else 
                                {#no creds, so use sso
                                    $target_hvObject = Connect-HVServer -Server $target_hv -ErrorAction Stop
                                }
                            }
                            catch 
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the TARGET Horizon View server $target_hv"
                            #create API object
                            $target_hvObjectAPI = $target_hvObject.ExtensionData
                        #endregion

                        #region get
                            #retrieve the view object
                            $target_hvVirtualCenter = $target_hvObjectAPI.VirtualCenter.VirtualCenter_List() | Where-Object {$_.Enabled -eq $true}
                            if ($target_hvVirtualCenter -is [array]) 
                            {#more than one vcenter
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one enabled vCenter on $target_hv!"
                                Exit
                            }
                            
                            #retrieve the list of available vms in vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving virtual machines information from the TARGET Horizon View server $target_hv..."
                            $target_hvAvailableVms = $target_hvObjectAPI.VirtualMachine.VirtualMachine_List($target_hvVirtualCenter.Id)
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved virtual machines information from the TARGET Horizon View server $target_hv."

                            #extract desktop pools
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving desktop pools information from the TARGET Horizon View server $target_hv..."
                            $target_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $target_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved desktop pools information from the TARGET Horizon View server $target_hv."
                            
                            #extract Active Directory users & groups
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Active Directory user information from the TARGET Horizon View server $target_hv..."
                            $target_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $target_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Active Directory user information from the TARGET Horizon View server $target_hv."
                        #endregion

                        #! processing here
                        #region process
                            ForEach ($desktop_pool in $desktop_pool_names) 
                            {#process each desktop pool
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing desktop pool $desktop_pool on the TARGET Horizon View server $target_hv..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    AddVmsToPool
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping processing desktop pool $desktop_pool on the TARGET Horizon View server $target_hv..."
                                }
                            }
                        #endregion

                        #region disconnect
                            Disconnect-HVServer * -Confirm:$false
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the TARGET Horizon View server $target_hv..."

                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done processing items on TARGET Horizon View server $target_hv"
                            Write-Host ""
                        #endregion
                    #endregion

                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done! Make sure you enable your desktop pools on $target_hv now so that users can connect!"
                    Write-Host ""
                }  
            #endregion

            #region -unplanned
                if ($unplanned) 
                {#we're doing an unplanned failover
                    #region prepare
                        #we need to know the desktop pools and protection domains for unplanned, so let's figure that out now
                        if (!$desktop_pools) 
                        {#no desktop pool was specified which is mandatory for unplanned
                            $desktop_pools = Read-Host "Please enter the desktop pool(s) you want to failover (unplanned)"
                            $desktop_pools = $desktop_pools.Split(",") #make sure we process desktop_pools as an array
                        }
                        #figure out the matching protection domains from the reference file
                        $matching_protection_domains = @()
                        ForEach ($desktop_pool in $desktop_pools) 
                        {#match all specified desktop pools to a protection domain using the reference file
                            $matching_protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                        }   
                    #endregion

                    #region deal with the target Prism bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing items on TARGET Nutanix cluster $target_cluster..."
                        if ($confirmSteps) 
                        {#give the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #let's retrieve the list of protection domains from the target
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from target Nutanix cluster $target_cluster ..."
                        $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                        $method = "GET"
                        $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from target Nutanix cluster $target_cluster"

                        $pds2activate = @()
                        ForEach ($matching_protection_domain in $matching_protection_domains) 
                        {#make sure the matching protection domains are not active already on the target Prism, then build the list of protection domains to process
                            if (($targetClusterPd.entities | Where-Object {$_.name -eq $matching_protection_domain}).active -eq $true) 
                            {#pd is already active
                                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Protection domain $matching_protection_domain is already active on target Prism $target_cluster. Skipping."
                            } 
                            else 
                            {#add pd to the list of objects to process
                                $pds2activate += $targetClusterPd.entities | Where-Object {$_.name -eq $matching_protection_domain}
                            }
                        }

                        if (!$pds2activate) 
                        {#there are no pds to process
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There were no matching protection domain(s) to process. Make sure the selected desktop pools have a matching protection domain in the reference file and that those protection domains exist on the target Prism cluster and are in standby status."
                            Exit
                        }

                        #now let's call the activate workflow
                        ForEach ($pd2activate in $pds2activate) 
                        {#activate each pd
                            #activate the protection domain
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Activating protection domain $($pd2activate.name) on $target_cluster ..."
                            if ($confirmSteps) 
                            {#give the opportunity to skip
                                $promptUser = ConfirmStep -skip
                            }
                            if ($promptUser -ne "s")
                            {#process
                                $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate.name)/activate"
                                $method = "POST"
                                $content = @{}
                                $body = (ConvertTo-Json $content -Depth 4)
                                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully activated protection domain $($pd2activate.name) on $target_cluster"
                            }
                            else 
                            {#we skipped
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping activation of protection domain $($pd2activate.name) on $target_cluster ..."
                            }
                        }

                        #let's make sure all protection domain migrations have been processed successfully
                        #retrieve the list of tasks in the cluster
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of tasks on the TARGET cluster $target_cluster ..."
                        $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                        $method = "GET"
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved list of tasks on the TARGET cluster $target_cluster"
                        #select only the tasks of operation type "deactivate" which were created after this script was started
                        $pdActivateTasks = $response.entities | Where-Object {$_.operation -eq "activate"} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                        #let's loop now until the tasks status are completed and successfull. If a task fails, we'll throw an exception.
                        ForEach ($pdActivateTask in $pdActivateTasks) 
                        {#examine all tasks sequentially
                            if ($pdActivateTask.percentageCompleted -ne "100") 
                            {#task is not completed yet
                                Do 
                                {#loop until it's completed
                                    Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Waiting 5 seconds for task $($pdActivateTask.taskName) to complete : $($pdActivateTask.percentageCompleted)%"
                                    Sleep 5
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of tasks on the TARGET cluster $target_cluster ..."
                                    $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                                    $method = "GET"
                                    $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved list of tasks on the TARGET cluster $target_cluster"
                                    $task = $response.entities | Where-Object {$_.taskName -eq $pdActivateTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                                    if ($task.status -ne "running") 
                                    {#check the final status
                                        if ($task.status -ne "succeeded") 
                                        {#task did not success
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Task $($pdActivateTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)"
                                            Exit
                                        }
                                    }
                                }
                                While ($task.percentageCompleted -ne "100")
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Protection domain migration task $($pdActivateTask.taskName) completed on the TARGET cluster $target_cluster"
                            } 
                            else 
                            {#task has already completed
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Protection domain migration task $($pdActivateTask.taskName) completed on the TARGET cluster $target_cluster"
                            }
                        }

                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "All protection domain activation tasks have completed. Moving on to vCenter."

                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done processing items on TARGET Nutanix server $target_cluster"
                        Write-Host ""
                    #endregion

                    #region deal with the target vCenter bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Waiting 30 seconds before processing items on TARGET vCenter server $target_vc..."
                        Sleep 30 #adding sleep here because sometimes the vSphere API does not return the objects immediately for some reason
                        if ($confirmSteps) 
                        {#give the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #region connect
                            #connect to the target vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the TARGET vCenter server $target_vc ..."
                            try 
                            {#connect
                                if ($vcCreds) 
                                {#with specified creds
                                    $target_vcObject = Connect-VIServer $target_vc -Credential $vcCreds -ErrorAction Stop
                                }
                                else 
                                {#no creds specified, so just try and rely on sso
                                    $target_vcObject = Connect-VIServer $target_vc -ErrorAction Stop
                                }
                            }
                            catch 
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to TARGET vCenter server $target_vc : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to TARGET vCenter server $target_vc"
                        #endregion
                       
                        #! processing here
                        #region process
                            ForEach ($desktop_pool in $desktop_pools) 
                            {#our reference point is the desktop pool, so let's process vms in each desktop pool
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing vms in the desktop pool $desktop_pool..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($confirmSteps -ne "s")
                                {
                                    #determine which vms belong to the desktop pool(s) we are processing
                                    $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                                    #process all vms for that desktop pool
                                    $dvPortgroups = Get-VDPortGroup | Where-Object {$_.IsUplink -eq $false} #retrieve distributed portgroup names in the target infrastructure which are not uplinks
                                    ForEach ($vm in $vms) 
                                    {
                                        try 
                                        {#getting vm object
                                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving vm object for $($vm.vmName) from $target_vc"
                                            $vmObject = Get-VM -Name $vm.vmName -ErrorAction Stop    
                                        }
                                        catch 
                                        {#couldn't get vm object so skipping to next vm
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not retrieve vm object for $($vm.vmName) from $target_vc : $($_.Exception.Message)"
                                            Continue
                                        }

                                        #! ACTION 1/2: move vms to their correct folder
                                        $folder = Get-Folder -Name (($oldVcRef | Where-Object {$_.vmName -eq $vm.vmName}).folder) #figure out which folder this vm was in and move it
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Trying to move $($vm.vmName) to folder $($folder.Name)..."
                                        MoveVmToFolder

                                        #! ACTION 2/2: connect vms to the portgroup
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Re-connecting the virtual machine $($vm.vmName) virtual NIC..."
                                        ConnectVmToPortGroup
                                    }
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping processing of vms in the desktop pool $desktop_pool..."
                                }
                            }
                        #endregion

                        #region disconnect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from TARGET vCenter server $source_vc..."
                            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
                        #endregion
                    #endregion

                    #region deal with the target view bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing items on TARGET Horizon View server $target_hv..."
                        if ($confirmSteps) 
                        {#give the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }

                        #region connect
                            #connect to the target view server
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the TARGET Horizon View server $target_hv..."
                            try 
                            {#connect
                                if ($hvCreds) 
                                {#with specified creds
                                    $target_hvObject = Connect-HVServer -Server $target_hv -Credential $hvCreds -ErrorAction Stop
                                } 
                                else 
                                {#no specified creds so rely on sso
                                    $target_hvObject = Connect-HVServer -Server $target_hv -ErrorAction Stop
                                }
                            }
                            catch
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the TARGET Horizon View server $target_hv : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the TARGET Horizon View server $target_hv"
                            #create API object
                            $target_hvObjectAPI = $target_hvObject.ExtensionData
                        #endregion

                        #region get
                            
                            #retrieve the vCenter object
                            $target_hvVirtualCenter = $target_hvObjectAPI.VirtualCenter.VirtualCenter_List() | Where-Object {$_.Enabled -eq $true}
                            if ($target_hvVirtualCenter -is [array]) 
                            {#more than 1 vCenter
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one enabled vCenter on $target_hv!"
                                Exit
                            }
                            
                            #retrieve the list of available vms in vCenter
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving virtual machines information from the TARGET Horizon View server $target_hv..."
                            $target_hvAvailableVms = $target_hvObjectAPI.VirtualMachine.VirtualMachine_List($target_hvVirtualCenter.Id)
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved virtual machines information from the TARGET Horizon View server $target_hv."

                            #extract desktop pools
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving desktop pools information from the TARGET Horizon View server $target_hv..."
                            $target_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $target_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved desktop pools information from the TARGET Horizon View server $target_hv."
                            
                            #extract Active Directory users & groups
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Active Directory user information from the TARGET Horizon View server $target_hv..."
                            $target_hvADUsers = Invoke-HvQuery -QueryType ADUserOrGroupSummaryView -ViewAPIObject $target_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Active Directory user information from the TARGET Horizon View server $target_hv."
                        #endregion

                        #! processing here
                        #region process
                            ForEach ($desktop_pool in $desktop_pools) 
                            {process each desktop pool
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing desktop pool $desktop_pool..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    AddVmsToPool
                                }
                                else 
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping processing of desktop pool $desktop_pool..."
                                }
                            }
                        #endregion

                        #region disconnect
                            Disconnect-HVServer * -Confirm:$false
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the TARGET Horizon View server $target_hv..."
                        #endregion
                    #endregion

                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Done! Make sure you enable your desktop pools on $target_hv now so that users can connect!"
                    Write-Host ""
                }   
            #endregion
        }   
    #endregion

    #region -cleanup
        if ($cleanup) 
        {#we're doing a cleanup 
            if ((!$prompt) -and (!$noprompt))
            {#prompt for step by step confirmation
                do 
                {#prompt
                    $promptUser = Read-Host -Prompt "Do you want to confirm every step? (y/n)"
                }
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {#decide what to do based on prompt result
                    "y" {$confirmSteps = $true}
                    "n" {$confirmSteps = $false}
                }
            }

            #region -planned
                if ($planned) 
                {#we're doing a cleanup planned
                    #region prepare
                        try 
                        {#load pool2pd reference
                            $poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop
                        } 
                        catch 
                        {#couldn't load the file we need
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"
                            Exit
                        }
                    #endregion

                    #region deal with source Prism
                        #region get
                            #let's retrieve the list of protection domains from the source
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from source Nutanix cluster $source_cluster ..."
                            $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                            $method = "GET"
                            $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from source Nutanix cluster $source_cluster"

                            #first, we need to figure out which protection domains need to be updated. If none have been specified, we'll assume all those which are referenced in the PoolRef.csv file.
                            if (!$protection_domains) 
                            {#no pd was specified
                                if ($desktop_pools) 
                                { #no protection domain was specified, but one or more dekstop pool(s) was/were, so let's match to protection domains using the reference file
                                    $protection_domains = @()
                                    ForEach ($desktop_pool in $desktop_pools) 
                                    {#match each pool to a pd
                                        $protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                                    }
                                    $standbyProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name
                                    $protection_domains = $standbyProtectionDomains | Where-Object {$protection_domains -contains $_}
                                } 
                                else 
                                { #no protection domains were specified, and no desktop pools either, so let's assume we have to do all the active protection domains referenced in PoolRef.csv
                                    $protection_domains = ($poolRef | Select-Object -Property protection_domain -Unique).protection_domain
                                    $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                                }
                            } 
                            else 
                            {#a pd was specified
                                $protection_domains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$protection_domains -contains $_}
                            }

                            if (!$protection_domains) 
                            {#no pd in correct status
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $source_cluster!"
                                Exit
                            }
                        #endregion

                        #! processing here
                        #region process
                            ForEach ($pd2update in $protection_domains) 
                            {#now let's remove the schedules
                                #remove all schedules from the protection domain
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing all schedules from protection domain $pd2update on $source_cluster ..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2update/schedules"
                                    $method = "DELETE"
                                    $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully removed all schedules from protection domain $pd2update on $source_cluster"
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping removing all schedules from protection domain $pd2update on $source_cluster ..."
                                }
                            }
                        #endregion
                    #endregion
                }   
            #endregion

            #region -unplanned
                if ($unplanned) 
                {#we're doing a cleanup unplanned
                    #region check we have the appropriate references                       
                        try 
                        {#load pool2pd reference
                            $poolRef = Import-Csv -Path ("$referentialPath\poolRef.csv") -ErrorAction Stop
                        } 
                        catch 
                        {#couldn't load the file we need
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\PoolRef.csv : $($_.Exception.Message)"
                            Exit
                        }
                        #load old references
                        If (Test-Path -Path ("$referentialPath\hvRef.csv")) 
                        {#check if a file already exists
                            try 
                            {#load the file
                                $oldHvRef = Import-Csv -Path ("$referentialPath\hvRef.csv") -ErrorAction Stop
                            } 
                            catch 
                            {#we couldn't load the file
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\hvRef.csv : $($_.Exception.Message)"
                                Exit
                            }
                        }
                        If (Test-Path -Path ("$referentialPath\vcRef.csv")) 
                        {#check if a file already exists
                            try 
                            {#load the file
                                $oldVcRef = Import-Csv -Path ("$referentialPath\vcRef.csv") -ErrorAction Stop
                            } 
                            catch 
                            {#we couldn't load the file
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not import data from $referentialPath\vcRef.csv : $($_.Exception.Message)"
                                Exit
                            }
                        }
                    #endregion

                    #region figure out what needs to be processed
                        #we need to know the desktop pools and protection domains for unplanned, so let's figure that out now
                        if (!$desktop_pools) 
                        {#no desktop pool was specified which is mandatory
                            $desktop_pools = Read-Host "Please enter the desktop pool(s) you want to failover (unplanned)"
                            $desktop_pools = $desktop_pools.Split(",") #make sure we process desktop_pools as an array
                        }
                        
                        $protection_domains = @()
                        ForEach ($desktop_pool in $desktop_pools) 
                        {#figure out the matching protection_domains
                            $protection_domains += ($poolRef | Where-Object {$_.desktop_pool -eq $desktop_pool}).protection_domain
                        }
                        #let's retrieve the list of protection domains from the target
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from SOURCE Nutanix cluster $source_cluster ..."
                        $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                        $method = "GET"
                        $sourceClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from SOURCE Nutanix cluster $source_cluster"
                        #keep only those that are active and match
                        $activeProtectionDomains = ($sourceClusterPd.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                        $protection_domains = $activeProtectionDomains | Where-Object {$protection_domains -contains $_}
                        if (!$protection_domains) 
                        {#no pd was found
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find any matching protection domains in the reference file!"
                            Exit
                        }
                    #endregion

                    #cleanup source/primary View
                    #region deal with the source view bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing the source Horizon View Connection server $source_hv..."
                        if ($confirmSteps) 
                        {#give the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #region connect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE Horizon View server $source_hv..."
                            try 
                            {#connect
                                if ($hvCreds) 
                                {#with specified creds
                                    $source_hvObject = Connect-HVServer -Server $source_hv -Credential $hvCreds -ErrorAction Stop
                                } 
                                else 
                                {#no creds specified so rely on sso
                                    $source_hvObject = Connect-HVServer -Server $source_hv -ErrorAction Stop
                                }
                            }
                            catch
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to the SOURCE Horizon View server $source_hv"
                            #create API object
                            $source_hvObjectAPI = $source_hvObject.ExtensionData
                        #endregion

                        #region get
                            #extract desktop pools
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving desktop pools information from the SOURCE Horizon View server $source_hv..."
                            $source_hvDesktopPools = Invoke-HvQuery -QueryType DesktopSummaryView -ViewAPIObject $source_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved desktop pools information from the SOURCE Horizon View server $source_hv"

                            #extract Virtual Machines summary information
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Virtual Machines summary information from the SOURCE Horizon View server $source_hv..."
                            $source_hvVMs = Invoke-HvQuery -QueryType MachineSummaryView -ViewAPIObject $source_hvObjectAPI
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved Virtual Machines summary information from the SOURCE Horizon View server $source_hv"

                            #find out which pool we are working with (assume all which are disabled if none have been specified)
                            if (!$desktop_pools) 
                            {#find disabled pools
                                $desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false}
                            } 
                            else 
                            { #extract the desktop pools information
                                $desktop_pools = $source_hvDesktopPools.Results | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name}
                                #$disabled_desktop_pools = $source_hvDesktopPools.Results | Where-Object {$_.DesktopSummaryData.Enabled -eq $false} #used to be we filtered for pools that were disabled
                                #$desktop_pools = $disabled_desktop_pools | Where-Object {$desktop_pools -contains $_.DesktopSummaryData.Name} #used to be we filtered for pools that were disabled
                            }

                            if (!$desktop_pools) 
                            {#no valid pool found
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no desktop pool(s) to process on SOURCE horizon view server $source_hv!"
                                Exit
                            }
                        #endregion

                        #! processing here
                        #region process
                            #creating a map_entry variable that will be used to disable desktop pools if they are enabled
                            $update = New-Object VMware.Hv.MapEntry
                            $update.key = "desktopSettings.enabled"
                            $update.value = $false

                            ForEach ($desktop_pool in $desktop_pools) 
                            {#process each desktop pool
                                if ($desktop_pool.DesktopSummaryData.Enabled -eq $true) 
                                {#pool is enabled
                                    Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "$($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv is enabled, disabling..."
                                    try 
                                    {#trying to disable the desktop pool
                                        $result = $source_hvObjectAPI.Desktop.Desktop_Update($desktop_pool.Id,$update)
                                    }
                                    catch 
                                    {#we couldn't disable the desktop pool
                                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not disable the desktop pool $($desktop_pool.DesktopSummaryData.Name) on the SOURCE Horizon View server $source_hv : $($_.Exception.Message)"
                                        Continue
                                    }
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Disabled the desktop pool $($desktop_pool.DesktopSummaryData.Name) on the SOURCE Horizon View server $source_hv"
                                }
                                #figure out which machines are in that desktop pool
                                $vms = $source_hvVMs.Results | Where-Object {$_.Base.Desktop.id -eq $desktop_pool.Id.Id}
                                
                                #remove machines from the desktop pool
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    if ($vms -is [array]) 
                                    {#we use different methods based on the number of vms in the pool
                                        try 
                                        {#remove vms from the pool
                                            $result = $source_hvObjectAPI.Machine.Machine_DeleteMachines($vms.Id,$null)
                                        } 
                                        catch 
                                        {#failed to remove vms from the pool
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"
                                            Exit
                                        }
                                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv"
                                    } 
                                    else 
                                    {#single vm
                                        if ($vms -ne $null) 
                                        {#there is only a single vm in the pool to remove, so we use a different method
                                            try 
                                            {#remove vm from the pool
                                                $result = $source_hvObjectAPI.Machine.Machine_Delete($vms.Id,$null)
                                            } 
                                            catch 
                                            {#failed to remove vm from the pool
                                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not remove machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv : $($_.Exception.Message)"
                                                Exit
                                            }
                                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Removed machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv"
                                        } 
                                        else 
                                        {#there were no vms in the pool
                                            Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "There were no vms to remove from pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv!"
                                        }
                                    }
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping removal of machines from the pool $($desktop_pool.DesktopSummaryData.Name) on SOURCE VMware View server $source_hv..."
                                }
                            }
                        #endregion

                        #save the desktop pool names we processed for later
                        $desktop_pool_names = $desktop_pools.DesktopSummaryData.Name

                        #region disconnect
                            Disconnect-HVServer * -Confirm:$false
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnected from the SOURCE Horizon View server $source_hv..."
                        #endregion
                    #endregion

                    #cleanup source/primary Prism
                    #region deal with source Prism
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing the source Nutanix Prism Element environment $source_cluster..."
                        if ($confirmSteps) 
                        {
                            $promptUser = ConfirmStep
                        }
                        
                        #! processing here
                        #let's call the deactivate workflow
                        ForEach ($pd2deactivate in $protection_domains) 
                        {
                            #activate the protection domain
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "De-activating protection domain $pd2deactivate on $source_cluster ..."
                            if ($confirmSteps) 
                            {#give the opportunity to skip
                                $promptUser = ConfirmStep -skip
                            }
                            if ($promptUser -ne "s")
                            {#process
                                $url = "https://$($source_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
                                $method = "POST"
                                $content = @{}
                                $body = (ConvertTo-Json $content -Depth 4)
                                $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully de-activated protection domain $pd2deactivate on $source_cluster"
                                #TODO: enhance this with a proper task status check
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Waiting 1 minute for tasks to complete..."
                                Sleep 60
                            }
                            else
                            {#we skipped
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping de-activation of protection domain $pd2deactivate on $source_cluster ..."
                            }
                        }
                    #endregion

                    #cleanup source/primary vCenter
                    #region deal with the source vCenter bits
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing the source vCenter server $source_vc..."
                        if ($confirmSteps) 
                        {#give the opportunity to interrupt the script
                            $promptUser = ConfirmStep
                        }
                        
                        #region connect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to the SOURCE vCenter server $source_vc ..."
                            try 
                            {#connect
                                if ($vcCreds) 
                                {#with specified creds
                                    $source_vcObject = Connect-VIServer $source_vc -Credential $vcCreds -ErrorAction Stop
                                } 
                                else 
                                {#no specified creds so rely on sso
                                    $source_vcObject = Connect-VIServer $source_vc -ErrorAction Stop
                                }
                            }
                            catch 
                            {#couldn't connect
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to SOURCE vCenter server $source_vc : $($_.Exception.Message)"
                                Exit
                            }
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Connected to SOURCE vCenter server $source_vc"
                        #endregion

                        #! processing here: remove orphaned entries from SOURCE vCenter
                        #region process                 
                            ForEach ($desktop_pool in $desktop_pool_names) 
                            {#our reference point is the desktop pool, so let's process vms in each desktop pool
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing vms in desktop pool $desktop_pool from inventory in $source_vc ..."
                                if ($confirmSteps) 
                                {#give the opportunity to skip
                                    $promptUser = ConfirmStep -skip
                                }
                                if ($promptUser -ne "s")
                                {#process
                                    #determine which vms belong to the desktop pool(s) we are processing
                                    $vms = $oldHvRef | Where-Object {$_.desktop_pool -eq $desktop_pool}
                                    
                                    ForEach ($vm in $vms) 
                                    {#process all vms for that desktop pool
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Removing $($vm.vmName) from inventory in $source_vc ..."    
                                        try 
                                        {#remove vm from inventory
                                            $result = Get-VM -Name $vm.vmName | Where-Object {$_.ExtensionData.Summary.OverallStatus -eq 'gray'} | remove-vm -Confirm:$false
                                        } 
                                        catch 
                                        {#couldn't remove vm from inventory
                                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not remove VM $($vm.vmName): $($_.Exception.Message)"
                                            Exit
                                        }
                                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Removed $($vm.vmName) from inventory in $source_vc."
                                    }
                                }
                                else
                                {#we skipped
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping removal of vms in desktop pool $desktop_pool from inventory in $source_vc ..."
                                }
                            }
                        #endregion

                        #region disconnect
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from SOURCE vCenter server $source_vc..."
                            Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
                        #endregion   
                    #endregion
                }  
            #endregion
        }  
    #endregion

    #region -deactivate
        if ($deactivate) 
        {
            
            if ((!$prompt) -and (!$noprompt))
            {#prompt for step by step confirmation
                do 
                {#loop on prompt until response is valid
                    $promptUser = Read-Host -Prompt "Do you want to confirm every step? (y/n)"
                }
                while ($promptUser -notmatch '[ynYN]')
                switch ($promptUser)
                {#process response
                    "y" {$confirmSteps = $true}
                    "n" {$confirmSteps = $false}
                }
            }
            
            #region get
                #let's retrieve the list of protection domains from the target
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from target Nutanix cluster $target_cluster ..."
                $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $targetClusterPd = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from target Nutanix cluster $target_cluster"

                #first, we need to figure out which protection domains need to be deactivated.
                if (!$protection_domains) 
                {#no pd was given which is mandatory
                    $protection_domains = Read-Host "Enter the name of the protection domain(s) you want to deactivate on $target_cluster. !!!WARNING!!! All VMs in that protection domain will be deleted!"
                    $protection_domains = $protection_domains.Split(",") #make sure we process protection_domains as an array
                }
            #endregion

            #! processing here
            #region process
                ForEach ($pd2deactivate in $protection_domains) 
                {#now let's call the deactivate workflow for each pd
                    #activate the protection domain
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "De-activating protection domain $pd2deactivate on $target_cluster ..."
                    if ($confirmSteps) 
                    {#give the opportunity to skip
                        $promptUser = ConfirmStep -skip
                    }
                    if ($promptUser -ne "s")
                    {#process
                        $url = "https://$($target_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
                        $method = "POST"
                        $content = @{}
                        $body = (ConvertTo-Json $content -Depth 4)
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully de-activated protection domain $pd2deactivate on $target_cluster"
                    }
                    else
                    {#we skipped
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Skipping de-activation of protection domain $pd2deactivate on $target_cluster ..."
                    }
                }
            #endregion
        }  
    #endregion

#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-LogOutput -Category "SUM" -LogFile $myvarOutputLogFile -Message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion