<#
.SYNOPSIS
This script configures a Nutanix cluster after Foundation. It will let you specify both Nutanix 

.DESCRIPTION
This is a detailed description of what the script does and how it is used.

.PARAMETER Log
Specifies that you want to log all output to a log file in addition to the console. The log file will be <TimeStamp>-Output.log in the current directory.

.PARAMETER DebugMe
Turns off SilentlyContinue for errors and warnings.

.PARAMETER VerboseOutput
Turns off SilentlyContinue for Write-Verbose.

.PARAMETER Prism
Url to the Prism Element of the Nutanix cluster you want to configure.

.PARAMETER Username
Username for Prism Element.

.PARAMETER Password
Password for the Prism Element user.

.PARAMETER Online
Use this switch once the Nutanix cluster has been foundationed and is connected to the production network.  This assumes that VLANs and LACP has been configured already.
This switch cannot be used with -Offline.

.PARAMETER Offline
Use this switch when you are still connected on your private switch and you need to configure VLANs and/or LACP before you can connect the servers to the production network.
This is default scipt behavior.
This switch cannot be used with -Online or -DataProtection.

.PARAMETER DataProtection
Use this switch when you have VMs running on the Nutanix cluster and you are ready to setup Protection Domains (async or metro).
This switch cannot be used with -Offline.

.EXAMPLE
.\SetNutanixClusterConfiguration.ps1 -Cluster ntnxc1.local -Username admin -Password admin -Offline

Start configuring a cluster when still connected to the private switch, right after Foundation.

.LINK
https://github.com/sbourdeaud/nutanix

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
Revision: May 17th 2017
#>

#region parameters
    [cmdletbinding(DefaultParameterSetName=’ByOffline’)]
    Param
    (   
        [Parameter(mandatory = $false)]
        [Switch]
        $Log,

        [Parameter(mandatory = $false)]
        [Switch]
        $DebugMe,

        [Parameter(mandatory = $false)]
        [Switch]
        $VerboseOutput,

        [Parameter(mandatory = $true)]
        [String]
        $Prism,
	    
        [Parameter(mandatory = $true)]
        [String]
        $Username,
	    
        [Parameter(mandatory = $false)]
        [String]
        $Password,

        [Parameter(mandatory = $true,ParameterSetName = "ByOnline")]
        [Switch]
        $Online,

        [Parameter(mandatory = $true, ParameterSetName = "ByOffline")]
        [Switch]
        $Offline,

        [Parameter(mandatory = $false, ParameterSetName = "ByOnline")]
        [Switch]
        $DataProtection

    )
#endregion
#region variables

    #keeping track of when we're starting this script
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    
    if ($Log) #if user wants to log to a file, configure the file name
    {
        $LogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $LogFile += "OutputLog.log"
    }

    #handle output based on -debugme and -verbose parameters. By default, the script will ignore all error, warning and verbose messages
    if (!$DebugMe) {$ErrorActionPreference = 'SilentlyContinue'} else {$ErrorActionPreference = 'Continue'}
    if (!$DebugMe) {$WarningPreference = 'SilentlyContinue'} else {$WarningPreference = 'Continue'}
    if (!$VerboseOutput) {$VerbosePreference = 'SilentlyContinue'} else {$VerbosePreference = 'Continue'}

    #let's deal with the password
    if (!$Password) #if it was not passed as an argument, let's prompt for it
    {
        $SecurePassword = read-host "Enter the Prism password" -AsSecureString
    }
    else #if it was passed as an argument, let's convert the string to a secure string and flush the memory
    {
        $SecurePassword = ConvertTo-SecureString $Password –asplaintext –force
        Remove-Variable Password
    }

#endregion
#region prepwork

    #import the modules we need
    try
    {
        Import-Module -Name sbourdeaud -ErrorAction Stop
    }
    catch #we couldn't import the module, so let's download it
    {
        $ModulesPath = ($env:PsModulePath -split ";")[0]
        $MyModulePath = "$ModulesPath\sbourdeaud"
        New-Item -Type Container -Force -path $MyModulePath | out-null
        (New-Object net.webclient).DownloadString("https://raw.github.com/sbourdeaud/modules/master/sbourdeaud.psm1") | Out-File "$MyModulePath\sbourdeaud.psm1" -ErrorAction Continue
        (New-Object net.webclient).DownloadString("https://raw.github.com/sbourdeaud/modules/master/sbourdeaud.psd1") | Out-File "$MyModulePath\sbourdeaud.psd1" -ErrorAction Continue
    }
    finally
    {
        try
        {
            Import-Module -Name sbourdeaud -ErrorAction Stop
        }
        catch #we couldn't import the module
        {
            $ErrorCode = $Error[0]
            Write-Host $ErrorCode.Exception -ForegroundColor Red
            Write-Host "ERROR: Unable to import the module sbourdeaud.psm1.  Please download and install from https://github.com/sbourdeaud/modules"  -ForegroundColor Red
            Exit
        }
    }

    #let's load the Nutanix cmdlets
    try
    {
        Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction Stop #is it already there?
    }
    catch
    {
        try 
        {
	        Add-PSSnapin NutanixCmdletsPSSnapin -ErrorAction Stop #no? let's add it
	    }
        catch 
        {
            $ErrorCode = $Error[0]
            Write-Host $ErrorCode.Exception -ForegroundColor Red
            Write-Host "ERROR: The NutanixCmdletsPSSnapin is required. Please download it from your Prism interface and install it on this workstation." -ForegroundColor Red
            Exit
	    }
    }

#endregion

#region functions

function New-NutanixContainer
{
<#
.SYNOPSIS
Walks the user thru creating a new Nutanix storage container.

.DESCRIPTION
This function is used to prompt the user for all the information required to create a new Nutanix storage container.

.PARAMETER Cluster
Nutanix cluster system object returned by Get-NTNXCluster

.PARAMETER Hosts
System array object containing the Nutanix hosts in the cluster

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
New-NutanixContainer -Cluster $Cluster -Hosts $Hosts

Starts the creation workflow for a new container. The function will return the newly created container object.

.LINK
https://github.com/sbourdeaud/nutanix
#>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		[Parameter(Mandatory)]
        [System.Object]
        $Cluster,

        [Parameter(Mandatory)]
        [System.Array]
        $Hosts
	)

    process
    {
        #prompting the user for the required information while performing some validation
        $ContainerName = Read-Host "Enter the container name"
        [ValidateSet('y','n')]$Compression = Read-Host "Do you want to enable compression? (y/n)"
        if ($Compression -eq 'y') {[int]$CompressionDelay = Read-Host "What is the desired compression delay in seconds? (0 for inline compression)"}
        [ValidateSet('y','n')]$Deduplication = Read-Host "Do you want to enable deduplication? (y/n)"
        if ($Deduplication -eq 'y') {[ValidateSet('y','n')]$DeduplicationCapacity = Read-Host "Do you want to enable deduplication on the capacity tier? (y/n)"}
        if ($Hosts.Count -ge 4) {[ValidateSet('y','n')]$ErasureCoding = Read-Host "Do you want to enable erasure coding? (y/n)"}
        if ($Cluster.clusterRedundancyState.currentRedundancyFactor -ge 3) {[ValidateSet('2','3')][int]$ReplicationFactor = Read-Host "Which replication factor do you want to use for this container? (2/3)"} else {$ReplicationFactor = $Cluster.clusterRedundancyState.currentRedundancyFactor}

        #creating the container
        Write-LogOutput -Category INFO -Message "Creating the container $ContainerName..."
        try
        {
            $Result = New-NTNXContainer -Name $ContainerName -ReplicationFactor $ReplicationFactor -ErrorAction Stop
            Write-LogOutput -Category INFO -Message "Successfully created the container $ContainerName..."
            $Containers = Get-NTNXContainer
            $Container = $Containers | where {$_.name -eq $ContainerName}
        }
        catch
        {
            $ErrorCode = $Error[0]
            Write-Host $ErrorCode.Exception -ForegroundColor Red
	        Write-LogOutput -Category "ERROR" -Message "Could not create the container $ContainerName" -LogFile $LogFile
	        Exit
        }

        #modifying the container based on selected options
        if ($Compression -eq 'y') 
        {
            Write-LogOutput -Category INFO -Message "Enabling compression on $ContainerName..."
            try
            {
                $Container | Set-NTNXContainer -CompressionEnabled $true -CompressionDelayInSecs $CompressionDelay -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Successfully enabled compression on $ContainerName..."
            }
            catch
            {
                $ErrorCode = $Error[0]
                Write-Host $ErrorCode.Exception -ForegroundColor Red
	            Write-LogOutput -Category "ERROR" -Message "Could not enable compression on container $ContainerName" -LogFile $LogFile
            }
        }
        if ($Deduplication -eq 'y') 
        {
            Write-LogOutput -Category INFO -Message "Enabling deduplication on $ContainerName..."
            try
            {
                $Container | Set-NTNXContainer -FingerPrintOnWrite ON -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Successfully enabled deduplication on $ContainerName..."
            }
            catch
            {
                $ErrorCode = $Error[0]
                Write-Host $ErrorCode.Exception -ForegroundColor Red
	            Write-LogOutput -Category "ERROR" -Message "Could not enable deduplication on container $ContainerName" -LogFile $LogFile
            }
        }
        if ($DeduplicationCapacity -eq 'y') 
        {
            Write-LogOutput -Category INFO -Message "Enabling deduplication on capacity tier on $ContainerName..."
            try
            {
                $Container | Set-NTNXContainer -OnDiskDedup POST_PROCESS -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Successfully enabled deduplication on capacity tier on $ContainerName..."
            }
            catch
            {
                $ErrorCode = $Error[0]
                Write-Host $ErrorCode.Exception -ForegroundColor Red
	            Write-LogOutput -Category "ERROR" -Message "Could not enable deduplication on capacity tier on container $ContainerName" -LogFile $LogFile
            }
        }
        if ($ErasureCoding -eq 'y') 
        {
            Write-LogOutput -Category INFO -Message "Enabling erasure coding on $ContainerName..."
            try
            {
                $Container | Set-NTNXContainer -ErasureCode on -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Successfully enabled erasure coding on $ContainerName..."
            }
            catch
            {
                $ErrorCode = $Error[0]
                Write-Host $ErrorCode.Exception -ForegroundColor Red
	            Write-LogOutput -Category "ERROR" -Message "Could not enable erasure coding on container $ContainerName" -LogFile $LogFile
            }
        }

        #setting up to return the container object
        $Containers = Get-NTNXContainer
        $Container = $Containers | where {$_.name -eq $ContainerName}
        Return $Container
    }

}#end function New-NutanixContainer

#endregion

#region processing

    #region connect to the Nutanix cluster
    Write-LogOutput -Category "INFO" -Message "Connecting to Nutanix cluster $Prism..." -LogFile $LogFile
        try
        {
            Write-Verbose "Storing results of Connect-NutanixCluster in the NutanixCluster variable."
            $NutanixCluster = Connect-NutanixCluster -Server $Prism -UserName $Username -Password $SecurePassword –acceptinvalidsslcerts -ForcedConnection -ErrorAction Stop
        }
        catch
        {
	        $ErrorCode = $Error[0]
            Write-Host $ErrorCode.Exception -ForegroundColor Red
	        Write-LogOutput -Category "ERROR" -Message "Could not connect to $Prism" -LogFile $LogFile
	        Exit
        }
    Write-LogOutput -category "INFO" -message "Connected to Nutanix cluster $Prism." -LogFile $LogFile
    #endregion

    #region offline (wip)
        if ($Offline)
        {
        #region general Nutanix cluster configuration
         Write-LogOutput -Category INFO -Message "Configuring general Nutanix cluster settings..."
         Write-LogOutput -Category INFO -Message "Retrieving cluster information..."
         $Cluster = Get-NTNXCluster
         Write-LogOutput -Category INFO -Message "Retrieving host information..."
         $Hosts = Get-NTNXHost
         Write-LogOutput -Category INFO -Message "Retrieving container information..."
         $Containers = Get-NTNXContainer


            #region remove the default container
            [ValidateSet('y','n')]$RemoveDefaultContainer = Read-Host "Do you want to remove the default container? (y/n)"
            if ($RemoveDefaultContainer -eq 'y')
            {
                Write-LogOutput -Category INFO -Message "Removing the default container"
                try
                {
                    $DefaultContainer = $Containers | where {$_.name -like "default-container*"}
                    $Result = $DefaultContainer | Remove-NTNXContainer -ErrorAction Stop
                }
                catch
                {
                    $ErrorCode = $Error[0]
                    Write-Host $ErrorCode.Exception -ForegroundColor Red
	                Write-LogOutput -Category "ERROR" -Message "Could not remove the default container" -LogFile $LogFile
	                Exit
                }
                if ($DefaultContainer) {Write-LogOutput -Category INFO -Message "Successfully removed the default container ($($DefaultContainer.name))"} else {Write-LogOutput -Category WARNING -Message "There was no default container to remove"}
            }
            #endregion
            #region add one or more new containers
            do
            {
                [ValidateSet('y','n')]$NewContainer = Read-Host "Do you want to create a new container? (y/n)"
                if ($NewContainer -eq 'y')
                {
                    $Container = New-NutanixContainer -Hosts $Hosts -Cluster $Cluster
                    $Containers = Get-NTNXContainer
                }
            }
            while ($NewContainer -eq 'y')
                #region add container for reserved space
                #endregion

            #endregion
            #region configure Ntp servers
            #endregion
            #region configure DNS servers
            #endregion

        #endregion
        #region hypervisor configuration

            #region get the hypervisor
            #endregion

            #region VMware vSphere configuration

                #region configure Ntp on ESXi hosts
                #endregion
                #region configure Dns on ESXi hosts
                #endregion
                #region configure vlans
                #endregion

            #endregion
            #region Microsoft Hyper-V configuration

                #region configure vlans
                #endregion

            #endregion
            #region AHV configuration

                #region configure lacp
                #endregion
                #region configure vlans
                #endregion

            #endregion

        #endregion
        }
    #endregion

    #region online (wip)
        #region general Nutanix cluster configuration

        #region remove the default container
        #endregion
        #region add one or more new containers

            #region add container for reserved space
            #endregion

        #endregion
        #region configure Ntp servers
        #endregion
        #region configure DNS servers
        #endregion
        #region configure LDAP authentication
        #endregion
        #region licensing configuration
        #endregion

        #endregion
        #region hypervisor configuration

        #region get the hypervisor
        #endregion

        #region VMware vSphere configuration

            #region connect to vCenter
            #endregion

            #region create the datacenter
            #endregion

            #region create the cluster
            #endregion

            #region configure the cluster
            #endregion

            #region configure Ntp on ESXi hosts
            #endregion

            #region configure Dns on ESXi hosts
            #endregion

            #region networking
            #endregion

        #endregion

        #region Microsoft Hyper-V configuration
        #endregion

        #region AHV configuration
        #endregion

        #endregion
    #endregion

    #region data protection (wip)

        #region async protection domains
        #endregion

        #region metro availability
        #endregion

    #endregion

#endregion

#region cleanup

    #cleanup after ourselves and disconnect from the Nutanix cluster
    Write-LogOutput -Category "INFO" -Message "Disconnecting from Nutanix cluster $Prism..." -LogFile $LogFile
	Disconnect-NutanixCluster -Servers $Prism
    
    #let's figure out how much time this all took
	Write-LogOutput -Category "SUM" -Message "total processing time: $($ElapsedTime.Elapsed.ToString())" -LogFile $LogFile

    #removing modules and snapins from memory
    Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
    Remove-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue

#endregion