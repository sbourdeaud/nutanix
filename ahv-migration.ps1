<#
.SYNOPSIS
  This script can be used to import VMs which have been exported from Scale Computing.  It assumes XML and qcow2 files have been desposited into a container on the Nutanix cluster.
.DESCRIPTION
  Given a Nutanix cluster and container, the script will process all XML files it finds at the root of that container and create corresponding VMs in AHV.  Qcow2 disks are imported in the image library and then added to the newly created VM.  If network labels do not match, the script will prompt for a vlan id.
.PARAMETER prism
  IP address or FQDN of the Nutanix cluster (this can also be a single CVM IP or FQDN).
.PARAMETER username
  Prism username (with privileged cluster admin access).
.PARAMETER password
  Prism username password.
.PARAMETER container
  Name of the storage container where the Scale Computing VM export files have been put.  Files (xml and qcow2) must be placed in the root folder of that container.
.PARAMETER import
  Switch to specify you want to import VMs.  All XML files in the container will be processed.
.PARAMETER export
  Switch to specify you want to export a given AHV virtual machine instead.  The script will use SSHSessions to start the qemu-img conversion process on the AHV VM raw files and drop them in the specified container.
.PARAMETER cleanup
  When used with import, the cleanup switch will have the script remove imported disk images from the AHV image library as well as delete the xml and qcow2 file(s) in the container once the AHV VM has been created successfully.
.PARAMETER vm
  Required when using export to specify the name of the AHV virtual machine you want to export.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
  Import all VMs in the ctr1 container and cleanup after a successful import:
  PS> .\ahv-migration.ps1 -prism 10.10.10.1 -username admin -password nutanix/4u -container ctr1 -import -cleanup
  Export AHV virtual machine vm1 in the ctr1 container:
  PS> .\ahv-migration.ps1 -prism 10.10.10.1 -username admin -password nutanix/4u -container ctr1 -export -vm vm1
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: March 13th 2017
#>

#region Parameters
######################################
##   parameters and initial setup   ##
######################################
#let's start with some command line parsing
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$prism,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] [string]$container,
    [parameter(mandatory = $false)] [switch]$import,
    [parameter(mandatory = $false)] [switch]$export,
    [parameter(mandatory = $false)] [switch]$cleanup,
    [parameter(mandatory = $false)] [string]$vm
)
#endregion

#region Prep-work

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 03/13/2017 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\ahv-migration.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#let's load the Nutanix cmdlets
if ((Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue) -eq $null)#is it already there?
{
    try {
	    Add-PSSnapin NutanixCmdletsPSSnapin -ErrorAction Stop #no? let's add it
	}
    catch {
        Write-Warning $($_.Exception.Message)
		OutputLogData -category "ERROR" -message "Unable to load the Nutanix snapin.  Please make sure the Nutanix Cmdlets are installed on this server."
		return
	}
}


#let's get ready to use the Nutanix REST API
#Accept self signed certs
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#endregion

#region Functions
########################
##   main functions   ##
########################

#this function is used to output log data
Function OutputLogData 
{
	#input: log category, log message
	#output: text to standard output
<#
.SYNOPSIS
  Outputs messages to the screen and/or log file.
.DESCRIPTION
  This function is used to produce screen and log output which is categorized, time stamped and color coded.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER myCategory
  This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".
.PARAMETER myMessage
  This is the actual message you want to display.
.EXAMPLE
  PS> OutputLogData -mycategory "ERROR" -mymessage "You must specify a cluster name!"
#>
	param
	(
		[string] $category,
		[string] $message
	)

    begin
    {
	    $myvarDate = get-date
	    $myvarFgColor = "Gray"
	    switch ($category)
	    {
		    "INFO" {$myvarFgColor = "Green"}
		    "WARNING" {$myvarFgColor = "Yellow"}
		    "ERROR" {$myvarFgColor = "Red"}
		    "SUM" {$myvarFgColor = "Magenta"}
	    }
    }

    process
    {
	    Write-Host -ForegroundColor $myvarFgColor "$myvarDate [$category] $message"
	    if ($log) {Write-Output "$myvarDate [$category] $message" >>$myvarOutputLogFile}
    }

    end
    {
        Remove-variable category
        Remove-variable message
        Remove-variable myvarDate
        Remove-variable myvarFgColor
    }
}#end function OutputLogData

#this function is used to connect to Prism REST API
Function PrismRESTCall
{
	#input: username, password, url, method, body
	#output: REST response
<#
.SYNOPSIS
  Connects to Nutanix Prism REST API.
.DESCRIPTION
  This function is used to connect to Prism REST API.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER username
  Specifies the Prism username.
.PARAMETER password
  Specifies the Prism password.
.PARAMETER url
  Specifies the Prism url.
.EXAMPLE
  PS> PrismRESTCall -username admin -password admin -url https://10.10.10.10:9440/PrismGateway/services/rest/v1/ 
#>
	param
	(
		[string] $username,
		[string] $password,
        [string] $url,
        [string] $method,
        $body
	)

    begin
    {
	 	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process
    {
        if ($body) {
            try {
                $myvarHeader += @{"Accept"="application/json"}
		        $myvarHeader += @{"Content-Type"="application/json"}
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
		    }
		    catch {
			    OutputLogData -category "ERROR" -message "$($_.Exception.Message)"
			    Exit
		    }
        } else {
            try {
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
		    }
		    catch {
			    OutputLogData -category "ERROR" -message "$($_.Exception.Message)"
			    Exit
		    }
        }
    }

    end
    {
        return $myvarRESTOutput
        Remove-variable username
        Remove-variable password
        Remove-variable url
        Remove-variable myvarHeader
    }
}#end function PrismRESTCall

#endregion

#region Variables
#initialize variables
#misc variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
$myvarOutputLogFile += "OutputLog.log"
	
############################################################################
# command line arguments initialization
############################################################################	
#let's initialize parameters if they haven't been specified
if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism"}
if (!$username) {$username = read-host "Enter the Prism username"}
if (!$password) {
    $spassword = read-host "Enter the Prism password" -AsSecureString
    $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($spassword))
}
else
{
    $spassword = ConvertTo-SecureString $password –asplaintext –force
}
if (!$container) {$container = read-host "Enter the name of the Nutanix container you want ot import from or export to"}
if ($export -and (!$vm)) {$vm = read-host "Enter the name of the VM you want to export"}


#endregion

#region Processing
#########################
##   main processing   ##
#########################

#region Connect to Prism using PoSH cmdlets

    OutputLogData -category "INFO" -message "Connecting to Nutanix cluster $prism..."
    try
    {
        $myvarNutanixCluster = Connect-NutanixCluster -Server $prism -UserName $username -Password $spassword –acceptinvalidsslcerts -ForcedConnection -ErrorAction Stop
    }
    catch
    {#error handling
	    Write-Warning $($_.Exception.Message)
	    OutputLogData -category "ERROR" -message "Could not connect to $prism"
	    Exit
    }
    OutputLogData -category "INFO" -message "Connected to Nutanix cluster $prism."

#endregion

#region Import VM(s)
if ($import) {

#region Connect network drive to Nutanix container
OutputLogData -category "INFO" -message "Connecting to \\$prism\$container..."
try {
    $myvarConnectedDrive = New-PSDrive -Name "N" -PSProvider FileSystem -Root "\\$prism\$container" -ErrorAction Stop
}
catch {
    Write-Warning $($_.Exception.Message)
    OutputLogData -category "ERROR" -message "Could not connect to \\$prism\$container, exiting!"
	Exit
}
#endregion

#region Process XML files
OutputLogData -category "INFO" -message "Processing XML files in \\$prism\$container..."
$myvarXMLFiles = Get-ChildItem N:\ | where {$_.extension -eq '.xml'}

foreach ($myvarXMLFile in $myvarXMLFiles) {

        #region Read from XML
        OutputLogData -category "INFO" -message "Processing $myvarXMLFile..."
        try #let's make sure we can import the XML file content
        {
            #remove NUL characters from the XML file if there are any
            (get-content N:\$($myvarXMLFile.Name)) -replace "`0", "" | Set-Content N:\$($myvarXMLFile.Name)
            $myvarXML = [xml](get-content N:\$($myvarXMLFile.Name) | Where-Object {$_ -notmatch '<scale:os'})
        }#end try xml import
        catch
        {
	        Write-Warning $($_.Exception.Message)
            OutputLogData -category "ERROR" -message "Could not read the XML file $myvarXMLFile, exiting."
	        Exit
        }#end catch xml import error
        #endregion

    #region Import into image library

        OutputLogData -category "INFO" -message "Importing disks for VM $($myvarXML.domain.name)..."
        $myvarVmDisks = @()
        #create a disk image in the ahv library given a source file
        $myvarUrl = "https://"+$prism+":9440/api/nutanix/v0.8/images/"
        if ($myvarXML.domain.description) {
            $myvarAnnotation = $myvarXML.domain.description
        }
        else {
            $myvarAnnotation = "Imported using ahv-migration.ps1 script"
        }
    
        $myvarVmDisks = $myvarXML.domain.devices.disk | where {$_.device -eq "Disk"}
        foreach ($myvarVmDisk in $myvarVmDisks) {
            $myvarDiskName = $myvarVmDisk.source.name
            $myvarDiskName = $myvarDiskName -creplace '^[^/]*/', ''
            if (!(Test-Path N:\$myvarDiskName.qcow2)) {
                OutputLogData -category "ERROR" -message "Disk $myvarDiskName.qcow2 is not in \\$prism\$container"
	            Exit
            }
            
            $myvarImageName = $myvarXML.domain.name+"_"+$myvarVmDisk.target.dev
            $myvarImage = Get-NTNXImage | where {$_.Name -eq $myvarImageName}
            if ($myvarImage) {OutputLogData -category "WARNING" -message "Image $myvarImageName already exists in the library: skipping import..."}
            else {
                $myvarSource = "nfs://127.0.0.1/"+$container+"/"+$myvarDiskName+".qcow2"
                $myvarBody = @{annotation=$myvarAnnotation;image_type="disk_image";imageImportSpec=@{containerName=$container;url=$myvarSource};name=$myvarImageName}
                $myvarBody = ConvertTo-Json $myvarBody
                $myvarImageImportTaskId = PrismRESTCall -method "Post" -username $username -password $password -url $myvarUrl -body $myvarBody
                Do {
		            Start-Sleep -Seconds 15
                    $myvarTask = (Get-NTNXTask -TaskId $myvarImageImportTaskId)
                    if ($myvarTask) {OutputLogData -category "INFO" -message "Waiting for the Image import task for $myvarImageName to complete ($($myvarTask.percentageComplete)%)..."}
                    else {OutputLogData -category "INFO" -message "Image import task for $myvarImageName has completed!"}
	            } While ($myvarTask.progressStatus -eq "Running")
            }
        }

    #endregion

    #region Create VM

        $myvarVMName = $myvarXML.domain.name
        $myvarMemoryUnit = $myvarXML.domain.memory.unit
        $myvarMemory = $myvarXML.domain.memory.'#text'
        switch ($myvarMemoryUnit)
        {
	        "KiB" {$myvarMemoryMB = $myvarMemory / 976.5625}
	        "MiB" {$myvarMemoryMB = $myvarMemory / 0.953674316406}
	        "GiB" {$myvarMemoryMB = $myvarMemory / 0.000931322574615}
        }
        $myvarCpuSockets = $myvarXML.domain.cpu.topology.sockets
        $myvarCpuCores = $myvarXML.domain.cpu.topology.cores

        $myvarVmInfo = Get-NTNXVM | where {$_.vmName -eq $myvarVMName}
        if ($myvarVmInfo) {OutputLogData -category "WARNING" -message "VM $myvarVMName already exists: skipping creation!"}
        else {
            OutputLogData -category "INFO" -message "Creating VM $myvarVMName..."
            try 
            {
                $myvarCreateVMTaskId = New-NTNXVirtualMachine -Name $myvarVMName -NumVcpus $myvarCpuSockets -NumCoresPerVcpu $myvarCpuCores -MemoryMb $myvarMemoryMB -ErrorAction Stop
            }
            catch
            {#error handling
	            Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not create VM $myvarVMName"
	            Exit
            }
            Do {
		        Start-Sleep -Seconds 5
                $myvarTask = (Get-NTNXTask -TaskId $myvarCreateVMTaskId)
                if ($myvarTask) {OutputLogData -category "INFO" -message "Waiting for the create VM task for $myvarVMName to complete ($($myvarTask.percentageComplete)%)..."}
                else {OutputLogData -category "INFO" -message "Image create VM task for $myvarVMName has completed!"}
	        } While ($myvarTask.progressStatus -eq "Running")
        }#end else vm exists
    #endregion

    #region Connect VM to Network

        OutputLogData -category "INFO" -message "Connecting VM to the network..."
        $myvarAHVNetworks = Get-NTNXNetwork
        $myvarVmNICs = @()
        $myvarVmNICs = $myvarXML.domain.devices.interface

        foreach ($myvarVmNIC in $myvarVmNICs) {
            $myvarNetwork = $myvarVmNIC.source.bridge

            $myvarVmInfo = Get-NTNXVM | where {$_.vmName -eq $myvarVMName}
            $myvarVmId = ($myvarVmInfo.vmid.split(":"))[2]
        
            $myvarTargetNetwork = $myvarAHVNetworks | where {$_.name -eq $myvarNetwork}
            if (!$myvarTargetNetwork) {
                $myvarVLAN = Read-Host "We could not find a network with the label $myvarNetwork. Which VLAN id should this VM be connected to?"
                $myvarTargetNetwork = $myvarAHVNetworks | where {$_.vlanId -eq $myvarVLAN}
                if (!$myvarTargetNetwork) {
                    Do {
                        $myvarVLAN = Read-Host "This VLAN id does not exist on AHV. Which VLAN id should this VM be connected to?"
                        $myvarTargetNetwork = $myvarAHVNetworks | where {$_.vlanId -eq $myvarVLAN}
                    }
                    While (!$myvarTargetNetwork)
                }#endif no network
            }#endif no network

            $myvarNic = New-NTNXObject -Name VMNicSpecDTO
            $myvarNic[1].networkUuid = $myvarTargetNetwork.uuid
            $myvarNic[1].adapterType = "E1000"

            try 
            {
                $myvarConnectVmTaskId = Add-NTNXVMNic -Vmid $myvarVmId -SpecList $myvarNic[1] -ErrorAction Stop
            }
            catch
            {#error handling
	            Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not connect VM $myvarVMName"
	            Exit
            }
            Do {
		        Start-Sleep -Seconds 5
                $myvarTask = (Get-NTNXTask -TaskId $myvarConnectVmTaskId)
                if ($myvarTask) {OutputLogData -category "INFO" -message "Waiting for the connect VM task for $myvarVMName to complete ($($myvarTask.percentageComplete)%)..."}
                else {OutputLogData -category "INFO" -message "Connect VM task for $myvarVMName has completed!"}
	        } While ($myvarTask.progressStatus -eq "Running")
        }

    #endregion

    #region Add VM disk(s)

        OutputLogData -category "INFO" -message "Adding disks..."
        foreach ($myvarVmDisk in $myvarVmDisks) {
            $myvarImageName = $myvarXML.domain.name+"_"+$myvarVmDisk.target.dev
            $myvarDiskImage = Get-NTNXImage | where {$_.name -eq $myvarImageName}
            $myvarDiskUuId = $myvarDiskImage.vmDiskId
            $myvarDisk = New-NTNXObject -Name VMDiskDTO
            $myvarDiskClone = New-NTNXObject -Name VMDiskSpecCloneDTO
            $myvarDiskClone.vmDiskUuid = $myvarDiskUuId
            $myvarDisk.vmDiskClone = $myvarDiskClone

            try 
            {
                $myvarAddVmDiskTaskId = Add-NTNXVMDisk -Vmid $myvarVmId -Disk $myvarDisk -ErrorAction Stop
            }
            catch
            {#error handling
	            Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not add disk $myvarImageName to VM $myvarVMName"
	            Exit
            }
            Do {
		        Start-Sleep -Seconds 5
                $myvarTask = (Get-NTNXTask -TaskId $myvarAddVmDiskTaskId)
                if ($myvarTask) {OutputLogData -category "INFO" -message "Waiting for the VM add disk task for $myvarVMName to complete ($($myvarTask.percentageComplete)%)..."}
                else {OutputLogData -category "INFO" -message "VM add disk task for $myvarVMName has completed!"}
	        } While ($myvarTask.progressStatus -eq "Running")
        }#end foreach vmdisk

    #endregion

    #region Add CDROM device

        OutputLogData -category "INFO" -message "Adding cdrom device..."
        $myvarDisk = New-NTNXObject -Name VMDiskDTO
        $myvarDisk.isCdrom = $true
        $myvarDisk.isEmpty = $true
        try 
            {
                $myvarAddVmDiskTaskId = Add-NTNXVMDisk -Vmid $myvarVmId -Disk $myvarDisk -ErrorAction Stop
            }
            catch
            {#error handling
	            Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not add cdrom device to VM $myvarVMName"
	            Exit
            }
            Do {
		        Start-Sleep -Seconds 5
                $myvarTask = (Get-NTNXTask -TaskId $myvarAddVmDiskTaskId)
                if ($myvarTask) {OutputLogData -category "INFO" -message "Waiting for the VM add cdrom task for $myvarVMName to complete ($($myvarTask.percentageComplete)%)..."}
                else {OutputLogData -category "INFO" -message "VM add cdrom task for $myvarVMName has completed!"}
	        } While ($myvarTask.progressStatus -eq "Running")

    #endregion

    #region Import cleanup
    if ($cleanup) {

        #region Remove images from library
        foreach ($myvarVmDisk in $myvarVmDisks) {
            $myvarImageName = $myvarXML.domain.name+"_"+$myvarVmDisk.target.dev
            OutputLogData -category "INFO" -message "Removing image $myvarImageName from the library..."
            $myvarImage = Get-NTNXImage | where {$_.Name -eq $myvarImageName}
            $myvarImageId = $myvarImage.uuid
            try 
            {
                $myvarRemoveImageTaskId = Remove-NTNXImage -ImageId $myvarImageId -ErrorAction Stop
            }
            catch
            {#error handling
	            Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not remove image $myvarImageName from the image library"
            }
            Do {
		        Start-Sleep -Seconds 5
                $myvarTask = (Get-NTNXTask -TaskId $myvarRemoveImageTaskId)
                if ($myvarTask) {OutputLogData -category "INFO" -message "Waiting for the remove image task for $myvarVMName to complete ($($myvarTask.percentageComplete)%)..."}
                else {OutputLogData -category "INFO" -message "Remove image task for $myvarImageName has completed!"}
	        } While ($myvarTask.progressStatus -eq "Running")

            $myvarDiskName = $myvarVmDisk.source.name
            $myvarDiskName = $myvarDiskName -creplace '^[^/]*/', ''
            OutputLogData -category "INFO" -message "Deleting source file $myvarDiskName..."
            try {
                $myvarResults = Remove-Item N:\$myvarDiskName
            }
            catch
            {
                Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not delete source file $myvarDiskName!"
            }
        }#end foreach vmdisk
        #endregion
    
        #remove XML file from container
        OutputLogData -category "INFO" -message "Deleting XML file $($myvarXMLFile.Name)..."
        try {
            $myvarResults = Remove-Item N:\$($myvarXMLFile.Name)
        }
        catch
        {
            Write-Warning $($_.Exception.Message)
	        OutputLogData -category "ERROR" -message "Could not delete XML file $($myvarXMLFile.Name)!"
        }

    }#endif cleanup
    #endregion import cleanup
}#end foreach XML file

#endregion process XML files
}#endif import
#endregion

#region Export VM
if ($export) {
    
    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        OutputLogData -category "ERROR" -message "Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
        exit
    }

    #let's load SSHSessions
    if (!Import-Module SSHSessions) {
        OutputLogData -category "WARNING" -message "We need to install the SSHSessions module!"
        Install-Module SSHSessions
        Import-Module SSHSessions
    }

    #get vm information
    OutputLogData -category "INFO" -message "Retrieving VM object $vm..."
    try {
        $myvarVmInfo = Get-NTNXVM | where {$_.vmName -eq $vm} -ErrorAction Stop
    }
    catch {
        Write-Warning $($_.Exception.Message)
	    OutputLogData -category "ERROR" -message "Could not find VM $vm"
	    Exit
    }
    $myvarVmId = ($myvarVmInfo.vmid.split(":"))[2]
    $myvarVmDiskPaths = $myvarVmInfo.nutanixVirtualDisks
    if ($myvarVmInfo.powerState -eq "on") {
        OutputLogData -category "ERROR" -message "VM $vm is powered on! Do you want to shut it down?"
        Do {
            Read-Host ($myvarUserInput = "y/n")
        }
        While ($myvarUserInput -notmatch "y|n")
        if ($myvarUserInput -eq "n") {Exit}
        else {
            OutputLogData -category "INFO" -message "Shutting down $vm..."
            try {
                Set-NTNXVMPowerOff -VmId $myvarVmId -ErrorAction Stop
            }
            catch {
                Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not shutdown VM $vm"
	            Exit
            }
        }
        OutputLogData -category "INFO" -message "Retrieving VM object $vm..."
        try {
            $myvarVmInfo = Get-NTNXVM | where {$_.vmName -eq $vm} -ErrorAction Stop
        }
        catch {
            Write-Warning $($_.Exception.Message)
	        OutputLogData -category "ERROR" -message "Could not find VM $vm"
	        Exit
        }
    }

    #get vmdisks
    OutputLogData -category "INFO" -message "Retrieving disks for VM object $vm..."
    try {
        $myvarVmDisks = Get-NTNXVMDisk -Vmid $myvarVmId | where {$_.isCdrom -eq $false} -ErrorAction Stop
    }
    catch {
        Write-Warning $($_.Exception.Message)
	    OutputLogData -category "ERROR" -message "Could not find any disks for VM $vm"
	    Exit
    }
    #open ssh session to cluster
    OutputLogData -category "INFO" -message "Opening ssh session to $prism..."
    try {
        $myvarSSHSession = New-SshSession -ComputerName $prism -Username "nutanix" -ErrorAction Stop
    }
    catch {
        Write-Warning $($_.Exception.Message)
	    OutputLogData -category "ERROR" -message "Could not open ssh session to $prism"
	    Exit
    }
    #convert all disks to qcow2
    OutputLogData -category "INFO" -message "Exporting all disks for VM object $vm..."
    foreach ($myvarVmDisk in $myvarVmDisks) {
        OutputLogData -category "INFO" -message "Converting disk $($myvarVmDisk.id) to /$container/$vm`_$($myvarVmDisk.id).qcow2..."
        $myvarVmDiskPath = $myvarVmDiskPaths | where {$_ -match $myvarVmDisk.vmDiskUuid}
        try {
            OutputLogData -category "INFO" -message "Running command /usr/local/nutanix/bin/qemu-img convert -f raw -O qcow2 -c nfs://127.0.0.1$myvarVmDiskPath nfs://127.0.0.1/$container/$vm`_$($myvarVmDisk.id).qcow2"
            Invoke-SshCommand -ComputerName $prism -Command "/usr/local/nutanix/bin/qemu-img convert -f raw -O qcow2 -c nfs://127.0.0.1$myvarVmDiskPath nfs://127.0.0.1/$container/$vm`_$($myvarVmDisk.id).qcow2" -ErrorAction Stop
        }
        catch {
            Write-Warning $($_.Exception.Message)
	        OutputLogData -category "ERROR" -message "Could not invoke ssh command to convert disk $($myvarVmDisk.id)"
	        Exit
        }
    }

    if ($myvarVmInfo.powerState -eq "off") {
        OutputLogData -category "ERROR" -message "VM $vm is powered off! Do you want to power it on?"
        Do {
            Read-Host ($myvarUserInput = "y/n")
        }
        While ($myvarUserInput -notmatch "y|n")
        if ($myvarUserInput -eq "n") {Continue}
        else {
            OutputLogData -category "INFO" -message "Powering on $vm..."
            try {
                Set-NTNXVMPowerOn -VmId $myvarVmId -ErrorAction Stop
            }
            catch {
                Write-Warning $($_.Exception.Message)
	            OutputLogData -category "ERROR" -message "Could not power on VM $vm"
	            Continue
            }
        }
        OutputLogData -category "INFO" -message "Retrieving VM object $vm..."
        try {
            $myvarVmInfo = Get-NTNXVM | where {$_.vmName -eq $vm} -ErrorAction Stop
        }
        catch {
            Write-Warning $($_.Exception.Message)
	        OutputLogData -category "ERROR" -message "Could not find VM $vm"
	        Exit
        }
    }
    #create xml
    #OutputLogData -category "INFO" -message "Exporting XML definition for VM object $vm..."
    #
}
#endregion

#endregion processing

#region Cleanup	
#########################
##       cleanup       ##
#########################

    OutputLogData -category "INFO" -message "Disconnecting from Nutanix cluster $prism..."
	Disconnect-NutanixCluster -Servers $prism #cleanup after ourselves and disconnect from the Nutanix cluster

	#let's figure out how much time this all took
	OutputLogData -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable username -ErrorAction SilentlyContinue
    Remove-Variable password -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable container -ErrorAction SilentlyContinue
    Remove-Variable import -ErrorAction SilentlyContinue
    Remove-Variable export -ErrorAction SilentlyContinue
    Remove-Variable cleanup -ErrorAction SilentlyContinue
    Remove-Variable vm -ErrorAction SilentlyContinue
#endregion