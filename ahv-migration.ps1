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

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 03/13/2017 sb   Initial release.
 06/18/2018 sb   Modified prep-work section to handle updates better and added bettertls module to deal with tls 1.2.
                 Fixed an issue with disk uuid enumeration with recent releases of AOS.
################################################################################
'@
$myvarScriptName = ".\ahv-migration.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

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
if (((Get-Module -Name sbourdeaud).Version.Major -le 1) -and ((Get-Module -Name sbourdeaud).Version.Minor -le 1)) {
    Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
    try {Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop}
    catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
}
#endregion

#region module BetterTls
if (!(Get-Module -Name BetterTls)) {
    Write-Host "$(get-date) [INFO] Importing module 'BetterTls'..." -ForegroundColor Green
    try
    {
        Import-Module -Name BetterTls -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Imported module 'BetterTls'!" -ForegroundColor Cyan
    }#end try
    catch #we couldn't import the module, so let's install it
    {
        Write-Host "$(get-date) [INFO] Installing module 'BetterTls' from the Powershell Gallery..." -ForegroundColor Green
        try {Install-Module -Name BetterTls -Scope CurrentUser -ErrorAction Stop}
        catch {throw "$(get-date) [ERROR] Could not install module 'BetterTls': $($_.Exception.Message)"}

        try
        {
            Import-Module -Name BetterTls -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Imported module 'BetterTls'!" -ForegroundColor Cyan
        }#end try
        catch #we couldn't import the module
        {
            Write-Host "$(get-date) [ERROR] Unable to import the module BetterTls : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/BetterTls/0.1.0.0" -ForegroundColor Yellow
            Exit
        }#end catch
    }#end catch
}
Write-Host "$(get-date) [INFO] Disabling Tls..." -ForegroundColor Green
try {Disable-Tls -Tls -Confirm:$false -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not disable Tls : $($_.Exception.Message)"}
Write-Host "$(get-date) [INFO] Enabling Tls 1.2..." -ForegroundColor Green
try {Enable-Tls -Tls12 -Confirm:$false -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not enable Tls 1.2 : $($_.Exception.Message)"}
#endregion

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
#we also need to use the proper encryption protocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol =  [System.Security.Authentication.SslProtocols] "tls12"

#endregion

#region Functions
########################
##   main functions   ##
########################
<#
.Synopsis
   Gets status for a given Prism task uuid
.DESCRIPTION
   Gets status for a given Prism task uuid
#>
function Get-NTNXTask
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $TaskId
    )

    Begin
    {
    }
    Process
    {
        $myvarUrl = "https://"+$prism+":9440/PrismGateway/services/rest/v2.0/tasks/$($TaskId.task_uuid)"
        $result = Invoke-PrismRESTCall -username $username -password $password -method "GET" -url $myvarUrl
    }
    End
    {
        return $result
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-NTNXVM
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
    )

    Begin
    {
    }
    Process
    {
        $myvarUrl = "https://"+$prism+":9440/PrismGateway/services/rest/v2.0/vms/"
        $result = Invoke-PrismRESTCall -username $username -password $password -method "GET" -url $myvarUrl
    }
    End
    {
        return $result
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-NTNXImage
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        
    )

    Begin
    {
    }
    Process
    {
        $myvarUrl = "https://"+$prism+":9440/PrismGateway/services/rest/v2.0/images/"
        $result = Invoke-PrismRESTCall -username $username -password $password -method "GET" -url $myvarUrl
    }
    End
    {
        return $result
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Remove-NTNXImage
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ImageId
    )

    Begin
    {
    }
    Process
    {
        $myvarUrl = "https://"+$prism+":9440/PrismGateway/services/rest/v2.0/images/$ImageId"
        $result = Invoke-PrismRESTCall -username $username -password $password -method "DELETE" -url $myvarUrl
    }
    End
    {
        return $result
    }
}
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
if (!$import -and !$export) {throw "$(get-date) [ERROR] You must specify import or export!"}
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
if (!$container) {$container = read-host "Enter the name of the Nutanix container you want to import from or export to"}
if ($export -and (!$vm)) {$vm = read-host "Enter the name of the VM you want to export"}


#endregion

#region Processing
#########################
##   main processing   ##
#########################

#region Import VM(s)
if ($import) {

#region Connect network drive to Nutanix container
Write-Host "$(get-date) [INFO] Connecting to \\$prism\$container..." -ForegroundColor Green
try {
    $myvarConnectedDrive = New-PSDrive -Name "N" -PSProvider FileSystem -Root "\\$prism\$container" -ErrorAction Stop
}
catch {
    throw "$(get-date) [ERROR] Could not connect to \\$prism\$container : $($_.Exception.Message)"
}
#endregion

#region Process XML files
Write-Host "$(get-date) [INFO] Processing XML files in \\$prism\$container..." -ForegroundColor Green
$myvarXMLFiles = Get-ChildItem N:\ | where {$_.extension -eq '.xml'}

foreach ($myvarXMLFile in $myvarXMLFiles) {

    #region Read from XML
        Write-Host "$(get-date) [INFO] Processing $myvarXMLFile..." -ForegroundColor Green
        try #let's make sure we can import the XML file content
        {
            #remove NUL characters from the XML file if there are any
            (get-content N:\$($myvarXMLFile.Name)) -replace "`0", "" | Set-Content N:\$($myvarXMLFile.Name)
            $myvarXML = [xml](get-content N:\$($myvarXMLFile.Name) | Where-Object {$_ -notmatch '<scale:os'})
        }#end try xml import
        catch
        {
	        throw "$(get-date) [ERROR] Could not read the XML file $myvarXMLFile : $($_.Exception.Message)"
        }#end catch xml import error
        #endregion

    #region Import into image library
        Write-Host "$(get-date) [INFO] Importing disks for VM $($myvarXML.domain.name)..." -ForegroundColor Green
        $myvarVmDisks = @()
        #create a disk image in the ahv library given a source file
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
                throw "$(get-date) [ERROR] Disk $myvarDiskName.qcow2 is not in \\$prism\$container"
            }
            
            $myvarImageName = $myvarXML.domain.name+"_"+$myvarVmDisk.target.dev
            $myvarUrl = "https://"+$prism+":9440/PrismGateway/services/rest/v2.0/images/"
            $myvarImages = Invoke-PrismRESTCall -username $username -password $password -method "GET" -url $myvarUrl
            $myvarImage = $myvarImages.entities | where {$_.name -eq $myvarImageName}
            if ($myvarImage) {Write-Host "$(get-date) [WARNING] Image $myvarImageName already exists in the library: skipping import..." -ForegroundColor Yellow}
            else {
                $myvarUrl = "https://"+$prism+":9440/PrismGateway/services/rest/v2.0/images/"
                $myvarSource = "nfs://127.0.0.1/"+$container+"/"+$myvarDiskName+".qcow2"
                $myvarBody = @{annotation=$myvarAnnotation;image_type="disk_image";image_import_spec=@{storage_container_name=$container;url=$myvarSource};name=$myvarImageName}
                $myvarBody = ConvertTo-Json $myvarBody
                $myvarImageImportTaskId = Invoke-PrismRESTCall -method "POST" -username $username -password $password -url $myvarUrl -body $myvarBody
                Do {
		            Start-Sleep -Seconds 15
                    $myvarTask = (Get-NTNXTask -TaskId $myvarImageImportTaskId)
                    if ($myvarTask) {Write-Host "$(get-date) [INFO] Waiting for the Image import task for $myvarImageName to complete ($($myvarTask.percentage_complete)%)..." -ForegroundColor Green}
                    else {Write-Host "$(get-date) [INFO] Image import task for $myvarImageName has completed!" -ForegroundColor Green}
	            } While ($myvarTask.progressStatus -eq "Running")
            }
        }

    #endregion

    #region Create VM (POST v2 /vms/)

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

        $myvarVMs = Get-NTNXVM
        $myvarVmInfo = $myvarVMs.entities | where {$_.name -eq $myvarVMName}
        if ($myvarVmInfo) {
            Write-Host "$(get-date) [WARNING] VM $myvarVMName already exists: skipping creation!" -ForegroundColor Yellow
            $vm_uuid = $myvarVmInfo.uuid
        } else {
            Write-Host "$(get-date) [INFO] Creating VM $myvarVMName..." -ForegroundColor Green
            
            #create the vm
            Write-Host "$(get-date) [INFO] Creating vm $myvarVMName..." -ForegroundColor Green
            if ($myvarVmInfo.description) {$description = $myvarVmInfo.description} else {$description = "This vm was imported on $(get-date) using the ahv-migration.ps1 script"}
            $memory_mb = $myvarMemoryMB
            $name = $myvarVMName
            $num_cores_per_vcpu = $myvarCpuCores
            $num_vcpus = $myvarCpuSockets

            $body = @{
                description=$description;
                memory_mb=$memory_mb;
                name=$name;
                num_cores_per_vcpu=$num_cores_per_vcpu;
                num_vcpus=$num_vcpus
            }
            $body = ConvertTo-Json $body
            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/vms/"
            $method = "POST"
            $vmCreateTask = Invoke-PrismRESTCall -method $method -url $url -username $username -password $password -body $body

            #check on vm create task status
            Write-Host "$(get-date) [INFO] Checking status of the vm creation task $($vmCreateTask.task_uuid)..." -ForegroundColor Green
            Do {
                $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/tasks/$($vmCreateTask.task_uuid)"
                $method = "GET"
                $vmCreateTaskStatus = Get-PrismRESTCall -method $method -username $username -password $password -url $url
                if ($vmCreateTaskStatus.progress_status -eq "Failed") {
                    Write-Host "$(get-date) [ERROR] VM creation task for $myvarVMName failed. Exiting!" -ForegroundColor Red
                    Exit
                } elseIf ($vmCreateTaskStatus.progress_status -eq "Succeeded") {
                    Write-Host "$(get-date) [SUCCESS] VM $myvarVMName create task status has $($vmCreateTaskStatus.progress_status)!" -ForegroundColor Cyan
                } else {
                    Write-Host "$(get-date) [WARNING] VM $myvarVMName create task status is $($vmCreateTaskStatus.progress_status) with $($vmCreateTaskStatus.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 5
                }
            } While ($vmCreateTaskStatus.progress_status -ne "Succeeded")

            $vm_uuid = $vmCreateTaskStatus.entity_list.entity_id
        }#end else vm exists
        
    #endregion

    #region attach network (POST v2 /vms/{uuid}/nics/)
    Write-Host "$(get-date) [INFO] Retrieving network information from $prism..." -ForegroundColor Green
    $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/networks/"
    $method = "GET"
    $clusterNetworks = Get-PrismRESTCall -method $method -url $url -username $username -password $password
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved the list of networks on $prism!" -ForegroundColor Cyan

    $myvarVmNICs = @()
    $myvarVmNICs = $myvarXML.domain.devices.interface

    Write-Host "$(get-date) [INFO] Attaching network devices to $myvarVMName..." -ForegroundColor Green
    ForEach ($nic in $myvarVmNICs) {
        #check if the network already exists, otherwise prompt for a network name
        if (!($clusterNetworks.Entities | where {$_.uuid -eq $nic.network_uuid})) {
            Write-Host "$(get-date) [WARNING] Network uuid $($nic.network_uuid) does not exist on $prism..." -ForegroundColor Yellow
            Foreach ($networkEntry in $clusterNetworks.Entities) {
                Write-Host "$(get-date) [INFO] Network $($networkEntry.name) with VLAN id $($networkEntry.vlan_id) is available on $prism..." -ForegroundColor Green
            }
            Do {
                $network_label = Read-Host "Please enter the network label (case sensitive) you want to connect this VM to"
                $network = $clusterNetworks.Entities | where {$_.name -eq $network_label}
                if ($network) {
                    $network_uuid = $network.uuid
                } else {
                    Write-Host "$(get-date) [ERROR] Network $network_label does not exist on $prism..." -ForegroundColor Red
                }
            }
            While (!$network)
        } else {
            $network_uuid = $nic.network_uuid
        }

        $mac_address = $nic.mac.address
        $model = ""

        #attach nic to vm
        $body = @{
            uuid=$vm_uuid;
            spec_list=@(@{
                mac_address=$mac_address;
                network_uuid=$network_uuid;
                model=$model
            })
        }
        $body = ConvertTo-Json $body -Depth 5
        $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/vms/$($vm_uuid)/nics/"
        $method = "POST"
        $nicAttachTask = Get-PrismRESTCall -method $method -url $url -username $username -password $password -body $body

        #check on attach nic task status
        Write-Host "$(get-date) [INFO] Checking status of the NIC attach task $($nicAttachTask.task_uuid)..." -ForegroundColor Green
        Do {
            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/tasks/$($nicAttachTask.task_uuid)"
            $method = "GET"
            $nicAttachTaskStatus = Get-PrismRESTCall -method $method -username $username -password $password -url $url
            if ($nicAttachTaskStatus.progress_status -eq "Failed") {
                Write-Host "$(get-date) [ERROR] NIC $mac_address attach task for $myvarVMName failed. Exiting!" -ForegroundColor Red
                Exit
            } elseIf ($nicAttachTaskStatus.progress_status -eq "Succeeded") {
                Write-Host "$(get-date) [SUCCESS] NIC $mac_address attach task status has $($nicAttachTaskStatus.progress_status)!" -ForegroundColor Cyan
            } else {
                Write-Host "$(get-date) [WARNING] NIC $mac_address attach task status is $($nicAttachTaskStatus.progress_status) with $($nicAttachTaskStatus.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
        } While ($nicAttachTaskStatus.progress_status -ne "Succeeded")

    }#end foreach nic
        
    #endregion

    #region attach disks (POST v2 /vms/{uuid}/disks/attach)
    Write-Host "$(get-date) [INFO] Retrieving the list of images in $prism library..." -ForegroundColor Green
    $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/images/"
    $method = "GET"
    $imageList = Invoke-PrismRESTCall -method $method -url $url -username $username -password $password
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved the list of images in $prism library!" -ForegroundColor Cyan

    $vm_uuid = $vmCreateTaskStatus.entity_list.entity_id
    Write-Host "$(get-date) [INFO] Attaching disks to VM $myvarVMName ($vm_uuid)..." -ForegroundColor Green

    $myvarVmDisks = $myvarXML.domain.devices.disk | where {$_.device -eq "Disk"}

    ForEach ($disk in $myvarVmDisks) {
            
            #figure out what the disk name should be
            $myvarDiskName = $disk.source.name
            $myvarDiskName = $myvarDiskName -creplace '^[^/]*/', ''
            if (!(Test-Path N:\$myvarDiskName.qcow2)) {
                throw "$(get-date) [ERROR] Disk $myvarDiskName.qcow2 is not in \\$prism\$container"
            }
            $myvarImageName = $myvarXML.domain.name+"_"+$disk.target.dev

            #get the corresponding image disk id
            $image = $imageList.Entities | where {$_.Name -eq $myvarImageName}
            if (!$image) {throw "$(get-date) [ERROR] Could not find image $myvarImageName on $prism"}
            $vmdisk_uuid = $image.vm_disk_id

            #create the attach disk task
            Write-Host "$(get-date) [INFO] Attaching disk $myvarImageName to $myvarVMName..." -ForegroundColor Green
            $body = @{
                uuid=$vm_uuid;
                vm_disks=@(@{
                    is_cdrom=$false;
                    vm_disk_clone=@{
                        disk_address=@{
                            vmdisk_uuid=$vmdisk_uuid
                        }
                    }
                })
            }
            $body = ConvertTo-Json $body -Depth 5
            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/vms/$($vm_uuid)/disks/attach"
            $method = "POST"
            $diskAttachTask = Invoke-PrismRESTCall -method $method -url $url -username $username -password $password -body $body

            #check on attach disk task status
            Write-Host "$(get-date) [INFO] Checking status of the disk attach task $($diskAttachTask.task_uuid)..." -ForegroundColor Green
            Do {
                $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/tasks/$($diskAttachTask.task_uuid)"
                $method = "GET"
                $diskAttachTaskStatus = Invoke-PrismRESTCall -method $method -username $username -password $password -url $url
                if ($diskAttachTaskStatus.progress_status -eq "Failed") {
                    Write-Host "$(get-date) [ERROR] Disk attach task for $myvarImageName for $myvarVMName failed. Exiting!" -ForegroundColor Red
                    Exit
                } elseIf ($diskAttachTaskStatus.progress_status -eq "Succeeded") {
                    Write-Host "$(get-date) [SUCCESS] Disk attach task status for $myvarImageName has $($diskAttachTaskStatus.progress_status)!" -ForegroundColor Cyan
                } else {
                    Write-Host "$(get-date) [WARNING] Disk attach task status for $myvarImageName is $($diskAttachTaskStatus.progress_status) with $($diskAttachTaskStatus.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 5
                }
            } While ($diskAttachTaskStatus.progress_status -ne "Succeeded")

    }#end foreach disk

    #endregion

    #region attach cdrom
    $myvarVmCDROMs = $myvarXML.domain.devices.disk | where {$_.device -eq "cdrom"}
    ForEach ($disk in $myvarVmCDROMs) {     
        Write-Host "$(get-date) [INFO] Attaching CDROM to $myvarVMName..." -ForegroundColor Green
        $body = @{
            uuid=$vm_uuid;
            vm_disks=@(@{
                is_cdrom=$true;
                is_empty=$true
            })
        }
        $body = ConvertTo-Json $body
        $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/vms/$($vm_uuid)/disks/attach"
        $method = "POST"
        $diskAttachTask = Invoke-PrismRESTCall -method $method -url $url -username $username -password $password -body $body

        #check on attach cdrom task status
        Write-Host "$(get-date) [INFO] Checking status of the CDROM attach task $($diskAttachTask.task_uuid)..." -ForegroundColor Green
        Do {
            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/tasks/$($diskAttachTask.task_uuid)"
            $method = "GET"
            $diskAttachTaskStatus = Invoke-PrismRESTCall -method $method -username $username -password $password -url $url
            if ($diskAttachTaskStatus.progress_status -eq "Failed") {
                Write-Host "$(get-date) [ERROR] CDROM attach task for $myvarVMName failed. Exiting!" -ForegroundColor Red
                Exit
            } elseIf ($diskAttachTaskStatus.progress_status -eq "Succeeded") {
                Write-Host "$(get-date) [SUCCESS] CDROM attach task status has $($diskAttachTaskStatus.progress_status)!" -ForegroundColor Cyan
            } else {
                Write-Host "$(get-date) [WARNING] CDROM attach task status is $($diskAttachTaskStatus.progress_status) with $($diskAttachTaskStatus.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
        } While ($diskAttachTaskStatus.progress_status -ne "Succeeded")
    }#endif foreach disk

    #endregion

    #region Import cleanup
    if ($cleanup) {

        #region Remove images from library
        foreach ($myvarVmDisk in $myvarVmDisks) {
            $myvarImageName = $myvarXML.domain.name+"_"+$myvarVmDisk.target.dev
            Write-Host "$(get-date) [INFO] Removing image $myvarImageName from the library..." -ForegroundColor Green
            $myvarImages = Get-NTNXImage
            $myvarImage = $myvarImages.entities | where {$_.name -eq $myvarImageName}
            $myvarImageId = $myvarImage.uuid
            try 
            {
                $myvarRemoveImageTaskId = Remove-NTNXImage -ImageId $myvarImageId -ErrorAction Stop
            }
            catch
            {#error handling
	            throw "$(get-date) [ERROR] Could not remove image $myvarImageName from the image library : $($_.Exception.Message)"
            }
            Do {
		        Start-Sleep -Seconds 5
                $myvarTask = (Get-NTNXTask -TaskId $myvarRemoveImageTaskId)
                if ($myvarTask) {Write-Host "$(get-date) [INFO] Waiting for the remove image task for $myvarVMName to complete ($($myvarTask.percentage_complete)%)..." -ForegroundColor Green}
                else {Write-Host "$(get-date) [INFO] Remove image task for $myvarImageName has completed!" -ForegroundColor Green}
	        } While ($myvarTask.progressStatus -eq "Running")

            $myvarDiskName = $myvarVmDisk.source.name
            $myvarDiskName = $myvarDiskName -creplace '^[^/]*/', ''
            Write-Host "$(get-date) [INFO] Deleting source file $myvarDiskName.qcow2..." -ForegroundColor Green
            try {
                $myvarResults = Remove-Item N:\$myvarDiskName.qcow2 -ErrorAction Stop
            }
            catch
            {
                throw "$(get-date) [ERROR] Could not delete source file $myvarDiskName.qcow2! : $($_.Exception.Message)"
            }
        }#end foreach vmdisk
        #endregion
    
        #remove XML file from container
        Write-Host "$(get-date) [INFO] Deleting XML file $($myvarXMLFile.Name)..." -ForegroundColor Green
        try {
            $myvarResults = Remove-Item N:\$($myvarXMLFile.Name)
        }
        catch
        {
            throw "$(get-date) [ERROR] Could not delete XML file $($myvarXMLFile.Name) : $($_.Exception.Message)"
        }

    }#endif cleanup
    #endregion import cleanup
}#end foreach XML file

#endregion process XML files
}#endif import
#endregion

#region Export VM
if ($export) {
    
    Write-Host "$(get-date) [ERROR] Export is no longer an available feature of this script!" -ForegroundColor Red
   
}
#endregion

#endregion processing

#region Cleanup	
#########################
##       cleanup       ##
#########################
    
	#let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
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
