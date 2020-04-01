<#
.SYNOPSIS
  This script uses Prism Central to add a virtual machine to the given AHV cluster.
.DESCRIPTION
  This script takes user input and creates a virtual machine on an AHV cluster using Prism Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER cluster
  Name of the AHV cluster you want to create the VM on.
.PARAMETER vm
  Name of the virtual machine you want to create
.PARAMETER cpu
  Number of vCPUs to allocate to the VM.
.PARAMETER ram
  GiB amount of memory to allocate to the VM.
.PARAMETER image
  Name of the AHV virtual library image to base the VM on.
.PARAMETER disk
  GiB amount for data disks (optional). If you specify multiple values separated by a comma, multiple disks will be added.
.PARAMETER net
  Name of the AHV network the VM should be attached to.  If you specify multiple values separated by a comma, multiple vnics will be added.
.PARAMETER cust
  Name of the guest OS customization file you want to inject (optional; use cloud-init.yaml for linux and unattend.xml for windows).
.PARAMETER ostype
  Specify either linux or windows (required with -cust)
.EXAMPLE
.\new-AhvVm.ps1 -cluster ntnxc1.local -username admin -password admin -vm myvmhostname -cpu 2 -ram 8 -image myahvimagelibraryitem -disk 50 -net vlan-99 -cust unattend.xml -ostype windows
Connect to a Nutanix Prism Central VM of your choice and retrieve the list of VMs.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: July 3rd 2019
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $true)] [string]$prismcentral,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $true)] [string]$cluster,
    [parameter(mandatory = $true)] [string]$vm,
    [parameter(mandatory = $true)] [int]$cpu,
    [parameter(mandatory = $true)] [int]$ram,
    [parameter(mandatory = $true)] [string]$image,
    [parameter(mandatory = $false)] [array]$disk,
    [parameter(mandatory = $true)] [array]$net,
    [parameter(mandatory = $false)] [string]$cust,
    [parameter(mandatory = $false)] [ValidateSet('linux','windows')] [string]$ostype
)
#endregion

#region functions

#this function is used to create saved credentials for the current user
function Set-CustomCredentials 
{
#input: path, credname
	#output: saved credentials file
<#
.SYNOPSIS
  Creates a saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to create a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Set-CustomCredentials -path c:\creds -credname prism-apiuser
Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
#>
	param
	(
		[parameter(mandatory = $false)]
        [string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Set path to $path" -ForegroundColor Green
        } 
    }
    process
    {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
		$credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
		
		#put details in hashed format
		$user = $credentials.UserName
		$securePassword = $credentials.Password
        
        #convert secureString to text
        try 
        {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch 
        {
            throw "$(get-date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        #create directory to store creds if it does not already exist
        if(!(Test-Path $path))
		{
            try 
            {
                $result = New-Item -type Directory $path -ErrorAction Stop
            } 
            catch 
            {
                throw "$(get-date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
		}

        #save creds to file
        try 
        {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try 
        {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(get-date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan                
    }
    end
    {}
}

#this function is used to retrieve saved credentials for the current user
function Get-CustomCredentials 
{
#input: path, credname
	#output: credential object
<#
.SYNOPSIS
  Retrieves saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Get-CustomCredentials -path c:\creds -credname prism-apiuser
Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
#>
	param
	(
        [parameter(mandatory = $false)]
		[string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        } 
    }
    process
    {
        $credentialsFilePath = "$path\$credname.txt"
        if(!(Test-Path $credentialsFilePath))
	    {
            throw "$(get-date) [ERROR] Could not access file $credentialsFilePath : $($_.Exception.Message)"
        }

        $credFile = Get-Content $credentialsFilePath
		$user = $credFile[0]
		$securePassword = $credFile[1] | ConvertTo-SecureString

        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(get-date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan 
    }
    end
    {
        return $customCredentials
    }
}

#endregion

#region prepwork

$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
07/03/2019 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\new-AhvVm.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

# ignore SSL warnings
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

# add Tls12 support
Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
[Net.ServicePointManager]::SecurityProtocol = `
    ([Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12)

#endregion

#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
#prepare our overall results variable
#[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
$length=100 #this specifies how many entities we want in the results of each API query
$api_server_port = "9440"
#endregion

#region parameters validation
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
}
if ($cust -and (!$ostype)) {
    Write-Host "$(Get-Date) [ERROR] You must specify an ostype (linux or windows) when using -cust" -ForegroundColor Red
    Exit 1
}
$headers = @{
    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
    "Content-Type"="application/json";
    "Accept"="application/json"
}
#endregion

#*STEP1/4: RETRIEVE CLUSTERS
#region retrieve clusters 

#region prepare api call
$api_server_endpoint = "/api/nutanix/v3/clusters/list"
$url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
$method = "POST"

# this is used to capture the content of the payload
$content = @{
    kind="cluster";
    offset=0;
    length=$length;
    sort_order="ASCENDING";
    sort_attribute="name"
}
$payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call
Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
Do {
    try {
        #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
        } else {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
        }
        
        Write-Host "$(Get-Date) [INFO] Processing results from $($resp.metadata.offset) to $($resp.metadata.offset + $resp.metadata.length)" -ForegroundColor Green
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

        #grab the information we need in each entity
        ForEach ($entity in $resp.entities) {
            #grab the uuid of the specified cluster
            if ($entity.spec.name -eq $cluster) {
                $cluster_uuid = $entity.metadata.uuid
            }
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="cluster";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length;
            sort_order="ASCENDING";
            sort_attribute="name"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
        #add any last words here; this gets processed no matter what
    }
}
While ($resp.metadata.length -eq $length)

if (!$cluster_uuid) {
    Write-Host "$(Get-Date) [ERROR] There is no cluster named $($cluster) on Prism Central $($prismcentral)" -ForegroundColor Red
    Exit 1
} else {
    Write-Host "$(Get-Date) [SUCCESS] Cluster $($cluster) has uuid $($cluster_uuid)" -ForegroundColor Cyan
}
#endregion

#endregion

#*STEP2/4: RETRIEVE NETWORKS/SUBNETS
#region retrieve networks/subnets

#region prepare api call
$api_server_endpoint = "/api/nutanix/v3/subnets/list"
$url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
$method = "POST"

# this is used to capture the content of the payload
$content = @{
    kind="subnet";
    offset=0;
    length=$length;
    sort_order="ASCENDING";
    sort_attribute="name"
}
$payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call
[System.Collections.ArrayList]$myvarNetResults = New-Object System.Collections.ArrayList($null)
Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
Do {
    try {
        #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
        } else {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
        }
        
        Write-Host "$(Get-Date) [INFO] Processing results from $($resp.metadata.offset) to $($resp.metadata.offset + $resp.metadata.length)" -ForegroundColor Green
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

        #grab the information we need in each entity
        ForEach ($entity in $resp.entities) {
            ForEach ($network in $net) {
                if ($entity.status.name -eq $network) {
                    if ($entity.spec.cluster_reference.name -eq $cluster) {
                        $myvarNetInfo = [ordered]@{
                            "name" = $entity.status.name;
                            "uuid" = $entity.metadata.uuid
                        }
                        $myvarNetResults.Add((New-Object PSObject -Property $myvarNetInfo)) | Out-Null
                        Write-Host "$(Get-Date) [SUCCESS] Network $($network) on cluster ($cluster) has uuid $($entity.metadata.uuid)" -ForegroundColor Cyan
                    }
                }
            }
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="subnet";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length;
            sort_order="ASCENDING";
            sort_attribute="name"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
        #add any last words here; this gets processed no matter what
    }
}
While ($resp.metadata.length -eq $length)

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $myvarResults
}

if (!$myvarNetResults) {
    Write-Host "$(Get-Date) [ERROR] Could not find any valid networks on cluster $($cluster)" -ForegroundColor Red
    Exit 1
}
#endregion

#endregion

#*STEP3/4: RETRIEVE IMAGES
#region retrieve images 

#region prepare api call
$api_server_endpoint = "/api/nutanix/v3/images/list"
$url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
$method = "POST"

# this is used to capture the content of the payload
$content = @{
    kind="image";
    offset=0;
    length=$length;
    sort_order="ASCENDING";
    sort_attribute="name"
}
$payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make api call
Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
Do {
    try {
        #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
        } else {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
        }
        
        Write-Host "$(Get-Date) [INFO] Processing results from $($resp.metadata.offset) to $($resp.metadata.offset + $resp.metadata.length)" -ForegroundColor Green
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

        #grab the information we need in each entity
        ForEach ($entity in $resp.entities) {
            if ($entity.spec.name -eq $image) {
                if ($entity.spec.resources.image_type -ne "DISK_IMAGE") {
                    Write-Host "$(Get-Date) [ERROR] Image $($image) is not a disk image" -ForegroundColor Red
                    Exit 1
                }
                $image_uuid = $entity.metadata.uuid
            }
        }

        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="image";
            offset=($resp.metadata.length + $resp.metadata.offset);
            length=$length;
            sort_order="ASCENDING";
            sort_attribute="name"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
        #add any last words here; this gets processed no matter what
    }
}
While ($resp.metadata.length -eq $length)

if ($debugme) {
    Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
    $myvarResults
}

if (!$image_uuid) {
    Write-Host "$(Get-Date) [ERROR] Could not find image $($image)" -ForegroundColor Red
    Exit 1
}
Write-Host "$(Get-Date) [SUCCESS] Image $($image) has uuid $($image_uuid)" -ForegroundColor Cyan
#endregion

#endregion

#*STEP4/4: CREATE VM
#region create vm 

#region check guest customization file
if ($cust) {
    if (!(Test-Path $cust)) {
        Write-Host "$(get-date) [ERROR] Can't find $($cust)! Please make sure the specified guest customization file exists. Exiting." -ForegroundColor Red
        Exit
    }
    $guest_customization_file = Get-Content -Path $cust -Raw
    $base64_string = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($guest_customization_file))    
}
#endregion

#region prepare api call
$api_server_endpoint = "/api/nutanix/v3/vms"
$url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
$method = "POST"

# this is used to capture the content of the payload
$i = 0 #used for device index
if ($cust -and ($ostype -eq "linux")) {
    $content = @{
        spec = @{
            name = $vm
            description = "Created using REST API on $(Get-Date)"
            resources = @{
                num_threads_per_core = 1
                num_vcpus_per_socket = 1
                num_sockets = $cpu
                memory_size_mib = $($ram * 1024)
                vnuma_config = @{
                    num_vnuma_nodes = 0
                }
                vga_console_enabled = $true
                serial_port_list = @()
                gpu_list = @()
                nic_list = @(ForEach ($subnet in $myvarNetResults) {
                    @{
                        nic_type = "NORMAL_NIC"
                        subnet_reference = @{
                            kind = "subnet"
                            name = $subnet.name
                            uuid = $subnet.uuid
                        }
                        is_connected = $true
                    }
                }
                )
                boot_config = @{
                    boot_device = @{
                        disk_address = @{
                            device_index = 0
                            adapter_type = "SCSI"
                        }
                    }
                }
                disk_list = @(
                    @{
                        device_properties = @{
                            disk_address = @{
                                device_index = 1
                                adapter_type = "IDE"
                            }
                            device_type = "CDROM"
                        }
                    }
                    @{
                        data_source_reference = @{
                            kind = "image"
                            uuid = $image_uuid
                        }
                        device_properties = @{
                            disk_address = @{
                                device_index = 0
                                adapter_type = "SCSI"
                            }
                            device_type = "DISK"
                        }
                    }
                    ForEach ($drive in $disk) {
                        @{
                            device_properties = @{
                                disk_address = @{
                                    device_index = (++$i)
                                    adapter_type = "SCSI"
                                }
                                device_type = "DISK"
                            }
                            disk_size_mib = $($drive * 1024)
                        }
                    }
                )
                guest_customization = @{
                    cloud_init = @{
                      user_data = $base64_string
                    }
                    is_overridable = $false
                  }
            }
            cluster_reference = @{
                kind = "cluster"
                name = $cluster
                uuid = $cluster_uuid
            }
    
        }
        metadata = @{
            kind = "vm"
            spec_version = 3
            categories = @{}
        }
    }
} elseif ($cust -and ($ostype -eq "windows")) {
    $content = @{
        spec = @{
            name = $vm
            description = "Created using REST API on $(Get-Date)"
            resources = @{
                num_threads_per_core = 1
                num_vcpus_per_socket = 1
                num_sockets = $cpu
                memory_size_mib = $($ram * 1024)
                vnuma_config = @{
                    num_vnuma_nodes = 0
                }
                vga_console_enabled = $true
                serial_port_list = @()
                gpu_list = @()
                nic_list = @(ForEach ($subnet in $myvarNetResults) {
                    @{
                        nic_type = "NORMAL_NIC"
                        subnet_reference = @{
                            kind = "subnet"
                            name = $subnet.name
                            uuid = $subnet.uuid
                        }
                        is_connected = $true
                    }
                }
                )
                boot_config = @{
                    boot_device = @{
                        disk_address = @{
                            device_index = 0
                            adapter_type = "SCSI"
                        }
                    }
                }
                disk_list = @(
                    @{
                        device_properties = @{
                            disk_address = @{
                                device_index = 1
                                adapter_type = "IDE"
                            }
                            device_type = "CDROM"
                        }
                    }
                    @{
                        data_source_reference = @{
                            kind = "image"
                            uuid = $image_uuid
                        }
                        device_properties = @{
                            disk_address = @{
                                device_index = 0
                                adapter_type = "SCSI"
                            }
                            device_type = "DISK"
                        }
                    }
                    ForEach ($drive in $disk) {
                        @{
                            device_properties = @{
                                disk_address = @{
                                    device_index = (++$i)
                                    adapter_type = "SCSI"
                                }
                                device_type = "DISK"
                            }
                            disk_size_mib = $($drive * 1024)
                        }
                    }
                )
                guest_customization = @{
                    sysprep = @{
                      unattend_xml = $base64_string
                    }
                    is_overridable = $false
                  }
            }
            cluster_reference = @{
                kind = "cluster"
                name = $cluster
                uuid = $cluster_uuid
            }
    
        }
        metadata = @{
            kind = "vm"
            spec_version = 3
            categories = @{}
        }
    }
} else {
    $content = @{
        spec = @{
            name = $vm
            description = "Created using REST API on $(Get-Date)"
            resources = @{
                num_threads_per_core = 1
                num_vcpus_per_socket = 1
                num_sockets = $cpu
                memory_size_mib = $($ram * 1024)
                vnuma_config = @{
                    num_vnuma_nodes = 0
                }
                vga_console_enabled = $true
                serial_port_list = @()
                gpu_list = @()
                nic_list = @(ForEach ($subnet in $myvarNetResults) {
                    @{
                        nic_type = "NORMAL_NIC"
                        subnet_reference = @{
                            kind = "subnet"
                            name = $subnet.name
                            uuid = $subnet.uuid
                        }
                        is_connected = $true
                    }
                }
                )
                boot_config = @{
                    boot_device = @{
                        disk_address = @{
                            device_index = 0
                            adapter_type = "SCSI"
                        }
                    }
                }
                disk_list = @(
                    @{
                        device_properties = @{
                            disk_address = @{
                                device_index = 1
                                adapter_type = "IDE"
                            }
                            device_type = "CDROM"
                        }
                    }
                    @{
                        data_source_reference = @{
                            kind = "image"
                            uuid = $image_uuid
                        }
                        device_properties = @{
                            disk_address = @{
                                device_index = 0
                                adapter_type = "SCSI"
                            }
                            device_type = "DISK"
                        }
                    }
                    ForEach ($drive in $disk) {
                        @{
                            device_properties = @{
                                disk_address = @{
                                    device_index = (++$i)
                                    adapter_type = "SCSI"
                                }
                                device_type = "DISK"
                            }
                            disk_size_mib = $($drive * 1024)
                        }
                    }
                )
            }
            cluster_reference = @{
                kind = "cluster"
                name = $cluster
                uuid = $cluster_uuid
            }
    
        }
        metadata = @{
            kind = "vm"
            spec_version = 3
            categories = @{}
        }
    }
}
$payload = (ConvertTo-Json $content -Depth 9)
if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Paylod: $($payload)" -ForegroundColor White}
#endregion

#region make api call
Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green

try {
    #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
    } else {
        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
    }
    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    $task_uuid = $resp.status.execution_context.task_uuid
    Write-Host "$(Get-Date) [INFO] Task $($task_uuid) is in $($resp.status.state) status..." -ForegroundColor Green

    #check on task status
    $api_server_endpoint = "/api/nutanix/v3/tasks/{0}" -f $task_uuid
    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
    $method = "GET"
    try {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
        } else {
            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
        }
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    $displayed_progress=$false
    While ($resp.status -ne "SUCCEEDED")
    {
        if ($resp.status -eq "FAILED") 
        {#task failed
            throw "$(get-date) [ERROR] VM creation task failed. Exiting!"
        }
        else 
        {#task hasn't completed yet
            Write-Host -NoNewLine "`r$(get-date) [PENDING] VM creation task status is $($resp.status) with $($resp.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
            $displayed_progress=$true
            Start-Sleep -Seconds 5
        }
        try {
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
            }
        }
        catch {
            $saved_error = $_.Exception.Message
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            Throw "$(get-date) [ERROR] $saved_error"
        }
    } 
    if ($displayed_progress) {Write-Host}
    Write-Host "$(get-date) [SUCCESS] VM creation task has $($resp.status)!" -ForegroundColor Cyan

}
catch {
    $saved_error = $_.Exception.Message
    # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
    Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
    Throw "$(get-date) [ERROR] $saved_error"
}
finally {
    #add any last words here; this gets processed no matter what
}

#endregion

#endregion

#region Cleanup	
#let's figure out how much time this all took
Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable help -ErrorAction SilentlyContinue
Remove-Variable history -ErrorAction SilentlyContinue
Remove-Variable log -ErrorAction SilentlyContinue
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable cluster -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
