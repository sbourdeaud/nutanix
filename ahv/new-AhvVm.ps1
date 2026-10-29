<#
.SYNOPSIS
  This script uses Prism Central to add a virtual machine to the given AHV cluster.
.DESCRIPTION
  This script takes user input and creates a virtual machine on an AHV cluster using Prism Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER cluster
  Name of the AHV cluster you want to create the VM on.
.PARAMETER vm
  Name of the virtual machine you want to create
.PARAMETER bootype
  Specifies the boot type as either legacy or uefi.
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
.PARAMETER qty
  Specifies how many virtual machines with same configuration you want to create.  By default, this is equal to 1.
.PARAMETER cust
  Name of the guest OS customization file you want to inject (optional; use cloud-init.yaml for linux and unattend.xml for windows).
.PARAMETER ostype
  Specify either linux or windows (required with -cust). Defaults to uefi.
.PARAMETER csv
  Specifies a csv file containing a list of vms to create. It must contain the following columns (fields marked with * must have a value defined): cluster*,vm*,cpu*,ram*,image,disk,net*,cust,ostype,storage_containers,mount_iso
  Note that you must specify a value for disk (which can be itself a comma separated list) if you do not specify an image, and that you must specify an ostype if you specify cust.  You can specify where each disk will be created with storage_containers, and if you wish to mount an iso image in the cdrom drive, you can specifiy the iso image name with mount_iso.
.EXAMPLE
.\new-AhvVm.ps1 -prismcentral mypc.local -cluster ntnxc1.local -vm myvmhostname -cpu 2 -ram 8 -image myahvimagelibraryitem -disk 50 -net vlan-99 -cust unattend.xml -ostype windows
Connect to a Nutanix Prism Central VM of your choice and create the specified VM.
.\new-AhvVm.ps1 -prismcentral mypc.local -csv my_list_of_vms.csv
Connect to a Nutanix Prism Central VM of your choice and create all the VMs defined in the specified csv file.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#todo: add ability to specify image to mount on cdrom
#todo: add check on specified image type (if of type iso, error out)


#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$prismcentral,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [string]$cluster,
        [parameter(mandatory = $false)] [string]$vm,
        [parameter(mandatory = $false)] [int]$cpu,
        [parameter(mandatory = $false)] [int]$ram,
        [parameter(mandatory = $false)] [string]$image,
        [parameter(mandatory = $false)] [array]$disk,
        [parameter(mandatory = $false)] [array]$net,
        [parameter(mandatory = $false)] [string]$cust,
        [parameter(mandatory = $false)] [ValidateSet('linux','windows')] [string]$ostype,
        [parameter(mandatory = $false)] [ValidateSet('legacy','uefi')] [string]$bootype,
        [parameter(mandatory = $false)] [int]$qty,
        [parameter(mandatory = $false)] [string]$csv
    )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
10/14/2024 sb   Added csv with storage_containers and mount_iso.
02/06/2021 sb   Replaced username with get-credential
04/06/2020 sb   Do over with sbourdeaud module
07/03/2019 sb   Initial release.
################################################################################
'
    $myvarScriptName = ".\new-AhvVm.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

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


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
    $length = 500
    $api_server_port = "9440"
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

    if ($cust -and (!$ostype)) {
        Write-Host "$(Get-Date) [ERROR] You must specify an ostype (linux or windows) when using -cust" -ForegroundColor Red
        Exit 1
    }

    if (!$csv)
    {#no csv file was specified, so let's make sure we have what we need before we proceed
        if (!$image -and !$disk) {Throw "$(Get-Date) [ERROR] You must specify either an image name (with -image) with a disk size or a disk size (with -disk)!"}
        if (!$disk) {Throw "$(Get-Date) [ERROR] You must specify a disk size (with -disk)!"}
        if (!$cluster) {$cluster = read-host "Enter the Prism Element cluster name as it appears in Prism Element where you want to create the vm(s)"}
        if (!$vm) {$vm = read-host "Enter the name of the virtual machine you want to create"}
        if (!$cpu) {$cpu = read-host "Enter the number of desired CPU sockets for the vm"}
        if (!$ram) {$ram = read-host "Enter the RAM in GB for the vm"}
        if (!$net) {$net = read-host "Enter the name of the AHV network you want to connect the vm to"}
        #cluster,vm,cpu,ram,image,disk,net,cust,ostype
        $myvar_vm_list = @(@{
            "cluster"=$cluster;
            "vm"=$vm;
            "cpu"=$cpu;
            "ram"=$ram;
            "image"=$image;
            "disk"=$disk;
            "net"=$net;
            "cust"=$cust;
            "ostype"=$ostype
        })
    }
    else 
    {#a csv file was specified
        #make sure the csv file specified exists
        if (Test-Path -Path $csv) 
        {#file exists
          $myvar_vm_list = Import-Csv -Path $csv #import the csv file data
        }
        else 
        {#file does not exist
          throw "The specified csv file $($csv) does not exist!"
        }
    }

    #defaults vm quantity to 1
    if (!$qty) {$qty=1}
    if (!$bootype) {$bootype = "uefi"}
    $user_specified_qty = $qty
#endregion


#*STEP1/5: RETRIEVE CLUSTERS
#region retrieve clusters 

    Write-Host "$(Get-Date) [INFO] Retrieving list of clusters from Prism Central $($prismcentral)..." -ForegroundColor Green
    $myvar_cluster_list = @()
    $url = "https://{0}:{1}/api/nutanix/v3/clusters/list" -f $prismcentral,$api_server_port
    $method = "POST"
    $content = @{
        kind="cluster";
        offset=0;
        length=$length;
        sort_order="ASCENDING";
        sort_attribute="name"
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    Do {
        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
        if ($resp.entities) {
            $myvar_cluster_list += $resp.entities
        }
        $content.offset = $content.offset + $content.length
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    While ($resp.metadata.length -eq $length)
    
    Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved $($myvar_cluster_list.count) clusters from Prism Central $($prismcentral)" -ForegroundColor Cyan

#endregion


#*STEP2/5: RETRIEVE NETWORKS/SUBNETS
#region retrieve networks/subnets

    Write-Host "$(Get-Date) [INFO] Retrieving list of subnets from Prism Central $($prismcentral)..." -ForegroundColor Green
    $myvar_network_list = @()
    $url = "https://{0}:{1}/api/nutanix/v3/subnets/list" -f $prismcentral,$api_server_port
    $method = "POST"
    $content = @{
        kind="subnet";
        offset=0;
        length=$length;
        sort_order="ASCENDING";
        sort_attribute="name"
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    Do {
        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
        if ($resp.entities) {
            $myvar_network_list += $resp.entities
        }
        $content.offset = $content.offset + $content.length
        $payload = (ConvertTo-Json $content -Depth 4)
    }
    While ($resp.metadata.length -eq $length)
    
    Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved $($myvar_network_list.count) subnets from Prism Central $($prismcentral)" -ForegroundColor Cyan

#endregion


#*STEP3/5: RETRIEVE IMAGES
#region retrieve images 
    if ($image -or $csv)
    {#an image was specified
        Write-Host "$(Get-Date) [INFO] Retrieving list of images from Prism Central $($prismcentral)..." -ForegroundColor Green
        $myvar_image_list = @()
        $url = "https://{0}:{1}/api/nutanix/v3/images/list" -f $prismcentral,$api_server_port
        $method = "POST"
        $content = @{
            kind="image";
            offset=0;
            length=$length;
            sort_order="ASCENDING";
            sort_attribute="name"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        Do {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            if ($resp.entities) {
                $myvar_image_list += $resp.entities
            }
            $content.offset = $content.offset + $content.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        While ($resp.metadata.length -eq $length)
        
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved $($myvar_image_list.count) images from Prism Central $($prismcentral)" -ForegroundColor Cyan
    }

#endregion


#*STEP4/5: RETRIEVE STORAGE CONTAINERS
#region retrieve storage containers 
    if ($csv)
    {#specifying containers is only possible by passing the container names in a csv, so if we don't have a csv file, no need to retrieve the storage containers list
        Write-Host "$(Get-Date) [INFO] Retrieving list of storage containers from Prism Central $($prismcentral)..." -ForegroundColor Green
        $api_server_endpoint = "/api/nutanix/v3/groups"
        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
        $method = "POST"
        $content = @{
            entity_type = "storage_container"
            group_member_attributes = @(
                @{attribute = "container_name"}
                @{attribute = "cluster_name"}
                @{attribute = "cluster"}
            )
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
        
        [System.Collections.ArrayList]$myvar_container_list = New-Object System.Collections.ArrayList($null)
        
        Foreach ($container in $resp.group_results.entity_results)
        {#process each retrieved container and build an array of objects that is easily addressable for future use
            $myvar_container_info = [ordered]@{
                "container_name" = ($container.data | Where-Object {$_.name -eq "container_name"}).values.values;
                "container_uuid" = $container.entity_id;
                "cluster_name" = ($container.data | Where-Object {$_.name -eq "cluster_name"}).values.values;
                "cluster_uuid" = ($container.data | Where-Object {$_.name -eq "cluster"}).values.values;
            }
            $myvar_container_list.Add((New-Object PSObject -Property $myvar_container_info)) | Out-Null
        }
        
        Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved list of $($myvar_container_list.count) storage containers from Prism Central $($prismcentral)" -ForegroundColor Cyan
    }
#endregion


#*STEP5/5: CREATE VM
#region create vm 

    Foreach ($myvar_vm_spec in $myvar_vm_list)
    {#process each vm
        #region check guest customization file
            if ($myvar_vm_spec.cust) 
            {
                if (!(Test-Path $myvar_vm_spec.cust)) 
                {
                    Write-Host "$(get-date) [ERROR] Can't find $($myvar_vm_spec.cust)! Please make sure the specified guest customization file exists. Exiting." -ForegroundColor Red
                    Exit
                }
                $guest_customization_file = Get-Content -Path $myvar_vm_spec.cust -Raw
                $base64_string = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($guest_customization_file))    
            }
        #endregion
        
        #* assign cluster uuid
        if ($myvar_vm_spec.cluster)
        {#figure out the cluster uuid
            $cluster_uuid = ($myvar_cluster_list | Where-Object {$_.spec.name -eq $myvar_vm_spec.cluster}).metadata.uuid
            if (!$cluster_uuid) 
            {
                Throw "$(Get-Date) [ERROR] There is no cluster named $($myvar_vm_spec.cluster) on Prism Central $($prismcentral)"
            }
            Write-Host "$(Get-Date) [SUCCESS] Cluster $($myvar_vm_spec.cluster) has uuid $($cluster_uuid)" -ForegroundColor Cyan
        }
        else 
        {#no specified cluster
            throw "$(Get-Date) [ERROR] There is no specified cluster for vm $($myvar_vm_spec.vm)"
        }
        
        #* assign network uuid
        if ($myvar_vm_spec.net)
        {#figure out the network(s) uuid(s)
            [System.Collections.ArrayList]$myvarNetResults = New-Object System.Collections.ArrayList($null)
            ForEach ($entity in $myvar_network_list) 
            {#process each network retrieved from Prism Central
                ForEach ($network in ($myvar_vm_spec.net -Split ",")) 
                {#process each network required by our vm
                    if ($entity.status.name -eq $network) 
                    {#we found a network on PC that matches a network required by our vm 
                        if ($entity.spec.cluster_reference.name -eq $myvar_vm_spec.cluster) 
                        {#making sure the network on PC exists on the cluster our VM will be created on
                            $myvarNetInfo = [ordered]@{
                                "name" = $entity.status.name;
                                "uuid" = $entity.metadata.uuid
                            }
                            $myvarNetResults.Add((New-Object PSObject -Property $myvarNetInfo)) | Out-Null
                            Write-Host "$(Get-Date) [DATA] Network $($network) on cluster $($myvar_vm_spec.cluster) has uuid $($entity.metadata.uuid)" -ForegroundColor White
                        }
                    }
                }
            }
            
            if (!$myvarNetResults) 
            {#we couldn't find the specified networks
                Throw "$(Get-Date) [ERROR] Could not find any valid networks on cluster $($myvar_vm_spec.cluster)"
            }
        }
        else 
        {#no specified network
            throw "$(Get-Date) [ERROR] There is no specified network for vm $($myvar_vm_spec.vm)"
        }
        
        #* assign image uuid
        if ($myvar_vm_spec.image)
        {#a disk image was specified
            $image_uuid = ($myvar_image_list | Where-Object {$_.spec.name -eq $myvar_vm_spec.image}).metadata.uuid
            if (!$image_uuid) 
            {#we couldn't find the specified disk image
                Throw "$(Get-Date) [ERROR] There is no image named $($myvar_vm_spec.image) on Prism Central $($prismcentral)"
            }
            Write-Host "$(Get-Date) [DATA] Image $($myvar_vm_spec.image) has uuid $($image_uuid)" -ForegroundColor White
        }
        elseif (!$myvar_vm_spec.disk)
        {#no specified image or disk configuration
            throw "$(Get-Date) [ERROR] There is no specified image or disk configuration for vm $($myvar_vm_spec.vm)"
        }

        #* assign iso image uuid
        if ($myvar_vm_spec.mount_iso)
        {#we want to mount an iso image
            $iso_image_uuid = ($myvar_image_list | Where-Object {$_.spec.name -eq $myvar_vm_spec.mount_iso}).metadata.uuid
            if (!$iso_image_uuid) 
            {#we couldn't find the specified iso image
                Throw "$(Get-Date) [ERROR] There is no iso image named $($myvar_vm_spec.mount_iso) on Prism Central $($prismcentral)"
            }
            Write-Host "$(Get-Date) [DATA] ISO image $($myvar_vm_spec.mount_iso) has uuid $($iso_image_uuid)" -ForegroundColor White
        }
        else 
        {#no iso image was specified
            $iso_image_uuid = $null
        }

        Do 
        {#keep creating vms as long as the desired quantity has not been provisioned
            #region prepare api call
                $api_server_endpoint = "/api/nutanix/v3/vms"
                $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                $method = "POST"

                #* this is used to capture the content of the payload
                
                #? determining the correct CDROM configuration
                if ($iso_image_uuid)
                {#we need to include an iso image to mount on the cdrom
                    $myvar_cdrom_device = @{
                        data_source_reference = @{
                            kind = "image"
                            uuid = $iso_image_uuid
                        }
                        device_properties = @{
                            disk_address = @{
                                device_index = 1
                                adapter_type = "IDE"
                            }
                            device_type = "CDROM"
                        }
                    }
                }
                else 
                {#cdrom device does not include mounted iso image
                    $myvar_cdrom_device = @{
                        device_properties = @{
                            disk_address = @{
                                device_index = 1
                                adapter_type = "IDE"
                            }
                            device_type = "CDROM"
                        }
                    }
                }

                #? determining the correct disk device list
                $i = 0 #used for device index
                [System.Collections.ArrayList]$disk_device_list = New-Object System.Collections.ArrayList($null)
                #create here the content for disk device list ($disk_device_list)
                if ($myvar_vm_spec.image)
                {#an image was specified, so it will be our first disk
                    $disk_device = @{
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
                        disk_size_mib = ([int]($disk -Split ",")[0] * 1024)
                    }
                    $disk_device_list.Add((New-Object PSObject -Property $disk_device)) | Out-Null
                    
                    ForEach ($drive in ($myvar_vm_spec.disk -Split ",")) 
                    {
                        if ($image -and ($disk.Length -gt 1))
                        {#we have speficied multiple disks besides the image
                            if ($myvar_vm_spec.storage_containers)
                            {#we have specified storage containers
                                if (($myvar_vm_spec.storage_containers -Split ",").count -ne ($myvar_vm_spec.disk -Split ",").count)
                                {#the numbers of disks and specified storage containers don't match
                                    Throw "$(get-date) [ERROR] The number of disks ($(($myvar_vm_spec.disk -Split ",").count)) and specified storage containers ($(($myvar_vm_spec.storage_containers -Split ",").count)) do not match for VM $($myvar_vm_spec.vm). Please make sure that you specifiy a storage container for each disk, or none at all."
                                }
                                else 
                                {#specify the storage container name and uuid in the storage config for each disk
                                    #find the storage container uuid
                                    $storage_container_uuid = ($myvar_container_list | Where-Object {$_.container_name -eq (($myvar_vm_spec.storage_containers -Split ",")[$i])}).container_uuid
                                    if ($storage_container_uuid)
                                    {#we found the storage container uuid
                                        $disk_device = @{
                                            storage_config = @{
                                                storage_container_reference = @{
                                                uuid = $storage_container_uuid
                                                kind = "storage_container"
                                                }
                                            }
                                            device_properties = @{
                                                disk_address = @{
                                                    device_index = (++$i)
                                                    adapter_type = "SCSI"
                                                }
                                                device_type = "DISK"
                                            }
                                            disk_size_mib = $([int]$drive * 1024)
                                        }
                                        $disk_device_list.Add((New-Object PSObject -Property $disk_device)) | Out-Null
                                    }
                                    else 
                                    {#we couldn't find the storage container uuid
                                        Throw "$(get-date) [ERROR] Could not find the container $(($myvar_vm_spec.storage_containers -Split ",")[$i]) for VM $($myvar_vm_spec.vm). Please make sure that you specifiy a valid storage container, or none at all."
                                    }
                                }
                            }
                            else 
                            {#we don't have a storage container specified (disks will be provisioned in default container on the cluster)
                                $disk_device = @{
                                    device_properties = @{
                                        disk_address = @{
                                            device_index = (++$i)
                                            adapter_type = "SCSI"
                                        }
                                        device_type = "DISK"
                                    }
                                    disk_size_mib = $([int]$drive * 1024)
                                }
                                $disk_device_list.Add((New-Object PSObject -Property $disk_device)) | Out-Null
                            }
                        }
                    }
                }
                else 
                {#no image was specified so we'll start with a blank disk
                    ForEach ($drive in ($myvar_vm_spec.disk -Split ",")) 
                    {
                        if ($myvar_vm_spec.storage_containers)
                        {#we have specified storage containers
                            if (($myvar_vm_spec.storage_containers -Split ",").count -ne ($myvar_vm_spec.disk -Split ",").count)
                            {#the numbers of disks and specified storage containers don't match
                                Throw "$(get-date) [ERROR] The number of disks ($(($myvar_vm_spec.disk -Split ",").count)) and specified storage containers ($(($myvar_vm_spec.storage_containers -Split ",").count)) do not match for VM $($myvar_vm_spec.vm). Please make sure that you specifiy a storage container for each disk, or none at all."
                            }
                            else 
                            {#specify the storage container name and uuid in the storage config for each disk
                                #find the storage container uuid
                                $storage_container_uuid = ($myvar_container_list | Where-Object {$_.container_name -eq (($myvar_vm_spec.storage_containers -Split ",")[$i])}).container_uuid
                                if ($storage_container_uuid)
                                {#we found the storage container uuid
                                    $disk_device = @{
                                        storage_config = @{
                                            storage_container_reference = @{
                                              uuid = $storage_container_uuid
                                              kind = "storage_container"
                                            }
                                        }
                                        device_properties = @{
                                            disk_address = @{
                                                device_index = ($i)
                                                adapter_type = "SCSI"
                                            }
                                            device_type = "DISK"
                                        }
                                        disk_size_mib = $([int]$drive * 1024)
                                    }
                                    $disk_device_list.Add((New-Object PSObject -Property $disk_device)) | Out-Null
                                }
                                else 
                                {#we couldn't find the storage container uuid
                                    Throw "$(get-date) [ERROR] Could not find the container $(($myvar_vm_spec.storage_containers -Split ",")[$i]) for VM $($myvar_vm_spec.vm). Please make sure that you specifiy a valid storage container, or none at all."
                                }
                            }
                        }
                        else 
                        {#we don't have a storage container specified (disks will be provisioned in default container on the cluster)
                            $disk_device = @{
                                device_properties = @{
                                    disk_address = @{
                                        device_index = ($i)
                                        adapter_type = "SCSI"
                                    }
                                    device_type = "DISK"
                                }
                                disk_size_mib = $([int]$drive * 1024)
                            }
                            $disk_device_list.Add((New-Object PSObject -Property $disk_device)) | Out-Null
                        }
                        
                        ++$i
                    }
                }

                #? appending numerical index to vm name if there is more than 1
                if ($user_specified_qty -gt 1)
                {#there is more than 1 vm to create, so we'll add a number to the vm name
                    $vm_name = $myvar_vm_spec.vm + "_$($qty)"
                }
                else 
                {#there is only 1 vm to create
                    $vm_name = $myvar_vm_spec.vm
                }

                #? create the payload which varies between specified guest OS with customization (linux, windows or none)
                if ($myvar_vm_spec.cust -and ($myvar_vm_spec.ostype -eq "linux")) 
                {
                    $content = @{
                        spec = @{
                            name = $vm_name
                            description = "Created using REST API on $(Get-Date)"
                            resources = @{
                                num_threads_per_core = 1
                                num_vcpus_per_socket = 1
                                num_sockets = [int]$myvar_vm_spec.cpu
                                memory_size_mib = $([int]$myvar_vm_spec.ram * 1024)
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
                                    boot_type = $bootype.ToUpper()
                                }
                                disk_list = @(
                                    $myvar_cdrom_device
                                    $disk_device_list
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
                                name = $myvar_vm_spec.cluster
                                uuid = $cluster_uuid
                            }
                    
                        }
                        metadata = @{
                            kind = "vm"
                            spec_version = 1
                            categories = @{}
                        }
                    }
                } 
                elseif ($myvar_vm_spec.cust -and ($myvar_vm_spec.ostype -eq "windows")) 
                {
                    $content = @{
                        spec = @{
                            name = $vm_name
                            description = "Created using REST API on $(Get-Date)"
                            resources = @{
                                num_threads_per_core = 1
                                num_vcpus_per_socket = 1
                                num_sockets = [int]$myvar_vm_spec.cpu
                                memory_size_mib = $([int]$myvar_vm_spec.ram * 1024)
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
                                    boot_type = $bootype.ToUpper()
                                }
                                disk_list = @(
                                    $myvar_cdrom_device
                                    $disk_device_list
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
                                name = $myvar_vm_spec.cluster
                                uuid = $cluster_uuid
                            }
                    
                        }
                        metadata = @{
                            kind = "vm"
                            spec_version = 1
                            categories = @{}
                        }
                    }
                }
                else 
                {
                    $content = @{
                        spec = @{
                            name = $vm_name
                            description = "Created using REST API on $(Get-Date)"
                            resources = @{
                                num_threads_per_core = 1
                                num_vcpus_per_socket = 1
                                num_sockets = [int]$myvar_vm_spec.cpu
                                memory_size_mib = $([int]$myvar_vm_spec.ram * 1024)
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
                                    $myvar_cdrom_device
                                    $disk_device_list
                                )
                            }
                            cluster_reference = @{
                                kind = "cluster"
                                name = $myvar_vm_spec.cluster
                                uuid = $cluster_uuid
                            }
                    
                        }
                        metadata = @{
                            kind = "vm"
                            spec_version = 1
                            categories = @{}
                        }
                    }
                }
                $payload = (ConvertTo-Json $content -Depth 9)
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Payload: $($payload)" -ForegroundColor White}
            #endregion

            #region make api call
                Write-Host "$(Get-Date) [STEP] Creating VM $($vm_name) on cluster $($myvar_vm_spec.cluster)" -ForegroundColor Magenta

                try 
                {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
                    $task_uuid = $resp.status.execution_context.task_uuid
                    Write-Host "$(Get-Date) [INFO] Task $($task_uuid) is in $($resp.status.state) status..." -ForegroundColor Green

                    #check on task status
                    $api_server_endpoint = "/api/nutanix/v3/tasks/{0}" -f $task_uuid
                    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                    $method = "GET"
                    try 
                    {
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    }
                    catch 
                    {
                        $saved_error = $_.Exception.Message
                        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                        Throw "$(get-date) [ERROR] $saved_error"
                    }
                    While ($resp.status -ne "SUCCEEDED")
                    {
                        if ($resp.status -eq "FAILED") 
                        {#task failed
                            throw "$(get-date) [ERROR] VM creation task failed. Exiting!"
                        }
                        else 
                        {#task hasn't completed yet
                            Write-Host "$(get-date) [PENDING] VM creation task status is $($resp.status) with $($resp.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                            Start-Sleep -Seconds 5
                        }
                        try 
                        {
                            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                        }
                        catch 
                        {
                            $saved_error = $_.Exception.Message
                            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                            Throw "$(get-date) [ERROR] $saved_error"
                        }
                    }
                    Write-Host "$(get-date) [SUCCESS] VM creation task has $($resp.status)!" -ForegroundColor Cyan

                }
                catch 
                {
                    $saved_error = $_.Exception.Message
                    Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                    Throw "$(get-date) [ERROR] $saved_error"
                }
                finally 
                {
                    #add any last words here; this gets processed no matter what
                }

            #endregion

            $qty = $qty - 1
        } While ($qty -ge 1)
    }

#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable vm -ErrorAction SilentlyContinue
    Remove-Variable bootype -ErrorAction SilentlyContinue
    Remove-Variable cpu -ErrorAction SilentlyContinue
    Remove-Variable ram -ErrorAction SilentlyContinue
    Remove-Variable image -ErrorAction SilentlyContinue
    Remove-Variable disk -ErrorAction SilentlyContinue
    Remove-Variable net -ErrorAction SilentlyContinue
    Remove-Variable qty -ErrorAction SilentlyContinue
    Remove-Variable cust -ErrorAction SilentlyContinue
    Remove-Variable ostype -ErrorAction SilentlyContinue
    Remove-Variable csv -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
#endregion