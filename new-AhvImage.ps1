<#
.SYNOPSIS
  Use this script to create a new AHV disk image in the library based on an existing VM.
.DESCRIPTION
  The script takes a VM and new image name as input. It fetches details of the specified VM, grabs the nfs file path for its first scsi disk, and adds it to the AHV image library with the specified image name.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vm
  Specifies the name of the VM to base the image on. Only its first scsi disk will be used.
.PARAMETER image
  Name of the image when the disk is added to the image library.
.PARAMETER container
  Name of the container where you want the image to reside. If none is specified, the image will be created in the same container as the VM.
.EXAMPLE
.\new-AhvImage.ps1 -cluster ntnxc1.local -username admin -password admin -vm myvm -image _template-windows2016
Create a new image called _template-windows2016 in the image library of AHV cluster ntnxc1.local based on the first scsi disk of VM myvm.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: November 6th 2018
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
        [parameter(mandatory = $false)] [string]$username,
        [parameter(mandatory = $false)] [string]$password,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true,HelpMessage = "Enter the name of the VM to base the image on")] [string]$vm,
        [parameter(mandatory = $true,HelpMessage = "Enter the name you want to give to the new image")] [string]$image,
        [parameter(mandatory = $false)] [string]$container
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
  
    function Get-NTNXTask
    {
    <#
    .SYNOPSIS
    Gets status for a given Prism task uuid (replaces NTNX cmdlet)
    .DESCRIPTION
    Gets status for a given Prism task uuid
    #>
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
            $myvarUrl = "https://"+$cluster+":9440/PrismGateway/services/rest/v2.0/tasks/$($TaskId.task_uuid)"
            $result = Invoke-PrismRESTCall -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -method "GET" -url $myvarUrl
        }
        End
        {
            return $result
        }
    }

    #this function is used to connect to Prism REST API
    function Invoke-PrismRESTCall
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
            [string] 
            $username,
            
            [string] 
            $password,
            
            [string] 
            $url,
            
            [string] 
            [ValidateSet('GET','PATCH','PUT','POST','DELETE')]
            $method,
            
            $body
        )

        begin
        {
            #Setup authentication header for REST call
            $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
        }

        process
        {
            if ($body) 
            {
                $myvarHeader += @{"Accept"="application/json"}
                $myvarHeader += @{"Content-Type"="application/json"}
                
                if ($IsLinux -or $IsMacOS) 
                {
                    try 
                    {
                        if ($PSVersionTable.PSVersion.Major -ge 6) 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                        } 
                        else 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
                        }
                    }
                    catch 
                    {
                        $exception = $_.Exception.Message
                        $message = $_.ErrorDetails.Message
                        Write-LogOutput -category "ERROR" -message "$exception $message"
                        try 
                        {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) 
                            {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        }
                        catch 
                        {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                        }
                        Exit
                    }
                }
                else 
                {
                    try 
                    {
                        if ($PSVersionTable.PSVersion.Major -ge 6) 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                        } 
                        else 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
                        }
                    }
                    catch 
                    {
                        $exception = $_.Exception.Message
                        $message = $_.ErrorDetails.Message
                        Write-LogOutput -category "ERROR" -message "$exception $message"
                        try 
                        {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) 
                            {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        }
                        catch 
                        {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve additional REST error details."
                        }
                        Exit
                    }
                }
            } 
            else 
            {
                if ($IsLinux -or $IsMacOS) 
                {
                    try 
                    {
                        if ($PSVersionTable.PSVersion.Major -ge 6) 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                        } 
                        else 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
                        }
                    }
                    catch 
                    {
                        $exception = $_.Exception.Message
                        $message = $_.ErrorDetails.Message
                        Write-LogOutput -category "ERROR" -message "$exception $message"
                        try 
                        {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) 
                            {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        }
                        catch 
                        {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve additional REST error details."
                        }
                        Exit
                    }
                }
                else 
                {
                    try 
                    {
                        if ($PSVersionTable.PSVersion.Major -ge 6) 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                        } 
                        else 
                        {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
                        }
                    }
                    catch 
                    {
                        $exception = $_.Exception.Message
                        $message = $_.ErrorDetails.Message
                        Write-LogOutput -category "ERROR" -message "$exception $message"
                        try 
                        {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) 
                            {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        }
                        catch 
                        {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve additional REST error details."
                        }
                        Exit
                    }
                }
            }
        }

        end
        {
            return $myvarRESTOutput
        }
    }#end function Get-PrismRESTCall

    #function Get-RESTError
    function Get-RESTError 
    {
        $global:helpme = $body
        $global:helpmoref = $moref
        $global:result = $_.Exception.Response.GetResponseStream()
        $global:reader = New-Object System.IO.StreamReader($global:result)
        $global:responseBody = $global:reader.ReadToEnd();

        return $global:responsebody

        break
    }#end function Get-RESTError

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
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
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
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
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

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/11/2018 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\new-AhvImage.ps1"
 
    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    #region get ready to use the Nutanix REST API
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

#endregion

#region variables

	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

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
            Set-CustomCredentials -credname $prismCreds
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
    }
#endregion

#region processing	
	################################
	##  Main execution here       ##
	################################
    
    #region check cluster is running AHV
        Write-Host "$(get-date) [INFO] Retrieving details of Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $cluster_details = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of Nutanix cluster $cluster" -ForegroundColor Cyan

        Write-Host "$(get-date) [INFO] Hypervisor on Nutanix cluster $cluster is of type $($cluster_details.hypervisor_types)." -ForegroundColor Green

        if ($cluster_details.hypervisor_types -ne "kKvm")
        {#this isn't an AHV cluster
            Throw "$(get-date) [ERROR] $cluster is not an AHV cluster!"
        }
    #endregion

    #region check the VM exists
        Write-Host "$(get-date) [INFO] Retrieving VMs from cluster $cluster..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true"
        $method = "GET"
        $vmList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved VMs from $cluster!" -ForegroundColor Cyan
        
        if (!($vmDetails = $vmList.entities | Where-Object {$_.name -eq $vm}))
        {#couldn't find a matching VM
            Throw "$(get-date) [ERROR] Could not find VM $vm on $cluster!"
        }
    #endregion

    #region find the disk labeled scsi.0
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
    #endregion

    #region get the disk nfs file path
        Write-Host "$(get-date) [INFO] Retrieving details of disk $diskUuid..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/virtual_disks/$diskUuid"
        $method = "GET"
        $diskDetails = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of disk $diskUuid!" -ForegroundColor Cyan

        $diskContainerUUid = $diskDetails.storage_container_uuid
        $diskNfsFilePath = "nfs://127.0.0.1"+$diskDetails.nutanix_nfsfile_path
    #endregion

    #region check the specified container exists
        if ($container)
        {#a container was specified
            Write-Host "$(get-date) [INFO] Retrieving storage containers from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/storage_containers/"
            $method = "GET"
            $storage_containers = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved storage containers from Nutanix cluster $cluster" -ForegroundColor Cyan

            if (!($diskContainerUUid = ($storage_containers.entities | Where-Object {$_.name -eq $container}).storage_container_uuid))
            {#couldn't find a matching container
                Throw "$(get-date) [ERROR] Could not find container $container on $cluster!"
            }
        }
    #endregion

    #region check if the image name already exists
        Write-Host "$(get-date) [INFO] Retrieving images from Nutanix cluster $cluster ..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/images/"
        $method = "GET"
        $images = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved images from Nutanix cluster $cluster" -ForegroundColor Cyan

        if ($image_object = $images.entities | Where-Object {$_.name -eq $image})
        {#found an existing image with the same name
            Write-Host "$(get-date) [WARNING] There is already an image with the name $($image) on cluster $cluster" -ForegroundColor Yellow
            do {$promptUser = Read-Host -Prompt "Do you want to overwrite this image? (y/n)"}
            while ($promptUser -notmatch '[yn]')
            switch ($promptUser)
            {
                "y" {$overwrite = $true}
                "n" {$overwrite = $false}
            }

            if ($overwrite)
            {#user wants to overwrite the image
                Write-Host "$(get-date) [INFO] Requesting deletion of image $($image) with uuid $($image_object.uuid) from Nutanix cluster $cluster ..." -ForegroundColor Green
                $url = "https://"+$cluster+":9440/PrismGateway/services/rest/v2.0/images/$($image_object.uuid)"
                $imageRemove_taskUuid = Invoke-PrismRESTCall -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -method "DELETE" -url $url
                Write-Host "$(get-date) [SUCCESS] Successfully requested deletion of image $($image) with uuid $($image_object.uuid) from Nutanix cluster $cluster" -ForegroundColor Cyan

                Write-Host "$(get-date) [INFO] Checking status of the image $($image) delete task $($imageRemove_taskUuid.task_uuid)..." -ForegroundColor Green
                $task = (Get-NTNXTask -TaskId $imageRemove_taskUuid)
                $displayed_progress=$false
                While ($task.progress_status -ne "Succeeded")
                {#checking image delete task status
                    $task = (Get-NTNXTask -TaskId $imageRemove_taskUuid)
                    if ($task.progress_status -eq "Failed") 
                    {#task failed
                        throw "$(get-date) [ERROR] Image $($image) delete task failed. Exiting!"
                    } 
                    else 
                    {#task hasn't completed yet
                        Write-Host -NoNewLine "`r$(get-date) [WARNING] Image $($image) delete task status is $($task.progress_status) with $($task.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                        $displayed_progress=$true
                        Start-Sleep -Seconds 5
                    }
                }
                if ($displayed_progress) {Write-Host}
                Write-Host "$(get-date) [SUCCESS] Image $($image) delete task has $($task.progress_status)!" -ForegroundColor Cyan
            }
            else 
            {
                Write-Host "$(get-date) [ERROR] Please run this script again with a different image name!" -ForegroundColor Red
                Exit
            }
        }
    #endregion

    #region create the image

        Write-Host "$(get-date) [INFO] Creating image $($image) based on disk $diskNfsFilePath in container $diskContainerUUid..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/images/"
        $method = "POST"
        $content = @{image_type="disk_image";image_import_spec=@{storage_container_uuid=$diskContainerUUid;url=$diskNfsFilePath};name=$image}
        $body = (ConvertTo-Json $content -Depth 4)
        $taskUuid = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
        Write-Host "$(get-date) [SUCCESS] Successfully requested creation of image $($image) based on disk $diskUuid in container $diskContainerUUid!" -ForegroundColor Cyan

        #check on image import task status
        Write-Host "$(get-date) [INFO] Checking status of the image $($image) import task $($taskUuid.task_uuid)..." -ForegroundColor Green
        $task = (Get-NTNXTask -TaskId $taskUuid)
        $displayed_progress=$false
        While ($task.progress_status -ne "Succeeded")
        {
            if ($task.progress_status -eq "Failed") 
            {#task failed
                throw "$(get-date) [ERROR] Image $($image) import task failed. Exiting!"
            }
            else 
            {#task hasn't completed yet
                Write-Host -NoNewLine "`r$(get-date) [WARNING] Image $($image) import task status is $($task.progress_status) with $($task.percentage_complete)% completion, waiting 5 seconds..." -ForegroundColor Yellow
                $displayed_progress=$true
                Start-Sleep -Seconds 5
            }
            $task = (Get-NTNXTask -TaskId $taskUuid)
        } 
        if ($displayed_progress) {Write-Host}
        Write-Host "$(get-date) [SUCCESS] Image $($image) import task has $($task.progress_status)!" -ForegroundColor Cyan

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