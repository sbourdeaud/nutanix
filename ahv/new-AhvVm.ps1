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
.PARAMETER qty
  Specifies how many virtual machines with same configuration you want to create.  By default, this is equal to 1.
.PARAMETER cust
  Name of the guest OS customization file you want to inject (optional; use cloud-init.yaml for linux and unattend.xml for windows).
.PARAMETER ostype
  Specify either linux or windows (required with -cust)
.EXAMPLE
.\new-AhvVm.ps1 -cluster ntnxc1.local -vm myvmhostname -cpu 2 -ram 8 -image myahvimagelibraryitem -disk 50 -net vlan-99 -cust unattend.xml -ostype windows
Connect to a Nutanix Prism Central VM of your choice and retrieve the list of VMs.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 19th 2021
#>

#todo: modify script to be able to add multiple vms
#todo: from a source csv, or just by specifying qty
#todo: make source image and customization optional

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$prismcentral,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $true)] [string]$vm,
        [parameter(mandatory = $true)] [int]$cpu,
        [parameter(mandatory = $true)] [int]$ram,
        [parameter(mandatory = $false)] [string]$image,
        [parameter(mandatory = $false)] [array]$disk,
        [parameter(mandatory = $true)] [array]$net,
        [parameter(mandatory = $false)] [string]$cust,
        [parameter(mandatory = $false)] [ValidateSet('linux','windows')] [string]$ostype,
        [parameter(mandatory = $false)] [int]$qty
    )
#endregion

#region function
#this function is used to process output to console (timestamped and color coded) and log file
function Write-LogOutput
{#used to format output
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
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG','DATA')]
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
            "DATA" {$FgColor = "Gray"}
        }

        Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
        if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput

#this function loads a powershell module
function LoadModule
{#tries to load a module, import it, install it if necessary
    <#
    .SYNOPSIS
    Tries to load the specified module and installs it if it can't.
    .DESCRIPTION
    Tries to load the specified module and installs it if it can't.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER module
    Name of PowerShell module to import.
    .EXAMPLE
    PS> LoadModule -module PSWriteHTML
    #>
    param 
    (
        [string] $module
    )

    begin
    {
        
    }

    process
    {   
        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Trying to get module $($module)..."
        if (!(Get-Module -Name $module)) 
        {#we could not get the module, let's try to load it
            try
            {#import the module
                Import-Module -Name $module -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
            }#end try
            catch 
            {#we couldn't import the module, so let's install it
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Installing module '$($module)' from the Powershell Gallery..."
                try 
                {#install module
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                }
                catch 
                {#could not install module
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Could not install module '$($module)': $($_.Exception.Message)"
                    exit 1
                }

                try
                {#now that it is intalled, let's import it
                    Import-Module -Name $module -ErrorAction Stop
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
                }#end try
                catch 
                {#we couldn't import the module
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Unable to import the module $($module).psm1 : $($_.Exception.Message)"
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Please download and install from https://www.powershellgallery.com"
                    Exit 1
                }#end catch
            }#end catch
        }
    }

    end
    {

    }
}

function Set-CustomCredentials 
{#creates files to store creds
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
{#retrieves creds from files
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

#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{#disables unsecure Tls protocols
    <#
    .SYNOPSIS
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .DESCRIPTION
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

    .EXAMPLE
    .\Set-PoshTls
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .LINK
    https://github.com/sbourdeaud
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param 
    (
        
    )

    begin 
    {
    }

    process
    {
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = `
        ([Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12)
    }

    end
    {

    }
}

#this function is used to configure posh to ignore invalid ssl certificates
function Set-PoSHSSLCerts
{#configures posh to ignore self-signed certs
    <#
    .SYNOPSIS
    Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
    .DESCRIPTION
    Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
    #>
    
    begin
    {

    }#endbegin
    
    process
    {
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
        }#endif
        [ServerCertificateValidationCallback]::Ignore()
    }#endprocess
    
    end
    {

    }#endend
}#end function Set-PoSHSSLCerts

#this function is used to make a REST api call to Prism
function Invoke-PrismAPICall
{#makes a REST API call to Prism
    <#
    .SYNOPSIS
    Makes api call to prism based on passed parameters. Returns the json response.
    .DESCRIPTION
    Makes api call to prism based on passed parameters. Returns the json response.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER method
    REST method (POST, GET, DELETE, or PUT)
    .PARAMETER credential
    PSCredential object to use for authentication.
    PARAMETER url
    URL to the api endpoint.
    PARAMETER payload
    JSON payload to send.
    .EXAMPLE
    .\Invoke-PrismAPICall -credential $MyCredObject -url https://myprism.local/api/v3/vms/list -method 'POST' -payload $MyPayload
    Makes a POST api call to the specified endpoint with the specified payload.
    #>
    param
    (
        [parameter(mandatory = $true)]
        [ValidateSet("POST","GET","DELETE","PUT")]
        [string] 
        $method,
        
        [parameter(mandatory = $true)]
        [string] 
        $url,

        [parameter(mandatory = $false)]
        [string] 
        $payload,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential
    )

    begin
    {
        
    }
    
    process
    {
        Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
        try {
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
            if ($PSVersionTable.PSVersion.Major -gt 5) 
            {
                $headers = @{
                    "Content-Type"="application/json";
                    "Accept"="application/json"
                }
                if ($payload) 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                } 
                else 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
            } 
            else 
            {
                $username = $credential.UserName
                $password = $credential.Password
                $headers = @{
                    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                    "Content-Type"="application/json";
                    "Accept"="application/json"
                }
                if ($payload) 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                } 
                else 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
            Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
        }
        catch {
            $saved_error = $_.Exception
            $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message_list.message
            $resp_return_code = $_.Exception.Response.StatusCode.value__
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            if ($resp_return_code -eq 409) 
            {
                Write-Host "$(Get-Date) [WARNING] $saved_error_message" -ForegroundColor Yellow
                Throw
            }
            else 
            {
                if ($saved_error_message -match 'rule already exists')
                {
                    Throw "$(get-date) [WARNING] $saved_error_message" 
                }
                else 
                {
                    if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
                    Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"    
                }
            }
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
    }
    
    end
    {
        return $resp
    }    
}

#helper-function Get-RESTError
function Help-RESTError 
{#tries to retrieve full REST messages
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();

    return $global:responsebody

    break
}#end function Get-RESTError
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
07/03/2019 sb   Initial release.
04/06/2020 sb   Do over with sbourdeaud module
02/06/2021 sb   Replaced username with get-credential
10/19/2021 sb   Added the qty parameter and made image optional.
                Removed dependency on external module sbourdeaud.
################################################################################
'@
    $myvarScriptName = ".\new-AhvVm.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    Set-PoSHSSLCerts
    Set-PoshTls
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
    <#
    $headers = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
        "Content-Type"="application/json";
        "Accept"="application/json"
    }
    #>

    #defaults vm quantity to 1
    if (!$qty) {$qty=1}
    $user_specified_qty = $qty
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
        Do 
        {
            try 
            {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                $listLength = 0
                if ($resp.metadata.offset) 
                {
                    $firstItem = $resp.metadata.offset
                } 
                else 
                {
                    $firstItem = 0
                }
                if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) 
                {
                    $listLength = $resp.metadata.length
                } 
                else 
                {
                    $listLength = $resp.metadata.total_matches
                }
                Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) 
                {
                    #grab the uuid of the specified cluster
                    if ($entity.spec.name -eq $cluster) 
                    {
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
            catch 
            {
                $saved_error = $_.Exception.Message
                # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                Throw "$(get-date) [ERROR] $saved_error"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }
        While ($resp.metadata.length -eq $length)

        if (!$cluster_uuid) 
        {
            Write-Host "$(Get-Date) [ERROR] There is no cluster named $($cluster) on Prism Central $($prismcentral)" -ForegroundColor Red
            Exit 1
        } 
        else 
        {
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
        Do 
        {
            try 
            {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                $listLength = 0
                if ($resp.metadata.offset) 
                {
                    $firstItem = $resp.metadata.offset
                } 
                else 
                {
                    $firstItem = 0
                }
                if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) 
                {
                    $listLength = $resp.metadata.length
                } 
                else 
                {
                    $listLength = $resp.metadata.total_matches
                }
                Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) 
                {
                    ForEach ($network in $net) 
                    {
                        if ($entity.status.name -eq $network) 
                        {
                            if ($entity.spec.cluster_reference.name -eq $cluster) 
                            {
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
            catch 
            {
                $saved_error = $_.Exception.Message
                # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                Throw "$(get-date) [ERROR] $saved_error"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }
        While ($resp.metadata.length -eq $length)

        if ($debugme) 
        {
            Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
            $myvarResults
        }

        if (!$myvarNetResults) 
        {
            Write-Host "$(Get-Date) [ERROR] Could not find any valid networks on cluster $($cluster)" -ForegroundColor Red
            Exit 1
        }
    #endregion

#endregion

#*STEP3/4: RETRIEVE IMAGES
#region retrieve images 
    if ($image)
    {#an image was specified
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
            Do 
            {
                try 
                {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    $listLength = 0
                    if ($resp.metadata.offset) 
                    {
                        $firstItem = $resp.metadata.offset
                    } 
                    else 
                    {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) 
                    {
                        $listLength = $resp.metadata.length
                    } 
                    else 
                    {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                    #grab the information we need in each entity
                    ForEach ($entity in $resp.entities) 
                    {
                        if ($entity.spec.name -eq $image) 
                        {
                            if ($entity.spec.resources.image_type -ne "DISK_IMAGE") 
                            {
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
                catch 
                {
                    $saved_error = $_.Exception.Message
                    # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                    Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                    Throw "$(get-date) [ERROR] $saved_error"
                }
                finally 
                {
                    #add any last words here; this gets processed no matter what
                }
            }
            While ($resp.metadata.length -eq $length)

            if ($debugme) 
            {
                Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
                $myvarResults
            }

            if (!$image_uuid) 
            {
                Write-Host "$(Get-Date) [ERROR] Could not find image $($image)" -ForegroundColor Red
                Exit 1
            }
            Write-Host "$(Get-Date) [SUCCESS] Image $($image) has uuid $($image_uuid)" -ForegroundColor Cyan
        #endregion
    }
    else 
    {#no image was specified
        
    }

#endregion

#*STEP4/4: CREATE VM
#region create vm 

    #region check guest customization file
        if ($cust) 
        {
            if (!(Test-Path $cust)) 
            {
                Write-Host "$(get-date) [ERROR] Can't find $($cust)! Please make sure the specified guest customization file exists. Exiting." -ForegroundColor Red
                Exit
            }
            $guest_customization_file = Get-Content -Path $cust -Raw
            $base64_string = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($guest_customization_file))    
        }
    #endregion
    
    Do 
    {#keep creating vms as long as the desired quantity has not been provisioned
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/vms"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $i = 0 #used for device index
            if ($user_specified_qty -gt 1)
            {#there is more than 1 vm to create, so we'll add a number to the vm name
                $vm_name = $vm + "_$($qty)"
            }
            else 
            {#there is only 1 vm to create
                $vm_name = $vm
            }

            if ($cust -and ($ostype -eq "linux")) 
            {
                $content = @{
                    spec = @{
                        name = $vm_name
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
                                if ($image)
                                {#an image was specified, so it will be our first disk}
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
                                    ForEach ($drive in $disk) 
                                    {
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
                                }
                                else 
                                {#no image was specified so we'll start with a blank disk
                                    ForEach ($drive in $disk) 
                                    {
                                        @{
                                            device_properties = @{
                                                disk_address = @{
                                                    device_index = ($i)
                                                    adapter_type = "SCSI"
                                                }
                                                device_type = "DISK"
                                            }
                                            disk_size_mib = $($drive * 1024)
                                        }
                                        ++$i
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
            } 
            elseif ($cust -and ($ostype -eq "windows")) 
            {
                $content = @{
                    spec = @{
                        name = $vm_name
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
                                if ($image)
                                {#an image was specified, so it will be our first disk}
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
                                    ForEach ($drive in $disk) 
                                    {
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
                                }
                                else 
                                {#no image was specified so we'll start with a blank disk
                                    ForEach ($drive in $disk) 
                                    {
                                        @{
                                            device_properties = @{
                                                disk_address = @{
                                                    device_index = ($i)
                                                    adapter_type = "SCSI"
                                                }
                                                device_type = "DISK"
                                            }
                                            disk_size_mib = $($drive * 1024)
                                        }
                                        ++$i
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
                                if ($image)
                                {#an image was specified, so it will be our first disk}
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
                                    ForEach ($drive in $disk) 
                                    {
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
                                }
                                else 
                                {#no image was specified so we'll start with a blank disk
                                    ForEach ($drive in $disk) 
                                    {
                                        @{
                                            device_properties = @{
                                                disk_address = @{
                                                    device_index = ($i)
                                                    adapter_type = "SCSI"
                                                }
                                                device_type = "DISK"
                                            }
                                            disk_size_mib = $($drive * 1024)
                                        }
                                        ++$i
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
                        spec_version = 1
                        categories = @{}
                    }
                }
            }
            $payload = (ConvertTo-Json $content -Depth 9)
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Paylod: $($payload)" -ForegroundColor White}
        #endregion

        #region make api call
            Write-Host "$(Get-Date) [STEP] Creating VM $($vm_name) on cluster $($cluster)" -ForegroundColor Magenta
            Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green

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
                    # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
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
                        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                        Throw "$(get-date) [ERROR] $saved_error"
                    }
                }
                Write-Host "$(get-date) [SUCCESS] VM creation task has $($resp.status)!" -ForegroundColor Cyan

            }
            catch 
            {
                $saved_error = $_.Exception.Message
                # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
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
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
