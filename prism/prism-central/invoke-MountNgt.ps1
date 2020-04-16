<#
.SYNOPSIS
  This script is used to mount the Nutanix Guest Tools iso on all VMs which are part of a specified protection domain.
.DESCRIPTION
  This script is used to mount the Nutanix Guest Tools iso on all VMs which are part of a specified protection domain.  This can be useful after failing over a protection domain in order to regenerate the NGT certificates.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Fully qualified domain name or IP address of Prism Element.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
.PARAMETER pd
  Name of the protection domain to use as a reference list of virtual machines.
.EXAMPLE
.\invoke-MountNgt.ps1 -prism ntnx1.local -username admin -password nutanix/4u -pd MyProtectionDomain
Mount the NGT iso on all VMs which are in the protection domain called "MyProtectionDomain".
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 24th 2020
#>

#region A - parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$prism,
	[parameter(mandatory = $false)] [string]$pd,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds
)
#endregion

#region B - functions
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
Function Invoke-PrismRESTCall
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
			        Write-Host "$(get-date) [ERROR] $exception $message" -ForegroundColor Red
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) 
                        {
                            Write-Host "$(get-date) [ERROR] $RESTErrorMessage" -ForegroundColor Red
                        }
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not retrieve full REST error details." -ForegroundColor Red
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
			        Write-Host "$(get-date) [ERROR] $exception $message" -ForegroundColor Red
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) 
                        {
                            Write-Host "$(get-date) [ERROR] $RESTErrorMessage" -ForegroundColor Red
                        }
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not retrieve full REST error details." -ForegroundColor Red
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
			        Write-Host "$(get-date) [ERROR] $exception $message" -ForegroundColor Red
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) 
                        {
                            Write-Host "$(get-date) [ERROR] $RESTErrorMessage" -ForegroundColor Red
                        }
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not retrieve full REST error details." -ForegroundColor Red
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
			        Write-Host "$(get-date) [ERROR] $exception $message" -ForegroundColor Red
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) 
                        {
                            Write-Host "$(get-date) [ERROR] $RESTErrorMessage" -ForegroundColor Red
                        }
                    }
                    catch 
                    {
                        Write-Host "$(get-date) [ERROR] Could not retrieve full REST error details." -ForegroundColor Red
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

#Function Get-RESTError
Function Get-RESTError 
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

#region C - prepwork
    #region C1 - misc preparation
        # get rid of annoying error messages
        #if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 02/24/2020 sb   Initial release.
 ###############################################################################
'@
        $myvarScriptName = ".\invoke-MountNgt.ps1"

        if ($help) 
        {
            get-help $myvarScriptName
            exit
        }
        if ($History) {
        $HistoryText
        exit
    }

    
        if ($PSVersionTable.PSVersion.Major -lt 5) 
        {#check PoSH version
            throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
        }
    #endregion

    #check if we have all the required PoSH modules
    Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green

    #region C5 - get ready to use the Nutanix REST API
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

    #region C6 - set some runtime variables
        $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
        $myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
        $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvarOutputLogFile += "OutputLog.log"
    #endregion

#endregion

#region D - parameters validation	
    if (!$prism) 
    {#prompt for the Nutanix cluster name
        $prism = read-host "Enter the hostname or IP address of the Nutanix cluster"
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

#region E - processing

    #region retrieve protection domain   
    Write-Host "$(get-date) [INFO] Retrieving protection domains information from Nutanix cluster $prism ..." -ForegroundColor Green
    $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/protection_domains/"
    $method = "GET"
    try 
    {
        $myvar_protection_domains = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
    }
    catch
    {
        throw "$(get-date) [ERROR] Could not retrieve protection domains information from Nutanix cluster $prism : $($_.Exception.Message)"
    }
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains information from Nutanix cluster $prism" -ForegroundColor Cyan
    $myvar_protection_domain = $myvar_protection_domains.entities | Where-Object {$_.name -eq $pd}
    if (!$myvar_protection_domain) {throw "$(get-date) [ERROR] Could not find protection domain $($pd) on cluster $($prism)"}
    if (!$myvar_protection_domain.vms) {throw "$(get-date) [ERROR] There are no VMs to process in protection domain $($pd) on cluster $($prism)"}

    foreach ($vm in $myvar_protection_domain.vms) {
        #region mount NGT iso  
        Write-Host "$(get-date) [INFO] Mounting NGT on vm $($vm.vm_name) ..." -ForegroundColor Green
        $url = "https://$($prism):9440/PrismGateway/services/rest/v1/vms/$($vm.vm_id)/guest_tools/mount"
        $method = "POST"
        try 
        {
            $result = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        }
        catch
        {
            Write-Host "$(get-date) [WARNING] Could not mount NGT on vm $($vm.vm_name) : $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Write-Host "$(get-date) [SUCCESS] Successfully mounting NGT on vm $($vm.vm_name)" -ForegroundColor Cyan
        #endregion
    }
    #endregion
#endregion

#region F - cleanup
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
