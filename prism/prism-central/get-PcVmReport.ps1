<#
.SYNOPSIS
  Generates a csv file containing a virtual machine inventory for all clusters managed by Prism Central, regardless of the hypervisor.
.DESCRIPTION
  VM inventory for all clusters managed by Prism Central. Generates a single csv file with cluster name, hypervisor, vm name, cpu, ram, vnic and vdisk information.
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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\get-PcVmReport.ps1 -prismcentral myprismcentral.local
Collect VM inventory from prismcentral.local (and get prompted for credentials)
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 10th 2022
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
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion

#region functions
#this function is used to make a REST api call to Prism
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
function Invoke-PrismAPICall
{
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
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
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
                "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($payload) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
            }
        }
        Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
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
end
{
    return $resp
}    
}

#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{
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
{
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
05/26/2020 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
12/02/2021 sb   Added cdrom mount status to vm report.
                Removed dependency on sbourdeaud external module.
                Thx Drew Henning for catching the error in the online help
                example section :)
                Adding cdrom_present and details about iso image mounted.
                Adding network name information vnics are connected to.
06/10/2022 sb   Now retrieving hosts as well so that host name is shown per
                vm. Note that when a vm is powered off, the host is blank.
################################################################################
'@
    $myvarScriptName = ".\get-PcVmReport.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    <# #region module sbourdeaud is used for facilitating Prism REST calls
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
    #endregion #>
    #Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = 9440
    $length = 200
    [System.Collections.ArrayList]$myvarClustersResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarNetworksResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarHostsResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvarVmReport = New-Object System.Collections.ArrayList($null)
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
#endregion

#region processing

    #* step 1: retrieve list of clusters managed by Prism Central
    #region get clusters
        Write-Host "$(get-date) [INFO] Retrieving list of clusters..." -ForegroundColor Green
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/clusters/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $content = @{
                kind="cluster";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion
        #region make api call
            Do {
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    $listLength = 0
                    if ($resp.metadata.offset) {
                        $firstItem = $resp.metadata.offset
                    } else {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                        $listLength = $resp.metadata.length
                    } else {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                    #grab the information we need in each entity
                    ForEach ($entity in $resp.entities) {
                        if ($entity.status.resources.nodes.hypervisor_server_list) {
                            $myvarClusterInfo = [ordered]@{
                                "name" = $entity.status.name;
                                "uuid" = $entity.metadata.uuid;
                                "nos_version" = $entity.status.resources.config.software_map.NOS.version;
                                "redundancy_factor" = $entity.status.resources.config.redundancy_factor;
                                "domain_awareness_level" = $entity.status.resources.config.domain_awareness_level;
                                "is_long_term_support" = $entity.status.resources.config.build.is_long_term_support;
                                "timezone" = $entity.status.resources.config.timezone;
                                "external_ip" = $entity.status.resources.network.external_ip;
                                "hypervisor" = $entity.status.resources.nodes.hypervisor_server_list.type | Select-Object -Unique
                            }
                            #store the results for this entity in our overall result variable
                            $myvarClustersResults.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
                        }
                    }

                    #prepare the json payload for the next batch of entities/response
                    $content = @{
                        kind="cluster";
                        offset=($resp.metadata.length + $resp.metadata.offset);
                        length=$length
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
                $myvarClustersResults
            }
        #endregion
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved clusters list from $prismcentral!" -ForegroundColor Cyan
    #endregion

    #* step 2: retrieve list of networks managed by Prism Central
    #region get networks
        Write-Host "$(get-date) [INFO] Retrieving list of networks..." -ForegroundColor Green
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/subnets/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $content = @{
                kind="subnet";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion
        #region make api call
            Do {
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    $listLength = 0
                    if ($resp.metadata.offset) {
                        $firstItem = $resp.metadata.offset
                    } else {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                        $listLength = $resp.metadata.length
                    } else {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                    #grab the information we need in each entity
                    ForEach ($entity in $resp.entities) {
                        $myvarNetworkInfo = [ordered]@{
                            "name" = $entity.status.name;
                            "uuid" = $entity.metadata.uuid
                        }
                        #store the results for this entity in our overall result variable
                        $myvarNetworksResults.Add((New-Object PSObject -Property $myvarNetworkInfo)) | Out-Null
                    }

                    #prepare the json payload for the next batch of entities/response
                    $content = @{
                        kind="subnet";
                        offset=($resp.metadata.length + $resp.metadata.offset);
                        length=$length
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
                $myvarNetworksResults
            }
        #endregion
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved networks list from $prismcentral!" -ForegroundColor Cyan
    #endregion

    #* step 3: retrieve list of hosts managed by Prism Central
    #region get hosts
        Write-Host "$(get-date) [INFO] Retrieving list of hosts..." -ForegroundColor Green
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/hosts/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $content = @{
                kind="host";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion
        #region make api call
            Do {
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    
                    $listLength = 0
                    if ($resp.metadata.offset) {
                        $firstItem = $resp.metadata.offset
                    } else {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                        $listLength = $resp.metadata.length
                    } else {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

                    #grab the information we need in each entity
                    ForEach ($entity in $resp.entities) {
                        $myvarHostInfo = [ordered]@{
                            "name" = $entity.status.name;
                            "uuid" = $entity.metadata.uuid
                        }
                        #store the results for this entity in our overall result variable
                        $myvarHostsResults.Add((New-Object PSObject -Property $myvarHostInfo)) | Out-Null
                    }

                    #prepare the json payload for the next batch of entities/response
                    $content = @{
                        kind="host";
                        offset=($resp.metadata.length + $resp.metadata.offset);
                        length=$length
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
                $myvarNetworksResults
            }
        #endregion
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts list from $prismcentral!" -ForegroundColor Cyan
    #endregion

    #* step 4: retrieve vms using groups
    #region get vms using groups
        Write-Host "$(get-date) [INFO] Retrieving virtual machines information from Prism Central..." -ForegroundColor Green
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/groups"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            $attributes = "vm_name,uuid,cluster_name,categories,project_name,ip_addresses,owner_username,_created_timestamp_usecs_,ngt.installed_version,ngt.communication_over_serial_port_active,ngt.communication_active,memory_reserved_bytes,memory_overcommit,is_live_migratable,network_security_rule_id_list,zone_type,capacity.policy_anomaly_detail,capacity.vm_constrained_status,capacity.vm_constrained_detail,capacity.policy_efficiency_detail,protection_type,guest_os_name,ngt.guest_os,ngt.enabled_applications,ngt.cluster_version,volume_group,protection_policy_state,recovery_plan_state_list,cbr_not_capable_reason"
            # this is used to capture the content of the payload
            $content = @{
                entity_type="mh_vm";
                query_name="";
                grouping_attribute=" ";
                group_count=3;
                group_offset=0;
                group_attributes=@();
                group_member_count=$length;
                group_member_offset=$page_offset;
                group_member_sort_attribute="vm_name";
                group_member_sort_order="ASCENDING";
                group_member_attributes=@(
                    ForEach ($attribute in ($attributes -Split ","))
                    {
                        @{attribute="$($attribute)"}
                    } 
                );
                filter_criteria="(platform_type!=aws,platform_type==[no_val]);is_cvm==0"
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion
        #region make api call
            try {
                $myvar_mh_vms_groups = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
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
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved virtual machines information from $prismcentral!" -ForegroundColor Cyan
    #endregion get vms using groups

    #* step 5: for each cluster, get the list of hosts and vms
    ForEach ($cluster in $myvarClustersResults) {        
        #region get vms
            $api_server_endpoint = "/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true&include_vm_nic_config=true"
            $method = "GET"
            Write-Host "$(get-date) [INFO] Retrieving list of vms for cluster $($cluster.name)..." -ForegroundColor Green
            $url = "https://{0}:{1}{2}" -f $cluster.external_ip,$api_server_port, $api_server_endpoint
            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of vms for cluster $($cluster.name)!" -ForegroundColor Cyan
            ForEach ($entity in $resp.entities) {
                $vm_networks = @()
                ForEach ($network_uuid in $entity.vm_nics.network_uuid)
                {
                    $vm_networks += ($myvarNetworksResults | Where-Object {$_.uuid -eq $network_uuid}).Name
                }
                if ($debugme) {Write-Host "$(get-date) [DATA] Processing virtual machine $($entity.name)..." -ForegroundColor White}
                $myvarVmInfo = [ordered]@{
                    "cluster" = $cluster.name;
                    "host" = ($myvarHostsResults | Where-Object {$_.uuid -eq $entity.host_uuid}).name;
                    "hypervisor" = $cluster.hypervisor;
                    "name" = $entity.name;
                    "description" = $entity.description;
                    "uuid" = $entity.uuid;
                    "num_vcpus" = $entity.num_vcpus;
                    "num_cores_per_vcpu" = $entity.num_cores_per_vcpu;
                    "memory_mb" = $entity.memory_mb;
                    "power_state" = $entity.power_state;
                    "gpus_assigned" = $entity.gpus_assigned;
                    "uefi_boot" = $entity.boot.uefi_boot;
                    "ip_addresses" = $entity.vm_nics.ip_address -join ',';
                    "mac_addresses" = $entity.vm_nics.mac_address -join ',';
                    "networks" = $vm_networks -join ',';
                    "vdisks" = $entity.vm_disk_info.disk_address.disk_label -join ',';
                    "cdrom_present" = if (($entity.vm_disk_info | Where-Object {$_.is_cdrom -eq $true})) {"true"} else {"false"};
                    "cdrom_iso" = (($entity.vm_disk_info | Where-Object {$_.is_cdrom -eq $true}) | select-object -property source_disk_address).source_disk_address.ndfs_filepath -join ',';
                    "vdisk_total_bytes" = if (($entity.vm_disk_info | where-object {$_.is_cdrom -eq $false}).size) {($entity.vm_disk_info | where-object {$_.is_cdrom -eq $false} | Measure-Object size -Sum).Sum} else {0};
                }
                #store the results for this entity in our overall result variable
                $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
            }
        #endregion
    }

    #*step 6: building the report for al vms
    ForEach ($myvar_vm in $myvarVmResults) {
        $myvar_vm_groups_information = $myvar_mh_vms_groups.group_results[0].entity_results | ?{$_.data.values.values -eq $myvar_vm.name}
        if ($myvar_vm_groups_information -is [array])
        {#we found more than 1 vm with the same name, let's filter down using the mac address
            ForEach ($myvar_vm_uuid in $(($myvar_vm_groups_information | ?{$_.data.name -eq "vm_name"}).entity_id))
            {
                $api_server_endpoint = "/api/nutanix/v3/vms/$($myvar_vm_uuid)"
                $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                $method = "GET"
                $myvar_vm_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                if ($($myvar_vm_details.spec.resources.nic_list.mac_address -join ",") -eq $myvar_vm.mac_addresses)
                {#we found a vm match!
                    $myvar_vm_groups_information = $myvar_vm_groups_information | ?{$_.data.entity_id -eq $myvar_vm_uuid}
                }
            }
        }
        $myvar_creation_timestamp = [int64]($myvar_vm_groups_information.data | ?{$_.name -eq "_created_timestamp_usecs_"}).values.values
        $myvar_creation_date = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds( $myvar_creation_timestamp / 1000000))
        $myvarVmInfo = [ordered]@{
            "cluster" = $myvar_vm.cluster;
            "host" = $myvar_vm.host;
            "hypervisor" = $myvar_vm.hypervisor;
            "name" = $myvar_vm.name;
            "description" = $myvar_vm.description;
            "uuid" = $myvar_vm.uuid;
            "num_vcpus" = $myvar_vm.num_vcpus;
            "num_cores_per_vcpu" = $myvar_vm.num_cores_per_vcpu;
            "memory_mb" = $myvar_vm.memory_mb;
            "power_state" = $myvar_vm.power_state;
            "gpus_assigned" = $myvar_vm.gpus_assigned;
            "uefi_boot" = $myvar_vm.uefi_boot;
            "ip_addresses" = $myvar_vm.ip_addresses;
            "mac_addresses" = $myvar_vm.mac_addresses;
            "networks" = $myvar_vm.networks;
            "vdisks" = $myvar_vm.vdisks;
            "cdrom_present" = $myvar_vm.cdrom_present;
            "cdrom_iso" = $myvar_vm.cdrom_iso;
            "vdisk_total_bytes" = $myvar_vm.vdisk_total_bytes;
            "categories" = ($myvar_vm_groups_information.data | ?{$_.name -eq "categories"}).values.values -join ",";
            "project" = ($myvar_vm_groups_information.data | ?{$_.name -eq "project_name"}).values.values;
            "owner"= ($myvar_vm_groups_information.data | ?{$_.name -eq "owner_username"}).values.values;
            "creation_date"= $myvar_creation_date;
            "ngt_version"= ($myvar_vm_groups_information.data | ?{$_.name -eq "ngt.installed_version"}).values.values;
            "ngt_communication_over_serial"= ($myvar_vm_groups_information.data | ?{$_.name -eq "ngt.communication_over_serial_port_active"}).values.values;
            "protection_type"= ($myvar_vm_groups_information.data | ?{$_.name -eq "protection_type"}).values.values;
            "guest_os_name"= ($myvar_vm_groups_information.data | ?{$_.name -eq "ngt.guest_os"}).values.values
        }
        $myvarVmReport.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
    }
    

    #* step 4: export results
    $report_name = "$(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($prismcentral)_VmList.csv"
    Write-Host "$(Get-Date) [INFO] Writing results to $($report_name)" -ForegroundColor Green
    $myvarVmReport | export-csv -NoTypeInformation $report_name

#endregion

#region cleanup
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