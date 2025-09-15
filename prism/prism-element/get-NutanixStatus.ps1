<#
.SYNOPSIS
  This script can be used to retrieve the overall status of one or more Nutanix cluster(s).
.DESCRIPTION
  The following information is retrieved from each Nutanix cluster: nos version, capacity (total, used, free) of each container (converted from TiB into TB), the storage efficiency factor (as displayed on the Prism home page) and the number of nodes for each model.
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
.PARAMETER email
  If used, this will send an email to the recipients specified in the script (you will need to customize that section by editing the script).
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\get-NutanixStatus.ps1 -cluster ntnxc1.local,ntnxc2.local
Retrieve status for a list of Nutanix clusters.

.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 12th 2022
#>

#region parameters
	Param
	(
		#[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
		[parameter(mandatory = $false)] [switch]$help,
		[parameter(mandatory = $false)] [switch]$history,
		[parameter(mandatory = $false)] [switch]$log,
		[parameter(mandatory = $false)] [switch]$debugme,
		[parameter(mandatory = $false)] [string]$cluster,
		[parameter(mandatory = $false)] [string]$prismCreds,
		[parameter(mandatory = $false)] [switch]$email
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

function Get-PrismCentralObjectList
{#retrieves multiple pages of Prism REST objects v3
    [CmdletBinding()]
    param 
    (
        [Parameter(mandatory = $true)][string] $pc,
        [Parameter(mandatory = $true)][string] $object,
        [Parameter(mandatory = $true)][string] $kind
    )

    begin 
    {
        if (!$length) {$length = 100} #we may not inherit the $length variable; if that is the case, set it to 100 objects per page
        $total, $cumulated, $first, $last, $offset = 0 #those are used to keep track of how many objects we have processed
        [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #this is variable we will use to keep track of entities
        $url = "https://{0}:9440/api/nutanix/v3/{1}/list" -f $pc,$object
        $method = "POST"
        $content = @{
            kind=$kind;
            offset=0;
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4) #this is the initial payload at offset 0
    }
    
    process 
    {
        Do {
            try {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                
                if ($total -eq 0) {$total = $resp.metadata.total_matches} #this is the first time we go thru this loop, so let's assign the total number of objects
                $first = $offset #this is the first object for this iteration
                $last = $offset + ($resp.entities).count #this is the last object for this iteration
                if ($total -le $length)
                {#we have less objects than our specified length
                    $cumulated = $total
                }
                else 
                {#we have more objects than our specified length, so let's increment cumulated
                    $cumulated += ($resp.entities).count
                }
                
                Write-Host "$(Get-Date) [INFO] Processing results from $(if ($first) {$first} else {"0"}) to $($last) out of $($total)" -ForegroundColor Green
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    
                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) {                
                    $myvarResults.Add($entity) | Out-Null
                }
                
                $offset = $last #let's increment our offset
                #prepare the json payload for the next batch of entities/response
                $content = @{
                    kind=$kind;
                    offset=$offset;
                    length=$length
                }
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            catch {
                $saved_error = $_.Exception.Message
                # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
                Throw "$(get-date) [ERROR] $saved_error"
            }
            finally {
                #add any last words here; this gets processed no matter what
            }
        }
        While ($last -lt $total)
    }
    
    end 
    {
        return $myvarResults
    }
}
#endregion

#region prepwork
	#check if we need to display help and/or history
	$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 03/14/2016 sb   Initial release.
 03/22/2016 sb   Added the email parameter.
 04/21/2020 sb	 Do over with sbourdeaud module.
 02/06/2021 sb   Replaced username with get-credential
 04/15/2022 sb	 Fixed divide by zero error. Added functions and removed 
 				 dependency to sbourdeaud module.
 10/12/2022 sb   Added multiple cluster information entries.
                 Added HA information (at Drew Henning's request)
################################################################################
'@
	$myvarScriptName = ".\get-NutanixStatus.ps1"
	
	if ($help) {get-help $myvarScriptName; exit}
	if ($History) {$HistoryText; exit}

	Set-PoSHSSLCerts
	Set-PoshTls
#endregion

#region variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
	$myvarNutanixHosts = @()
    

    ############################################################################
	# customize this section for your environment
	############################################################################
    $myvarEmailFrom = "john.doe@acme.com"
	$myvarSmtpServer = "smtp.acme.com"
    $myvarEmailRecipients = "jane.doe@acme.com"
	
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	if (!$cluster) {$cluster = read-host "Enter the Nutanix cluster(s) name(s) separated by commas"}
	$myvarClusters = $cluster.Split(",") #make sure we parse the argument in case it contains several entries
	
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
	
	[System.Collections.ArrayList]$myvarClusterReport = New-Object System.Collections.ArrayList($null) #used for storing all entries.
	[System.Collections.ArrayList]$myvarContainerReport = New-Object System.Collections.ArrayList($null) #used for storing all entries.
#endregion	

#region main processing

	foreach ($myvarCluster in $myvarClusters)	
	{
		
		$myvarClusterReportEntry = @{}
		
		#! step 1: get cluster information
		#region get cluster
			Write-Host "$(get-date) [INFO] Retrieving cluster information..." -ForegroundColor Green
			$url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
			$method = "GET"
			$myvarClusterInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
			Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information!" -ForegroundColor Cyan
			
            $myvarClusterReportEntry = [ordered]@{
                "name" = $myvarClusterInfo.name;
			    "version" = $myvarClusterInfo.version;
                "ncc_version" = $myvarClusterInfo.ncc_version;
                "is_lts" = $myvarClusterInfo.is_lts;
                "hypervisor_types" = $myvarClusterInfo.hypervisor_types -join ";";
                "num_nodes" = $myvarClusterInfo.num_nodes;
                "encrypted" = $myvarClusterInfo.encrypted;
                "storage_type" = $myvarClusterInfo.storage_type;
                "current_redundancy_factor" = $myvarClusterInfo.cluster_redundancy_state.current_redundancy_factor;
                "fault_tolerance_domain_type" = $myvarClusterInfo.fault_tolerance_domain_type;
                "enable_rebuild_reservation" = $myvarClusterInfo.enable_rebuild_reservation
                "timezone" = $myvarClusterInfo.timezone;
                "is_registered_to_pc" = $myvarClusterInfo.is_registered_to_pc;
                "block_serials" = $myvarClusterInfo.block_serials -join ";";
                "cluster_external_address" = $myvarClusterInfo.cluster_external_address.ipv4 -join ";";
                "cluster_external_data_services_address" = $myvarClusterInfo.cluster_external_data_services_address.ipv4 -join ";";
            }

			foreach ($myvarUnit in $myvarClusterInfo.rackable_units)
			{
				if ($myvarUnit.model_name)
				{
					$myvarClusterReportEntry.($myvarUnit.model_name) += ($myvarUnit.nodes).Count
				}
				else
				{
					$myvarClusterReportEntry.($myvarUnit.model) += ($myvarUnit.nodes).Count               
				}
			}
		#endregion
        
        #! step 2: get ha information
		#region get ha
			Write-Host "$(get-date) [INFO] Retrieving HA information..." -ForegroundColor Green
			$url = "https://$($cluster):9440/api/nutanix/v2.0/ha/"
			$method = "GET"
			$myvarHAInfo = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
			Write-Host "$(get-date) [SUCCESS] Successfully retrieved HA information!" -ForegroundColor Cyan
			
            $myvarClusterReportEntry.ha_failover_enabled = $myvarHAInfo.failover_enabled
            $myvarClusterReportEntry.ha_num_host_failures_to_tolerate = $myvarHAInfo.num_host_failures_to_tolerate
            $myvarClusterReportEntry.ha_reservation_type = $myvarHAInfo.reservation_type
            $myvarClusterReportEntry.ha_state = $myvarHAInfo.ha_state
		#endregion

		#! step 3: get container information
		#region get containers
			Write-Host "$(get-date) [INFO] Retrieving storage containers information..." -ForegroundColor Green
			$url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/storage_containers/"
			$method = "GET"
			$myvarContainers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
			Write-Host "$(get-date) [SUCCESS] Successfully retrieved storage containers information!" -ForegroundColor Cyan

		
			foreach ($myvarContainer in $myvarContainers.entities)
			{
				$myvarStats = $myvarContainer.usage_stats

				$myvarContainerReportEntry = [ordered]@{
					"ClusterName" = $myvarClusterInfo.name
					"ContainerName" = $myvarContainer.name
					"CapacityBytes" = $myvarStats."storage.user_capacity_bytes"
					"UsageBytes" = $myvarStats."storage.user_usage_bytes"
					"FreeBytes" = $myvarStats."storage.user_free_bytes"
					"PreReductionBytes" = $myvarStats."data_reduction.pre_reduction_bytes"
					"PostReductionBytes" = $myvarStats."data_reduction.post_reduction_bytes"
					"Efficiency" = if ($myvarStats."data_reduction.post_reduction_bytes" -gt 0) {$myvarStats."data_reduction.pre_reduction_bytes" / $myvarStats."data_reduction.post_reduction_bytes"} else {0}
				}
			
				$myvarContainerReport.Add((New-Object PSObject -Property $myvarContainerReportEntry)) | Out-Null
			
			}
			$myvarClusterReport.Add((New-Object PSObject -Property $myvarClusterReportEntry)) | Out-Null
		#endregion
		
	}#end foreach cluster
	
	write-host
	write-host "***************************" -ForegroundColor White
	write-host "****** ClusterReport ******" -ForegroundColor White
	write-host "***************************" -ForegroundColor White
	$myvarClusterReport | fl
	write-host "*****************************" -ForegroundColor White
	write-host "****** ContainerReport ******" -ForegroundColor White
	write-host "*****************************" -ForegroundColor White
	$myvarContainerReport | ft -autosize
	Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($myvarClusterInfo.name)_container-report.csv" -ForegroundColor Green
    $myvarContainerReport | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($myvarClusterInfo.name)+"_container-report.csv")

    if ($email)
    {
        #send that email
        Write-LogOutput -category "INFO" -message "Building the email content..."
		$myvarEmailSubject = "Acme Capacity Report " + $myvarReportTimeStamp
        
        $myvarhtml = "Container report is  attached in csv.  Copy and paste its content into the NTNX-CLusters tab in the master spreadsheet. Make sure the efficiency column is correctly formatted as numbers and if appropriate, replace the decimal spearator."
        $myvarEmailBody += "<br /><br />" + $myvarhtml

        Write-LogOutput -category "INFO" -message "Sending the email..."
        Send-MailMessage -SmtpServer $myvarSmtpServer -From $myvarEmailFrom -To $myvarEmailRecipients -Subject $myvarEmailSubject -Body $myvarEmailBody -bodyashtml -Attachments container-report.csv

    }#endif email
#endregion

#region cleanup

	#let's figure out how much time this all took
	Write-LogOutput -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
	Remove-Variable email -ErrorAction SilentlyContinue
	
#endregion