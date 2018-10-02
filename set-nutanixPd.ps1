<#
.SYNOPSIS
  This script is used to edit and control Nutanix protection domains.
.DESCRIPTION
  In its current state, this script lets you remove all orphaned VMs from a given protection domain.
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
.PARAMETER pd
  Name of the protection domain you want to edit/control.
.PARAMETER clean
  Removes orphaned VM entries from the protection domain specified by -pd. An orphaned VM entry means that the virtual machine object no longer exists in the Nutanix cluster, but it is still defined as a protected entiry in the protection domain. After removing an orphaned entry, you will still be able to restore the VM from non expired snapshots that contain it.

.EXAMPLE
.\set-nutanixPd.ps1 -cluster ntnxc1.local -username admin -password admin -pd protect1 -clean
Removes all orphaned VM entries from the protection domain "protect1" on Nutanix cluster ntnxc1.local

.LINK
  http://www.nutanix.com/services
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: Oct 3rd 2017
#>

#region parameters
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
    [parameter(mandatory = $true)] [string]$cluster,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $pd,
    [parameter(mandatory = $false)] [switch]$clean
)
#endregion

#region functions
########################
##   main functions   ##
########################
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
PS> Write-LogOutput -category "ERROR" -message "You must be kidding!"

Displays an error message.

.LINK
https://github.com/sbourdeaud
#>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		[Parameter(Mandatory)]
        [ValidateSet('INFO','WARNING','ERROR','SUM')]
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
	    }

	    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
	    if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput

#this function is used to connect to Prism REST API
function Get-PrismRESTCall
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
        if ($body) {
            $myvarHeader += @{"Accept"="application/json"}
		    $myvarHeader += @{"Content-Type"="application/json"}
            
            if ($IsLinux) {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }else {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }
        } else {
            if ($IsLinux) {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }else {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
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
function Get-RESTError {
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
# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 12/07/2017 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\set-nutanixPd.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}


#process requirements (PoSH version and modules)
    Write-Host "$(get-date) [INFO] Checking the Powershell version..." -ForegroundColor Green
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "$(get-date) [WARNING] Powershell version is less than 5. Trying to upgrade from the web..." -ForegroundColor Yellow
        if (!$IsLinux) {
            $ChocoVersion = choco
            if (!$ChocoVersion) {
                Write-Host "$(get-date) [WARNING] Chocolatey is not installed!" -ForegroundColor Yellow
                [ValidateSet('y','n')]$ChocoInstall = Read-Host "Do you want to install the chocolatey package manager? (y/n)"
                if ($ChocoInstall -eq "y") {
                    Write-Host "$(get-date) [INFO] Downloading and running chocolatey installation script from chocolatey.org..." -ForegroundColor Green
                    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    Write-Host "$(get-date) [INFO] Downloading and installing the latest Powershell version from chocolatey.org..." -ForegroundColor Green
                    choco install -y powershell
                } else {
                    Write-Host "$(get-date) [ERROR] Please upgrade to Powershell v5 or above manually (https://www.microsoft.com/en-us/download/details.aspx?id=54616)" -ForegroundColor Red
                    Exit
                }#endif choco install
            }#endif not choco
        } else {
            Write-Host "$(get-date) [ERROR] Please upgrade to Powershell v5 or above manually by running sudo apt-get upgrade powershell" -ForegroundColor Red
            Exit
        } #endif not Linux
    }#endif PoSH version

    #let's get ready to use the Nutanix REST API
    #Accept self signed certs
if (!$IsLinux) {
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
}#endif not Linux

#endregion

#region variables
#initialize variables
	#misc variables
	$ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp


    #let's deal with the password
    if (!$password) #if it was not passed as an argument, let's prompt for it
    {
        $PrismSecurePassword = Read-Host "Enter the Prism admin user password" -AsSecureString
    }
    else #if it was passed as an argument, let's convert the string to a secure string and flush the memory
    {
        $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
        Remove-Variable password
    }
    if (!$username) {
        $username = "admin"
    }#endif not username
#endregion

#region parameters validation
	############################################################################
	# command line arguments initialization
	############################################################################	
    
    

    
#endregion

#region processing	
	################################
	##  Main execution here       ##
	################################
   
    #region GET
    if (!$pd)
    {
        Write-Host "$(get-date) [INFO] Retrieving list of protection domains on cluster $cluster..." -ForegroundColor Green
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
        $method = "GET"
        $pdList = Get-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved the protection domains on cluster $cluster!" -ForegroundColor Cyan

        $pd = $pdList.entities.name
    }
    
    Write-Host "$(get-date) [INFO] Retrieving the list of VMs on cluster $cluster..." -ForegroundColor Green
    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
    $method = "GET"
    $vmList = Get-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved the list of VMs on cluster $cluster!" -ForegroundColor Cyan
    #endregion

    #region CLEAN
    if ($clean) {
        ForEach ($pdEntry in $pd )
        {
            Write-Host "$(get-date) [INFO] Retrieving the configuration of protection domain $pdEntry on cluster $cluster..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/?names=$($pdEntry)"
            $method = "GET"
            $pdConfig = Get-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved the configuration of protection domain $pdEntry on cluster $cluster!" -ForegroundColor Cyan

            Write-Host "$(get-date) [INFO] Looking for orphaned entries in protection domain $pdEntry..." -ForegroundColor Green
            $orphanedVms = ($pdConfig.entities.vms).vm_name | Where {($vmList.entities).name -notcontains $_}
            $orphanedList = @()
            ForEach ($orphanedVm in $orphanedVms) {
                Write-Host "$(get-date) [INFO] Marking VM $orphanedVm for removal from protection domain $pdEntry..." -ForegroundColor Green
                $orphanedList += $orphanedVm
            }#endforeach $orphanedVm
            
            if ($orphanedList) {
                Write-Host "$(get-date) [INFO] Removing oprhaned VM entries from protection domain $pdEntry..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pdEntry)/unprotect_vms"
                $method = "POST"
                $body = (ConvertTo-Json $orphanedList)
                $unprotectVms = Get-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                Write-Host "$(get-date) [SUCCESS] Successfully removed orphaned VM entries from protection domain $pdEntry!" -ForegroundColor Cyan
            } else {
                Write-Host "$(get-date) [WARNING] Could not find any orphaned VM entries in protection domain $pdEntry!" -ForegroundColor Yellow
            }#endif $orphanedList
        }
    
    }#endif $clean
    #endregion

#endregion

#region cleanup
#########################
##       cleanup       ##
#########################

	#let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
#endregion