<#
.SYNOPSIS
  You can use this script to retrieve active BIOS settings from one or more out of band management modules (currently supports HPE ILOs and SuperMicro IPMIs).
.DESCRIPTION
  Script will use the Redfish API of the OOBM module to retrieve active configured BIOS settings.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER mms
  One or more OOBM module IP addresses or FQDNs (if multiple, separate them with commas and enclose the list in double quotes).  This can also be a path and file name to a csv file containing a list of management modules (mms). The csv can have any attributes you want, but one of them MUST be called "mm_ipv4_address".  You can also have attributes called "username" and "password" if you want to specify credentials for each mm in that csv file (although this is not advisable since those would be clear text in your csv).
.PARAMETER mmCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details. This option assumes that you can use the same credential for all management modules you need to probe.  If that is not the case, don't specify credentials and you will be prompted for them for each management module.
.PARAMETER mmType
  Specifies the type of management module you are querying. Valid values are either ilo (for HPE hardware), idrac (for Dell hardware), or ipmi (for SuperMicro hardware).
.EXAMPLE
.\get-BiosSettings.ps1 -mms my_list_of_ilos.csv
Retrieve settings from the specified list of management modules.
.LINK
  http://www.nutanix.com/services
.NOTES
  Authors: Michael Nichols (michael.nichols@nutanix.com), Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: July 13th 2022
#>


#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $true)] [string]$mms,
    [parameter(mandatory = $false)] $mmCreds,
    [parameter(mandatory = $false)][ValidateSet("ilo","ipmi","idrac")] [string]$mmType
)
#endregion


#region functions
#this function is used to process output to console (timestamped and color coded) and log file
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

function Invoke-RESTAPICall
{
<#
.SYNOPSIS
  Makes REST api call based on passed parameters. Returns the json response.
.DESCRIPTION
  Makes REST api call based on passed parameters. Returns the json response.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER method
  REST method (POST, GET, DELETE, or PUT)
.PARAMETER credential
  PSCredential object to use for authentication.
.PARAMETER url
  URL to the api endpoint.
.PARAMETER payload
  JSON payload to send.
.EXAMPLE
.\Invoke-RESTAPICall -credential $MyCredObject -url https://myprism.local/api/v3/vms/list -method 'POST' -payload $MyPayload
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
#endregion


#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
07/12/2022 sb   Initial release (based on mn's work).
07/13/2022 sb   Making it compatible with SMC as well as HPE.
                Adding Dell iDRAC (untested).
################################################################################
'@
    $myvarScriptName = ".\get-BiosSettings.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvar_mm_configuration_results = New-Object System.Collections.ArrayList($null)
#endregion


#region parameters validation
    if ($mmCreds)  
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {
            $mmCredentials = Get-CustomCredentials -credname $mmCreds -ErrorAction Stop
        }
        catch 
        {
            Set-CustomCredentials -credname $mmCreds
            $mmCredentials = Get-CustomCredentials -credname $mmCreds -ErrorAction Stop
        }
        $username = $mmCredentials.UserName
        $mmSecurePassword = $mmCredentials.Password
        $mmCredentials = New-Object PSCredential $username, $mmSecurePassword
    }
#endregion


#region processing

    #* figure out if mms is a csv file or not
    if ($mms.contains(".csv")) 
    {#-mms is a csv file
        if (Test-Path -Path $mms) 
        {#file exists
            $myvar_mm_list = Import-Csv -Path $mms #import the csv file data
        }
        else 
        {#file does not exist
          throw "The specified csv file $($mms) does not exist!"
        }
    }
    else 
    {#-mms is not a csv file
        $myvar_mms = $mms.Split(",")
        [System.Collections.ArrayList]$myvar_mm_list = New-Object System.Collections.ArrayList($null)
        ForEach ($mm in $myvar_mms)
        {
            $myvar_mm_item = @{"mm_ipv4_address" = $mm}
            $myvar_mm_list.Add((New-Object PSObject -Property $myvar_mm_item)) | Out-Null
        }
    }

    ForEach ($mm in $myvar_mm_list)
    {#loop thru each mm
        if (!$mm.mm_ipv4_address)
        {
            Write-Host "$(get-date) [ERROR] You must specify an mm_ipv4_address attribute in your csv file!" -ForegroundColor Red
            exit(1)
        }
        Write-Host "$(get-date) [INFO] Processing management module $($mm.mm_ipv4_address)..." -ForegroundColor Green
        
        if ($mmCredentials)
        {#user has defined a single credential to use
            $myvar_credentials = $mmCredentials
        }
        else 
        {#user has not specified a single credential so let's prompt for credentials for this management module
            if ($mm.username -and $mm.password)
            {
                $myvar_credentials = new-object -typename System.Management.Automation.PSCredential -argumentlist $mm.username, $(ConvertTo-SecureString $mm.password -AsPlainText -Force)
            }
            else 
            {
                $myvar_credentials = Get-Credential -Message "Please enter credentials for management module $($mm.mm_ipv4_address)"
            }
        }

        #* make the api call
        if ($mm.mmType)
        {#mmType is specified in the csv file, let's figure out what it is
            if (($mm.mmType -ne "ilo") -and ($mm.mmType -ne "ipmi") -and ($mm.mmType -ne "idrac"))
            {
                Write-Host "$(get-date) [ERROR] You must specify an mmType attribute (either ilo or ipmi) in your csv file!" -ForegroundColor Red
                exit(1)
            }
            else 
            {
                $mmType = $mm.mmType
            }
        }
        if (!$mmType) 
        {#the mmType was not specified by the user and was not in the csv file either
            Write-Host "$(get-date) [ERROR] You must specify an mmType (ilo or ipmi)!" -ForegroundColor Red
            exit(1)
        }
        if ($mmType -eq "ilo")
        {#this is an ilo (HPE)
            $api_server_endpoint = "/redfish/v1/systems/1/bios/settings/"
        }
        elseif ($mmType -eq "ipmi")
        {#this is an ipmi (SuperMicro): the redfish endpoint is not the same
            $api_server_endpoint = "/redfish/v1/Systems/1/Bios/"
        }
        elseif ($mmType -eq "idrac")
        {#this is an ipmi (SuperMicro): the redfish endpoint is not the same
            $api_server_endpoint = "/redfish/v1/Systems/System.Embedded.1/Bios/Settings"
        }
        $url = "https://{0}{1}" -f $mm.mm_ipv4_address, $api_server_endpoint
        $method = "GET"
        $api_response = Invoke-RESTAPICall -method $method -url $url -credential $myvar_credentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved configuration BIOS settings for $($mm.mm_ipv4_address)!" -ForegroundColor Cyan
        
        #* process results

        $myvar_mm_configuration = [ordered]@{}
        if ($mms.contains(".csv")) 
        {#-mms is a csv file, so import all custom properties in that csv
            foreach ($property in $mm.psobject.properties.name)
            {#processing all properties in that csv
                if ($property -eq "mm_ipv4_address")
                {#this is the ipv4 address
                    $myvar_mm_configuration.management_module = $mm.$property
                }
                elseif (($property -eq "username") -or ($property -eq "password"))
                {#we're skipping username and password
                    #do nothing
                }
                else
                {#add the custom attribute and value
                    $myvar_mm_configuration[$property] = $mm.$property
                }
            }
        }
        else 
        {#-mms is not a csv file
            $myvar_mm_configuration.management_module = $mm.mm_ipv4_address
        }
        
        if ($mmType -eq "ipmi")
        {#for some reason, we need to convert the response when it's returned by a SuperMicro IPMI
            foreach( $property in ($api_response | ConvertFrom-Json -AsHashTable).Attributes.Keys )
            {#process all attributes/configuration settings returned by the API
                $myvar_mm_configuration[$property] = ($api_response | ConvertFrom-Json -AsHashTable).Attributes.$property
            }
        }
        else 
        {
            foreach( $property in $api_response.Attributes.psobject.properties.name )
            {#process all attributes/configuration settings returned by the API
                $myvar_mm_configuration[$property] = $api_response.Attributes.$property
            }
        }

        $myvar_mm_configuration_results.Add((New-Object PSObject -Property $myvar_mm_configuration)) | Out-Null
    }
    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")mms_configuration.csv" -ForegroundColor Green
    $myvar_mm_configuration_results | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+"mms_configuration.csv")
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable mm* -ErrorAction SilentlyContinue
    Remove-Variable api* -ErrorAction SilentlyContinue
#endregion
