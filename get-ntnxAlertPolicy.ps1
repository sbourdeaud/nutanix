<#
.SYNOPSIS
  This script can be used to retrieve all alerts and their configuration from a Prism instance.
.DESCRIPTION
  Given a Nutanix cluster, retrieve all alerts and healthchecks with full information, including severity, causes, resolutions, KB, etc... and export to a CSV file.
.PARAMETER prism
  IP address or FQDN of the Nutanix cluster (this can also be a single CVM IP or FQDN).
.PARAMETER username
  Prism username (with privileged cluster admin access).
.PARAMETER password
  Prism username password.
.PARAMETER csv
  Name of csv file to export to. By default this is prism-alerts-report.csv in the working directory.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
  PS> .\get-ntnxAlertPolicy.ps1 -prism 10.10.10.1 -username admin -password nutanix/4u -csv c:\temp\production-cluster-report.csv
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 4th 2017
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
    [parameter(mandatory = $false)] [string]$csv
)
#endregion

#region Prep-work

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 04/04/2017 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\get-ntnxAlertPolicy.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#let's load the Nutanix cmdlets
if ((Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue) -eq $null)#is it already there?
{
    try {
	    Add-PSSnapin NutanixCmdletsPSSnapin -ErrorAction Stop #no? let's add it
	}
    catch {
        Write-Warning $($_.Exception.Message)
		OutputLogData -category "ERROR" -message "Unable to load the Nutanix snapin.  Please make sure the Nutanix Cmdlets are installed on this server."
		return
	}
}


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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#endregion

#region Functions
########################
##   main functions   ##
########################

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
Function PrismRESTCall
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
		[string] $username,
		[string] $password,
        [string] $url,
        [string] $method,
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
            try {
                $myvarHeader += @{"Accept"="application/json"}
		        $myvarHeader += @{"Content-Type"="application/json"}
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
		    }
		    catch {
			    OutputLogData -category "ERROR" -message "$($_.Exception.Message)"
			    Exit
		    }
        } else {
            try {
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
		    }
		    catch {
			    OutputLogData -category "ERROR" -message "$($_.Exception.Message)"
			    Exit
		    }
        }
    }

    end
    {
        return $myvarRESTOutput
        Remove-variable username
        Remove-variable password
        Remove-variable url
        Remove-variable myvarHeader
    }
}#end function PrismRESTCall

#endregion

#region Variables
#initialize variables
#misc variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
$myvarOutputLogFile += "OutputLog.log"

[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all entries.  This is what will be exported to csv
	
############################################################################
# command line arguments initialization
############################################################################	
#let's initialize parameters if they haven't been specified
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
if (!$csv) {$csv = "prism-alerts-report.csv"}

#endregion

#region Processing
#########################
##   main processing   ##
#########################

#region Connect to Prism using PoSH cmdlets

    OutputLogData -category "INFO" -message "Connecting to Nutanix cluster $prism..."
    try
    {
        $myvarNutanixCluster = Connect-NutanixCluster -Server $prism -UserName $username -Password $spassword –acceptinvalidsslcerts -ForcedConnection -ErrorAction Stop
    }
    catch
    {#error handling
	    Write-Warning $($_.Exception.Message)
	    OutputLogData -category "ERROR" -message "Could not connect to $prism"
	    Exit
    }
    OutputLogData -category "INFO" -message "Connected to Nutanix cluster $prism."

#endregion

#region Retrieve alerts
    OutputLogData -category "INFO" -message "Retrieving alert definitions from $prism..."
    try
    {
        $myvarHealthChecks = Get-NTNXHealthCheck -IncludeInternalChecks -ErrorAction Stop
    }
    catch
    {#error handling
	    Write-Warning $($_.Exception.Message)
	    OutputLogData -category "ERROR" -message "Could not retrieve alert definitions from $prism"
	    Exit
    }

    #process each retrieved alert and keep only what we want
    foreach ($myvarHealthCheck in $myvarHealthChecks) {

        #figure out severity
        $myvarSeverity = ""
        if ($myvarHealthCheck.severityThresholdInfos) {
            if ($myvarHealthCheck.severityThresholdInfos[0].enabled -eq $true) {
                $myvarSeverity = $myvarHealthCheck.severityThresholdInfos[0].severity
            }
            if ($myvarHealthCheck.severityThresholdInfos[1].enabled -eq $true) {
                $myvarSeverity = $myvarHealthCheck.severityThresholdInfos[1].severity
            }
            if ($myvarHealthCheck.severityThresholdInfos[2].enabled -eq $true) {
                $myvarSeverity = $myvarHealthCheck.severityThresholdInfos[2].severity
            }
        }#endif severityInfo


        #populate hash
        $myvarHealthCheckInfo = @{"name" = $myvarHealthCheck.name;
                                  "description" = $myvarHealthCheck.description;
                                  "enabled" = $myvarHealthCheck.enabled;
                                  "checkType" = $myvarHealthCheck.checkType;
                                  "affectedEntityTypes" = $myvarHealthCheck.affectedEntityTypes -join " ";
                                  "categoryTypes" = $myvarHealthCheck.categoryTypes -join " ";
                                  "subCategoryTypes" = $myvarHealthCheck.subCategoryTypes -join " ";
                                  "scope" = $myvarHealthCheck.scope;
                                  "kbList" = $myvarHealthCheck.kbList -join " ";
                                  "causes" = $myvarHealthCheck.causes -join " ";
                                  "resolutions" = $myvarHealthCheck.resolutions -join " ";
                                  "scheduleIntervalInSecs" = $myvarHealthCheck.scheduleIntervalInSecs;
                                  "title" = $myvarHealthCheck.title;
                                  "alertTypeId" = $myvarHealthCheck.alertTypeId;
                                  "message" = $myvarHealthCheck.message;
                                  "severity" = $myvarSeverity}
        #populate array
        $myvarResults.Add((New-Object PSObject -Property $myvarHealthCheckInfo)) | Out-Null
    }#end foreach healthcheck

    #$myvarResults | ft -AutoSize -Wrap

    OutputLogData -category "INFO" -message "Exporting results to $csv..."
	$myvarResults | export-csv -NoTypeInformation $csv
#endregion

#region Export results
#endregion

#endregion processing

#region Cleanup	
#########################
##       cleanup       ##
#########################

    OutputLogData -category "INFO" -message "Disconnecting from Nutanix cluster $prism..."
	Disconnect-NutanixCluster -Servers $prism #cleanup after ourselves and disconnect from the Nutanix cluster

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
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable export -ErrorAction SilentlyContinue
    
#endregion