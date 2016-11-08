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
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER searchstring
  Searchstring for containers. This enables you to filter which containers are returned in the container report.
.PARAMETER email
  If used, this will send an email to the recipients specified in the script (you will need to customize that section by editing the script).
.EXAMPLE
  Retrieve status for a list of Nutanix clusters:
  PS> .\get-NutanixStatus.ps1 -cluster ntnxc1.local,ntnxc2.local -username admin -password admin
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: March 22nd 2016
#>

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
    [parameter(mandatory = $false)] [string]$cluster,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
	[parameter(mandatory = $false)] [string]$searchstring,
	[parameter(mandatory = $false)] [switch]$email
)

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

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

#########################
##   main processing   ##
#########################

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 03/14/2016 sb   Initial release.
 03/22/2016 sb   Added the email parameter.
################################################################################
'@
$myvarScriptName = ".\get-NutanixStatus.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}


#let's load the Nutanix cmdlets
if ((Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue) -eq $null)#is it already there?
{
	Add-PSSnapin NutanixCmdletsPSSnapin #no? let's add it
	if (!$?) #have we been able to add it successfully?
	{
		OutputLogData -category "ERROR" -message "Unable to load the Nutanix snapin.  Please make sure the Nutanix Cmdlets are installed on this server."
		return
	}
}

#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
	$myvarNutanixHosts = @()
    

    ############################################################################
	# customize this section for your environment
	############################################################################
    $myvarEmailFrom = "stephane.bourdeaud@krollontrack.com"
	$myvarSmtpServer = "koltsmtpr.ccp.edp.local"
    $myvarEmailRecipients = "stephane.bourdeaud@nutanix.com"
	
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	if (!$cluster) {$cluster = read-host "Enter the Nutanix cluster(s) name(s) separated by commas"}
	$myvarClusters = $cluster.Split(",") #make sure we parse the argument in case it contains several entries
	
	if (!$username) {$username = "admin"}
	if (!$password) {$password = "nutanix/4u"}
	
	[System.Collections.ArrayList]$myvarClusterReport = New-Object System.Collections.ArrayList($null) #used for storing all entries.
	[System.Collections.ArrayList]$myvarContainerReport = New-Object System.Collections.ArrayList($null) #used for storing all entries.
	
	
	################################
	##  Main execution here       ##
	################################
	foreach ($myvarCluster in $myvarClusters)	
	{
		OutputLogData -category "INFO" -message "Connecting to Nutanix cluster $myvarCluster..."
        $spassword = $password | ConvertTo-SecureString -AsPlainText -Force
		if (!($myvarNutanixCluster = Connect-NutanixCluster -Server $myvarCluster -UserName $username -Password $spassword –acceptinvalidsslcerts -ForcedConnection))#make sure we connect to the Nutanix cluster OK...
		{#error handling
			$myvarerror = $error[0].Exception.Message
			OutputLogData -category "ERROR" -message "$myvarerror"
			return
		}
		else #...otherwise show confirmation
		{
			OutputLogData -category "INFO" -message "Connected to Nutanix cluster $myvarCluster."
		}#endelse
		
		if ($myvarNutanixCluster)
		{
		
			######################
			#main processing here#
			######################
			
			$myvarClusterReportEntry = @{}
			
			$myvarClusterInfo = Get-NTNXCluster
			
			$myvarClusterReportEntry.Version = $myvarClusterInfo.version
			$myvarClusterReportEntry.Name = $myvarClusterInfo.name
			
			foreach ($myvarUnit in $myvarClusterInfo.rackableUnits)
			{
                if ($myvarUnit.modelName)
                {
				    $myvarClusterReportEntry.($myvarUnit.modelName) += ($myvarUnit.nodes).Count
                }
                else
                {
 				    $myvarClusterReportEntry.($myvarUnit.model) += ($myvarUnit.nodes).Count               
                }
			}
			
			if ($searchstring)
			{
				$myvarContainers = Get-NTNXContainer -SearchString $searchstring
			}
			else
			{
				$myvarContainers = Get-NTNXContainer
			}
			
			foreach ($myvarContainer in $myvarContainers)
			{
				$myvarContainerReportEntry = @{}
				
				$myvarStats = $myvarContainer.usageStats
				
				$myvarContainerReportEntry.Cluster = $myvarClusterInfo.Name
				$myvarContainerReportEntry.Name = $myvarContainer.name
				$myvarContainerReportEntry.Capacity = foreach ($key in $myvarStats.GetEnumerator() | where-object {$_.Key -eq "storage.user_capacity_bytes"}) {$key.value}
				$myvarContainerReportEntry.Usage = foreach ($key in $myvarStats.GetEnumerator() | where-object {$_.Key -eq "storage.user_usage_bytes"}) {$key.value}
				$myvarContainerReportEntry.Free = foreach ($key in $myvarStats.GetEnumerator() | where-object {$_.Key -eq "storage.user_free_bytes"}) {$key.value}
				$myvarContainerReportEntry.PreReduction = foreach ($key in $myvarStats.GetEnumerator() | where-object {$_.Key -eq "data_reduction.pre_reduction_bytes"}) {$key.value}
				$myvarContainerReportEntry.PostReduction = foreach ($key in $myvarStats.GetEnumerator() | where-object {$_.Key -eq "data_reduction.post_reduction_bytes"}) {$key.value}
				$myvarContainerReportEntry.Efficiency = $myvarContainerReportEntry.PreReduction / $myvarContainerReportEntry.PostReduction
			
				$myvarContainerReport.Add((New-Object PSObject -Property $myvarContainerReportEntry)) | Out-Null
			
			}
            $myvarClusterReport.Add((New-Object PSObject -Property $myvarClusterReportEntry)) | Out-Null
		}#endif	
		
	    OutputLogData -category "INFO" -message "Disconnecting from Nutanix cluster $myvarCluster..."
		Disconnect-NutanixCluster -Servers $myvarCluster #cleanup after ourselves and disconnect from the Nutanix cluster
	}#end foreach cluster
	
	write-host "ClusterReport"
    $myvarClusterReport | fl
	write-host "ContainerReport"
    $myvarContainerReport | ft -autosize
    $myvarContainerReport | export-csv container-report.csv -NoTypeInformation

    if ($email)
    {
        #send that email
        OutputLogData -category "INFO" -message "Building the email content..."
		$myvarEmailSubject = "Kroll Capacity Report " + $myvarReportTimeStamp
        
        $myvarhtml = "Container report is  attached in csv.  Copy and paste its content into the NTNX-CLusters tab in the master spreadsheet. Make sure the efficiency column is correctly formatted as numbers and if appropriate, replace the decimal spearator."
        $myvarEmailBody += "<br /><br />" + $myvarhtml

        OutputLogData -category "INFO" -message "Sending the email..."
        Send-MailMessage -SmtpServer $myvarSmtpServer -From $myvarEmailFrom -To $myvarEmailRecipients -Subject $myvarEmailSubject -Body $myvarEmailBody -bodyashtml -Attachments container-report.csv

    }#endif email
	
#########################
##       cleanup       ##
#########################

	#let's figure out how much time this all took
	OutputLogData -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar*
	Remove-Variable ErrorActionPreference
	Remove-Variable help
    Remove-Variable history
	Remove-Variable log
	Remove-Variable cluster
	Remove-Variable username
	Remove-Variable password
	Remove-Variable searchstring
    Remove-Variable debugme
    Remove-Variable email