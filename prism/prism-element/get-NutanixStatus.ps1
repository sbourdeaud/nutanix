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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\get-NutanixStatus.ps1 -cluster ntnxc1.local,ntnxc2.local
Retrieve status for a list of Nutanix clusters.

.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
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

#region functions
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
################################################################################
'@
	$myvarScriptName = ".\get-NutanixStatus.ps1"
	
	if ($help) {get-help $myvarScriptName; exit}
	if ($History) {$HistoryText; exit}

	#region module sbourdeaud is used for facilitating Prism REST calls
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
		Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop
		Import-Module -Name sbourdeaud -ErrorAction Stop
	}
	catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
	}
	#endregion
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
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }
	
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
			
			$myvarClusterReportEntry.Version = $myvarClusterInfo.version
			$myvarClusterReportEntry.Name = $myvarClusterInfo.name
			
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

		#! step 2: get container information
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
					"Efficiency" = $myvarStats."data_reduction.pre_reduction_bytes" / $myvarStats."data_reduction.post_reduction_bytes"
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
        OutputLogData -category "INFO" -message "Building the email content..."
		$myvarEmailSubject = "Acme Capacity Report " + $myvarReportTimeStamp
        
        $myvarhtml = "Container report is  attached in csv.  Copy and paste its content into the NTNX-CLusters tab in the master spreadsheet. Make sure the efficiency column is correctly formatted as numbers and if appropriate, replace the decimal spearator."
        $myvarEmailBody += "<br /><br />" + $myvarhtml

        OutputLogData -category "INFO" -message "Sending the email..."
        Send-MailMessage -SmtpServer $myvarSmtpServer -From $myvarEmailFrom -To $myvarEmailRecipients -Subject $myvarEmailSubject -Body $myvarEmailBody -bodyashtml -Attachments container-report.csv

    }#endif email
#endregion

#region cleanup

	#let's figure out how much time this all took
	OutputLogData -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
	Remove-Variable email -ErrorAction SilentlyContinue
	
#endregion