<#
.SYNOPSIS
  This script can be used to retrieve the overall status of one or more Nutanix cluster(s).
.DESCRIPTION
  The following information is retrieved from each Nutanix cluster: nos version, capacity (total, used, free) of each container (converted from TiB into TB), the storage efficiency factor (as displayed on the Prism home page) and the number of nodes for each model.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER email
  If used, this will send an email to the recipients specified in the script (you will need to customize that section by editing the script).
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.EXAMPLE
.\get-NutanixStatus.ps1 -cluster ntnxc1.local,ntnxc2.local
Retrieve status for a list of Nutanix clusters.

.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region parameters
	Param
	(
		#[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
		[parameter(mandatory = $false)] [switch]$help,
		[parameter(mandatory = $false)] [switch]$history,
		[parameter(mandatory = $false)] [switch]$debugme,
		[parameter(mandatory = $false)] [string]$cluster,
		[parameter(mandatory = $false)] [string]$prismCreds,
		[parameter(mandatory = $false)] [switch]$email
	)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
10/12/2022 sb   Added multiple cluster information entries. Added HA information
04/15/2022 sb   Fixed divide by zero error. Added functions and removed dependency to sbourdeaud module.
02/06/2021 sb   Replaced username with get-credential
04/21/2020 sb   Do over with sbourdeaud module.
03/22/2016 sb   Added the email parameter.
03/14/2016 sb   Initial release.
################################################################################
'
    $myvarScriptName = ".\get-NutanixStatus.ps1"
    
    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $true)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string]$method,

            [parameter(mandatory = $true)]
            [string]$url,

            [parameter(mandatory = $false)]
            [string]$payload,

            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]$credential
        )

        Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
        try {
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json"
                    "Accept"       = "application/json"
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
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))))
                    "Content-Type"  = "application/json"
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                } else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
            Write-Host "$(Get-Date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White }
        }
        catch {
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            throw "$(Get-Date) [ERROR] $($_.Exception.Message)"
        }
        return $resp
    }

    function Set-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $true)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Set path to $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
        $user = $credentials.UserName
        $securePassword = $credentials.Password

        try {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        if (!(Test-Path $path)) {
            try {
                New-Item -Type Directory $path -ErrorAction Stop | Out-Null
            }
            catch {
                throw "$(Get-Date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
        }

        try {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(Get-Date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan
    }

    function Get-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $true)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        if (!(Test-Path $credentialsFilePath)) {
            throw "$(Get-Date) [ERROR] Could not access file $credentialsFilePath"
        }

        $credFile = Get-Content $credentialsFilePath
        $user = $credFile[0]
        $securePassword = $credFile[1] | ConvertTo-SecureString
        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(Get-Date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan
        return $customCredentials
    }

    function Set-PoshTls {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            # PowerShell 7+ already defaults to TLS 1.2+; Invoke-PrismAPICall also sets -SslProtocol Tls12
            return
        }
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = (
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        )
    }

    function Set-PoSHSSLCerts {
        # PowerShell 6+ uses -SkipCertificateCheck on Invoke-RestMethod (see Invoke-PrismAPICall).
        # The old ServicePointManager Add-Type path is obsolete on modern .NET and fails to compile (SYSLIB0014).
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates (SkipCertificateCheck)" -ForegroundColor Green
            return
        }

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
        if (ServicePointManager.ServerCertificateValidationCallback == null)
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                delegate (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
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
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
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
			$url = "https://$($myvarCluster):9440/PrismGateway/services/rest/v2.0/cluster/"
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
			$url = "https://$($myvarCluster):9440/api/nutanix/v2.0/ha/"
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
			$url = "https://$($myvarCluster):9440/PrismGateway/services/rest/v2.0/storage_containers/"
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
        Write-Host "$(Get-Date) [INFO] Building the email content..." -ForegroundColor Green
		$myvarEmailSubject = "Acme Capacity Report " + $myvarReportTimeStamp
        
        $myvarhtml = "Container report is  attached in csv.  Copy and paste its content into the NTNX-CLusters tab in the master spreadsheet. Make sure the efficiency column is correctly formatted as numbers and if appropriate, replace the decimal spearator."
        $myvarEmailBody += "<br /><br />" + $myvarhtml
        $myvarReportTimeStamp = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")

        Write-Host "$(Get-Date) [INFO] Sending the email..." -ForegroundColor Green
        Send-MailMessage -SmtpServer $myvarSmtpServer -From $myvarEmailFrom -To $myvarEmailRecipients -Subject $myvarEmailSubject -Body $myvarEmailBody -bodyashtml -Attachments container-report.csv

    }#endif email
#endregion


#region cleanup

	#let's figure out how much time this all took
	Write-Host ""
	Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
	Remove-Variable email -ErrorAction SilentlyContinue
	Remove-Variable prismCreds -ErrorAction SilentlyContinue
	
#endregion