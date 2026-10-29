<#
.SYNOPSIS
  This script configures DNS and NTP for all hosts in a given cluster.
.DESCRIPTION
  This script configures the DNS domain name, primary DNS server, secondary DNS server and NTP servers for all hosts in a given vSphere cluster.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER vcenter
  VMware vCenter server hostname. You can specify several hostnames by separating entries with commas and using double quotes. If none is specified, the script will prompt you.
.PARAMETER cluster
  vSphere cluster name. If none is specified, the script will prompt you.
.PARAMETER domain
  Domain name (exp: acme.local). If none is specified, the script will prompt you.
.PARAMETER dns
  IP address(es) of the DNS server(s). Separate multiple entries with commas and use double quotes. You can specify up to two DNS servers. If none is specified, the script will prompt you.
.PARAMETER ntp
  IP address(es) of the NTP server(s).  Separate multiple entries with commas and use double quotes. You can specify up to two NTP servers. If none is specified, the script will prompt you.
.PARAMETER clearntp
  If specified, this will clear the existing ntp server configuration instead of appending to it.
.EXAMPLE
  Configure all hosts in clusterA:
  PS> .\set-hostconfig.ps1 -vcenter myvcenter.mydomain.local -cluster clusterA -domain mydomain.local -dns "10.10.10.1,10.10.10.2" -ntp "10.10.10.1,10.10.10.2"
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
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
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$vcenter,
    [parameter(mandatory = $false)] [string]$cluster,
    [parameter(mandatory = $false)] [string]$domain,
    [parameter(mandatory = $false)] [string]$dns,
    [parameter(mandatory = $false)] [string]$ntp,
	[parameter(mandatory = $false)] [boolean]$clearntp
)
#endregion

#region prepwork
# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}
#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed -log parameter and OutputLogData function; updated PowerCLI handling
10/01/2015 sb   Initial release.
02/02/2022 sb   Changed errors to warnings.
################################################################################
'@
$myvarScriptName = ".\set-hostconfig.ps1"
 
    if ($help) {
        $helpContent = Get-Content $PSCommandPath -Raw
        $inHelp = $false
        $helpLines = @()
        foreach ($line in $helpContent -split "`n") {
            if ($line -match '^<#') { $inHelp = $true; continue }
            if ($line -match '^#>') { break }
            if ($inHelp) { $helpLines += $line }
        }
        $helpLines -join "`n" | Write-Host
        exit
    }
if ($History) {$HistoryText; exit}

#region Load/Install VMware.PowerCLI
if (!(Get-Module VMware.PowerCLI)) {
    try {
        Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
        Import-Module VMware.VimAutomation.Core -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
    }
    catch { 
        Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
        try {
            Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
            Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
            try {
                Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"}
        }
        catch {throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"} 
    }
}

#check PowerCLI version
if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) {
    try {Update-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop} catch {throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"}
    throw "$(get-date) [ERROR] Please upgrade PowerCLI to version 10 or above by running the command 'Update-Module VMware.PowerCLI' as an admin user"
}
#endregion

#endregion prepwork

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
#endregion variables

#region parameters validation
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	if (!$vcenter) {$vcenter = read-host "Enter vCenter server name or IP address"}#prompt for vcenter server name
	$myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
    if (!$cluster) {$cluster = read-host "Enter the vSphere cluster name"}
    if (!$domain) {$domain = read-host "Enter DNS domain name"}
    if (!$dns) {$dns = read-host "Enter primary and secondary DNS servers separated by a comma and WITHOUT double quotes"}
    $myvarDns = $dns.Split(",") #make sure we parse the argument in case it contains several entries
    if (!$ntp) {$ntp = read-host "Enter NTP servers separated by a comma and WITHOUT double quotes"}
    $myvarNtp = $ntp.Split(",") #make sure we parse the argument in case it contains several entries
#endregion parameters validation
	
#region processing
	foreach ($myvarvCenter in $myvarvCenterServers)	
	{#process all vcenters
		Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
		if (!($myvarvCenterObject = Connect-VIServer $myvarvCenter))#make sure we connect to the vcenter server OK...
		{#we did not get a vCenter object back when we tried to connect
			$myvarerror = $error[0].Exception.Message
			Write-Host "$(get-date) [ERROR] Could not connect to vCenter $myvarerror" -ForegroundColor Red
			return
		}
		else 
		{#we connected OK
			Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter." -ForegroundColor Cyan
		}#endelse
		
		if ($myvarvCenterObject)
		{#we have a vcenter connection, let's proceed            
            #let's gather hosts in the cluster
            Write-Host "$(get-date) [INFO] Figuring out which hosts are in cluster $cluster..." -ForegroundColor Green
            $myvarHosts = get-cluster -name $cluster | Get-VMHost

            foreach ($myvarHost in $myvarHosts)
            {
              Write-Host "$(get-date) [INFO] Configuring DNS domain name and servers for $myvarHost..." -ForegroundColor Green
              try
              {#* DNS
                  $setDNSAction = Get-VMHostNetwork -VMHost $myvarHost | Set-VMHostNetwork -DomainName $domain -DnsAddress $myvarDns -Confirm:$false -ErrorAction Stop
                  Write-Host "$(get-date) [SUCCESS] Successfully configured DNS domain name and servers for $myvarHost..." -ForegroundColor Cyan
              }
              catch
              {
                  Write-Host "$(get-date) [WARNING] Could not configure DNS domain name and servers for $myvarHost : $($_.Exception.Message)" -ForegroundColor Yellow
              }

              if ($clearntp)
              {#* Clear NTP
                Write-Host "$(get-date) [INFO] Clearing NTP servers for $myvarHost..." -ForegroundColor Green
                $myvarExistingNTParray = $myvarHost | Get-VMHostNTPServer
                try
                {#* Clear NTP
                    $clearNTPAction = Get-VMHost $myvarHost | Remove-VMHostNTPServer -NtpServer $myvarExistingNTParray -Confirm:$false -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Successfully cleared NTP configuration on $myvarHost." -ForegroundColor Cyan
                }
                catch
                {
                    Write-Host "$(get-date) [WARNING] Could not clear NTP configuration for $myvarHost : $($_.Exception.Message)" -ForegroundColor Yellow
                }
              }#endif
				
				      Write-Host "$(get-date) [INFO] Configuring NTP servers for $myvarHost..." -ForegroundColor Green
              try
              {#* Add NTP
                  $addNTPAction = Add-VMHostNtpServer -NtpServer $myvarNtp -VMHost $myvarHost -ErrorAction Stop
                  Write-Host "$(get-date) [SUCCESS] Successfully configured NTP servers on $myvarHost." -ForegroundColor Cyan
              }
              catch
              {
                  Write-Host "$(get-date) [WARNING] Could not configure NTP on $myvarHost : $($_.Exception.Message)" -ForegroundColor Yellow
              }

              Write-Host "$(get-date) [INFO] Configuring NTP client policy for $myvarHost..." -ForegroundColor Green
              try
              {#* NTP service on
                  $configureNTPPolicyAction = Get-VMHostService -VMHost $myvarHost | where {$_.Key -eq "ntpd"} | Set-VMHostService -policy "on" -Confirm:$false -ErrorAction Stop
                  Write-Host "$(get-date) [SUCCESS] Successfully configured the NTP policy on $myvarHost." -ForegroundColor Cyan
              }
              catch
              {
                  Write-Host "$(get-date) [WARNING] Could not configure NTP policy on $myvarHost : $($_.Exception.Message)" -ForegroundColor Yellow
              }

              Write-Host "$(get-date) [INFO] Restarting NTP client on $myvarHost..." -ForegroundColor Green
              try
              {#* restart NTP service
                  $restartNtpAction = Get-VMHostService -VMHost $myvarHost | where {$_.Key -eq "ntpd"} | Restart-VMHostService -Confirm:$false -ErrorAction Stop
                  Write-Host "$(get-date) [SUCCESS] Successfully restarted the NTP client on $myvarHost." -ForegroundColor Cyan
              }
              catch
              {
                  Write-Host "$(get-date) [WARNING] Could not restart the NTP client on $myvarHost : $($_.Exception.Message)" -ForegroundColor Yellow
              }
            }#end foreach host loop
		
		}#endif
        Write-Host "$(get-date) [INFO] Disconnecting from vCenter server $vcenter..." -ForegroundColor Green
		Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
	}#end foreach vCenter
#endregion

#region cleanup

	#let's figure out how much time this all took
	Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable debugme -ErrorAction SilentlyContinue
	Remove-Variable vcenter -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable domain -ErrorAction SilentlyContinue
    Remove-Variable dns -ErrorAction SilentlyContinue
    Remove-Variable ntp -ErrorAction SilentlyContinue
    Remove-Variable clearntp -ErrorAction SilentlyContinue
#endregion