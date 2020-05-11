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
  Revision: April 21st 2020
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
 04/21/2020 sb   Do over with sbourdeaud module.
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
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
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
            $credname = Read-Host "Enter the credentials name"
            Set-CustomCredentials -credname $credname
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }
#endregion

#region E - processing

    #region retrieve protection domain   
    Write-Host "$(get-date) [INFO] Retrieving protection domains information from Nutanix cluster $prism ..." -ForegroundColor Green
    $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/protection_domains/"
    $method = "GET"
    try 
    {
        $myvar_protection_domains = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
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
            $result = Invoke-PrismRESTCall -method $method -url $url  -credential $prismCredentials
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
