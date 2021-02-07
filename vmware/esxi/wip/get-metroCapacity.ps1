<#
.SYNOPSIS
  This is a summary of what the script is.
.DESCRIPTION
  This is a detailed description of what the script does and how it is used.
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
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vcenterCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\template.ps1 -cluster ntnxc1.local -username admin -password admin
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 7th 2021
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] [string]$prismCreds,
        [parameter(mandatory = $false)] [string]$vcenterCreds
    )
#endregion

#region functions

#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
02/07/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-metroCapacity.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    #region Load/Install VMware.PowerCLI
        if (!(Get-Module VMware.PowerCLI)) 
        {#module VMware.PowerCLI is not loaded
            try 
            {#load module VMware.PowerCLI
                Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                Import-Module VMware.PowerCLI -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
            }
            catch 
            {#couldn't load module VMware.PowerCLI
                Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
                try 
                {#install module VMware.PowerCLI
                    Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
                    Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
                    try 
                    {#loading module VMware.PowerCLI
                        Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                        Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
                    }
                    catch 
                    {#couldn't load module VMware.PowerCLI
                        throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
                    }
                }
                catch 
                {#couldn't install module VMware.PowerCLI
                    throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"
                }
            }
        }
        
        if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
        {#check PowerCLI version
            try 
            {#update module VMware.PowerCLI
                Update-Module -Name VMware.PowerCLI -ErrorAction Stop
            } 
            catch 
            {#couldn't update module VMware.PowerCLI
                throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"
            }
        }
    #endregion
    if ((Get-PowerCLIConfiguration | where-object {$_.Scope -eq "User"}).InvalidCertificateAction -ne "Ignore") 
    {#ignore invalid certificates for vCenter
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false
    }

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
                Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
                Import-Module -Name sbourdeaud -ErrorAction Stop
            }
            catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
        }
    #endregion
    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#* constants and configuration here
#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

    #* constants
    $myvar_cpu_over_subscription_ratio = 4
    $myvar_ram_over_subscription_ratio = 1
    $myvar_cvm_cpu_reservation = 0 #if this is set to 0, we'll use the largest cvm cpu allocation
    $myvar_cvm_ram_gib_reservation = 0 #if this is set to 0, we'll use the largest cvm ram allocation
    $myvar_hypervisor_cpu_overhead = 0 #if this is set to 0, we'll look at the replication factor, then subtract the assume biggest host(s) cpu capacity
    $myvar_hypervisor_ram_gib_overhead = 0 #if this is set to 0, we'll look at the replication factor, then subtract the assume biggest host(s) ram capacity

    #* configuration
    $myvar_smtp_server = ""
    $myvar_smtp_from = ""
    $myvar_smtp_to = ""
    $myvar_zabbix_server = ""
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

    if ($vcenterCreds) 
    {#vcenterCreds was specified
        try 
        {
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
            $vcenterUsername = $vcenterCredentials.UserName
            $vcenterSecurePassword = $vcenterCredentials.Password
        }
        catch 
        {
            Set-CustomCredentials -credname $vcenterCreds
            $vcenterCredentials = Get-CustomCredentials -credname $vcenterCreds -ErrorAction Stop
            $vcenterUsername = $vcenterCredentials.UserName
            $vcenterSecurePassword = $vcenterCredentials.Password
        }
        $vcenterCredentials = New-Object PSCredential $vcenterUsername, $vcenterSecurePassword
    }
	else 
	{#no vcenter creds were given
		$vcenterCredentials = Get-Credential -Message "Please enter vCenter credentials"
	}
#endregion

#* processing here
#region processing	
    #* retrieve information from Prism
    #region retrieve information from Prism
        #* retrieve cluster information
        #region GET cluster

        #endregion
        
        #* retrieve host information
        #region GET hosts

        #endregion
        
        #* retrieve storage containers information
        #region GET containers

        #endregion
        
        #* retrieve protection domains information
        #region GET protection_domains

        #endregion
        
        #* retrieve remote site information
            #region GET remote_site

            #endregion
            
            #* retrieve remote cluster information
            #region GET remote_site cluster

            #endregion
            
            #* retrieve remote host information
            #region GET remote_site hosts

            #endregion
            
            #* retrieve remote storage containers information
            #region GET remote_site containers

            #endregion
        
            #* figure out vcenter information
        #region figure out vcenter information
            
        #endregion
    #endregion

    #* retrieve information from vCenter
    #region retrieve information from vCenter
        #* connect to vCenter
        #region connect-viserver
        #endregion

        #* figure out ha/drs cluster
        #region figure out ha/drs cluster

        #endregion
        
        #* retrieve vms
        #region Get-Vm

        #endregion

        Disconnect-viserver * -Confirm:$False #cleanup after ourselves and disconnect from vcenter
    #endregion

    #* compute capacity numbers
    #region compute capacity numbers
        #* total clusters capacity (cpu/ram)
        #* uvm clusters capacity (cpu/ram)
        #* uvm allocated (cpu/ram)
        #* metro uvm allocated (cpu/ram)
        #* uvm remaining (cpu/ram)
    #endregion

    #* create output
    #region create output
        #* html output
        #region html output

        #endregion
        
        #* console output
        #region console output
            
        #endregion

        #* smtp output
        #region smtp output
            
        #endregion

        #* zabbix output
        #region zabbix output
            
        #endregion
    #endregion
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
#endregion