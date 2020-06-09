<#
.SYNOPSIS
  Start a Nutanix Files failover (planned or unplanned) from one Nutanix cluster to another.
.DESCRIPTION
  Given a file server name, assuming protection domain and replication to another site is already in place, do a planned or unplanned failover of a Nutanix Files file server instance from one site to another.  The script will migrate or activate the protection domain, activate the file server and can also trigger DNS update.  The script is designed to be able to work also with a reference file so that it can be used to facilitate DR automation.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix cluster fully qualified domain name or IP address (source or target; the script will figure out which is which).
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER failover
  Specifies the type of failover (valid entries are planned or unplanned).
.PARAMETER fsname
  Name of the file server instance you want to failover.
.PARAMETER reference
  (Optional) Path to the reference file containing the following information in csv format: fsname,prism-primary,prism-dr,primary-client-network-name,primary-client-network-subnet,primary-client-network-gateway,primary-client-network-startip,primary-client-network-endip,primary-storage-network-name,primary-storage-network-subnet,primary-storage-network-gateway,primary-storage-network-startip,primary-storage-network-endip,dr-client-network-name,dr-client-network-subnet,dr-client-network-gateway,dr-client-network-startip,dr-client-network-endip,dr-storage-network-name,dr-storage-network-subnet,dr-storage-network-gateway,dr-storage-network-startip,dr-storage-network-endip,prismcreds,adcreds,pd,smtp,email
  If any of the client or storage networks are AHV managed, you do not need to specify values for the network name, subnet, gateway, startip and endip.
  The script will always look for a reference file in the current directory called <fsname>-reference.csv and use it if available.  Otherwise, it will prompt the user for the necessary information.
.PARAMETER pd
  (Optional) Name of protection domain for the file server instance (assumed name if NTNX-<file-server-name>).
.PARAMETER dns
  (Optional) Specifies that you want to trigger a DNS update after the file server has been activated (works only if your DNS server is a Microsoft DNS server).
.PARAMETER adcreds
  (Required if -dns) Name of credentials file for Active Directory (required for DNS update).  If the credentials file does not exist, you will be prompted for credentials.
.PARAMETER mail
  (Optional) Specifies that you want to notify by email when the script takes action.
.PARAMETER smtp
  (Required if -mail) FQDN or IP of the SMTP server to use for sending emails.
.PARAMETER email
  (Required if -mail) Comma separated list of email addresses to notify.
.EXAMPLE
.\Invoke-NutanixFilesDr.ps1 -fsname myfileserver -failover unplanned
Do an unplanned failover of a file server called myfileserver.  All reference information will be obtained from myfileserver.csv in the current directory:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 8th 2020
#>

#region parameters
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
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true)] [ValidateSet("planned","unplanned")] [string]$failover,
        [parameter(mandatory = $false)] [string]$fsname,
        [parameter(mandatory = $false)] [string]$reference,
        [parameter(mandatory = $false)] [string]$pd,
        [parameter(mandatory = $false)] [switch]$dns,
        [parameter(mandatory = $false)] $adCreds,
        [parameter(mandatory = $false)] [switch]$mail,
        [parameter(mandatory = $false)] [string]$smtp,
        [parameter(mandatory = $false)] [string]$email
    )
#endregion

#region functions
    function Invoke-NtnxPdMigration
    {
        <#
        .SYNOPSIS
        Triggers an asynchronous protection domain migration.
        .DESCRIPTION
        Triggers an asynchronous protection domain migration which (1)shuts down VMs, (2)syncs data with the remote site defined in its schedule, (3)unregisters VMs at the source and (4)registers VM on the remote site.
        .NOTES
        Author: Stephane Bourdeaud
        .PARAMETER pd
        Asynchronous protection domain name.
        .PARAMETER cluster
        FQDN or IP of Nutanix cluster.
        .PARAMETER username
        Nutanix cluster API username.
        .PARAMETER password
        Nutanix cluster API password (passed as a secure string).
        .EXAMPLE
        Invoke-NtnxPdMigration -pd <pd_name> -cluster ntnx1.local -username api-user -password $secret
        #>
        [CmdletBinding()]
        param
        (
            $pd,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]
            $credential            
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process
        { 
            #region get data
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -credential $credential
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                if (!$pd) 
                {#no pd specified
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                } 
                else 
                {#fetch specified pd
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
                }

                if (!$pd) 
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $cluster!"
                    Exit
                }
            #endregion

            #region process
                #now let's call the migrate workflow
                ForEach ($pd2migrate in $pd) 
                {
                    #figure out if there is more than one remote site defined for the protection domain
                    $remoteSite = $PdList.entities | Where-Object {$_.name -eq $pd2migrate} | Select-Object -Property remote_site_names
                    if (!$remoteSite.remote_site_names) 
                    {#no remote site defined or no schedule on the pd with a remote site
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no remote site defined for protection domain $pd2migrate"
                        Exit
                    }
                    if ($remoteSite -is [array]) 
                    {#more than 1 remote site target defined on the pd schedule
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one remote site for protection domain $pd2migrate"
                        Exit
                    }

                    #region migrate the protection domain
                        Write-Host ""
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Migrating $pd2migrate to $($remoteSite.remote_site_names) ..."
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                        $method = "POST"
                        $content = @{
                                        value = $($remoteSite.remote_site_names)
                                    }
                        $body = (ConvertTo-Json $content -Depth 4)
                        $response = Invoke-PrismRESTCall -method $method -url $url -credential $credential -payload $body
                        if ($debugme) {Write-LogOutput -Category "DEBUG" -LogFile $myvarOutputLogFile -Message "Migration request response is: $($response.metadata)"}
                        if ($response.metadata.count -ne 0)
                        {#something went wrong with our migration request
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not start migration of $pd2migrate to $($remoteSite.remote_site_names). Try to trigger it manually in Prism and see why it won't work (this could be caused ny NGT being disabled on some VMs, or by delta disks due to old snapshots)."
                            Exit
                        }
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)"
                    #endregion

                }
            #endregion
        }

        end
        {
        return $pd #list of protection domains which were processed 
        }
    }

    function Invoke-NtnxPdActivation
    {
        <#
        .SYNOPSIS
        Activates a Nutanix asynchronous protection domain (as part of an unplanned failover).
        .DESCRIPTION
        Activates a Nutanix asynchronous protection domain (as part of an unplanned failover), which will register VMs on the Nutanix cluster.
        .NOTES
        Author: Stephane Bourdeaud
        .PARAMETER pd
        Asynchronous protection domain name.
        .PARAMETER cluster
        FQDN or IP of Nutanix cluster.
        .PARAMETER username
        Nutanix cluster API username.
        .PARAMETER password
        Nutanix cluster API password (passed as a secure string).
        .EXAMPLE
        Invoke-NtnxPdActivation -pd <pd_name> -cluster ntnx1.local -username api-user -password $secret
        #>
        [CmdletBinding()]
        param
        (
            $pd,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process
        {            
            #region get data
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -credential $credential
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                if (!$pd) 
                {#no pd specified
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name
                } 
                else 
                {#fetch specified pd
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
                }

                if (!$pd) 
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $cluster!"
                    Exit
                }
            #endregion

            #now let's call the activate workflow
            ForEach ($pd2activate in $pd) 
            {#activate each pd
                #region activate the protection domain
                    Write-Host ""
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Activating protection domain $($pd2activate) on $cluster ..."
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate)/activate"
                    $method = "POST"
                    $content = @{}
                    $body = (ConvertTo-Json $content -Depth 4)
                    $response = Invoke-PrismRESTCall -method $method -url $url -credential $credential -payload $body
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully activated protection domain $($pd2activate) on $cluster"
                #endregion    
            }
        }

        end
        {
            return $pd #list of protection domains which were processed
        }
    }
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
06/08/2020 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\Invoke-NutanixFilesDr.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

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

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $StartEpochSeconds = Get-Date (Get-Date).ToUniversalTime() -UFormat %s #used to get tasks generated in Prism after the script was invoked
    $remote_site_ips = @() #initialize array here to collect remote site ips
#endregion

#region parameters validation
    if (!$reference) {
        if (!$fsname) {$fsname = Read-Host "Enter the name of the file server you want to failover"}
        #check if there is a default reference file for this file server in the current directory
        if (Test-Path ./$($fsname)-reference.csv -PathType Leaf) {
            Write-Host "$(get-date) [INFO] Found a reference file called $($fsname)-reference.csv in the current directory." -ForegroundColor Green
            $reference_data = Import-Csv -Path ./$($fsname)-reference.csv
        } else {
            Write-Host "$(get-date) [WARN] Could not find a reference file for file server $($fsname) in the current directory." -ForegroundColor Yellow
            if (!$prism) {$prism = Read-Host "Enter the FQDN or IP address of a Nutanix cluster"}
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
            if (!$pd) {$pd = "NTNX-$($fsname)"}
        }
    } else {
        $reference_data = Import-Csv -Path ./$($reference)
    }
    if ($dns) {
        if (!$adCreds) 
        {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
            $ad_username = Read-Host "Enter the Active Directory username for DNS updates"
            $ad_secure_password = Read-Host "Enter the Active Directory user $ad_username password" -AsSecureString
            $ad_credentials = New-Object PSCredential $ad_username, $ad_secure_password
        } 
        else 
        { #we are using custom credentials, so let's grab the username and password from that
            try 
            {
                $ad_credentials = Get-CustomCredentials -credname $adCreds -ErrorAction Stop
                $ad_username = $ad_credentials.UserName
                $ad_secure_password = $ad_credentials.Password
            }
            catch 
            {
                $credname = Read-Host "Enter the credentials name"
                Set-CustomCredentials -credname $credname
                $ad_credentials = Get-CustomCredentials -credname $adCreds -ErrorAction Stop
                $ad_username = $ad_credentials.UserName
                $ad_secure_password = $ad_credentials.Password
            }
            $ad_credentials = New-Object PSCredential $ad_username, $ad_secure_password
        }
    }
    if ($mail) {
        if (!$smtp) {$smtp = Read-Host "Enter the FQDN or IP address of an SMTP server"}
        if (!$email) {$email = Read-Host "Enter a comma separated list of email addresses to notify"}
    }
#endregion

#region processing
    #region check we have the data we need
        #TODO check reference_data (if it exists) and validate entries
        #TODO ELSE prompt prism to see if we are the primary or dr site
    #endregion
    
    #region check prism connectivity
        #TODO check if primary site is available (IF yes and unplanned, then error out)
        #TODO check if dr site is available (IF not, error out)
    #endregion
    
    #region additional checks before proceeding with failover
        #TODO check protection domain exists, figure out remote site
            #* code reuse
        #TODO check remote site exists
            #* code reuse
        #TODO if MAIL, send notification email
    #endregion
    
    #region failover pd
        #TODO migrate or activate protection domain
            #* code reuse
        #TODO check status of pd migration/activation
            #* code reuse
        #TODO if MAIL, send notification email
    #endregion
    
    #region activate file server
        #TODO activate file server (prompting for info if no reference)
        #TODO check on file server activation task status
        #TODO if MAIL, send notification email
    #endregion
    
    #region update DNS
        #TODO if DNS, send API call to update DNS
        #TODO check on DNS update task status
        #TODO if MAIL, send notification email
    #endregion

    #region print final file server status
        #TODO get file server status
        #TODO if MAIL, send notification email
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
    Remove-Variable username -ErrorAction SilentlyContinue
    Remove-Variable password -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion