<#
.SYNOPSIS
This script configures a Nutanix cluster after Foundation.

.DESCRIPTION
This is a detailed description of what the script does and how it is used.

.PARAMETER Log
Specifies that you want to log all output to a log file in addition to the console. The log file will be <TimeStamp>-Output.log in the current directory.

.PARAMETER DebugMe
Turns off SilentlyContinue for errors and warnings.

.PARAMETER VerboseOutput
Turns off SilentlyContinue for Write-Verbose.

.PARAMETER Prism
Url to the Prism Element of the Nutanix cluster you want to configure.

.PARAMETER Username
Username for Prism Element.

.PARAMETER Password
Password for the Prism Element user.

.PARAMETER Online
Use this switch once the Nutanix cluster has been foundationed and is connected to the production network.  This assumes that VLANs and LACP has been configured already.
This switch cannot be used with -Offline.

.PARAMETER Offline
Use this switch when you are still connected on your private switch and you need to configure VLANs and/or LACP before you can connect the servers to the production network.
This is default scipt behavior.
This switch cannot be used with -Online or -DataProtection.

.PARAMETER DataProtection
Use this switch when you have VMs running on the Nutanix cluster and you are ready to setup Protection Domains (async or metro).
This switch cannot be used with -Offline.

.EXAMPLE
.\SetNutanixClusterConfiguration.ps1 -Cluster ntnxc1.local -Username admin -Password admin -Offline

Start configuring a cluster when still connected to the private switch, right after Foundation.

.LINK
https://github.com/sbourdeaud/nutanix

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
Revision: May 17th 2017
#>

#region parameters
    [cmdletbinding(DefaultParameterSetName=’ByOffline’)]
    Param
    (   
        [Parameter(mandatory = $false)]
        [Switch]
        $Log,

        [Parameter(mandatory = $false)]
        [Switch]
        $DebugMe,

        [Parameter(mandatory = $false)]
        [Switch]
        $VerboseOutput,

        [Parameter(mandatory = $false)]
        [String]
        $ConfigPath,

        [Parameter(mandatory = $false)]
        [String]
        $PrismUsername,

        [Parameter(mandatory = $false)]
        [String]
        $PrismPassword,

        [Parameter(mandatory = $false,ParameterSetName = "ByOnline")]
        [Switch]
        $Online,

        [Parameter(mandatory = $false, ParameterSetName = "ByOffline")]
        [Switch]
        $Offline

    )
#endregion
#region variables

    #keeping track of when we're starting this script
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    
    if ($Log) #if user wants to log to a file, configure the file name
    {
        $LogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $LogFile += "OutputLog.log"
    }

    #handle output based on -debugme and -verbose parameters. By default, the script will ignore all error, warning and verbose messages
    if (!$DebugMe) {$ErrorActionPreference = 'SilentlyContinue'} else {$ErrorActionPreference = 'Continue'}
    if (!$DebugMe) {$WarningPreference = 'SilentlyContinue'} else {$WarningPreference = 'Continue'}
    if (!$VerboseOutput) {$VerbosePreference = 'SilentlyContinue'} else {$VerbosePreference = 'Continue'}

    #let's deal with the password
    if (!$PrismPassword) #if it was not passed as an argument, let's prompt for it
    {
        $PrismSecurePassword = read-host "Enter the Prism admin user password" -AsSecureString
    }
    else #if it was passed as an argument, let's convert the string to a secure string and flush the memory
    {
        $PrismSecurePassword = ConvertTo-SecureString $PrismPassword –asplaintext –force
        Remove-Variable PrismPassword
    }
    if (!$PrismUsername) {
        $PrismUsername = "admin"
    }#endif not username

    if (!$Online -and !$Offline) {Write-LogOutput -Category ERROR -Message "You must specify either -online or -offline!" -LogFile $LogFile; Exit}
    if (!$ConfigPath) {$ConfigPath = $pwd.Path}

    #CONSTANTS
    $BasicConfigFileName = "basic-config.csv"
    $vSwitchConfigFileName = "vswitch-config.csv"
    $ComputeConfigFileName = "compute-config.csv"
    $PrismConfigFileName = "prism-config.csv"
    $vMotionConfigFileName = "vmotion-config.csv"

#endregion
#region prepwork

    #process requirements (PoSH version and modules)
    Write-LogOutput -Category INFO -Message "Checking the Powershell version..." -LogFile $LogFile
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-LogOutput -Category WARNING -Message "Powershell version is less than 5. Trying to upgrade from the web..." -LogFile $LogFile
        $ChocoVersion = choco
        if (!$ChocoVersion) {
            Write-LogOutput -Category WARNING -Message "Chocolatey is not installed!" -LogFile $LogFile
            [ValidateSet('y','n')]$ChocoInstall = Read-Host "Do you want to install the chocolatey package manager? (y/n)"
            if ($ChocoInstall -eq "y") {
                Write-LogOutput -Category INFO -Message "Downloading and running chocolatey installation script from chocolatey.org..." -LogFile $LogFile
                iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                Write-LogOutput -Category INFO -Message "Downloading and installing the latest Powershell version from chocolatey.org..." -LogFile $LogFile
                choco install -y powershell
            } else {
                Write-LogOutput -Category ERROR -Message "Please upgrade to Powershell v5 or above manually (https://www.microsoft.com/en-us/download/details.aspx?id=54616)" -LogFile $LogFile
                Exit
            }#endif choco install
        }#endif not choco
    }#endif PoSH version
    Write-LogOutput -Category INFO -Message "Checking for required Powershell modules..." -LogFile $LogFile
    if (!(Get-Module -Name sbourdeaud)) {
        Write-LogOutput -Category INFO -Message "Importing module 'sbourdeaud'..." -LogFile $LogFile
        try
        {
            Import-Module -Name sbourdeaud -ErrorAction Stop
            Write-LogOutput -Category INFO -Message "Imported module 'sbourdeaud'..." -LogFile $LogFile
        }#end try
        catch #we couldn't import the module, so let's download it
        {
            Write-LogOutput -Category INFO -Message "Downloading module 'sbourdeaud' from github..." -LogFile $LogFile
            $ModulesPath = ($env:PsModulePath -split ";")[0]
            $MyModulePath = "$ModulesPath\sbourdeaud"
            New-Item -Type Container -Force -path $MyModulePath | out-null
            (New-Object net.webclient).DownloadString("https://raw.github.com/sbourdeaud/modules/master/sbourdeaud.psm1") | Out-File "$MyModulePath\sbourdeaud.psm1" -ErrorAction Continue
            (New-Object net.webclient).DownloadString("https://raw.github.com/sbourdeaud/modules/master/sbourdeaud.psd1") | Out-File "$MyModulePath\sbourdeaud.psd1" -ErrorAction Continue

            try
            {
                Import-Module -Name sbourdeaud -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Imported module 'sbourdeaud'..." -LogFile $LogFile
            }#end try
            catch #we couldn't import the module
            {
                Write-Host "ERROR: Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Please download and install from https://github.com/sbourdeaud/modules" -ForegroundColor Yellow
                Exit
            }#end catch
        }#end catch
    }#endif module sbourdeaud
    if (!(Get-Module -Name VMware.PowerCLI)) {
        Write-LogOutput -Category INFO -Message "Importing module 'VMware.PowerCLI'..." -LogFile $LogFile
        try
        {
            Import-Module VMware.PowerCLI -ErrorAction Stop
            Write-LogOutput -Category INFO -Message "Imported module 'VMware.PowerCLI'..." -LogFile $LogFile
        }#end try
        catch #we couldn't import the module, so let's download it
        {
            Write-LogOutput -Category WARNING -Message "Could not import the VMware.PowerCLI module. Trying to install from the web..." -LogFile $LogFile
            try {
                Install-Module -Name VMware.PowerCLI -Scope CurrentUser
                Write-LogOutput -Category INFO -Message "Installed module 'VMware.PowerCLI'..." -LogFile $LogFile
                Write-LogOutput -Category INFO -Message "Importing module 'VMware.PowerCLI'..." -LogFile $LogFile
                try {
                    Import-Module VMware.PowerCLI -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Imported module 'VMware.PowerCLI'..." -LogFile $LogFile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Unable to import the module VMware.PowerCLI : $($_.Exception.Message)" -Logfile $Logfile
                    Write-LogOutput -Category WARNING -Message "Please download and install from https://my.vmware.com/en/web/vmware/details?downloadGroup=PCLI650R1&productId=614" -LogFile $LogFile
                    Exit
                }#end catch
            }#end try
            catch {
                Write-LogOutput -Category ERROR -Message "Unable to import the module VMware.PowerCLI : $($_.Exception.Message)" -Logfile $Logfile
                Write-LogOutput -Category WARNING -Message "Please download and install from https://my.vmware.com/en/web/vmware/details?downloadGroup=PCLI650R1&productId=614" -LogFile $LogFile
                Exit
            }#end catch
        }#end catch
    }#endif module VMware.PowerCLI
    if (!(Get-Module -Name SSHSessions)) {
        Write-LogOutput -Category INFO -Message "Importing module 'SSHSessions'..." -LogFile $LogFile
        try {
            Import-Module SSHSessions -ErrorAction Stop
            Write-LogOutput -Category INFO -Message "Imported module 'SSHSessions'..." -LogFile $LogFile
        }#end try
        catch {
            Write-LogOutput -Category INFO -Message "Downloading module 'SSHSessions' from the web..." -LogFile $LogFile
            try {
                powershellget\Install-Module SSHSessions -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Installed module 'SSHSessions'." -LogFile $LogFile
                try {
                    Import-Module SSHSessions -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Imported module 'SSHSessions'..." -LogFile $LogFile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Unable to import the module SSHSessions : $($_.Exception.Message)" -Logfile $Logfile
                    Exit
                }#end catch
            }#end try
            catch {
                Write-LogOutput -Category ERROR -Message "Unable to import the module SSHSessions : $($_.Exception.Message)" -Logfile $Logfile
                Exit
            }#end catch
        }#end catch
    }#endif module SSHSessions

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

#region functions



#endregion

#region processing
    
    #region offline
        
        #region get required input

        #gather input from csv
        Write-LogOutput -Category INFO -Message "Importing basic configuration information from $($ConfigPath + $BasicConfigFileName)..." -Logfile $Logfile
        try {
            $BasicConfig = Import-Csv -Path ($ConfigPath + $BasicConfigFileName) -Delimiter ";" -ErrorAction Stop
        }#end try
        catch {
            Write-LogOutput -Category ERROR -Message "Could not find $BasicConfigFileName in $ConfigPath : $($_.Exception.Message)" -Logfile $Logfile
            Exit
        }#end catch

        #get nutanix cluster configuration
        Write-LogOutput -Category INFO -Message "Retrieving cluster information for $($BasicConfig.cluster_ip)..." -Logfile $Logfile
        $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        try {
            $NutanixCluster = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -ErrorAction Stop
            Write-LogOutput -Category INFO -Message "Successfully retrieved cluster information from $($BasicConfig.cluster_ip)..." -Logfile $Logfile
        }#end try
        catch {
            Write-LogOutput -Category ERROR -Message "Could not find retrieve cluster information for $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
            Exit
        }#end catch

        #endregion

        #region build json body for cluster/patch request
        $body = @{
            clusterUuid=$NutanixCluster.cluster_uuid;
            genericDTO=@{
                name=$NutanixCluster.name;
                clusterExternalDataServicesIPAddress=$BasicConfig.data_services_ip;
                timezone=$BasicConfig.timezone
            };
            operation="EDIT"
        }
        $body = ConvertTo-Json $body
        #endregion

        #region configure Nutanix cluster

        #region configure timezone and external data services ip
        if (($NutanixCluster.cluster_external_data_services_ipaddress -eq $BasicConfig.data_services_ip) -and ($NutanixCluster.timezone -eq $BasicConfig.timezone)) {
            Write-LogOutput -Category WARNING -Message "Cluster $($BasicConfig.cluster_ip) already has the correct data services IP and timezone. Skipping..." -Logfile $Logfile
        }
        else
        {
            Write-LogOutput -Category INFO -Message "Configuring cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
            $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v1/cluster/"
            $method = "PATCH"
            try {
                $RESTCall = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -body $body -ErrorAction Stop
                Write-LogOutput -Category INFO -Message "Successfully configured the timezone ($($BasicConfig.timezone)) and cluster external data services ip ($($BasicConfig.data_services_ip)) for cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
            }#end try
            catch {
                Write-LogOutput -Category ERROR -Message "Could not configure cluster $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
                Exit
            }#end catch
        }#endif already configured
        #endregion

        #region configure name servers
        if (($NutanixCluster.name_servers -Join ",") -notmatch $BasicConfig.dns) {
            if ($NutanixCluster.name_servers) {Write-LogOutput -Category INFO -Message "Removing configured name servers from cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile}
            ForEach ($item in $NutanixCluster.name_servers) {
                $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/cluster/name_servers/" + $item
                $method = "DELETE"
                try {
                    $RESTCall = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Successfully removed DNS server $item from cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Could not remove DNS server $item from cluster $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
                }#end catch
            }#end foreach name server in Prism
            
            Write-LogOutput -Category INFO -Message "Adding name servers to cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
            
            ForEach ($item in (($BasicConfig.dns).Split(","))) {
                $body = @{value = $item}
                $body = ConvertTo-Json $body
                $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/cluster/name_servers"
                $method = "POST"
                try {
                    $RESTCall = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -body $body -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Successfully added DNS server $item to cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Could not add DNS server $item to cluster $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
                    Exit
                }#end catch
            }#end foreach name server
        } 
        else {
            Write-LogOutput -Category WARNING -Message "Name servers on cluster $($BasicConfig.cluster_ip) are already defined. Skipping..." -Logfile $Logfile
        }#endif name servers match?
        #endregion

        #region configure ntp servers...
        if (($NutanixCluster.ntp_servers -Join ",") -notmatch $BasicConfig.ntp) {
            if ($NutanixCluster.ntp_servers) {Write-LogOutput -Category INFO -Message "Removing configured ntp servers from cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile}
            ForEach ($item in $NutanixCluster.ntp_servers) {
                $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/cluster/ntp_servers/" + $item
                $method = "DELETE"
                try {
                    $RESTCall = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Successfully removed ntp server $item from cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Could not remove ntp server $item from cluster $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
                }#end catch
            }#end foreach ntp server in Prism
            Write-LogOutput -Category INFO -Message "Adding ntp servers to cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
            
            ForEach ($item in (($BasicConfig.ntp).Split(","))) {
                $body = @{value = $item}
                $body = ConvertTo-Json $body
                $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/cluster/ntp_servers"
                $method = "POST"
                try {
                    $RESTCall = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -body $body -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Successfully added ntp server $item to cluster $($BasicConfig.cluster_ip)..." -Logfile $Logfile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Could not add ntp server $item to cluster $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
                    Exit
                }#end catch
            }#end foreach ntp server
        } 
        else {
            Write-LogOutput -Category WARNING -Message "Ntp servers on cluster $($BasicConfig.cluster_ip) are already defined. Skipping..." -Logfile $Logfile
        }#endif name servers match?
        #endregion

        #region process container
        #get cluster storage_containers information
        Write-LogOutput -Category INFO -Message "Retrieving storage containers information for $($BasicConfig.cluster_ip)..." -Logfile $Logfile
        $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/storage_containers/"
        $method = "GET"
        try {
            $StorageContainers = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -ErrorAction Stop
            Write-LogOutput -Category INFO -Message "Successfully retrieved storage containers information for $($BasicConfig.cluster_ip)" -Logfile $Logfile
        }#end try
        catch {
            Write-LogOutput -Category ERROR -Message "Could not retrieve storage containers information for $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
            Exit
        }#end catch
        #remove default container
        ForEach ($item in $StorageContainers.entities) {
            if ($item.name -like "*default*") {
                Write-LogOutput -Category INFO -Message "Deleting default container $($item.name) on $($BasicConfig.cluster_ip)..." -Logfile $Logfile
                $url = "https://" + $BasicConfig.cluster_ip + ":9440/PrismGateway/services/rest/v2.0/storage_containers/" + $item.storage_container_uuid
                $method = "DELETE"
                try {
                    $RESTCall = Get-PrismRESTCall -username $PrismUsername -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -url $url -method $method -ErrorAction Stop
                    Write-LogOutput -Category INFO -Message "Successfully deleted default storage container $($item.name) on $($BasicConfig.cluster_ip)" -Logfile $Logfile
                }#end try
                catch {
                    Write-LogOutput -Category ERROR -Message "Could not delete default storage container $($item.name) on $($BasicConfig.cluster_ip) : $($_.Exception.Message)" -Logfile $Logfile
                    Exit
                }#end catch
            }#endif default container
        }#end foreach existing container
        #add container >>>remove container list from basic-config.csv and put it in containers-config.csv to allow for multiple entries<<<
        #add reserved space container (best practice)
        #endregion

        #endregion

        #region configure cvms
        #figure out the date and time
        try {
        }#end try
        catch {
        }#end catch

        #set time and date on cvms
        try {
        }#end try
        catch {
        }#end catch
        #endregion

        #region configure vmhosts

        #set time and date on vmhosts
        try {
        }#end try
        catch {
        }#end catch

        #configure name servers on nutanix cluster
        try {
        }#end try
        catch {
        }#end catch

        #configure name servers on vmhosts
        try {
        }#end try
        catch {
        }#end catch

        #configure domain suffix on vmhosts
        try {
        }#end try
        catch {
        }#end catch

        #configure ntp servers on nutanix cluster
        try {
        }#end try
        catch {
        }#end catch

        #configure ntp servers on vmhosts
        try {
        }#end try
        catch {
        }#end catch

        #remove default container
        try {
        }#end try
        catch {
        }#end catch

        #create new container
        try {
        }#end try
        catch {
        }#end catch

        #stop nutanix cluster
        try {
        }#end try
        catch {
        }#end catch

        #configure vlan tagging for cvms
        try {
        }#end try
        catch {
        }#end catch

        #configure vlan tagging for vmhosts management network
        try {
        }#end try
        catch {
        }#end catch
        #endregion

    #endregion

    #region online

        #region prism configuration
            #add authentication domain
            #add role mapping
            #configure smtp
            #configure alert email recipients
            #configure http proxy
            #configure data services ip
        #endregion

        #region vcenter configuration
            #connect to vCenter server
            #create datacenter
            #create HA/DRS cluster
            #add vmshosts
            #create portgroups
            #copy portgroups
            #add vmotion network
            #disconnect from vCenter server
        #endregion

        #region change passwords
            #change vmhosts root password
            #change cvms nutanix password
            #change prism admin password
        #endregion

    #endregion

#endregion

#region cleanup
    
    #let's figure out how much time this all took
	Write-LogOutput -Category "SUM" -Message "total processing time: $($ElapsedTime.Elapsed.ToString())" -LogFile $LogFile

#endregion