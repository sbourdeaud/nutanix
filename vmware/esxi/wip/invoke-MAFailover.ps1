<#
.SYNOPSIS
  This script is used to trigger a planned failover for the specified metro availability protection domains on the specified cluster.
.DESCRIPTION
  The script will look at the Metro Availability setup for a pair of given Nutanix clusters and will create DRS affinity groups and rules so that VMs will run on hosts which hold the active copy of a given replicated datastore. This is to avoid I/O going over two sites in normal conditions.  If DRS groups and rules already exist that match the naming convention used in this script, then it will update those groups and rules (unless you use the -noruleupdate switch in which case only groups will be updated).  This script requires having both the Nutanix cmdlets and PowerCLI installed.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER pd
  Nutanix metro availability protection domain name (can be "all" or a comma separated list).
.PARAMETER action
  This defines what status the Nutanix cluster is left in. If not specified, the Nutanix cluster will be left as is.  If "maintenance", any remaiing UVMs will be powered off, then the Nutanix cluster will be stopped, the CVMs shut down and the ESXi hosts put in maintenance mode.  If "shutdown", UVMs will be powered off, the Nutanix cluster stopped, CVMs shut down, ESXI hosts put in maintenance mode and then powered off.
.PARAMETER username
  Username used to connect to the Nutanix clusters.
.PARAMETER password
  Password used to connect to the Nutanix clusters.
.PARAMETER prismCreds
  Specifies a custom credentials file name for Prism authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
.PARAMETER vcenterCreds
  Specifies a custom credentials file name for vCenter authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). The first time you run it, it will prompt you for a username and password, and will then store this information encrypted locally (the info can be decrupted only by the same user on the machine where the file was generated).
.EXAMPLE
.\invoke-MAFailover.ps1 -cluster c1.local -username admin -password nutanix/4u -pd all -action maintenance
Trigger a manual failover of all metro protection domains and put esxi hosts in maintenance mode:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: November 3rd 2020
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$cluster,
	[parameter(mandatory = $false)] [string]$pd,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $false)] $vcenterCreds,
    [parameter(mandatory = $false)] [string][ValidateSet("maintenance","shutdown")]$action
)
#endregion

#region functions
#this function is used to connect to Prism REST API
Function Invoke-PrismRESTCall
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
                $headers = @{
                    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
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
}#end function Get-PrismRESTCall

#Function Get-RESTError
Function Get-RESTError 
{
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();

    return $global:responsebody

    break
}#end function Get-RESTError

#this function is used to create saved credentials for the current user
function Set-CustomCredentials 
{
#input: path, credname
	#output: saved credentials file
<#
.SYNOPSIS
  Creates a saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to create a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Set-CustomCredentials -path c:\creds -credname prism-apiuser
Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
#>
	param
	(
		[parameter(mandatory = $false)]
        [string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Set path to $path" -ForegroundColor Green
        } 
    }
    process
    {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
		$credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
		
		#put details in hashed format
		$user = $credentials.UserName
		$securePassword = $credentials.Password
        
        #convert secureString to text
        try 
        {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch 
        {
            throw "$(get-date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        #create directory to store creds if it does not already exist
        if(!(Test-Path $path))
		{
            try 
            {
                $result = New-Item -type Directory $path -ErrorAction Stop
            } 
            catch 
            {
                throw "$(get-date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
		}

        #save creds to file
        try 
        {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try 
        {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(get-date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan                
    }
    end
    {}
}#end function Set-CustomCredentials

#this function is used to retrieve saved credentials for the current user
function Get-CustomCredentials 
{
#input: path, credname
	#output: credential object
<#
.SYNOPSIS
  Retrieves saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Get-CustomCredentials -path c:\creds -credname prism-apiuser
Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
#>
	param
	(
        [parameter(mandatory = $false)]
		[string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        } 
    }
    process
    {
        $credentialsFilePath = "$path\$credname.txt"
        if(!(Test-Path $credentialsFilePath))
	    {
            throw "$(get-date) [ERROR] Could not access file $credentialsFilePath : $($_.Exception.Message)"
        }

        $credFile = Get-Content $credentialsFilePath
		$user = $credFile[0]
		$securePassword = $credFile[1] | ConvertTo-SecureString

        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(get-date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan 
    }
    end
    {
        return $customCredentials
    }
}#end function Get-CustomCredentials

#this function is used to create a VM to host DRS rule
Function Update-DRSVMToHostRule
{
<#
.SYNOPSIS
  Creates a new DRS VM to host rule
.DESCRIPTION
  This function creates a new DRS vm to host rule
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VMGroup
  The VMGroup name to include in the rule.
.PARAMETER HostGroup
  The VMHostGroup name to include in the rule.
.PARAMETER Cluster
  The cluster to create the new rule on.
.PARAMETER Name
  The name for the new rule.
.PARAMETER AntiAffine
  Switch to make the rule an AntiAffine rule. Default rule type is Affine.
.PARAMETER Mandatory
  Switch to make the rule mandatory (Must run rule). Default rule is not mandatory (Should run rule)
.EXAMPLE
  PS> New-DrsVMToHostRule -VMGroup "VMGroup01" -HostGroup "HostGroup01" -Name "VMToHostRule01" -Cluster CL01 -AntiAffine -Mandatory
#>

    Param(
        [parameter(mandatory = $true,
        HelpMessage = "Enter a VM DRS group name")]
            [String]$VMGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a DRS rule key")]
            [String]$RuleKey,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a DRS rule uuid")]
            [String]$RuleUuid,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a host DRS group name")]
            [String]$HostGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name,
            [Switch]$AntiAffine,
            [Switch]$Mandatory)

    switch ($Cluster.gettype().name) {
        "String" {$cluster = Get-Cluster $cluster | Get-View}
        "ClusterImpl" {$cluster = $cluster | Get-View}
        "Cluster" {}
        default {throw "No valid type for parameter -Cluster specified"}
    }

    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $rule = New-Object VMware.Vim.ClusterRuleSpec
    $rule.operation = "edit"
    $rule.info = New-Object VMware.Vim.ClusterVmHostRuleInfo
    $rule.info.enabled = $true
    $rule.info.name = $Name
    $rule.info.mandatory = $Mandatory
    $rule.info.vmGroupName = $VMGroup
    $rule.info.Key = $RuleKey
    $rule.info.RuleUuid = $RuleUuid
    if ($AntiAffine) {
        $rule.info.antiAffineHostGroupName = $HostGroup
    }
    else {
        $rule.info.affineHostGroupName = $HostGroup
    }
    $spec.RulesSpec += $rule
    $cluster.ReconfigureComputeResource_Task($spec,$true) | Out-Null
}#end function Update-DRSVMToHostRule
#endregion

#! add posh-ssh module import
#region prepwork
    Write-Host ""
    Write-Host "$(get-date) [STEP] Checking PowerShell configuration ..." -ForegroundColor Magenta
    $HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 11/03/2020 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\invoke-MAFailover.ps1"

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

    #check if we have all the required PoSH modules
    Write-Host "$(get-date) [INFO] Checking for required Powershell modules..." -ForegroundColor Green
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

    # ignore SSL warnings
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
    }
    [ServerCertificateValidationCallback]::Ignore()
    # add Tls12 support
    Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
    [Net.ServicePointManager]::SecurityProtocol = `
    ([Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12)

    #set some runtime variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$pd_list = New-Object System.Collections.ArrayList($null)

#endregion

#todo make -pd "all" if action was specified
#todo process pd as a list if it is not equal to "all"
#region parameters validation       
    Write-Host "$(get-date) [STEP] Validating parameters ..." -ForegroundColor Magenta
    if (!$cluster) 
    {#prompt for the Nutanix cluster name
        $cluster = read-host "Enter the hostname or IP address of the Nutanix cluster"
    }

    if (!$pd) 
    {#prompt for the Nutanix protection domain name
        $pd = read-host "Enter the name of the protection domain to failover. You can also specify 'all' or a list of names separated by a comma"
    }
    if ($pd -ne "all") {$pd_names_list = $pd.Split(",")}

    if ($action -and ($pd -ne "all"))
    {#check that we are not trying to failover only some protection domains while putting esxi hosts in maintenance or shutting them down
        Throw "$(get-date) [ERROR] If you specify an action, you MUST use 'all' for protection domain as this otherwise would leave VMs on the cluster."
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
            Set-CustomCredentials -credname $prismCreds
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }

    if ($vcenterCreds) {
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

#endregion

#region execute
    Write-Host ""
    Write-Host "$(get-date) [STEP] Retrieving information from the Nutanix cluster and checking pre-requisites conditions are met ..." -ForegroundColor Magenta
    #region get info and check pre-requisites
        #* testing connection to prism
        #region GET cluster
        Write-Host "$(get-date) [INFO] Retrieving cluster information from Nutanix cluster $myvarNutanixCluster ..." -ForegroundColor Green
        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/cluster/" -f $cluster
        $method = "GET"
        try 
        {
            $myvarNTNXClusterInfo = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        }
        catch
        {
            throw "$(get-date) [ERROR] Could not retrieve cluster information from Nutanix cluster $myvarNutanixCluster : $($_.Exception.Message)"
        }
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved cluster information from Nutanix cluster $myvarNutanixCluster" -ForegroundColor Cyan
        #endregion
        
        #* getting cluster name and vcenter ip, checking DRS is enabled
        #region assign cluster name and vcenter ip
        $myvarNTNXClusterName = $myvarNTNXClusterInfo.name
        Write-Host "$(get-date) [DATA] Nutanix cluster name is $($myvarNTNXClusterName)" -ForegroundColor White
        if (($myvarNTNXClusterInfo.management_servers | where {$_.management_server_type -eq "vcenter"}).count -ne 1) {#houston, we have a problem, there is more than one registered vcenter
            Throw "$(get-date) [ERROR] There is more than 1 registered management server for cluster $($cluster). Exiting."
        } else {
            $myvarvCenterIp = ($myvarNTNXClusterInfo.management_servers | where {$_.management_server_type -eq "vcenter"}).ip_address
            Write-Host "$(get-date) [DATA] vCenter IP address for Nutanix cluster $($myvarNTNXClusterName) is $($myvarvCenterIp)" -ForegroundColor White
            if (!($myvarNTNXClusterInfo.management_servers | where {$_.management_server_type -eq "vcenter"}).drs_enabled) {#houston we have a problem, drs is not enabled on this cluster
                Throw "$(get-date) [ERROR] DRS is not enabled on vCenter $($myvarvCenterIp). Exiting."
            } else {
                Write-Host "$(get-date) [DATA] DRS is enabled on vCenter $($myvarvCenterIp)" -ForegroundColor White
            }
        }
        #endregion

        #* getting hosts ips
        #region GET hosts
        Write-Host "$(get-date) [INFO] Retrieving hosts information from Nutanix cluster $($cluster) ..." -ForegroundColor Green
        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/hosts/" -f $cluster
        $method = "GET"
        try 
        {
            $myvarNTNXHosts = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        }
        catch
        {
            throw "$(get-date) [ERROR] Could not retrieve hosts information from Nutanix cluster $(cluster) : $($_.Exception.Message)"
        }
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved hosts information from Nutanix cluster $($cluster)" -ForegroundColor Cyan
        $myvarNTNXHosts = ($myvarNTNXHosts.entities).hypervisor_address
        #endregion

        #* getting protection domains and checking they are active on this cluster, then build $pd_list
        #region GET protection_domains
        Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $($cluster) ..." -ForegroundColor Green
        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/protection_domains/" -f $cluster
        $method = "GET"
        try 
        {
            $myvarMaActivePDs = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        }
        catch
        {
            throw "$(get-date) [ERROR] Could not retrieve protection domains from Nutanix cluster $($cluster) : $($_.Exception.Message)"
        }
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $($cluster)" -ForegroundColor Cyan
        $myvarNtnxMaActiveCtrs = ($myvarMaActivePDs.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}).metro_avail.storage_container
        $myvarNtnxMaActivePds = $myvarMaActivePDs.entities | Where-Object {($_.active -eq $true) -and ($_.metro_avail.role -eq "Active")}
        if ($pd -eq "all") {
            $myvar_pd_list_details = $myvarNtnxMaActivePds
            foreach ($myvar_pd_detail in $myvar_pd_list_details) {
                $myvar_pd_info = [ordered]@{
                    "name" = $myvar_pd_detail.name;
                    "role" = $myvar_pd_detail.metro_avail.role;
                    "remote_site" = $myvar_pd_detail.metro_avail.remote_site;
                    "storage_container" = $myvar_pd_detail.metro_avail.storage_container;
                    "status" = $myvar_pd_detail.metro_avail.status;
                    "failure_handling" = $myvar_pd_detail.metro_avail.failure_handling
                }
                $pd_list.Add((New-Object PSObject -Property $myvar_pd_info)) | Out-Null
            }
        } else {#make sure all specified protection domain is indeed active on this cluster
            foreach ($pd_name in $pd_names_list) {
                if ($myvarNtnxMaActivePds.name -notcontains $pd_name) {
                    Throw "$(get-date) [ERROR] Protection domain $($pd_name) was not found active on cluster $($cluster). Exiting."
                } else {
                    Write-Host "$(get-date) [DATA] Protection domain $($pd_name) was found active on Nutanix cluster $($cluster)" -ForegroundColor White
                    $myvar_pd_details = $myvarNtnxMaActivePds | Where-Object {$_.name -eq $pd_name}
                    $myvar_pd_info = [ordered]@{
                        "name" = $myvar_pd_details.name;
                        "role" = $myvar_pd_details.metro_avail.role;
                        "remote_site" = $myvar_pd_details.metro_avail.remote_site;
                        "storage_container" = $myvar_pd_details.metro_avail.storage_container;
                        "status" = $myvar_pd_details.metro_avail.status;
                        "failure_handling" = $myvar_pd_details.metro_avail.failure_handling
                    }
                    $pd_list.Add((New-Object PSObject -Property $myvar_pd_info)) | Out-Null
                }
            }
        }
        #endregion

        #* getting remote site name and ip address
        #region GET remote_sites
        #* get remote site name ($remote_site_name) and make sure it is unique across all protection domains
        if (($pd_list.remote_site | select-object -unique).count -ne 1) {#houston we have a problem: active metro pds are pointing to more than one remote site!
            Throw "$(get-date) [ERROR] Cluster $($cluster) has metro availability protection domains which are pointing to different remote sites. Exiting."
        } else {
            $remote_site_name = $pd_list.remote_site | select-object -unique
            Write-Host "$(get-date) [DATA] Remote site name is $($remote_site_name)" -ForegroundColor White
        }
        #* query prism for remote sites
        Write-Host "$(get-date) [INFO] Retrieving remote sites from Nutanix cluster $($cluster) ..." -ForegroundColor Green
        $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/remote_sites/" -f $cluster
        $method = "GET"
        try 
        {
            $myvar_remote_sites = Invoke-PrismRESTCall -method $method -url $url -credential $prismCredentials
        }
        catch
        {
            throw "$(get-date) [ERROR] Could not retrieve remote sites from Nutanix cluster $($cluster) : $($_.Exception.Message)"
        }
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved remote sites from Nutanix cluster $($cluster)" -ForegroundColor Cyan
        #* grab ip for our remote site
        $myvar_remote_site_ip = (($myvar_remote_sites.entities | Where-Object {$_.name -eq $remote_site_name}).remote_ip_ports).psobject.properties.name
        Write-Host "$(get-date) [DATA] Remote site $($remote_site_name) ip address is $($myvar_remote_site_ip)" -ForegroundColor White
        #endregion

        #todo can we connect to vcenter?

        #todo if action was specified, can we ssh to cvm using cluster ip?
        
    #endregion

    #region move vms using drs
        #todo find matching drs rule(s)
        #todo update matching drs rule(s)
        #todo loop on vmotion status (until all vms have been moved)
    #endregion

    #region planned failover of the protection domain(s)
        #todo trigger pd activation on remote
        #todo disable pd on cluster
        #todo re-enable pd on remote
    #endregion

    #region maintenance
    #endregion

    #region shutdown
    #endregion
#endregion