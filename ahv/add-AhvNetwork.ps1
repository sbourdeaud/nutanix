<#
.SYNOPSIS
  This script can be used to add or remove an AHV network to a specified AHV vswitch.
.DESCRIPTION
  Given a Nutanix cluster, a network name, a vlan ID, a description and a virtual switch, add or remove the AHV network using Prism Element REST API.
.PARAMETER prism
  IP address or FQDN of Prism Element.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER network
  Name of the network to add.  You can also specify a csv file path. The csv file must have the following headers and information for each network to add: network_name,vlan_id,vswitch_name,description.
.PARAMETER id
  VLAN id of the network.
.PARAMETER description
  Description of the network.
.PARAMETER vswitch
  Name of the AHV virtual switch where the network should be added (exp: br1).
.PARAMETER uuid
  Uuid of the AHV network you want to remove (use -get to figure that out if needed). This is an alternative way to specify the network you want to remove when the name matches multiple instances.
.PARAMETER add
  Adds the specified network.
.PARAMETER remove
  Removes the specified network.
.PARAMETER get
  Retrieves and displays the specified network. (wip)
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\add-AhvNetwork.ps1 -prism 10.10.10.1 -prismCreds myuser -network mynetwork -id 100 -description "This is my network" -vswitch br1 -add
Adds the network mynetwork with vlan id 100 to the AHV br1 virtual switch on cluster 10.10.10.1.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region Parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$prism,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [string]$network,
      [parameter(mandatory = $false)] [Int32]$vlanid,
      [parameter(mandatory = $false)] [string]$description,
      [parameter(mandatory = $false)] [string]$vswitch,
      [parameter(mandatory = $false)] [string]$uuid,
      [parameter(mandatory = $false)] [switch]$get,
      [parameter(mandatory = $false)] [switch]$add,
      [parameter(mandatory = $false)] [switch]$remove
  )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
01/15/2020 sb   Initial release.
04/01/2020 sb   Do-over to use sbourdeaud module for functions to facilitate future maintenance.
01/14/2021 sb   Added ability to specify -network as a csv file to enable mass creation.
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\add-AhvNetwork.ps1"
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

    #region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $false)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string]$method,

            [parameter(mandatory = $false)]
            [string]$url,

            [parameter(mandatory = $false)]
            [string]$payload,

            [parameter(mandatory = $false)]
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

            [parameter(mandatory = $false)]
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

            [parameter(mandatory = $false)]
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
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
     
    #let's initialize parameters if they haven't been specified
    if ((!$add) -and !($remove) -and !($get)) {throw "You must specify either get, add or remove!"}
    if ($add -and $remove) {throw "You must specify either add or remove but not both!"}
    if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}

    if (!$network) {$network = read-host "Enter the network name or the path to a csv file to import"}
    else 
    {
        if ($network.contains(".csv")) 
        {#-network is a csv file
            if (Test-Path -Path $network) 
            {#file exists
                $myvar_network_list = Import-Csv -Path $network
            }
            else 
            {#file does not exist
                throw "The specified csv file $($network) does not exist!"
            }
        } 
        else 
        {#-network is not a csv file
            if ($add -and (!$description)) {$description = read-host "Enter a description for the network"}
            if ((!$get) -and (!$vswitch)) {$vswitch = read-host "Enter the name of the AHV virtual switch (br0, br1, ...)"}
            if ((!$get) -and (!$vlanid)) {$vlanid = read-host "Enter the vlan id"}
            #build network_list from parameters:
            $myvar_network_list = [ordered]@{
                "network_name" = $network;
                "vlan_id" = $vlanid;
                "vswitch_name" = $vswitch;
                "description" = $description
            }
        }
    }

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
#endregion


#region processing

    #! -add
    #region -add
    if ($add) {
        foreach ($myvar_ahv_network in $myvar_network_list) 
        {#process each entry in $myvar_network_list
            #region prepare api call
            $api_server = $prism
            $api_server_port = "9440"
            $api_server_endpoint = "/PrismGateway/services/rest/v2.0/networks/"
            $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
            $method = "POST"
            $content = @{
                annotation = $myvar_ahv_network.description;
                name = $myvar_ahv_network.network_name;
                vlan_id = $myvar_ahv_network.vlan_id;
                vswitch_name = $myvar_ahv_network.vswitch_name
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            #endregion

            #region make the api call
            Write-Host "$(Get-Date) [INFO] Adding network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) on $prism..." -ForegroundColor Green
            try {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully added network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) on $prism" -ForegroundColor Cyan
            }
            catch {
                $saved_error = $_.Exception.Message
                throw "$(get-date) [ERROR] $saved_error"
            }
            finally {
            }
            #endregion
        }
    }
    #endregion

    #! -remove
    #region -remove
    if ($remove) {
        foreach ($myvar_ahv_network in $myvar_network_list) 
        {#process each entry in $myvar_network_list
            #region get network uuid
                #region prepare api call
                $api_server = $prism
                $api_server_port = "9440"
                $api_server_endpoint = "/PrismGateway/services/rest/v2.0/networks/"
                $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
                $method = "GET"
                #endregion

                #region make the api call
                Write-Host "$(Get-Date) [INFO] Getting details of network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) from $prism..." -ForegroundColor Green
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) from $prism" -ForegroundColor Cyan
                    if (!$uuid) {
                        $network_uuid = ($resp.entities | Where-Object {$_.name -eq $myvar_ahv_network.network_name} | Where-Object {$_.vswitch_name -eq $myvar_ahv_network.vswitch_name} | Where-Object {$_.vlan_id -eq $myvar_ahv_network.vlan_id}).uuid
                        if (!$network_uuid) {
                            Write-Host "$(Get-Date) [ERROR] Could not find network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) on $prism!" -ForegroundColor Red
                            exit
                        }
                        if ($network_uuid -is [array]) {
                            Write-Host "$(Get-Date) [ERROR] There are multiple instances of network $($myvar_ahv_network.network_name) on vswitch $($myvar_ahv_network.vswitch_name) on $prism!" -ForegroundColor Red
                            exit
                        }
                    } else {$network_uuid = $uuid}
                }
                catch {
                    $saved_error = $_.Exception.Message
                    throw "$(get-date) [ERROR] $saved_error"
                }
                finally {
                }
                #endregion
            #endregion
            #region delete network
                #region prepare api call
                $api_server = $prism
                $api_server_port = "9440"
                $api_server_endpoint = "/PrismGateway/services/rest/v2.0/networks/{0}" -f $network_uuid
                $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
                $method = "DELETE"
                #endregion

                #region make the api call
                Write-Host "$(Get-Date) [INFO] Deleting network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) on $prism..." -ForegroundColor Green
                try {
                    $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(Get-Date) [SUCCESS] Successfully deleted network $($myvar_ahv_network.network_name) with vlan id $($myvar_ahv_network.vlan_id) on vswitch $($myvar_ahv_network.vswitch_name) on $prism" -ForegroundColor Cyan
                }
                catch {
                    $saved_error = $_.Exception.Message
                    throw "$(get-date) [ERROR] $saved_error"
                }
                finally {
                }
                #endregion
            #endregion
        }
    }
    #endregion

    #! -get
    #region -get
    if ($get) {
        #region get network details
            #region prepare api call
            $api_server = $prism
            $api_server_port = "9440"
            $api_server_endpoint = "/PrismGateway/services/rest/v2.0/networks/"
            $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, $api_server_endpoint
            $method = "GET"
            #endregion

            #region make the api call
            Write-Host "$(Get-Date) [INFO] Getting details of network $network with vlan id $vlanid on vswitch $vswitch from $prism..." -ForegroundColor Green
            try {
                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved details of network $network with vlan id $vlanid on vswitch $vswitch from $prism" -ForegroundColor Cyan
                $network_details = $resp.entities | Where-Object {$_.name -eq $network}
                ForEach ($network_entry in $network_details) {
                    Write-Host "Network Name: $($network_entry.name)" -ForegroundColor White
                    Write-Host "VLAN id: $($network_entry.vlan_id)" -ForegroundColor White
                    Write-Host "vSwitch: $($network_entry.vswitch_name)" -ForegroundColor White
                    Write-Host "Description: $($network_entry.annotation)" -ForegroundColor White
                    Write-Host "Uuid: $($network_entry.uuid)" -ForegroundColor White
                    Write-Host
                }
            }
            catch {
                $saved_error = $_.Exception.Message
                throw "$(get-date) [ERROR] $saved_error"
            }
            finally {
            }
            #endregion
        #endregion
    }
    #endregion

#endregion processing


#region cleanup	
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable network_uuid -ErrorAction SilentlyContinue
    Remove-Variable network -ErrorAction SilentlyContinue
    Remove-Variable vswitch -ErrorAction SilentlyContinue
    Remove-Variable vlanid -ErrorAction SilentlyContinue
    Remove-Variable description -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable add -ErrorAction SilentlyContinue
    Remove-Variable remove -ErrorAction SilentlyContinue
    Remove-Variable get -ErrorAction SilentlyContinue
    Remove-Variable uuid -ErrorAction SilentlyContinue
#endregion