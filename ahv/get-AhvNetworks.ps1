<#
.SYNOPSIS
  This script retrieves the complete list of AHV networks from Prism Central.
.DESCRIPTION
  This script retrieves the complete list of AHV networks from Prism Central, including IP pool information and exports the results to csv in the current directory.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.EXAMPLE
.\get-AhvNetworks.ps1 -cluster ntnxc1.local
Connect to a Nutanix Prism Central of your choice and retrieve the list of networks.
.LINK
  http://github.com/sbourdeaud/nutanix
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
      [parameter(mandatory = $false)] [string]$prismcentral,
      [parameter(mandatory = $false)] $prismCreds
  )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
11/13/2020 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
04/15/2022 sb   Added functions and removed dependency to sbourdeaud module.
################################################################################
'@
    $myvarScriptName = ".\get-AhvNetworks.ps1"

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

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

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
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
    $length = 100 #this specifies how many entities we want in the results of each API query
    $api_server_port = "9440"
#endregion


#region parameters validation
    if (!$prismcentral) {
        Throw "$(Get-Date) [ERROR] You must specify -prismcentral!"
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


#region main processing

    #region make v3 api call for vms using inline pagination
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving VM information from Prism Central $($prismcentral)" -ForegroundColor Magenta
    $content = @{
        kind = "vm";
        offset = 0;
        length = $length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
    $url = "https://{0}:{1}/api/nutanix/v3/vms/list" -f $prismcentral,$api_server_port
    $method = "POST"

    Do {
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            
            $listLength = 0
            if ($resp.metadata.offset) {
                $firstItem = $resp.metadata.offset
            } else {
                $firstItem = 0
            }
            if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                $listLength = $resp.metadata.length
            } else {
                $listLength = $resp.metadata.total_matches
            }
            Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

            ForEach ($entity in $resp.entities) 
            {
                $myvarVmInfo = [ordered]@{
                    "name" = $entity.spec.name;
                    "num_sockets" = $entity.spec.resources.num_sockets;
                    "memory_size_mib" = $entity.spec.resources.memory_size_mib;
                    "power_state" = $entity.spec.resources.power_state;
                    "cluster" = $entity.spec.cluster_reference.name;
                    "hypervisor" = $entity.status.resources.hypervisor_type;
                    "creation_time" = $entity.metadata.creation_time;
                    "owner" = $entity.metadata.owner_reference.name;
                    "vdisk_count" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"}).Count;
                    "vdisk_total_mib" = ($entity.spec.resources.disk_list | where-object {$_.device_properties.device_type -eq "DISK"} | Measure-Object disk_size_mib -Sum).Sum;
                    "vnic_count" = ($entity.spec.resources.nic_list).Count;
                    "vnic_vlans" = (($entity.spec.resources.nic_list | Select-Object -Property subnet_reference).subnet_reference.name) -join ',';
                    "vnic_macs" = (($entity.spec.resources.nic_list | Select-Object -Property mac_address).mac_address) -join ',';
                    "gpu" = $entity.status.resources.gpu_list | Select-Object -First 1;
                    "uuid" = $entity.metadata.uuid
                }
                #store the results for this entity in our overall result variable
                $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
            }

            $content.offset = $resp.metadata.offset + $resp.metadata.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        catch {
            $saved_error = $_.Exception.Message
            Throw "$(get-date) [ERROR] $saved_error"
        }
    }
    While ($content.offset -lt $resp.metadata.total_matches -and $resp.metadata.length -eq $length)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarVmResults
    }
    #endregion

    #region make v3 api call for networks using inline pagination
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving networks information from Prism Central $($prismcentral)" -ForegroundColor Magenta

    [System.Collections.ArrayList]$myvarNetworksResults = New-Object System.Collections.ArrayList($null)
    $api_server_endpoint = "/api/nutanix/v3/subnets/list"
    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
    $method = "POST"
    
    $content = @{
        kind = "subnet";
        offset = 0;
        length = $length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    Do {
        try {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            $listLength = 0
            if ($resp.metadata.offset) {
                $firstItem = $resp.metadata.offset
            } else {
                $firstItem = 0
            }
            if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                $listLength = $resp.metadata.length
            } else {
                $listLength = $resp.metadata.total_matches
            }
            Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    
            #grab the information we need in each entity
            ForEach ($entity in $resp.entities) {
              if ($entity.spec.resources.ip_config)
              {
                #* count here how many ips are available in total by looking at each ip pool: available ips
                [int]$ip_count=0
                ForEach ($range in $entity.spec.resources.ip_config.pool_list.range)
                {
                  $range_list = $range -split " "
                  $start_ip = [System.Net.IPAddress]::Parse($range_list[0]).GetAddressBytes() | ForEach-Object { $_ } | ForEach-Object -Begin { $result = 0 } -Process { $result = ($result * 256) + $_ } -End { $result }
                  $end_ip = [System.Net.IPAddress]::Parse($range_list[1]).GetAddressBytes() | ForEach-Object { $_ } | ForEach-Object -Begin { $result = 0 } -Process { $result = ($result * 256) + $_ } -End { $result }
                  $ip_count += $end_ip - $start_ip + 1
                }
                #* count here how many vms are connected to that network: used ips
                [int]$vm_count=0
                [int]$vm_count = ($myvarVmResults | Where-Object {$_.vnic_vlans -contains $entity.spec.name}).count
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Nb of VMs connected to network $($entity.spec.name): $($vm_count)" -ForegroundColor White}
                
                #convert prefix length to subnet mask
                $prefix = $entity.spec.resources.ip_config.prefix_length
                $mask = 0
                for ($i = 0; $i -lt $prefix; $i++) { $mask = ($mask * 2) + 1 }
                $mask = $mask -shl (32 - $prefix)
                $subnet_mask = [System.Net.IPAddress]::New(($mask[0], $mask[1], $mask[2], $mask[3])).IPAddressToString

                $myvarNetworkInfo = [ordered]@{
                  "network_name" = $entity.spec.name;
                  "network_uuid" = $entity.metadata.uuid;
                  "cluster_name" = $entity.spec.cluster_reference.name;
                  "cluster_uuid" = $entity.spec.cluster_reference.uuid;
                  "vswitch_name" = $entity.spec.resources.vswitch_name;
                  "vlan_id" = $entity.spec.resources.vlan_id;
                  "ipam" = "yes";
                  "default_gw" = $entity.spec.resources.ip_config.default_gateway_ip;
                  "ip_pools" = ($entity.spec.resources.ip_config.pool_list.range) -join ',';
                  "total_available_ips" = $ip_count;
                  "nb_connected_vms" = $vm_count;
                  "remaining_ips" = $ip_count - $vm_count;
                  "subnet_mask_length" = $entity.spec.resources.ip_config.prefix_length;
                  "subnet_mask" = $subnet_mask;
                  "network" = $entity.spec.resources.ip_config.subnet_ip;
                  "dns" = ($entity.spec.resources.ip_config.dhcp_options.domain_name_server_list) -join ',';
                  "dns_search_list" = ($entity.spec.resources.ip_config.dhcp_options.domain_search_list) -join ',';
                  "dns_domain" = $entity.spec.resources.ip_config.dhcp_options.domain_name
                }
              }
              else 
              {
                $myvarNetworkInfo = [ordered]@{
                  "network_name" = $entity.spec.name;
                  "network_uuid" = $entity.metadata.uuid;
                  "cluster_name" = $entity.spec.cluster_reference.name;
                  "cluster_uuid" = $entity.spec.cluster_reference.uuid;
                  "vswitch_name" = $entity.spec.resources.vswitch_name;
                  "vlan_id" = $entity.spec.resources.vlan_id;
                  "ipam" = "no";
                  "default_gw" = "";
                  "ip_pools" = "";
                  "total_available_ips" = "";
                  "nb_connected_vms" = "";
                  "remaining_ips" = "";
                  "subnet_mask_length" = "";
                  "subnet_mask" = "";
                  "network" = "";
                  "dns" = "";
                  "dns_search_list" = "";
                  "dns_domain" = ""
                }
              }
                 
              #store the results for this entity in our overall result variable
              $myvarNetworksResults.Add((New-Object PSObject -Property $myvarNetworkInfo)) | Out-Null
            }
     
            #prepare the json payload for the next batch of entities/response
            $content.offset = $resp.metadata.offset + $resp.metadata.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            Throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
    }
    While ($content.offset -lt $resp.metadata.total_matches -and $resp.metadata.length -eq $length)
    
    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvarNetworksResults
    }
    #endregion
   
    $myvar_csv_out_file = $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($prismcentral)+"_NetworksList.csv"
    Write-Host "$(Get-Date) [DATA] Writing results to $($myvar_csv_out_file)" -ForegroundColor White
    $myvarNetworksResults | export-csv -NoTypeInformation $($myvar_csv_out_file)
#endregion


#region Cleanup	
    #let's figure out how much time this all took
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
#endregion