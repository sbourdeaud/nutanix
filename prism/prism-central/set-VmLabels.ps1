<#
.SYNOPSIS
  Use this script to add one or more labels to virtual machines managed by Prism Central.
.DESCRIPTION
  Use this script to add one or more labels to virtual machines managed by Prism Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central instance fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER action
  Can be add or remove.
.PARAMETER vms
  One or more vm name (comma separated) to which you want to add or remove labels.
.PARAMETER labels
  One or more label that you want to apply to the specified vm(s). If the label does not exist, you will be prompted to create it.
.EXAMPLE
.\set-VmLabels.ps1 -prismcentral ntnxc1.local -labels "mylabel1,mylabel2" -vms "myvm1,myvm2" -action add
Connect to a Nutanix cluster of your choice:
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
    [parameter(mandatory = $true)] [string]$prismcentral,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $true)] [string][ValidateSet("add","remove")]$action,
    [parameter(mandatory = $true)] [string]$vms,
    [parameter(mandatory = $true)] [string]$labels
)
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
04/26/2021 sb   Initial release.
10/26/2022 sb   Tested version for add action.
################################################################################
'
    $myvarScriptName = ".\set-VmLabels.ps1"

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
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = "9440"
    $length = 100
    [System.Collections.ArrayList]$myvar_clusters_list = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvar_vms_list = New-Object System.Collections.ArrayList($null)
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
    $myvar_vms = $vms.Split(",")
    $myvar_labels = $labels.Split(",")
#endregion


#region processing

    #* get clusters using inline pagination (results stored in $myvar_clusters_list)
    #region get clusters
        Write-Host "$(get-date) [INFO] Retrieving information about managed clusters..." -ForegroundColor Green
        $content = @{
            kind = "cluster";
            offset = 0;
            length = $length;
            sort_order = "ASCENDING";
            sort_attribute = "name"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        $url = "https://{0}:{1}/api/nutanix/v3/clusters/list" -f $prismcentral,$api_server_port
        $method = "POST"

        Do {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials

            #region deal with offset for v3 API
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
            #endregion

            ForEach ($entity in $resp.entities) {
                $myvar_cluster_info = [ordered]@{
                    "name" = $entity.status.name;
                    "uuid" = $entity.metadata.uuid
                }
                $myvar_clusters_list.Add((New-Object PSObject -Property $myvar_cluster_info)) | Out-Null
            }

            #prepare the json payload for the next batch of entities/response
            $content.offset = $content.offset + $content.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        While ($resp.metadata.length -eq $length)
    #endregion

    #* get vms using inline pagination (results stored in $myvar_vms_list)
    #region get vms
        Write-Host "$(get-date) [INFO] Retrieving information about AHV vms..." -ForegroundColor Green
        $content = @{
            kind = "vm";
            offset = 0;
            length = $length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        $url = "https://{0}:{1}/api/nutanix/v3/vms/list" -f $prismcentral,$api_server_port
        $method = "POST"

        Do 
        {
            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials

            #region deal with offset for v3 API
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
            #endregion

            #grab the information we need in each entity
            ForEach ($entity in $resp.entities) {
                $myvar_vm_info = [ordered]@{
                    "name" = $entity.spec.name;
                    "power_state" = $entity.spec.resources.power_state;
                    "cluster" = $entity.spec.cluster_reference.name;
                    "uuid" = $entity.metadata.uuid
                }
                #store the results for this entity in our overall result variable
                $myvar_vms_list.Add((New-Object PSObject -Property $myvar_vm_info)) | Out-Null
            }

            #prepare the json payload for the next batch of entities/response
            $content.offset = $content.offset + $content.length
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        While ($resp.metadata.length -eq $length)

        if (!$myvar_vms_list) 
        {
            Write-Host "$(Get-Date) [ERROR] Query did not return any results/vms on Prism Central $($prismcentral)" -ForegroundColor Red
            Exit 1
        } 
        else 
        {
            Write-Host "$(Get-Date) [SUCCESS] Retrieved list of virtual machines from Prism Central $($prismcentral)" -ForegroundColor Cyan
        }

        if ($debugme) 
        {
            Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
            ForEach ($vm in $myvar_vms_list) {
                Write-Host "$vm" -ForegroundColor White
            }
        }
    #endregion

    #* get existing tags (results stored in $myvar_pc_tags)
    #region get tags
        $url = "https://{0}:{1}/PrismGateway/services/rest/v1/tags" -f $prismcentral,$api_server_port
        $method = "GET"
        $myvar_pc_tags = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    #endregion

    #* creating default tags if necessary
    #region creating tags
        $url = "https://{0}:{1}/PrismGateway/services/rest/v1/tags" -f $prismcentral,$api_server_port
        $method = "POST"

        Foreach ($myvar_label in $myvar_labels)
        {
            $content = @{
                name = $myvar_label;
                entityType = "vm";
                description = $null
            }
            $payload = (ConvertTo-Json $content -Depth 4)

            if (($myvar_pc_tags.entities.name) -contains $myvar_label) 
            {
                Write-Host "$(Get-Date) [INFO] Tag $($myvar_label) already exists on Prism Central $($prismcentral)" -ForegroundColor Green
            } 
            else 
            {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            }
        }
    #endregion

    #* refresh existing tags (results stored in $myvar_pc_tags)
    #region get tags
        $url = "https://{0}:{1}/PrismGateway/services/rest/v1/tags" -f $prismcentral,$api_server_port
        $method = "GET"
        $myvar_pc_tags = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    #endregion

    #* tagging vms
    #region tagging vms
        #build list of vm uuids
        $myvar_vms_to_process = $myvar_vms_list | ?{$_.name -in $myvar_vms}
        #build list of tag uuids
        $myvar_tags_to_process = $myvar_pc_tags.entities | ?{$_.name -in $myvar_labels}

        ForEach ($myvar_tag in $myvar_tags_to_process) {
            #region prepare api call
                $vm_uuid_list = $myvar_vms_to_process.uuid                
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] List of uuids for Vms to process: $($vm_uuid_list)" -ForegroundColor White}

                #build json payload
                $content = @{
                    tagUuid = $myvar_tag.uuid;
                    entitiesList = @(ForEach ($vm_uuid in $vm_uuid_list) {
                        @{
                            entityUuid = $vm_uuid;
                            entityType = "vm"
                        }
                    }
                    )
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Payload: $($payload)" -ForegroundColor White}

                if ($action -eq "add")
                {
                    $api_server_endpoint = "/PrismGateway/services/rest/v1/tags/add_entities/fanout?async=true"
                }
                elseif ($action -eq "remove")
                {
                    $api_server_endpoint = "/PrismGateway/services/rest/v1/tags/remove_entities/fanout?async=true"
                }
                $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port,$api_server_endpoint
                $method = "POST"
            #endregion
            
            #region make api call to add entities to tag
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
            #endregion
        }
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable action -ErrorAction SilentlyContinue
    Remove-Variable vms -ErrorAction SilentlyContinue
    Remove-Variable labels -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion