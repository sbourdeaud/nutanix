<#
.SYNOPSIS
  Retrieves access control policies defined in Prism Central (for role based access control/RBAC).
.DESCRIPTION
  Lists and exports to csv a view of roles, associated users & groups and applicable entities using the access_control_policies v3 API endpoint in Prsim Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.EXAMPLE
.\get-accessControlPolicies.ps1 -prismcentral pc.local
Restrieve access control policies for the given Prism Central:
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
05/05/2020 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\get-accessControlPolicies.ps1"

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
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = "9440"
    $length = 200
    [System.Collections.ArrayList]$myvar_results = New-Object System.Collections.ArrayList($null)
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


#region processing

    #region prepare the api call
        $api_server_endpoint = "/api/nutanix/v3/access_control_policies/list"
        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
        $method = "POST"
        $kind = "access_control_policy"

        # this is used to capture the content of the payload
        $content = @{
            kind = $kind;
            offset = 0;
            length = $length
        }
        $payload = (ConvertTo-Json $content -Depth 4)
    #endregion

    Write-Host "$(Get-Date) [INFO] Retrieving access control policies from Prism Central $($prismcentral)" -ForegroundColor Green
    Do {
        try {
            #region making the api call
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
            #endregion

            #! grabbing content here
            #grab the information we need in each entity
            ForEach ($entity in $resp.entities) {

                #region figure what objects the acl applies to
                    #initialize the variable we will use to keep track of objects/entities this acl applies to
                    [System.Collections.ArrayList]$myvar_entities = New-Object System.Collections.ArrayList($null)
                    
                    #each acl contains entity and scope filters to determine objects it applies to
                    ForEach ($context in $entity.status.resources.filter_list.context_list) {
                        #process entities
                        ForEach ($entity_object in $context.entity_filter_expression_list) {
                            $entity_object_property_left = $entity_object.left_hand_side.psobject.properties.name
                            $entity_object_property_right = $entity_object.right_hand_side.psobject.properties.name
                            if ($entity_object_property_left) {
                                $left = $entity_object.left_hand_side.$entity_object_property_left;
                            } else {
                                $left = $entity_object.left_hand_side
                            }
                            $myvar_entity_object = [ordered]@{
                                "left" = $left;
                                "right" = $entity_object.right_hand_side.$entity_object_property_right;
                            }
                            $myvar_entities.Add((New-Object PSObject -Property $myvar_entity_object)) | Out-Null
                            Remove-Variable entity_object_property_left -ErrorAction SilentlyContinue
                            Remove-Variable entity_object_property_right -ErrorAction SilentlyContinue
                        }
                        #process objects
                        ForEach ($scope in $context.scope_filter_expression_list) {
                            $scope_property_left = $scope.left_hand_side.psobject.properties.name
                            $scope_property_right = $scope.right_hand_side.psobject.properties.name
                            if ($scope_property_left -ne "Length") {
                                $left = $scope.left_hand_side.$scope_property_left;
                            } else {
                                $left = $scope.left_hand_side
                            }
                            if ($left -eq "CATEGORY") {
                                $myvar_categories = @()
                                ForEach ($category_name in $scope.right_hand_side.$scope_property_right) {
                                    $category_pair = $category_name.psobject.properties.name+":"+$category_name.($category_name.psobject.properties.name)
                                    $myvar_categories += $category_pair
                                }
                                $right = $myvar_categories -join ";"
                            } else {
                                $right = $scope.right_hand_side.$scope_property_right
                            }
                            $myvar_scope_object = [ordered]@{
                                "left" = $left;
                                "right" = $right;
                            }
                            $myvar_entities.Add((New-Object PSObject -Property $myvar_scope_object)) | Out-Null
                            Remove-Variable entity_object_property_left -ErrorAction SilentlyContinue
                            Remove-Variable entity_object_property_right -ErrorAction SilentlyContinue
                        }
                    }

                    #TODO: some object references will contain uuids instead of names. Figure out the names to make it more human readable.
                    #process each object in our list (type:value). If value is a uuid, then determine which api call to make 
                    #based on the type and replace the entry with type:name instead of type:uuid (remove and add or update?)
                    ForEach ($acl_object in $myvar_entities) {
                        #split based on ':' Left part is type, right is value (name or uuid)
                        #determine if value is uuid using a regex
                        #if it is a uuid, determine the api call to make based on the type
                        #make the api call and store the name of the object
                        #replace the entry type:uuid with type:name
                    }
                #endregion

                #grab other information about the acl and who it applies to
                $myvar_entity_info = [ordered]@{
                    #*about the acl
                    "access_control_list_name" = $entity.status.name;
                    "access_control_list_creation_time" = $entity.metadata.creation_time;
                    "access_control_list_last_update_time" = $entity.metadata.last_update_time;
                    "access_control_list_spec_version" = $entity.metadata.spec_version;
                    
                    #*what does it apply to
                    "entities" = ($myvar_entities | %{$_.left+":"+$_.right}) -join ",";
                    #$property = $entity.status.resources.filter_list.context_list.scope_filter_expression_list.right_hand_side.psobject.properties.name
                    #$entity.status.resources.filter_list.context_list.scope_filter_expression_list.right_hand_side.$property
                    #$entity.status.resources.filter_list.context_list.scope_filter_expression_list.left_hand_side

                    #*who does it apply to
                    "roles_name" = $entity.status.resources.role_reference.name;
                    #"roles_uuid" = $entity.spec.resources.role_reference.uuid;
                    "users" = (($entity.status.resources.user_reference_list | Select-Object -Property name).name) -join ',';
                    "groups" = (($entity.status.resources.user_group_reference_list | Select-Object -Property name).name) -join ';';
                }
                #store the results for this entity in our overall result variable
                $myvar_results.Add((New-Object PSObject -Property $myvar_entity_info)) | Out-Null
            }

            #region prepare the json payload for the next batch of entities/response
                $content.offset = $resp.metadata.offset + $resp.metadata.length
                $payload = (ConvertTo-Json $content -Depth 4)
            #endregion
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
    While ($content.offset -lt $resp.metadata.total_matches)

    if ($debugme) {
        Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
        $myvar_results
    }

    Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($prismcentral)_acls.csv" -ForegroundColor Green
    $myvar_results | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$prismcentral+"_acls.csv")
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
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
    Remove-Variable length -ErrorAction SilentlyContinue
#endregion