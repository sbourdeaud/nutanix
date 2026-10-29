<#
.SYNOPSIS
  Use this script to copy an existing Nutanix Flow application rule to a new rule on the same Prism Central.
.DESCRIPTION
  Given a Prism Central, a source and destination rule name, an AppType category and a policy mode (enforce/monitor) the script will copy the source rule to a new rule with the desired name and apply it to the specified AppType category.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER pc
  Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER sourceRule
  Name of the Flow policy you want to copy.
.PARAMETER targetRule
  Name of the new Flow policy you want to create from the source rule.
.PARAMETER appType
  Value of the AppType category you want the new rule to apply to.
.PARAMETER mode
  Specifies if you want the new rule to be in enforce or monitor mode. If this is not specified, it will use the same mode as the source rule.
.EXAMPLE
.\Copy-FlowRule.ps1 -pc pc1.local -prismCreds myadcreds -sourceRule myFlowRule1 -targetRule myFlowRule2 -appType app2 -mode monitor
Copy myFlowRule1 to myFlowRule2 and apply it to AppType app2 in monitor mode:
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
        [parameter(mandatory = $false)] [string]$pc,
        [parameter(mandatory = $false)] [string]$sourceRule,
        [parameter(mandatory = $false)] [string]$targetRule,
        [parameter(mandatory = $false)] [string]$appType,
        [parameter(mandatory = $false)] [ValidateSet("enforce","monitor")] [string]$mode,
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion


#region helper functions (previously from sbourdeaud module)
function Set-CustomCredentials 
{#creates files to store creds
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
        
        [parameter(mandatory = $false)]
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
}

#this function is used to retrieve saved credentials for the current user
function Get-CustomCredentials 
{#retrieves creds from files
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
        
        [parameter(mandatory = $false)]
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
}

#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{#disables unsecure Tls protocols
    <#
    .SYNOPSIS
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .DESCRIPTION
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

    .EXAMPLE
    .\Set-PoshTls
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .LINK
    https://github.com/sbourdeaud
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param 
    (
        
    )

    begin 
    {
    }

    process
    {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            # PowerShell 7+ already defaults to TLS 1.2+; REST helpers also set -SslProtocol Tls12
            return
        }
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = `
        ([Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12)
    }

    end
    {

    }
}#endfunction Set-PoshTls

#this function is used to configure posh to ignore invalid ssl certificates
function Set-PoSHSSLCerts
{#configures posh to ignore self-signed certs
    <#
    .SYNOPSIS
    Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
    .DESCRIPTION
    Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
    #>
    
    begin
    {

    }#endbegin
    
    process
    {
        # PowerShell 6+ uses -SkipCertificateCheck on Invoke-RestMethod.
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
        }#endif
        [ServerCertificateValidationCallback]::Ignore()
    }#endprocess
    
    end
    {
    }#endend
}#end function Set-PoSHSSLCerts

#this function is used to make a REST api call to Prism
function Invoke-PrismAPICall
{#makes a REST API call to Prism
    <#
    .SYNOPSIS
    Makes api call to prism based on passed parameters. Returns the json response.
    .DESCRIPTION
    Makes api call to prism based on passed parameters. Returns the json response.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER method
    REST method (POST, GET, DELETE, or PUT)
    .PARAMETER credential
    PSCredential object to use for authentication.
    PARAMETER url
    URL to the api endpoint.
    PARAMETER payload
    JSON payload to send.
    .EXAMPLE
    .\Invoke-PrismAPICall -credential $MyCredObject -url https://myprism.local/api/v3/vms/list -method 'POST' -payload $MyPayload
    Makes a POST api call to the specified endpoint with the specified payload.
    #>
    param
    (
        [parameter(mandatory = $false)]
        [ValidateSet("POST","GET","DELETE","PUT")]
        [string] 
        $method,
        
        [parameter(mandatory = $false)]
        [string] 
        $url,

        [parameter(mandatory = $false)]
        [string] 
        $payload,
        
        [parameter(mandatory = $false)]
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
            if ($PSVersionTable.PSVersion.Major -gt 5) 
            {
                $headers = @{
                    "Content-Type"="application/json";
                    "Accept"="application/json"
                }
                if ($payload) 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                } 
                else 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
            } 
            else 
            {
                $username = $credential.UserName
                $password = $credential.Password
                $headers = @{
                    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                    "Content-Type"="application/json";
                    "Accept"="application/json"
                }
                if ($payload) 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                } 
                else 
                {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
            Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
        }
        catch {
            $saved_error = $_.Exception
            if ($saved_error.Source -eq "System.net.Http")
            {
                $saved_error_message = $saved_error.Message
            }
            else 
            {
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message_list.message
            }
            $resp_return_code = $_.Exception.Response.StatusCode.value__
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            if ($resp_return_code -eq 409) 
            {
                Write-Host "$(Get-Date) [WARNING] $saved_error_message" -ForegroundColor Yellow
                Throw
            }
            else 
            {
                if ($saved_error_message -match 'rule already exists')
                {
                    Throw "$(get-date) [WARNING] $saved_error_message" 
                }
                else 
                {
                    if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
                    Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"    
                }
            }
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
    }
    
    end
    {
        return $resp
    }    
}

#helper-function Get-RESTError
function Help-RESTError 
{#tries to retrieve full REST messages
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();

    return $global:responsebody

    break
}#end function Get-RESTError

function Get-PrismCentralObjectList
{#retrieves multiple pages of Prism REST objects v3
    [CmdletBinding()]
    param 
    (
        [parameter(mandatory = $false)][string] $pc,
        [parameter(mandatory = $false)][string] $object,
        [parameter(mandatory = $false)][string] $kind
    )

    begin 
    {
        if (!$length) {$length = 100} #we may not inherit the $length variable; if that is the case, set it to 100 objects per page
        $total, $cumulated, $first, $last, $offset = 0 #those are used to keep track of how many objects we have processed
        [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #this is variable we will use to keep track of entities
        $url = "https://{0}:9440/api/nutanix/v3/{1}/list" -f $pc,$object
        $method = "POST"
        $content = @{
            kind=$kind;
            offset=0;
            length=$length
        }
        $payload = (ConvertTo-Json $content -Depth 4) #this is the initial payload at offset 0
    }
    
    process 
    {
        Do {
            try {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                
                if ($total -eq 0) {$total = $resp.metadata.total_matches} #this is the first time we go thru this loop, so let's assign the total number of objects
                $first = $offset #this is the first object for this iteration
                $last = $offset + ($resp.entities).count #this is the last object for this iteration
                if ($total -le $length)
                {#we have less objects than our specified length
                    $cumulated = $total
                }
                else 
                {#we have more objects than our specified length, so let's increment cumulated
                    $cumulated += ($resp.entities).count
                }
                
                Write-Host "$(Get-Date) [INFO] Processing results from $(if ($first) {$first} else {"0"}) to $($last) out of $($total)" -ForegroundColor Green
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    
                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) {                
                    $myvarResults.Add($entity) | Out-Null
                }
                
                $offset = $last #let's increment our offset
                #prepare the json payload for the next batch of entities/response
                $content = @{
                    kind=$kind;
                    offset=$offset;
                    length=$length
                }
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            catch {
                $saved_error = $_.Exception.Message
                # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
                Throw "$(get-date) [ERROR] $saved_error"
            }
            finally {
                #add any last words here; this gets processed no matter what
            }
        }
        While ($last -lt $total)
    }
    
    end 
    {
        return $myvarResults
    }
}

function Get-PrismCentralTaskStatus
{#loops on Prism Central task status until completed
    <#
    .SYNOPSIS
    Retrieves the status of a given task uuid from Prism and loops until it is completed.
    
    .DESCRIPTION
    Retrieves the status of a given task uuid from Prism and loops until it is completed.
    
    .PARAMETER Task
    Prism task uuid.
    
    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
    
    .EXAMPLE
    .\Get-PrismCentralTaskStatus -Task $task -cluster $cluster -credential $prismCredentials
    Prints progress on task $task until successfull completion. If the task fails, print the status and error code and details and exits.
    
    .LINK
    https://github.com/sbourdeaud
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param
    (
        [Parameter(Mandatory)]
        $task,
        
        [parameter(mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $credential,

        [parameter(mandatory = $false)]
        [String]
        $cluster
    )

    begin
    {
        $url = "https://$($cluster):9440/api/nutanix/v3/tasks/$task"
        $method = "GET"
    }
    
    process 
    {
        #region get initial task details
            Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
            $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
        #endregion

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Sleep 5
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.status -ne "running") 
                {
                    if ($taskDetails.status -ne "succeeded") 
                    {
                        Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) failed with the following status and error code : $($taskDetails.status) : $($taskDetails.progress_message)" -ForegroundColor Yellow
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            if ($taskDetails.status -ne "succeeded") {
                Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) status is $($taskDetails.status): $($taskDetails.progress_message)" -ForegroundColor Yellow
            } else {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
            }
        }
    }
    
    end
    {
        return $taskDetails.status
    }
}

function Sync-Categories
{#syncs Prism categories used in a given network policy
    param
    (
        [Parameter(Mandatory)]
        $rule
    )

    begin {}

    process 
    {
        #region which categories are used?
        #* figure out categories used in this rule
        Write-Host "$(get-date) [INFO] Examining categories..." -ForegroundColor Green
        [System.Collections.ArrayList]$used_categories_list = New-Object System.Collections.ArrayList($null)
        #types of rules (where categories are listed varies depending on the type of rule): 
        if ($rule.spec.resources.quarantine_rule)
        {#this is a quarantine rule
            Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is a Quarantine rule..." -ForegroundColor Green
            foreach ($category in ($rule.spec.resources.quarantine_rule.target_group.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in target_group
                foreach ($value in ($rule.spec.resources.quarantine_rule.target_group.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
        }
        elseif ($rule.spec.resources.isolation_rule) 
        {#this is an isolation rule
            Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Isolation rule..." -ForegroundColor Green
            foreach ($category in ($rule.spec.resources.isolation_rule.first_entity_filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in first_entity_filter
                foreach ($value in ($rule.spec.resources.isolation_rule.first_entity_filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
            foreach ($category in ($rule.spec.resources.isolation_rule.second_entity_filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in second_entity_filter
                foreach ($value in ($rule.spec.resources.isolation_rule.second_entity_filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
        }
        elseif ($rule.spec.resources.app_rule) 
        {#this is an app policy/rule
            Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Application rule..." -ForegroundColor Green
            foreach ($category in ($rule.spec.resources.app_rule.outbound_allow_list.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in outbound_allow_list
                foreach ($value in ($rule.spec.resources.app_rule.outbound_allow_list.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
            foreach ($category in ($rule.spec.resources.app_rule.target_group.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in target_group
                foreach ($value in ($rule.spec.resources.app_rule.target_group.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
            foreach ($category in ($rule.spec.resources.app_rule.inbound_allow_list.filter.params | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue).Name)
            {#process each category used in inbound_allow_list
                foreach ($value in ($rule.spec.resources.app_rule.inbound_allow_list.filter.params."$category" | Where-Object {$_}))
                {#process each value for this category
                    $category_value_pair = "$($category):$($value)"
                    $used_categories_list.Add($category_value_pair) | Out-Null
                }
            }
        }
        else 
        {#we don't know what type of rule this is
            Write-Host "$(get-date) [WARNING] Rule $($rule.spec.Name) is not a supported rule type for replication!" -ForegroundColor Yellow
        }

        Write-Host "$(get-date) [DATA] Flow rule $($rule.spec.Name) with UUID $($rule.metadata.uuid) uses the following category:value pairs: $($($used_categories_list | Select-Object -Unique) -Join ",")" -ForegroundColor White
        #endregion
        
        if ($import)
        {
            
            #region are all used category:value pairs on target?
                #* check each used category:value pair exists on target
                [System.Collections.ArrayList]$missing_categories_list = New-Object System.Collections.ArrayList($null)
                foreach ($category_value_pair in ($used_categories_list | Select-Object -Unique))
                {#process each used category
                    $category = ($category_value_pair -split ":")[0]
                    $value = ($category_value_pair -split ":")[1]

                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                    $url = "https://{0}:9440{1}" -f $pc,$api_server_endpoint
                    $method = "GET"

                    Write-Host "$(Get-Date) [INFO] Checking category:value pair $($category):$($value) exists in $pc..." -ForegroundColor Green
                    try 
                    {
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                        Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $pc" -ForegroundColor Cyan
                    }
                    catch 
                    {
                        $saved_error = $_.Exception.Message
                        $error_code = ($saved_error -split " ")[3]
                        if ($error_code -eq "404") 
                        {
                            Write-Host "$(get-date) [WARNING] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $pc" -ForegroundColor Yellow
                            $missing_categories_list.Add($category_value_pair) | Out-Null
                            Continue
                        }
                        else 
                        {
                            Write-Host "$saved_error" -ForegroundColor Yellow
                            Continue
                        }
                    }
                }

                if ($missing_categories_list)
                {#there are missing categories on target
                    Write-Host "$(get-date) [DATA] The following category:value pairs need to be added on $($pc):" -ForegroundColor White
                    $missing_categories_list
                }
            #endregion
            
            #region create missing category:value pairs on target
                [System.Collections.ArrayList]$processed_categories_list = New-Object System.Collections.ArrayList($null)
                foreach ($category_value_pair in $missing_categories_list)
                {#process all missing categories and values
                    #check if category exists
                    $category = ($category_value_pair -split ":")[0]
                    $value = ($category_value_pair -split ":")[1]

                    if (!$processed_categories_list)
                    {#we havent processed any category yet
                        if ($category -notin $processed_categories_list)
                        {#this category has not been found or added yet
                            $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                            $url = "https://{0}:9440{1}" -f $pc,$api_server_endpoint
                            $method = "GET"

                            Write-Host "$(Get-Date) [INFO] Checking category $($category) exists in $pc..." -ForegroundColor Green
                            try 
                            {#get the category
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                                Write-Host "$(Get-Date) [SUCCESS] Found the category $($category) in $pc" -ForegroundColor Cyan
                                $processed_categories_list.Add($category) | Out-Null
                            }
                            catch 
                            {#get category failed, or category was not found
                                $saved_error = $_.Exception.Message
                                $error_code = ($saved_error -split " ")[3]
                                if ($error_code -eq "404") 
                                {#category was not found
                                    Write-Host "$(get-date) [WARNING] The category specified $($category) does not exist in Prism Central $pc" -ForegroundColor Yellow
                                    #add category
                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                                    $url = "https://{0}:9440{1}" -f $pc,$api_server_endpoint
                                    $method = "PUT"
                                    $content = @{
                                        api_version="3.1.0";
                                        description="added by Invoke-FlowRuleSync.ps1 script";
                                        name="$category"
                                    }
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                    try 
                                    {#add the category
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                        Write-Host "$(Get-Date) [SUCCESS] Added category $($category) in $pc" -ForegroundColor Cyan
                                        if ($debugme) {$resp}
                                        #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $pc
                                        $processed_categories_list.Add($category) | Out-Null     
                                    }
                                    catch 
                                    {#we couldn't add the category
                                        Throw "$($_.Exception.Message)"
                                    }  
                                }
                                else 
                                {#we couldn't get the category
                                    Throw "$($_.Exception.Message)"
                                }
                            }
                        }
                    }
                    
                    #add value
                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                    $url = "https://{0}:9440{1}" -f $pc,$api_server_endpoint
                    $method = "PUT"
                    $content = @{
                        api_version="3.1.0";
                        description="added by Sync-FlowRules.ps1 script";
                        value="$value"
                    }
                    $payload = (ConvertTo-Json $content -Depth 4)
                    try 
                    {#add the value
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                        Write-Host "$(Get-Date) [SUCCESS] Added value $($value) to category $($category) in $pc" -ForegroundColor Cyan
                        if ($debugme) {$resp}
                        #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                    }
                    catch 
                    {#we couldn't add the value
                        Throw "$($_.Exception.Message)"
                    }
                }
            #endregion
        }
        elseif ($export)
        {
            return ($used_categories_list | Select-Object -Unique)
        }
    }

    end {}
}

function Sync-AddressGroups
{#syncs Prism address groups used in a given network policy
    param
    (
        [Parameter(Mandatory)]
        $rule
    )

    begin {}

    process 
    {
        #region which address groups are used?
            #* figure out address groups used in this rule
            Write-Host "$(get-date) [INFO] Examining address groups..." -ForegroundColor Green
            [System.Collections.ArrayList]$used_address_group_list = New-Object System.Collections.ArrayList($null)
            #types of rules (where categories are listed varies depending on the type of rule): 
            if ($rule.spec.resources.app_rule) 
            {#this is an app rule
                foreach ($address_group in $rule.spec.resources.app_rule.outbound_allow_list.address_group_inclusion_list)
                {#process each address group used in outbound_allow_list
                    $used_address_group_list.Add($address_group) | Out-Null
                }
                foreach ($address_group in $rule.spec.resources.app_rule.inbound_allow_list.address_group_inclusion_list)
                {#process each address group used in inbound_allow_list
                    $used_address_group_list.Add($address_group) | Out-Null
                }
            }
        #endregion
        
        
        if ($import)
        {
            #region are all used address groups on the target?

                [System.Collections.ArrayList]$missing_address_groups_list = New-Object System.Collections.ArrayList($null)
                foreach ($address_group in ($used_address_group_list | Select-Object -Property uuid -Unique))
                {#process each used address group

                    $source_address_group = $myvar_json_input.addresses | Where-Object {$_.uuid -eq $address_group.uuid}

                    if ($source_address_group.address_group.name -notin $address_groups.address_group.name)
                    {#based on its name, that address group does not exist on the target
                        $missing_address_groups_list.Add($source_address_group) | Out-Null
                    }
                    else 
                    {#the address group already exists on target, let's update the uuid reference in that rule
                        $target_address_group_uuid = ($address_groups | Where-Object {$_.address_group.Name -eq $source_address_group.address_group.name}).uuid
                        if ($address_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $source_address_group.uuid})
                        {#that address group is used in inbound allow list
                            ForEach ($address_group_item in $address_group_inbound)
                            {
                                $address_group_item.uuid = $target_address_group_uuid
                            }
                        }
                        if ($address_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $source_address_group.uuid})
                        {#that address group is used in outbound allow list
                            ForEach ($address_group_item in $address_group_outbound)
                            {
                                $address_group_item.uuid = $target_address_group_uuid
                            }
                        }
                    }
                }

                if ($missing_address_groups_list)
                {#there are missing address groups
                    Write-Host "$(get-date) [DATA] The following address groups need to be added on $($pc): $($missing_address_groups_list.address_group.name -join ",")" -ForegroundColor White                      
                }
            #endregion

            #region create missing address groups on target
                [System.Collections.ArrayList]$processed_address_groups_list = New-Object System.Collections.ArrayList($null)
                foreach ($address_group in $missing_address_groups_list)
                {#process all missing address groups
                    #add address group
                    $api_server_endpoint = "/api/nutanix/v3/address_groups" -f $category,$value
                    $url = "https://{0}:9440{1}" -f $pc,$api_server_endpoint
                    $method = "POST"
                    $payload = (ConvertTo-Json $address_group.address_group -Depth 10)
                    Write-Host "$(Get-Date) [INFO] Adding address group $($address_group.address_group.name) to $targetPc" -ForegroundColor Green
                    try 
                    {#add address group
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                        Write-Host "$(Get-Date) [SUCCESS] Added address group $($address_group.address_group.name) to $targetPc" -ForegroundColor Cyan
                        if ($debugme) {$resp}
                        #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                        if ($address_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $address_group.uuid})
                        {#that address group is used in inbound allow list, let's update the uuid with that of the newly created address group
                            ForEach ($address_group_item in $address_group_inbound)
                            {
                                $address_group_item.uuid = $resp.uuid
                            }
                        }
                        if ($address_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.address_group_inclusion_list | Where-Object {$_.uuid -eq $address_group.uuid})
                        {#that address group is used in outbound allow list, let's update the uuid with that of the newly created address group
                            ForEach ($address_group_item in $address_group_outbound)
                            {
                                $address_group_item.uuid = $resp.uuid
                            }
                        }
                    }
                    catch 
                    {#we couldn't add the address group
                        Throw "$($_.Exception.Message)"
                    }
                }
            #endregion
        }
        elseif ($export)
        {
            #region lookup address group names
                [System.Collections.ArrayList]$used_address_groups_objects = New-Object System.Collections.ArrayList($null)
                foreach ($address_group in ($used_address_group_list | Select-Object -Property uuid -Unique))
                {
                    $address_group_object = $myvar_json_input.addresses | Where-Object {$_.uuid -eq $address_group.uuid}
                    $used_address_groups_objects.Add($address_group_object) | Out-Null
                }
                return $used_address_groups_objects
            #endregion
        }
    }

    end {}
}
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter and Write-LogOutput/LoadModule functions
11/09/2022 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\Copy-FlowRule.ps1"

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

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = 9440
#endregion

#region parameters validation
    if (!$pc -or !$sourceRule -or !$targetRule -or !$appType) {
        Throw "$(Get-Date) [ERROR] You must specify -pc -sourceRule -targetRule -appType!"
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
#endregion

#region processing
    # Get source rule
    Write-Host "$(get-date) [INFO] Retrieving source rule $($sourceRule)..." -ForegroundColor Green
    $url = "https://$($pc):9440/api/nutanix/v3/security_policies/list"
    $method = "POST"
    $content = @{
        kind="security_policy";
        offset=0;
        length=100;
        filter="name==$($sourceRule)"
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials

    if ($resp.entities.Count -eq 0) {
        throw "$(get-date) [ERROR] Source rule $($sourceRule) not found!"
    }

    $sourceRuleObj = $resp.entities[0]
    Write-Host "$(get-date) [SUCCESS] Found source rule $($sourceRule) with UUID $($sourceRuleObj.metadata.uuid)" -ForegroundColor Cyan

    # Create new rule based on source
    $newRule = $sourceRuleObj.Clone()
    $newRule.metadata.name = $targetRule
    $newRule.spec.name = $targetRule
    $newRule.metadata.uuid = [Guid]::NewGuid().ToString()
    
    # Update AppType category
    # ... (category update logic here)
    
    # Update mode if specified
    if ($mode) {
        # Update mode logic here
    }

    # Create the new rule
    $url = "https://$($pc):9440/api/nutanix/v3/security_policies"
    $method = "POST"
    $payload = ($newRule | ConvertTo-Json -Depth 10)
    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
    Write-Host "$(get-date) [SUCCESS] Created rule $($targetRule)!" -ForegroundColor Cyan

#endregion processing

#region cleanup
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable pc -ErrorAction SilentlyContinue
    Remove-Variable sourceRule -ErrorAction SilentlyContinue
    Remove-Variable targetRule -ErrorAction SilentlyContinue
    Remove-Variable appType -ErrorAction SilentlyContinue
    Remove-Variable mode -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable api_server_port -ErrorAction SilentlyContinue
#endregion