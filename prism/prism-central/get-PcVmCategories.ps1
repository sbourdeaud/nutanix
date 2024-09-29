<#
.SYNOPSIS
  Generates a csv file containing a virtual machine inventory along with the categories they belong to.
.DESCRIPTION
  VM inventory for all clusters managed by Prism Central. Generates a single csv file with cluster name, hypervisor, vm name, cpu, ram, ip address and categories the vm belongs to.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\get-PcVmCategories.ps1 -prismcentral myprismcentral.local
Collect VM inventory from prismcentral.local (and get prompted for credentials)
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: September 29th 2024
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [switch]$backup,
    [parameter(mandatory = $true)] [string]$prismcentral,
    [parameter(mandatory = $false)] $prismCreds
)
#endregion


#region functions
#this function is used to make a REST api call to Prism
function Write-LogOutput
{
<#
.SYNOPSIS
Outputs color coded messages to the screen and/or log file based on the category.

.DESCRIPTION
This function is used to produce screen and log output which is categorized, time stamped and color coded.

.PARAMETER Category
This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".

.PARAMETER Message
This is the actual message you want to display.

.PARAMETER LogFile
If you want to log output to a file as well, use logfile to pass the log file full path name.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Write-LogOutput -category "ERROR" -message "You must be kidding!"
Displays an error message.

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

param
(
    [Parameter(Mandatory)]
    [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG','DATA')]
    [string]
    $Category,

    [string]
    $Message,

    [string]
    $LogFile
)

process
{
    $Date = get-date #getting the date so we can timestamp the output entry
    $FgColor = "Gray" #resetting the foreground/text color
    switch ($Category) #we'll change the text color depending on the selected category
    {
        "INFO" {$FgColor = "Green"}
        "WARNING" {$FgColor = "Yellow"}
        "ERROR" {$FgColor = "Red"}
        "SUM" {$FgColor = "Magenta"}
        "SUCCESS" {$FgColor = "Cyan"}
        "STEP" {$FgColor = "Magenta"}
        "DEBUG" {$FgColor = "White"}
        "DATA" {$FgColor = "Gray"}
    }

    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
    if ($LogFile) #add the entry to the log file if -LogFile has been specified
    {
        Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
        Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
    }
}

}#end function Write-LogOutput
function Invoke-PrismAPICall
{
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
        $username = $credential.UserName
        $password = $credential.Password
        $headers = @{
            "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
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
}

#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{
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
    Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
    [Net.ServicePointManager]::SecurityProtocol = `
    ([Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12)
}

end
{

}
}

#this function is used to configure posh to ignore invalid ssl certificates
function Set-PoSHSSLCerts
{
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
}

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
}

function Get-GroupsObjectList
{#retrieves multiple pages of Prism REST objects using the (undocumented) v3 groups endpoint with the specified attributes
    [CmdletBinding()]
    param 
    (
        [Parameter(mandatory = $true)][string] $prism,
        [Parameter(mandatory = $true)][string] $attributes
    )

    begin 
    {
        if (!$length) {$length = 100} #we may not inherit the $length variable; if that is the case, set it to 100 objects per page
        $total = 0
        $cumulated = 0
        $page_offset = 0 #those are used to keep track of how many objects we have processed
        [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #this is variable we will use to keep track of entities
        $url = "https://{0}:9440/api/nutanix/v3/groups" -f $prism
        $method = "POST"
        $content = @{
            entity_type="mh_vm";
            query_name="";
            grouping_attribute=" ";
            group_count=3;
            group_offset=0;
            group_attributes=@();
            group_member_count=$length;
            group_member_offset=$page_offset;
            group_member_sort_attribute="vm_name";
            group_member_sort_order="ASCENDING";
            group_member_attributes=@(
                ForEach ($attribute in ($attributes -Split ","))
                {
                    @{attribute="$($attribute)"}
                } 
            )
        }
        $payload = (ConvertTo-Json $content -Depth 4) #this is the initial payload at offset 0
    }
    
    process 
    {
        Do {
            try {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                
                if ($total -eq 0) 
                {
                    $total = $resp.group_results.total_entity_count
                } #this is the first time we go thru this loop, so let's assign the total number of objects
                $cumulated += $resp.group_results.entity_results.count
                
                Write-Host "$(Get-Date) [INFO] Processing results from $($page_offset) to $($cumulated) out of $($total)" -ForegroundColor Green
    
                #grab the information we need in each entity
                ForEach ($entity in $resp.group_results.entity_results) {                
                    $myvarResults.Add($entity) | Out-Null
                }
                
                $page_offset += $length #let's increment our offset
                #prepare the json payload for the next batch of entities/response
                $content = @{
                    entity_type="mh_vm";
                    query_name="";
                    grouping_attribute=" ";
                    group_count=3;
                    group_offset=0;
                    group_attributes=@();
                    group_member_count=$length;
                    group_member_offset=$page_offset;
                    group_member_sort_attribute="vm_name";
                    group_member_sort_order="ASCENDING";
                    group_member_attributes=@(
                        ForEach ($attribute in ($attributes -Split ","))
                        {
                            @{attribute="$($attribute)"}
                        } 
                    )
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
        While ($cumulated -lt $total)
    }
    
    end 
    {
        return $myvarResults
    }
}
#endregion


#region prepwork
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
06/29/2022 sb   Initial release.
06/30/2022 sb   Changed code to process correctly number of objects in groups 
                response.  Moved that code to a function.
09/29/2024 sb   Added the backup parameter to create sourcecsv file for
                set-category.ps1 script.
################################################################################
'@
$myvarScriptName = ".\get-PcVmCategories.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}
Set-PoSHSSLCerts
Set-PoshTls
#endregion


#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
[System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
[System.Collections.ArrayList]$myvarBackupResults = New-Object System.Collections.ArrayList($null)
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

#* step 1: Retrieve list of vms with the attributes we want
#region get vms
    Write-Host "$(get-date) [INFO] Retrieving list of vms for $($prismcentral)..." -ForegroundColor Green
    $vm_list = Get-GroupsObjectList -prism $prismcentral -attributes "vm_name,cluster_name,hypervisor_type,node_name,categories,ip_addresses,num_vcpus,num_threads_per_core,memory_size_bytes,capacity_bytes,gpus_in_use,power_state,protection_type,protection_policy_state,protection_domain_name"
    
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of $($vm_list.count) vms for $($prismcentral)!" -ForegroundColor Cyan
    ForEach ($entity in $vm_list) {
        $myvarVmInfo = [ordered]@{
            "name" = ($entity.data | Where-Object {$_.name -eq "vm_name"}).values.values;
            "cluster" = ($entity.data | Where-Object {$_.name -eq "cluster_name"}).values.values;
            "hypervisor" = ($entity.data | Where-Object {$_.name -eq "hypervisor_type"}).values.values;
            "host" = ($entity.data | Where-Object {$_.name -eq "node_name"}).values.values;
            "categories" = ($entity.data | Where-Object {$_.name -eq "categories"}).values.values -join ',';
            "ip_addresses" = ($entity.data | Where-Object {$_.name -eq "ip_addresses"}).values.values -join ',';
            "num_vcpus" = ($entity.data | Where-Object {$_.name -eq "num_vcpus"}).values.values;
            "num_cores_per_vcpu" = ($entity.data | Where-Object {$_.name -eq "num_threads_per_core"}).values.values;
            "memory_mb" = [math]::Round(($entity.data | Where-Object {$_.name -eq "memory_size_bytes"}).values.values /1024/1024);
            "capacity_gb" = [math]::Round(($entity.data | Where-Object {$_.name -eq "capacity_bytes"}).values.values /1024/1024/1024);
            "gpus_in_use" = ($entity.data | Where-Object {$_.name -eq "gpus_in_use"}).values.values;
            "power_state" = ($entity.data | Where-Object {$_.name -eq "power_state"}).values.values;
            "protection_type" = ($entity.data | Where-Object {$_.name -eq "protection_type"}).values.values;
            "protection_policy_compliance_status" = if (($entity.data | Where-Object {$_.name -eq "protection_policy_state"}).values.values) {(($entity.data | Where-Object {$_.name -eq "protection_policy_state"}).values.values | ConvertFrom-Json).compliance_status};
            "protection_policy_name" = if (($entity.data | Where-Object {$_.name -eq "protection_policy_state"}).values.values) {(($entity.data | Where-Object {$_.name -eq "protection_policy_state"}).values.values | ConvertFrom-Json).policy_reference.name};
            "protection_domain_name" = ($entity.data | Where-Object {$_.name -eq "protection_domain_name"}).values.values;
        }
        $myvarBackupInfo = [ordered]@{
            "vm_name" = ($entity.data | Where-Object {$_.name -eq "vm_name"}).values.values;
            "categories" = ($entity.data | Where-Object {$_.name -eq "categories"}).values.values;
        }
        #store the results for this entity in our overall result variable
        if ($myvarVmInfo.name) {$myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null}
        if ($backup) {
            ForEach ($category in $myvarBackupInfo.categories) {
                $myvarBackupEntry = [ordered]@{
                    "vm_name" = $myvarBackupInfo.vm_name;
                    "category_name" = $category.split(":")[0];
                    "category_value" = $category.split(":")[1];
                }
                if ($myvarBackupInfo.vm_name) {$myvarBackupResults.Add((New-Object PSObject -Property $myvarBackupEntry)) | Out-Null}
            }
        }
    }
#endregion


#* step 4: export results
Write-Host "$(Get-Date) [INFO] Writing results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($prismcentral)_PcVmCategories.csv" -ForegroundColor Green
$myvarVmResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($prismcentral)+"_PcVmCategories.csv")
if ($backup) {
    Write-Host "$(Get-Date) [INFO] Also exporting backup results to $(Get-Date -UFormat "%Y_%m_%d_%H_%M_")$($prismcentral)_categories_backup.csv" -ForegroundColor Green
    $myvarBackupResults | export-csv -NoTypeInformation $($(Get-Date -UFormat "%Y_%m_%d_%H_%M_")+$($prismcentral)+"_categories_backup.csv")
}
#endregion

#region cleanup
Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable help -ErrorAction SilentlyContinue
Remove-Variable history -ErrorAction SilentlyContinue
Remove-Variable log -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion