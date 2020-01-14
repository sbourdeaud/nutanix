<#
.SYNOPSIS
  This script can be used to add or remove categories from a virtual machine in Prism Central.
.DESCRIPTION
  Given a Nutanix cluster, a virtual machine name, a category name and a value name, add or remove that category from the virtual machine in Prism Central.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER username
  Prism Central username.
.PARAMETER password
  Prism Central username password.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vm
  Name of the virtual machine to edit (as displayed in Prism Central)
.PARAMETER category
  Name of the category to assign to the vm (which must already exists in Prism Central). This is case sensitive.
.PARAMETER value
  Name of the category value to assign to the vm (which must already exists in Prism Central).  This is case sensitive.
.PARAMETER add
  Adds the specified category:value to vm.
.PARAMETER remove
  Removes the specified category:value to vm.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\set-category.ps1 -prism 10.10.10.1 -prismCreds myuser -vm myvm -category mycategory -value myvalue -add
Adds the category mycategory:myvalue to myvm.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: January 14th 2020
#>

#region Parameters
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
    [parameter(mandatory = $false)] [string]$vm,
    [parameter(mandatory = $false)] [string]$category,
    [parameter(mandatory = $false)] [string]$value,
    [parameter(mandatory = $false)] [switch]$add,
    [parameter(mandatory = $false)] [switch]$remove
)
#endregion

#region prep-work
#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
01/14/2020 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\set-category.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#let's get ready to use the Nutanix REST API
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

#endregion

#region functions
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
#endregion

#region variables
#initialize variables
#misc variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
$myvarOutputLogFile += "OutputLog.log"
  
############################################################################
# command line arguments initialization
############################################################################	
#let's initialize parameters if they haven't been specified
if ((!$add) -and !($remove)) {throw "You must specify either add or remove!"}
if ($add -and $remove) {throw "You must specify either add or remove but not both!"}
if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
if (!$vm) {$vm = read-host "Enter the virtual machine name"}
if (!$category) {$category = read-host "Enter the category name"}
if (!$value) {$value = read-host "Enter the category value name"}
if (!$prismCreds) {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
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
} 
else { #we are using custom credentials, so let's grab the username and password from that
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
}
#endregion

#region processing

#! step 1: check category value pairs exists
#region check category:value pair exists

#region prepare api call
  $api_server = $prism
  $api_server_port = "9440"
  $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
  $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
      $api_server_endpoint
  $method = "GET"
  $headers = @{
      "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
      "Content-Type"="application/json";
      "Accept"="application/json"
  }
#endregion

#region make the api call
  Write-Host "$(Get-Date) [INFO] Checking $($category):$($value) exists in $prism..." -ForegroundColor Green
  try {
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
    if ($PSVersionTable.PSVersion.Major -gt 5) {
      $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
    } else {
        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
    }
    Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $prism" -ForegroundColor Cyan
  }
  catch {
    $saved_error = $_.Exception.Message
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        throw "$(get-date) [ERROR] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $prism"
    }
    else {
        throw "$(get-date) [ERROR] $saved_error"
    }
  }
  finally {
  }
#endregion

#endregion

#! step 2: retrieve vm details
#region retrieve the vm details
#region prepare api call
$api_server = $prism
$api_server_port = "9440"
$api_server_endpoint = "/api/nutanix/v3/vms/list"
$url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
    $api_server_endpoint
$method = "POST"
$headers = @{
    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
    "Content-Type"="application/json";
    "Accept"="application/json"
}
$content = @{
    filter= "vm_name==$($vm)";
    kind= "vm"
}
$payload = (ConvertTo-Json $content -Depth 4)
#endregion

#region make the api call
Write-Host "$(Get-Date) [INFO] Retrieving the configuration of vm $vm from $prism..." -ForegroundColor Green
try {
  Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
  #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
  if ($PSVersionTable.PSVersion.Major -gt 5) {
    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Body $payload -ErrorAction Stop
  } else {
      $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
  }
  if ($resp.metadata.total_matches -eq 0) {
      throw "$(get-date) [ERROR] VM $vm was not found on $prism"
  }
  elseif ($resp.metadata.total_matches -gt 1) {
    throw "$(get-date) [ERROR] There are multiple VMs matching name $vm on $prism"
  }
  $vm_config = $resp.entities[0]
  $vm_uuid = $vm_config.metadata.uuid
  Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved the configuration of vm $vm from $prism" -ForegroundColor Cyan
}
catch {
  $saved_error = $_.Exception.Message
  throw "$(get-date) [ERROR] $saved_error"
}
finally {
}
#endregion

#endregion

#! step 3: prepare the json payload
#region prepare the json payload
$vm_config.PSObject.Properties.Remove('status')
#endregion

#! step 4.1: process -add
#region process add
if ($add) {
  try {
    $vm_config.metadata.categories | Add-Member -MemberType NoteProperty -Name $category -Value $value -PassThru -ErrorAction Stop
    $vm_config.metadata.categories_mapping | Add-Member -MemberType NoteProperty -Name $category -Value @($value) -PassThru -ErrorAction Stop
  }
  catch {
    Write-Host "$(Get-Date) [ERROR] Could not add category:value pair ($($category):$($value)). It may already be assigned to the vm $vm in $prism" -ForegroundColor Red
    exit
  }
}
#endregion

#! step 4.2: process -remove
#region process remove
if ($remove) {
  #todo match the exact value pair here as a category could have multiple values assigned
  Write-Host "$(Get-Date) [WARNING] Remove hasn't been implemented yet (still working on it)" -ForegroundColor Yellow
  #$vm_config.metadata.categories.PSObject.Properties.Remove($category)
  #$vm_config.metadata.categories_mapping.PSObject.Properties.Remove($category)
}
#endregion

#! step 5: update the vm object
#region update vm

#region prepare api call
$api_server = $prism
$api_server_port = "9440"
$api_server_endpoint = "/api/nutanix/v3/vms/{0}" -f $vm_uuid
$url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
    $api_server_endpoint
$method = "PUT"
$headers = @{
    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))));
    "Content-Type"="application/json";
    "Accept"="application/json"
}
$payload = (ConvertTo-Json $vm_config -Depth 6)
#endregion

#region make the api call
Write-Host "$(Get-Date) [INFO] Updating the configuration of vm $vm in $prism..." -ForegroundColor Green
do {
  try {
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12
    if ($PSVersionTable.PSVersion.Major -gt 5) {
      $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Body $payload -ErrorAction Stop
    } else {
        $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
    }
    Write-Host "$(Get-Date) [SUCCESS] Successfully updated the configuration of vm $vm from $prism" -ForegroundColor Cyan
  }
  catch {
    $saved_error = $_.Exception
    if ($_.Exception.Response.StatusCode.value__ -eq 409) {
      Write-Host "$(Get-Date) [WARNING] VM $vm cannot be updated now. Retrying in 30 seconds..." -ForegroundColor Yellow
      sleep 30
    }
    else {
      Write-Host $payload -ForegroundColor White
      throw "$(get-date) [ERROR] $($saved_error.Message)"
    }
  }
  finally {
  }
} while ($saved_error.Response.StatusCode.value__ -eq 409)

#endregion

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
Remove-Variable log -ErrorAction SilentlyContinue
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable prism -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion