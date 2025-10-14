<#
.SYNOPSIS
  This script retrieves the complete list of AHV networks from Prism Central.
.DESCRIPTION
  This script retrieves the complete list of AHV networks from Prism Central, including IP pool information and exports the results to csv in the current directory.
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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.EXAMPLE
.\get-AhvNetworks.ps1 -cluster ntnxc1.local
Connect to a Nutanix Prism Central of your choice and retrieve the list of networks.
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 15th 2022
#>

#region parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$log,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $true)] [string]$prismcentral,
      [parameter(mandatory = $false)] $prismCreds
  )
#endregion

#region function
#this function is used to process output to console (timestamped and color coded) and log file
function Write-LogOutput
{#used to format output
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

#this function loads a powershell module
function LoadModule
{#tries to load a module, import it, install it if necessary
    <#
    .SYNOPSIS
    Tries to load the specified module and installs it if it can't.
    .DESCRIPTION
    Tries to load the specified module and installs it if it can't.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER module
    Name of PowerShell module to import.
    .EXAMPLE
    PS> LoadModule -module PSWriteHTML
    #>
    param 
    (
        [string] $module
    )

    begin
    {
        
    }

    process
    {   
        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Trying to get module $($module)..."
        if (!(Get-Module -Name $module)) 
        {#we could not get the module, let's try to load it
            try
            {#import the module
                Import-Module -Name $module -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
            }#end try
            catch 
            {#we couldn't import the module, so let's install it
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Installing module '$($module)' from the Powershell Gallery..."
                try 
                {#install module
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                }
                catch 
                {#could not install module
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Could not install module '$($module)': $($_.Exception.Message)"
                    exit 1
                }

                try
                {#now that it is intalled, let's import it
                    Import-Module -Name $module -ErrorAction Stop
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Imported module '$($module)'!"
                }#end try
                catch 
                {#we couldn't import the module
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Unable to import the module $($module).psm1 : $($_.Exception.Message)"
                    Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "Please download and install from https://www.powershellgallery.com"
                    Exit 1
                }#end catch
            }#end catch
        }
    }

    end
    {

    }
}

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
    $credential,
    
    [parameter(mandatory = $false)]
    [switch] 
    $checking_task_status
)

begin
{
    
}
process
{
    if (!$checking_task_status) {Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green}
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
        if (!$checking_task_status) {Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan} 
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
        [Parameter(mandatory = $true)][string] $pc,
        [Parameter(mandatory = $true)][string] $object,
        [Parameter(mandatory = $true)][string] $kind
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
#endregion

#region prepwork
  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
11/13/2020 sb   Initial release.
02/06/2021 sb   Replaced username with get-credential
04/15/2022 sb   Added functions and removed dependency to sbourdeaud module.
################################################################################
'@
  $myvarScriptName = ".\get-AhvNetworks.ps1"

  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

  #check PoSH version
  if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

  <# #region module sbourdeaud is used for facilitating Prism REST calls
    $required_version = "3.0.8"
    if (!(Get-Module -Name sbourdeaud)) 
    {
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
    if (($MyVarModuleVersion.Version.Major -lt $($required_version.split('.')[0])) -or (($MyVarModuleVersion.Version.Major -eq $($required_version.split('.')[0])) -and ($MyVarModuleVersion.Version.Minor -eq $($required_version.split('.')[1])) -and ($MyVarModuleVersion.Version.Build -lt $($required_version.split('.')[2])))) 
    {
      Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
      Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
      Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
      try 
      {
        Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
        Import-Module -Name sbourdeaud -ErrorAction Stop
      }
      catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
    }
  #endregion #>
  #Set-PoSHSSLCerts
  #Set-PoshTls

  if (!(Get-Module -Name Indented.net.IP))
  {
    Write-Host "$(get-date) [INFO] Importing module 'Indented.net.IP'..." -ForegroundColor Green
    try
    {
        Import-Module -Name Indented.net.IP -ErrorAction Stop
        Write-Host "$(get-date) [SUCCESS] Imported module 'Indented.net.IP'!" -ForegroundColor Cyan
    }#end try
    catch #we couldn't import the module, so let's install it
    {
        Write-Host "$(get-date) [INFO] Installing module 'Indented.net.IP' from the Powershell Gallery..." -ForegroundColor Green
        try {Install-Module -Name Indented.net.IP -Scope CurrentUser -Force -ErrorAction Stop}
        catch {throw "$(get-date) [ERROR] Could not install module 'Indented.net.IP': $($_.Exception.Message)"}

        try
        {
            Import-Module -Name Indented.net.IP -ErrorAction Stop
            Write-Host "$(get-date) [SUCCESS] Imported module 'Indented.net.IP'!" -ForegroundColor Cyan
        }#end try
        catch #we couldn't import the module
        {
            Write-Host "$(get-date) [ERROR] Unable to import the module Indented.net.IP : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/Indented.Net.IP/6.1.0" -ForegroundColor Yellow
            Exit
        }#end catch
    }#end catch
  }
#endregion

#region variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
  $length=100 #this specifies how many entities we want in the results of each API query
  $api_server_port = "9440"
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

#region main processing
  #region make v3 api call for vms
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving VM information from Prism Central $($prismcentral)" -ForegroundColor Magenta
    # this is used to capture the content of the payload
    $content = @{
      kind="vm";
      offset=0;
      length=$length
    }
    $payload = (ConvertTo-Json $content -Depth 4)
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
    $myvar_vms = Get-PrismCentralObjectList -pc $prismcentral -object "vms" -kind "vm"

    ForEach ($entity in $myvar_vms) 
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

    if ($debugme) {
      Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
      $myvarVmResults
    }
  #endregion

  #region make v3 api call for networks
    Write-Host ""
    Write-Host "$(Get-Date) [STEP] Retrieving networks information from Prism Central $($prismcentral)" -ForegroundColor Magenta

    [System.Collections.ArrayList]$myvarNetworksResults = New-Object System.Collections.ArrayList($null)
    $api_server_endpoint = "/api/nutanix/v3/subnets/list"
    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
    $method = "POST"
    
    # this is used to capture the content of the payload
    $content = @{
        kind="subnet";
        offset=0;
        length=$length
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
                  $start_ip = ConvertTo-DecimalIP $range_list[0]
                  $end_ip = ConvertTo-DecimalIP $range_list[1]
                  $ip_count += $end_ip - $start_ip +1
                }
                #* count here how many vms are connected to that network: used ips
                [int]$vm_count=0
                [int]$vm_count = ($myvarVmResults | Where-Object {$_.vnic_vlans -contains $entity.spec.name}).count
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Nb of VMs connected to network $($entity.spec.name): $($vm_count)" -ForegroundColor White}
                
                #todo figure out number of remaining ips for the network (available ips - used ips)
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
                  "subnet_mask" = (ConvertTo-Mask $entity.spec.resources.ip_config.prefix_length).IPAddressToString;
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
            $content = @{
                kind="subnet";
                offset=($resp.metadata.length + $resp.metadata.offset);
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
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
    While ($resp.metadata.length -eq $length)
    
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
  Remove-Variable log -ErrorAction SilentlyContinue
  Remove-Variable cluster -ErrorAction SilentlyContinue
  Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion
