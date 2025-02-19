<#
.SYNOPSIS
  This script can be used to create categories in Prism Central. It can take csv as input for mass creation.
.DESCRIPTION
  Given a Nutanix cluster and a list of category:value pairs, create that category:value in Prism Central.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER sourcecsv
  Indicates the path of a comma separated file including a list of VMs to modify. The format of each line (with headers) is: category_name,category_value.
.PARAMETER categories
  List of category:value pairs to create. This is case sensitive.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\new-category.ps1 -prism 10.10.10.1 -prismCreds myuser -categories "my_category:my_value1,my_category:my_value2,my_other_category:my_other_value1"
Creates the specified category:value pairs.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: January 31st 2025
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
    [parameter(mandatory = $false)] $prismCreds,[parameter(mandatory = $false)] [string]$sourcecsv,
    [parameter(mandatory = $false)] [string]$categories
)
#endregion

#region functions
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
  if (!$checking_task_status -and $debugme) {Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green}
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
      if (!$checking_task_status -and $debugme) {Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan} 
      if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
  }
  catch {
      $saved_error = $_.Exception.Message
      # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
      if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
      Write-Host "$(get-date) [ERROR] $saved_error" -ForegroundColor Red
      throw
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

#helper-function Get-RESTError
function Help-RESTError 
{
  $global:helpme = $body
  $global:helpmoref = $moref
  $global:result = $_.Exception.Response.GetResponseStream()
  $global:reader = New-Object System.IO.StreamReader($global:result)
  $global:responseBody = $global:reader.ReadToEnd();

  return $global:responsebody

  break
}#end function Get-RESTError

function CheckModule
{
  param 
  (
      [string] $module,
      [string] $version
  )

  #getting version of installed module
  $current_version = (Get-Module -ListAvailable $module) | Sort-Object Version -Descending  | Select-Object Version -First 1
  #converting version to string
  $stringver = $current_version | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
  $a = $stringver | Select-Object Moduleversion -ExpandProperty Moduleversion
  #converting version to string
  $targetver = $version | select @{n='TargetVersion'; e={$_ -as [string]}}
  $b = $targetver | Select-Object TargetVersion -ExpandProperty TargetVersion
  
  if ([version]"$a" -ge [version]"$b") {
      return $true
  }
  else {
      return $false
  }
}

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

Function Get-PrismCentralTaskStatus
{
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
      
      [parameter(mandatory = $true)]
      [System.Management.Automation.PSCredential]
      $credential,

      [parameter(mandatory = $true)]
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
          $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential -checking_task_status
          Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
      #endregion

      if ($taskDetails.percentage_complete -ne "100") 
      {
          Do 
          {
              #New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
              #$Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 2,$Host.UI.RawUI.CursorPosition.Y
              Write-Host "$(Get-Date) [INFO] Task $($taskDetails.operation_type) is still running: $($taskDetails.percentage_complete) completed" -ForegroundColor Green
              Sleep 5
              $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential -checking_task_status
              
              if ($taskDetails.status -ne "running") 
              {
                  if ($taskDetails.status -ne "succeeded") 
                  {
                      Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) failed with the following status and error code : $($taskDetails.status) : $($taskDetails.progress_message)" -ForegroundColor Yellow
                  }
              }
          }
          While ($taskDetails.percentage_complete -ne "100")
          
          New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
          Write-Host ""
          Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
      } 
      else 
      {
          if ($taskDetails.status -ine "succeeded") {
              Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) status is $($taskDetails.status): $($taskDetails.progress_message) $($taskDetails.error_detail)" -ForegroundColor Yellow
          } else {
              #New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
              #Write-Host ""
              Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
          }
      }
  }
  end
  {
      return $taskDetails.status
  }
}
#endregion

#region prep-work
#check if we need to display help and/or history
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
01/31/2025 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\new-category.ps1"
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

Set-PoSHSSLCerts
Set-PoshTls

#endregion

#region variables
#initialize variables
#misc variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
$myvarOutputLogFile += "OutputLog.log"
[System.Collections.ArrayList]$myvarListToProcess = New-Object System.Collections.ArrayList($null)
$myvarCategories = @()

$api_server_port = "9440"
$api_server = $prism
  
#let's initialize parameters if they haven't been specified
if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
if ($categories -and $sourcecsv) {throw "You must specify -categories OR -sourcecsv but NOT BOTH!"}
if ((!$categories) -and !($sourcecsv)) {$categories = read-host "Enter a list of category:value pairs to create"}
if ($categories) {
    $categories.Split(",")
    foreach ($pair in $categories) {
        #build dict with provided values
        $myvarItem = [ordered]@{
          "category_name" = $($pair.Split(":"))[0];
          "category_value" = $($pair.Split(":"))[1]
        }
        #store the results for this entity in our overall result variable
        $myvarListToProcess.Add((New-Object PSObject -Property $myvarItem)) | Out-Null
    }
}
if ($sourcecsv) {
  try {
    $myvarListToProcess = Import-Csv -Path $sourcecsv -ErrorAction Stop
  }
  catch {
    $saved_error = $_.Exception.Message
    throw "$(get-date) [ERROR] $saved_error"
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
ForEach ($item in $myvarListToProcess) {
  $myvar_already_tagged = $false
  $category = $item.category_name
  $value = $item.category_value

  #! step 1: check category value pairs exists
  #region get categories
  #* retrieve categories
  $api_server_endpoint = "/api/nutanix/v3/categories/list"
  $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
      $api_server_endpoint
  $method = "POST"
  $content = @{
      kind = "category";
      length = 500
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
        #Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}

        $myvarCategories += $resp.entities
        
        #prepare the json payload for the next batch of entities/response
        $content = @{
            kind="cluster";
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
  #endregion get categories

  #region check category:value pair exists
    #region prepare api call
      $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
      $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
          $api_server_endpoint
      $method = "GET"
    #endregion

    #region make the api call
      Write-Host "$(Get-Date) [INFO] Checking $($category):$($value) exists in $prism..." -ForegroundColor Green
      try {
        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(Get-Date) [SUCCESS] The category:value pair $($category):$($value) already exists in $prism" -ForegroundColor Cyan
        Continue
      }
      catch {
        $saved_error = $_.Exception.Message
        if ($_.Exception.Response.StatusCode -contains "NotFound") {
            #region check if category exists, if not create it
            #* create category if required
                if ($category -notin $myvarCategories.name) {
                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                    $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
                        $api_server_endpoint
                    $method = "PUT"
                    $content = @{
                        name = $category
                    }
                    $payload = (ConvertTo-Json $content -Depth 4)
                    try {
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                        Write-Host "$(get-date) [SUCCESS] Created category key $($category)." -ForegroundColor Cyan
                    }
                    catch {
                        Write-Host "$(get-date) [WARNING] Could not create category key $($category)!" -ForegroundColor Yellow
                    }
                }
                else {Write-Host "$(get-date) [INFO] The category key $($category) already exists." -ForegroundColor Green}
            #endregion check if category exists, if not create it

            #region: create category:value
                $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
                    $api_server_endpoint
                $method = "PUT"
                $content = @{
                  value = $value
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                try {
                  $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                  Write-Host "$(get-date) [SUCCESS] Created value $($value) in category key $($category)." -ForegroundColor Cyan
                }
                catch {
                  Write-Host "$(get-date) [WARNING] Could not create value $($value) in category key $($category)!" -ForegroundColor Yellow
                }
            #endregion create category:value
        }
        else {
            Write-Host "$(get-date) [WARNING] $saved_error" -ForegroundColor Yellow
            Continue
        }
      }
      finally {
      }
    #endregion

  #endregion
}
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
Remove-Variable prism -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion