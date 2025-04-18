<#
.SYNOPSIS
  Use this script to delete Calm application instances and blueprints based on a name pattern.
.DESCRIPTION
  Use this script to delete Calm application instances based on a name pattern.
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
.PARAMETER apps
  Name of the application instance(s) you want to delete. You can use wildcards, specify a single name, or comma separated values.
.PARAMETER soft
  Specifies you want to do a soft delete (which does not delete VMs).
.PARAMETER bps
  Name of the blueprint(s) you want to delete. You can use wildcards, specify a single name, or comma separated values.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.EXAMPLE
.\template.ps1 -prismcentral ntnxc1.local
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 2nd 2021
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
        [parameter(mandatory = $false)] [string]$apps,
        [parameter(mandatory = $false)] [switch]$soft,
        [parameter(mandatory = $false)] [string]$bps,
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion

#region functions
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
    if ($debugme) {Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green}
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
        if ($debugme) {
          Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
          Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White
        }
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
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/02/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\remove-calmApps.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    if ($log) 
    {#we want a log file
        $myvar_log_file = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvar_log_file += "$($prismcentral)_"
        $myvar_log_file += "remove-calmApps.log"
        $myvar_log_file = $dir + $myvar_log_file
    }

    #Set-PoSHSSLCerts
    #Set-PoshTls
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port = 9440
    $length = 250
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

  if (!$apps -and !$bps) 
  {
    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "You must specify either an application name or a blueprint name! Exiting."
    Exit 1
  }

  $myvar_apps = $apps.Split(",") #make sure we parse the argument in case it contains several entries
  $myvar_bps = $bps.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#region processing

    #region delete app
      if ($apps)
      {
        #region GET apps
          Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of NCM Self Service applications..."

          #region get total number of entities
            $url = "https://{0}:9440/api/nutanix/v3/apps/list" -f $prismcentral
            $method = "POST"
            $content = @{
                kind= "app";
                length = 1;
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Write-Host "$(Get-Date) [INFO] Retrieving total number of Apps available from $prismcentral..." -ForegroundColor Green
            $total_entities = (Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials).metadata.total_matches
          #endregion get total number of entities
          #region retrieve all entities
            $page_size = 250
            $total_pages = [Math]::Ceiling($total_entities / $page_size)
            $offsets = 0..($total_pages - 1) | ForEach-Object { $_ * $page_size }
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            Write-Host "$(Get-Date) [INFO] Retrieving $total_entities entities from $prismcentral..." -ForegroundColor Green
            $results = $offsets | ForEach-Object -ThrottleLimit 5 -Parallel {
                $offset = $_
                $url = "https://{0}:9440/api/nutanix/v3/apps/list" -f $($using:prismcentral)
                $method = "POST"
                $content = @{
                    kind= "app";
                    length = $($using:page_size);
                    offset = $offset;
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                
                try {
                    $response = Invoke-RestMethod -Method $method -Uri $url -Headers $($using:headers) -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $($using:prismCredentials) -ErrorAction Stop
                    $response.entities
                }
                catch {
                    $saved_error = $_.Exception
                    Write-Host "$(Get-Date) [ERROR] $saved_error" -ForegroundColor Red
                }
            }
          #endregion retrieve all entities
        #endregion GET apps in ERROR state

        #region build list of apps to delete
          [array]$myvar_app_list_to_delete=@()
          ForEach ($myvar_app in $myvar_apps)
          {
            if ($myvar_item = $results | Where-Object {$_.status.name -like $myvar_app})
            {#found a vm to delete
              $myvar_app_list_to_delete += $myvar_item
            }
          }
          if (!$myvar_app_list_to_delete)
          {#could not find any of the vms specified
            Throw "$(Get-Date) [ERROR] Could not find any Calm apps on Prism Central $($prismcentral) from the specified list!"
          }
        #endregion

        Foreach ($myvar_app in $myvar_app_list_to_delete)
        { 
          #DELETE apps/uuid
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Deleting Calm application $($myvar_app.status.name)..."
            #region prepare api call
              if ($soft)
              {
                $api_server_endpoint = "/api/nutanix/v3/apps/{0}?type=soft" -f $myvar_app.metadata.uuid
              }
              else 
              {
                $api_server_endpoint = "/api/nutanix/v3/apps/{0}" -f $myvar_app.metadata.uuid
              }
              $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
              $method = "DELETE"
            #endregion
            #region make api call
              try 
              {
                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
              }
              catch {
                  $saved_error = $_.Exception.Message
                  Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                  Throw "$(get-date) [ERROR] $saved_error"
              }
            #endregion
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully deleted Calm application $($myvar_app.status.name) from $prismcentral!"
        }
      }
    #endregion

    #region delete bp
      if ($bps)
      {
        #POST blueprints/list to retrieve app uuid
          Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of Calm blueprints..."
          #region prepare api call
              $api_server_endpoint = "/api/nutanix/v3/blueprints/list"
              $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
              $method = "POST"

              # this is used to capture the content of the payload
              $content = @{
                  kind="blueprint";
                  offset=0;
                  length=$length
              }
              $payload = (ConvertTo-Json $content -Depth 4)
          #endregion
          #region make api call
              [System.Collections.ArrayList]$myvarBlueprintsResults = New-Object System.Collections.ArrayList($null)
              Do 
              {
                  try 
                  {
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
                            $myvarBlueprintInfo = [ordered]@{
                                "name" = $entity.status.name;
                                "uuid" = $entity.metadata.uuid;
                            }
                            #store the results for this entity in our overall result variable
                            $myvarBlueprintsResults.Add((New-Object PSObject -Property $myvarBlueprintInfo)) | Out-Null
                      }

                      #prepare the json payload for the next batch of entities/response
                      $content = @{
                          kind="blueprint";
                          offset=($resp.metadata.length + $resp.metadata.offset);
                          length=$length
                      }
                      $payload = (ConvertTo-Json $content -Depth 4)
                  }
                  catch 
                  {
                      $saved_error = $_.Exception.Message
                      # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                      Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                      Throw "$(get-date) [ERROR] $saved_error"
                  }
              }
              While ($resp.metadata.length -eq $length)

              if ($debugme) 
              {
                  Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
                  $myvarBlueprintsResults
              }
          #endregion
          Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved list of Calm blueprints from $prismcentral!"
        
        #region build list of bps to delete
          [array]$myvar_bp_list_to_delete=@()
          ForEach ($myvar_bp in $myvar_bps)
          {
            if ($myvar_item = $myvarBlueprintsResults | Where-Object {$_.name -like $myvar_bp})
            {#found a vm to delete
              $myvar_bp_list_to_delete += $myvar_item
            }
          }
          if (!$myvar_bp_list_to_delete)
          {#could not find any of the vms specified
            Throw "$(Get-Date) [ERROR] Could not find any Calm blueprints on Prism Central $($prismcentral) from the specified list!"
          }
        #endregion

        Foreach ($myvar_bp in $myvar_bp_list_to_delete)
        { 
          #DELETE blueprint/uuid
          Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Deleting Calm blueprint $($myvar_bp.name)..."
          #region prepare api call
              $api_server_endpoint = "/api/nutanix/v3/blueprints/{0}" -f $myvar_bp.uuid
              $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
              $method = "DELETE"
          #endregion
          #region make api call
            try 
            {
              $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            }
            catch {
                $saved_error = $_.Exception.Message
                Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                Throw "$(get-date) [ERROR] $saved_error"
            }
          #endregion
          Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully deleted Calm blueprint $($myvar_bp.name) from $prismcentral!"
        }
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
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion