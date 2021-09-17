<#
.SYNOPSIS
  Use this script to synchronize Nutanix Flow rules between two Prism Central instances.
.DESCRIPTION
  Given a source and target Prism Central, a category and a rule prefix, script will synchronize Nutanix Flow rules between both Prism Central (from source to target).
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER sourcePc
  Source Prism Central fully qualified domain name or IP address.
.PARAMETER targetPc
  Target Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER action
  Can be either scan (to view changes only) or sync (to synchronize changes from source to target).
.PARAMETER prefix
  Prefix of Flow rule names on source to consider (this prevents deleting rules that need to exist only on target).
.EXAMPLE
.\Invoke-FlowRuleSync.ps1 -sourcePc pc1.local -targetPc pc2.local -prismCreds myadcreds -action sync -prefix flowPc1
Synchronize all rules starting with flowPc1 from pc1 to pc2:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: September 13th 2021
#>


#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$sourcePc,
        [parameter(mandatory = $true)] [string]$targetPc,
        [parameter(mandatory = $true)] [string]$prefix,
        [parameter(mandatory = $false)][ValidateSet("scan","sync")] [string]$action="scan",
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion


#region functions
    #this function is used to process output to console (timestamped and color coded) and log file
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
            $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message_list.message
            $resp_return_code = $_.Exception.Response.StatusCode.value__
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            if ($resp_return_code -eq 409) 
            {
                Write-Host "$(Get-Date) [WARNING] $saved_error_message" -ForegroundColor Yellow
                Throw
            }
            else 
            {
                if ($payload) {Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green}
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message" 
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
    {
        $global:helpme = $body
        $global:helpmoref = $moref
        $global:result = $_.Exception.Response.GetResponseStream()
        $global:reader = New-Object System.IO.StreamReader($global:result)
        $global:responseBody = $global:reader.ReadToEnd();

        return $global:responsebody

        break
    }#end function Get-RESTError

    function Get-PrismCentralObjectList
    {
        [CmdletBinding()]
        param 
        (
            [Parameter(mandatory = $true)][string] $pc,
            [Parameter(mandatory = $true)][string] $object,
            [Parameter(mandatory = $true)][string] $kind
        )

        begin 
        {
            [System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null)
            $url = "https://{0}:9440/api/nutanix/v3/{1}/list" -f $pc,$object
            $method = "POST"
            $content = @{
                kind=$kind;
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        }
        process 
        {
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
                        $myvarResults.Add($entity) | Out-Null
                    }
        
                    #prepare the json payload for the next batch of entities/response
                    $content = @{
                        kind=$kind;
                        offset=($resp.metadata.length + $resp.metadata.offset);
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
            While ($resp.metadata.length -eq $length)
        }
        end 
        {
            return $myvarResults
        }
    }

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

#endregion


#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
09/10/2021 sb   Initial release.
09/13/2021 sb   Added processing for rule(s) deletion.
################################################################################
'@
    $myvarScriptName = ".\Invoke-FlowRuleSync.ps1"

    if ($log) 
    {
        $myvar_output_log_file = (Get-Date -UFormat "%Y_%m_%d_%H_%M_") + "Invoke-FlowRuleSync.log"
        Start-Transcript -Path ./$myvar_output_log_file
    }

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $length = 100
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


#todo: wip: learn to deal with service groups: lookup service group name from uuid, check it exists on target and what the uuid is, create it if necessary, update uuid reference in payload (right now, that section is simply removed)
#todo: wip: implement correct processing of isolation rules: return warning rather than failure when duplicate isolation rule exists
#todo: improve: rule add/update/delete returns task uuid: check on task status: no task uuid is returned... check on status later?
#todo: improve: add export action for rules from source to json (for backup purposes)
#todo: improve: move code to figure out categories to a function
#todo: improve: implement category:value pair delete

#region main

    #region GET Flow rules
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting Flow rules" -ForegroundColor Magenta
        #region process source
            Write-Host "$(get-date) [INFO] Retrieving list of Flow rules from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            $source_rules_response = Get-PrismCentralObjectList -pc $sourcePc -object "network_security_rules" -kind "network_security_rule"
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of Flow rules from the source Prism Central instance $($sourcePc)" -ForegroundColor Cyan
            $filtered_source_rules_response = $source_rules_response | Where-Object {$_.spec.name -match "^$prefix"}
            Write-Host "$(get-date) [DATA] There are $($filtered_source_rules_response.count) Flow rules which match prefix $($prefix) on source Prism Central $($sourcePc)..." -ForegroundColor White
        #endregion

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of Flow rules from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_rules_response = Get-PrismCentralObjectList -pc $targetPc -object "network_security_rules" -kind "network_security_rule"
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of Flow rules from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            $filtered_target_rules_response = $target_rules_response | Where-Object {$_.spec.name -match "^$prefix"}
            Write-Host "$(get-date) [DATA] There are $($filtered_target_rules_response.count) Flow rules which match prefix $($prefix) on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion

        if (!$filtered_source_rules_response -and !$filtered_target_rules_response)
        {
            Throw "$(get-date) [ERROR] There are no Flow rules on $($sourcePc) or $($targetPc) which match prefix $($prefix)!"
        }
    #endregion

    #region COMPARE Flow rules
        Write-Host ""
        Write-Host "$(get-date) [STEP] Comparing Flow rules" -ForegroundColor Magenta

        #* rules to add ($add_rules_list)
        [System.Collections.ArrayList]$add_rules_list = New-Object System.Collections.ArrayList($null)
        foreach ($rule in $filtered_source_rules_response) 
        {#compare source with target
            if ($rule.spec.name -notin $filtered_target_rules_response.spec.name)
            {#rule exists on source but not on target
                Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) does not exist yet on target Prism Central $($targetPc)" -ForegroundColor Green
                $add_rules_list.Add($rule) | Out-Null
            }
        }
        Write-Host "$(get-date) [DATA] There are $($add_rules_list.count) Flow rules to add on target Prism Central $($targetPc)" -ForegroundColor White

        #* rules to remove ($remove_rules_list)
        [System.Collections.ArrayList]$remove_rules_list = New-Object System.Collections.ArrayList($null)
        foreach ($rule in $filtered_target_rules_response) 
        {#compare target with source
            if ($rule.spec.name -notin $filtered_source_rules_response.spec.name)
            {#rule exists on target but not on source
                Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) no longer exists on source Prism Central $($sourcePc)" -ForegroundColor Green
                $remove_rules_list.Add($rule) | Out-Null
            }
        }
        Write-Host "$(get-date) [DATA] There are $($remove_rules_list.count) Flow rules to remove on target Prism Central $($targetPc)" -ForegroundColor White

        #* rules to update ($update_rules_list)
        [System.Collections.ArrayList]$update_rules_list = New-Object System.Collections.ArrayList($null)
        foreach ($rule in $filtered_source_rules_response) 
        {#compare source with target
            if ($target_rule = $filtered_target_rules_response | Where-Object {$_.spec.Name -eq $rule.spec.Name})
            {#we have a matching rule on target, let's compare
                if (($($rule.spec.resources | ConvertTo-Json -depth 100) -ne $($target_rule.spec.resources | ConvertTo-Json -depth 100)) -or ($rule.spec.description -ne $target_rule.spec.description))
                {#rule configuration or description on source does not match rule configuration or description on target
                    Write-Host "$(get-date) [INFO] Flow rule $($rule.spec.name) needs to be updated on target Prism Central $($targetPc)" -ForegroundColor Green
                    $update_rules_list.Add($rule) | Out-Null
                }
            }
            
        }
        Write-Host "$(get-date) [DATA] There are $($update_rules_list.count) Flow rules to update on target Prism Central $($targetPc)" -ForegroundColor White

    #endregion
    
    #region ACTION
        if ($action -eq "scan")
        {#display what we would do

        }

        if ($action -eq "sync")
        {#synchronize (ADD, DELETE, UPDATE)
            #region process ADD
                if ($add_rules_list)
                {#there are rules to be added
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Adding Flow rules" -ForegroundColor Magenta
                    foreach ($rule in $add_rules_list)
                    {#process each rule to add
                        #region deal with categories
                            #region which categories are used?
                                #* figure out categories used in this rule
                                [System.Collections.ArrayList]$used_categories_list = New-Object System.Collections.ArrayList($null)
                                #types of rules: 
                                if ($rule.spec.resources.quarantine_rule)
                                {
                                    Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is a Quarantine rule..." -ForegroundColor Green
                                    foreach ($category in $rule.spec.resources.quarantine_rule.target_group.filter.params.PSObject.Properties.Name)
                                    {#process each category used in target_group
                                        foreach ($value in $rule.spec.resources.quarantine_rule.target_group.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                }
                                elseif ($rule.spec.resources.isolation_rule) 
                                {
                                    Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Isolation rule..." -ForegroundColor Green
                                    foreach ($category in $rule.spec.resources.isolation_rule.first_entity_filter.params.PSObject.Properties.Name)
                                    {#process each category used in first_entity_filter
                                        foreach ($value in $rule.spec.resources.isolation_rule.first_entity_filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                    foreach ($category in $rule.spec.resources.isolation_rule.second_entity_filter.params.PSObject.Properties.Name)
                                    {#process each category used in second_entity_filter
                                        foreach ($value in $rule.spec.resources.isolation_rule.second_entity_filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                }
                                elseif ($rule.spec.resources.app_rule) 
                                {
                                    Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Application rule..." -ForegroundColor Green
                                    foreach ($category in $rule.spec.resources.app_rule.outbound_allow_list.filter.params.PSObject.Properties.Name)
                                    {#process each category used in outbound_allow_list
                                        foreach ($value in $rule.spec.resources.app_rule.outbound_allow_list.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                    foreach ($category in $rule.spec.resources.app_rule.target_group.filter.params.PSObject.Properties.Name)
                                    {#process each category used in target_group
                                        foreach ($value in $rule.spec.resources.app_rule.target_group.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                    foreach ($category in $rule.spec.resources.app_rule.inbound_allow_list.filter.params.PSObject.Properties.Name)
                                    {#process each category used in inbound_allow_list
                                        foreach ($value in $rule.spec.resources.app_rule.inbound_allow_list.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                }
                                else 
                                {
                                    Write-Host "$(get-date) [WARNING] Rule $($rule.spec.Name) is not a supported rule type for replication!" -ForegroundColor Yellow
                                }

                                Write-Host "$(get-date) [DATA] Flow rule $($rule.spec.Name) uses the following category:value pairs:" -ForegroundColor White
                                $used_categories_list
                            #endregion
                            
                            #region are all used category:value pairs on target?
                                #* check each used category:value pair exists on target
                                [System.Collections.ArrayList]$missing_categories_list = New-Object System.Collections.ArrayList($null)
                                foreach ($category_value_pair in ($used_categories_list | Select-Object -Unique))
                                {#process each used category
                                    $category = ($category_value_pair -split ":")[0]
                                    $value = ($category_value_pair -split ":")[1]

                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                    $method = "GET"

                                    Write-Host "$(Get-Date) [INFO] Checking category:value pair $($category):$($value) exists in $targetPc..." -ForegroundColor Green
                                    try 
                                    {
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                                        Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $targetPc" -ForegroundColor Cyan
                                    }
                                    catch 
                                    {
                                        $saved_error = $_.Exception.Message
                                        $error_code = ($saved_error -split " ")[3]
                                        if ($error_code -eq "404") 
                                        {
                                            Write-Host "$(get-date) [WARNING] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
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
                                {
                                    Write-Host "$(get-date) [DATA] The following category:value pairs need to be added on $($targetPc):" -ForegroundColor White
                                    $missing_categories_list
                                }
                            #endregion
                            
                            #region create missing category:value pairs on target
                                [System.Collections.ArrayList]$processed_categories_list = New-Object System.Collections.ArrayList($null)
                                foreach ($category_value_pair in $missing_categories_list)
                                {
                                    #check if category exists
                                    $category = ($category_value_pair -split ":")[0]
                                    $value = ($category_value_pair -split ":")[1]

                                    if (!$processed_categories_list)
                                    {#we havent processed any category yet
                                        if ($category -notin $processed_categories_list)
                                        {#this category has not been found or added yet
                                            $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                            $method = "GET"

                                            Write-Host "$(Get-Date) [INFO] Checking category $($category) exists in $targetPc..." -ForegroundColor Green
                                            try 
                                            {
                                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                                                Write-Host "$(Get-Date) [SUCCESS] Found the category $($category) in $targetPc" -ForegroundColor Cyan
                                                $processed_categories_list.Add($category) | Out-Null
                                            }
                                            catch 
                                            {
                                                $saved_error = $_.Exception.Message
                                                $error_code = ($saved_error -split " ")[3]
                                                if ($error_code -eq "404") 
                                                {
                                                    Write-Host "$(get-date) [WARNING] The category specified $($category) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
                                                    #add category
                                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                                                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                                    $method = "PUT"
                                                    $content = @{
                                                        api_version="3.1.0";
                                                        description="added by Invoke-FlowRuleSync.ps1 script";
                                                        name="$category"
                                                    }
                                                    $payload = (ConvertTo-Json $content -Depth 4)
                                                    try 
                                                    {
                                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                                        Write-Host "$(Get-Date) [SUCCESS] Added category $($category) in $targetPc" -ForegroundColor Cyan
                                                        if ($debugme) {$resp}
                                                        #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                                                        $processed_categories_list.Add($category) | Out-Null     
                                                    }
                                                    catch 
                                                    {
                                                        Throw "$($_.Exception.Message)"
                                                    }  
                                                }
                                                else 
                                                {
                                                    Throw "$($_.Exception.Message)"
                                                }
                                            }
                                        }
                                    }
                                    
                                    #add value
                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                    $method = "PUT"
                                    $content = @{
                                        api_version="3.1.0";
                                        description="added by Invoke-FlowRuleSync.ps1 script";
                                        value="$value"
                                    }
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                    try 
                                    {
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                        Write-Host "$(Get-Date) [SUCCESS] Added value $($value) to category $($category) in $targetPc" -ForegroundColor Cyan
                                        if ($debugme) {$resp}
                                        #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
                                    }
                                    catch 
                                    {
                                        Throw "$($_.Exception.Message)"
                                    }
                                }
                            #endregion
                        #endregion

                        #region deal with service groups
                            #region which service groups are used?
                                #* figure out service groups used in this rule
                                [System.Collections.ArrayList]$used_service_group_list = New-Object System.Collections.ArrayList($null)
                                #types of rules: 
                                if ($rule.spec.resources.app_rule) 
                                {
                                    foreach ($service_group in $rule.spec.resources.app_rule.outbound_allow_list.service_group_list)
                                    {#process each service group used in outbound_allow_list
                                        $used_service_group_list.Add($service_group) | Out-Null
                                    }
                                    foreach ($service_group in $rule.spec.resources.app_rule.inbound_allow_list.service_group_list)
                                    {#process each service group used in inbound_allow_list
                                        $used_service_group_list.Add($service_group) | Out-Null
                                    }
                                }
                            #endregion

                            #region are all used service groups on the target?
                                #get target service groups
                                $api_server_endpoint = "/api/nutanix/v3/service_groups/list" -f $service_group.uuid
                                $url = "https://{0}:9440{1}" -f $sourcePc,$api_server_endpoint
                                $method = "POST"
                                $content = @{
                                    kind="service_group";
                                    offset=0;
                                    length=$length
                                }
                                $payload = (ConvertTo-Json $content -Depth 4)
                                #! resume here: find a way to get all service group records when payload doesn't include all metadata info
                                $target_service_groups = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload


                                [System.Collections.ArrayList]$missing_service_groups_list = New-Object System.Collections.ArrayList($null)
                                foreach ($service_group in ($used_service_group_list | Select-Object -Unique))
                                {#process each used service group
                                    $api_server_endpoint = "/api/nutanix/v3/service_groups/{0}" -f $service_group.uuid
                                    $url = "https://{0}:9440{1}" -f $sourcePc,$api_server_endpoint
                                    $method = "GET"

                                    $source_service_group = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials

                                    Write-Host "$(Get-Date) [INFO] Checking service group $($source_service_group.service_group.name) exists in $targetPc..." -ForegroundColor Green
                                    try 
                                    {
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                                        Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $targetPc" -ForegroundColor Cyan
                                    }
                                    catch 
                                    {
                                        $saved_error = $_.Exception.Message
                                        $error_code = ($saved_error -split " ")[3]
                                        if ($error_code -eq "404") 
                                        {
                                            Write-Host "$(get-date) [WARNING] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
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
                                {
                                    Write-Host "$(get-date) [DATA] The following category:value pairs need to be added on $($targetPc):" -ForegroundColor White
                                    $missing_categories_list
                                }
                            #endregion

                            #region create missing service groups on target
                            #endregion
                        #endregion

                        #region add rule on target
                            $api_server_endpoint = "/api/nutanix/v3/network_security_rules"
                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                            $method = "POST"
                            $rule.psobject.members.remove("status")
                            $rule.metadata.psobject.members.remove("uuid")
                            $rule.metadata.psobject.members.remove("owner_reference")
                            if ($rule.spec.resources.app_rule)
                            {#remove rule id references from the payload to avoid API errors
                                $rule.spec.resources.app_rule.outbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                                $rule.spec.resources.app_rule.inbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                            }
                            $payload = (ConvertTo-Json $rule -Depth 100)

                            try 
                            {#create network policy
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                Write-Host "$(Get-Date) [SUCCESS] Added Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan
                                if ($debugme) {$resp}
                                #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc 
                            }
                            catch 
                            {#we couldn't create the network policy
                                Throw "$($_.Exception.Message)"
                            }                            
                        #endregion

                        Write-Host ""
                    }
                }
            #endregion

            #region process DELETE
                if ($remove_rules_list)
                {#there are rules to be removed
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Removing Flow rules" -ForegroundColor Magenta
                    foreach ($rule in $remove_rules_list)
                    {#process each rule to remove
                        #todo: for each category, figure out if it is used anywhere else in rules on source: if not, delete the category
                        #? delete rule on target
                        $target_rule = $filtered_target_rules_response | Where-Object {$_.spec.Name -eq $rule.spec.Name}
                        $api_server_endpoint = "/api/nutanix/v3/network_security_rules/{0}" -f $target_rule.metadata.uuid
                        $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                        $method = "DELETE"

                        Write-Host "$(get-date) [STEP] Deleting Flow rule $($rule.spec.Name) on $($targetPc)" -ForegroundColor Green
                        try 
                        {
                            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                            Write-Host "$(Get-Date) [SUCCESS] Deleted Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan
                            
                        }
                        catch 
                        {
                            Throw "$($_.Exception.Message)"
                        }
                    }
                }
            #endregion

            #region process UPDATE 
                if ($update_rules_list)
                {#there are rules to be updated
                    Write-Host ""
                    Write-Host "$(get-date) [STEP] Updating Flow rules" -ForegroundColor Magenta
                    foreach ($rule in $update_rules_list)
                    {#process each rule to update
                        #region deal with categories
                            #region which categories are used?
                                #* figure out categories used in this rule
                                [System.Collections.ArrayList]$used_categories_list = New-Object System.Collections.ArrayList($null)
                                #types of rules: 
                                if ($rule.spec.resources.quarantine_rule)
                                {
                                    Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is a Quarantine rule..." -ForegroundColor Green
                                    foreach ($category in $rule.spec.resources.quarantine_rule.target_group.filter.params.PSObject.Properties.Name)
                                    {#process each category used in target_group
                                        foreach ($value in $rule.spec.resources.quarantine_rule.target_group.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                }
                                elseif ($rule.spec.resources.isolation_rule) 
                                {
                                    Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Isolation rule..." -ForegroundColor Green
                                    foreach ($category in $rule.spec.resources.isolation_rule.first_entity_filter.params.PSObject.Properties.Name)
                                    {#process each category used in first_entity_filter
                                        foreach ($value in $rule.spec.resources.isolation_rule.first_entity_filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                    foreach ($category in $rule.spec.resources.isolation_rule.second_entity_filter.params.PSObject.Properties.Name)
                                    {#process each category used in second_entity_filter
                                        foreach ($value in $rule.spec.resources.isolation_rule.second_entity_filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                }
                                elseif ($rule.spec.resources.app_rule) 
                                {
                                    Write-Host "$(get-date) [INFO] Rule $($rule.spec.Name) is an Application rule..." -ForegroundColor Green
                                    foreach ($category in $rule.spec.resources.app_rule.outbound_allow_list.filter.params.PSObject.Properties.Name)
                                    {#process each category used in outbound_allow_list
                                        foreach ($value in $rule.spec.resources.app_rule.outbound_allow_list.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                    foreach ($category in $rule.spec.resources.app_rule.target_group.filter.params.PSObject.Properties.Name)
                                    {#process each category used in target_group
                                        foreach ($value in $rule.spec.resources.app_rule.target_group.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                    foreach ($category in $rule.spec.resources.app_rule.inbound_allow_list.filter.params.PSObject.Properties.Name)
                                    {#process each category used in inbound_allow_list
                                        foreach ($value in $rule.spec.resources.app_rule.inbound_allow_list.filter.params."$category")
                                        {#process each value for this category
                                            $category_value_pair = "$($category):$($value)"
                                            $used_categories_list.Add($category_value_pair) | Out-Null
                                        }
                                    }
                                }
                                else 
                                {
                                    Write-Host "$(get-date) [WARNING] Rule $($rule.spec.Name) is not a supported rule type for replication!" -ForegroundColor Yellow
                                }

                                Write-Host "$(get-date) [DATA] Flow rule $($rule.spec.Name) uses the following category:value pairs:" -ForegroundColor White
                                $used_categories_list
                            #endregion
                            
                            #region are all used category:value pairs on target?
                                #* check each used category:value pair exists on target
                                [System.Collections.ArrayList]$missing_categories_list = New-Object System.Collections.ArrayList($null)
                                foreach ($category_value_pair in ($used_categories_list | Select-Object -Unique))
                                {#process each used category
                                    $category = ($category_value_pair -split ":")[0]
                                    $value = ($category_value_pair -split ":")[1]

                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                    $method = "GET"

                                    Write-Host "$(Get-Date) [INFO] Checking category:value pair $($category):$($value) exists in $targetPc..." -ForegroundColor Green
                                    try 
                                    {
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                                        Write-Host "$(Get-Date) [SUCCESS] Found the category:value pair $($category):$($value) in $targetPc" -ForegroundColor Cyan
                                    }
                                    catch 
                                    {
                                        $saved_error = $_.Exception.Message
                                        $error_code = ($saved_error -split " ")[3]
                                        if ($error_code -eq "404") 
                                        {
                                            Write-Host "$(get-date) [WARNING] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
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
                                {
                                    Write-Host "$(get-date) [DATA] The following category:value pairs need to be added on $($targetPc):" -ForegroundColor White
                                    $missing_categories_list
                                }
                            #endregion
                            
                            #region create missing category:value pairs on target
                                [System.Collections.ArrayList]$processed_categories_list = New-Object System.Collections.ArrayList($null)
                                foreach ($category_value_pair in $missing_categories_list)
                                {
                                    #check if category exists
                                    $category = ($category_value_pair -split ":")[0]
                                    $value = ($category_value_pair -split ":")[1]

                                    if (!$processed_categories_list)
                                    {#we havent processed any category yet
                                        if ($category -notin $processed_categories_list)
                                        {#this category has not been found or added yet
                                            $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                            $method = "GET"

                                            Write-Host "$(Get-Date) [INFO] Checking category $($category) exists in $targetPc..." -ForegroundColor Green
                                            try 
                                            {
                                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                                                Write-Host "$(Get-Date) [SUCCESS] Found the category $($category) in $targetPc" -ForegroundColor Cyan
                                                $processed_categories_list.Add($category) | Out-Null
                                            }
                                            catch 
                                            {
                                                $saved_error = $_.Exception.Message
                                                $error_code = ($saved_error -split " ")[3]
                                                if ($error_code -eq "404") 
                                                {
                                                    Write-Host "$(get-date) [WARNING] The category specified $($category) does not exist in Prism Central $targetPc" -ForegroundColor Yellow
                                                    #add category
                                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}" -f $category
                                                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                                    $method = "PUT"
                                                    $content = @{
                                                        api_version="3.1.0";
                                                        description="added by Invoke-FlowRuleSync.ps1 script";
                                                        name="$category"
                                                    }
                                                    $payload = (ConvertTo-Json $content -Depth 4)
                                                    try 
                                                    {
                                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                                        Write-Host "$(Get-Date) [SUCCESS] Added category $($category) in $targetPc" -ForegroundColor Cyan
                                                        $processed_categories_list.Add($category) | Out-Null     
                                                    }
                                                    catch 
                                                    {
                                                        Throw "$($_.Exception.Message)"
                                                    }  
                                                }
                                                else 
                                                {
                                                    Throw "$($_.Exception.Message)"
                                                }
                                            }
                                        }
                                    }
                                    
                                    #add value
                                    $api_server_endpoint = "/api/nutanix/v3/categories/{0}/{1}" -f $category,$value
                                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                                    $method = "PUT"
                                    $content = @{
                                        api_version="3.1.0";
                                        description="added by Invoke-FlowRuleSync.ps1 script";
                                        value="$value"
                                    }
                                    $payload = (ConvertTo-Json $content -Depth 4)
                                    try 
                                    {
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                        Write-Host "$(Get-Date) [SUCCESS] Added value $($value) to category $($category) in $targetPc" -ForegroundColor Cyan   
                                    }
                                    catch 
                                    {
                                        Throw "$($_.Exception.Message)"
                                    }
                                }
                            #endregion
                        #endregion

                        #region deal with service groups
                            #region which service groups are used?
                            #endregion

                            #region are all used service groups on the target?
                            #endregion

                            #region create missing service groups on target
                            #endregion
                        #endregion
                        
                        #region update rule on target
                            $target_rule = $filtered_target_rules_response | Where-Object {$_.spec.Name -eq $rule.spec.Name}
                            $api_server_endpoint = "/api/nutanix/v3/network_security_rules/{0}" -f $target_rule.metadata.uuid
                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                            $method = "PUT"
                            $rule.psobject.members.remove("status")
                            $rule.metadata.psobject.members.remove("uuid")
                            $rule.metadata.psobject.members.remove("owner_reference")
                            $rule.metadata.spec_version = $target_rule.metadata.spec_version
                            if ($rule.spec.resources.app_rule)
                            {#remove rule id references from the payload to avoid API errors
                                $rule.spec.resources.app_rule.outbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                                $rule.spec.resources.app_rule.inbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
                            }
                            $payload = (ConvertTo-Json $rule -Depth 100)

                            try 
                            {#update the network policy
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                                Write-Host "$(Get-Date) [SUCCESS] Updated Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan   
                            }
                            catch 
                            {#we couldn't update the network policy
                                Throw "$($_.Exception.Message)"
                            }                            
                        #endregion
                    }
                }
            #endregion
        }
    #endregion
    
#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
    
    if ($log) 
    {
        Stop-Transcript
    }

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable sourcePc -ErrorAction SilentlyContinue
    Remove-Variable targetPc -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion