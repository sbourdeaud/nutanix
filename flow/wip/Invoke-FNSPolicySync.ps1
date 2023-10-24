<#
.SYNOPSIS
  Use this script to synchronize Nutanix Flow Network Security rules between two Prism Central instances.
.DESCRIPTION
  Given a source and target Prism Central, a category and a rule prefix, script will synchronize Nutanix Flow rules between both Prism Central (from source to target).
  This script is meant to work with FNS 4.0 using API v4.
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
.PARAMETER securedCalls
  Use if you want to check SSL certificates with every API call (default if to skip SSL certs checks).
.EXAMPLE
.\Invoke-FlowRuleSync.ps1 -sourcePc pc1.local -targetPc pc2.local -prismCreds myadcreds -action sync -prefix flowPc1
Synchronize all rules starting with flowPc1 from pc1 to pc2:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 4th 2023
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
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [switch]$securedCalls
    )
#endregion


#region functions
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
            [parameter(mandatory = $true)][ValidateSet("POST","GET","DELETE","PUT")][string]$method,
            [parameter(mandatory = $true)][string]$url,
            [parameter(mandatory = $false)][string]$payload,
            [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$credential,
            [parameter(mandatory = $false)][boolean]$check_certificates=$false
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
                        if (!$check_certificates)
                        {#not checking ssl certs
                            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                        }
                        else 
                        {#checking ssl certs
                            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                        }
                    } 
                    else 
                    {
                        if (!$check_certificates)
                        {#not checking ssl certs
                            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                        }
                        else 
                        {#checking ssl certs
                            $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                        }
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
                if ($_.Exception.Source -ne "System.Net.Http")
                {
                    if (!($saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message_list.message))
                    {#trying another way to extract the detailed error message
                        $saved_error_message = "{0} {1}" -f ($_.ErrorDetails.Message | ConvertFrom-Json).data.error.code,($_.ErrorDetails.Message | ConvertFrom-Json).data.error.message
                    }
                    $resp_return_code = $_.Exception.Response.StatusCode.value__
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
                else 
                {
                    Throw "$(get-date) [ERROR] $($_.ErrorDetails.Message)"
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
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials -check_certificates $check_ssl_certificates
                    
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
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential -check_certificates $check_ssl_certificates
                Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
            #endregion

            if ($taskDetails.percentage_complete -ne "100") 
            {
                Do 
                {
                    New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                    Sleep 5
                    $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential -check_certificates $check_ssl_certificates
                    
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

    #TODO: update code here
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

            Write-Host "$(get-date) [DATA] Flow rule $($rule.spec.Name) uses the following category:value pairs:" -ForegroundColor White
            $used_categories_list | Select-Object -Unique
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
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -check_certificates $check_ssl_certificates
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
                {#there are missing categories on target
                    Write-Host "$(get-date) [DATA] The following category:value pairs need to be added on $($targetPc):" -ForegroundColor White
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
                            $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                            $method = "GET"

                            Write-Host "$(Get-Date) [INFO] Checking category $($category) exists in $targetPc..." -ForegroundColor Green
                            try 
                            {#get the category
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -check_certificates $check_ssl_certificates
                                Write-Host "$(Get-Date) [SUCCESS] Found the category $($category) in $targetPc" -ForegroundColor Cyan
                                $processed_categories_list.Add($category) | Out-Null
                            }
                            catch 
                            {#get category failed, or category was not found
                                $saved_error = $_.Exception.Message
                                $error_code = ($saved_error -split " ")[3]
                                if ($error_code -eq "404") 
                                {#category was not found
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
                                    {#add the category
                                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
                                        Write-Host "$(Get-Date) [SUCCESS] Added category $($category) in $targetPc" -ForegroundColor Cyan
                                        if ($debugme) {$resp}
                                        #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc
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
                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                    $method = "PUT"
                    $content = @{
                        api_version="3.1.0";
                        description="added by Invoke-FlowRuleSync.ps1 script";
                        value="$value"
                    }
                    $payload = (ConvertTo-Json $content -Depth 4)
                    try 
                    {#add the value
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
                        Write-Host "$(Get-Date) [SUCCESS] Added value $($value) to category $($category) in $targetPc" -ForegroundColor Cyan
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

        end {}
    }

    #TODO: update code here
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

            #region are all used address groups on the target?

                [System.Collections.ArrayList]$missing_address_groups_list = New-Object System.Collections.ArrayList($null)
                foreach ($address_group in ($used_address_group_list | Select-Object -Property uuid -Unique))
                {#process each used address group

                    #find out what the address group name is (only uuid is kept in rule definition)
                    $api_server_endpoint = "/api/nutanix/v3/address_groups/{0}" -f $address_group.uuid
                    $url = "https://{0}:9440{1}" -f $sourcePc,$api_server_endpoint
                    $method = "GET"

                    $source_address_group = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -check_certificates $check_ssl_certificates

                    if ($source_address_group.address_group.name -notin $target_address_groups.address_group.name)
                    {#based on its name, that address group does not exist on the target
                        $missing_address_groups_list.Add($source_address_group) | Out-Null
                    }
                    else 
                    {#the address group already exists on target, let's update the uuid reference in that rule
                        $target_address_group_uuid = ($target_address_groups | Where-Object {$_.address_group.Name -eq $source_address_group.address_group.name}).uuid
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
                    Write-Host "$(get-date) [DATA] The following address groups need to be added on $($targetPc):" -ForegroundColor White
                    $missing_address_groups_list.address_group.name
                }
            #endregion

            #region create missing address groups on target
                [System.Collections.ArrayList]$processed_address_groups_list = New-Object System.Collections.ArrayList($null)
                foreach ($address_group in $missing_address_groups_list)
                {#process all missing address groups
                    #add address group
                    $api_server_endpoint = "/api/nutanix/v3/address_groups" -f $category,$value
                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                    $method = "POST"
                    $payload = (ConvertTo-Json $address_group.address_group -Depth 10)
                    Write-Host "$(Get-Date) [INFO] Adding address group $($address_group.address_group.name) to $targetPc" -ForegroundColor Green
                    try 
                    {#add address group
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
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

        end {}
    }

    #TODO: update code here
    function Sync-ServiceGroups
    {#syncs Prism service groups used in a given network policy
        param
        (
            [Parameter(Mandatory)]
            $rule
        )

        begin {}

        process 
        {
            #region which service groups are used?
                #* figure out service groups used in this rule
                Write-Host "$(get-date) [INFO] Examining service groups..." -ForegroundColor Green
                [System.Collections.ArrayList]$used_service_group_list = New-Object System.Collections.ArrayList($null)
                #types of rules (where categories are listed varies depending on the type of rule): 
                if ($rule.spec.resources.app_rule) 
                {#this is an app rule
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

                [System.Collections.ArrayList]$missing_service_groups_list = New-Object System.Collections.ArrayList($null)
                foreach ($service_group in ($used_service_group_list | Select-Object -Property uuid -Unique))
                {#process each used service group

                    #find out what the service group name is (only uuid is kept in rule definition)
                    $api_server_endpoint = "/api/nutanix/v3/service_groups/{0}" -f $service_group.uuid
                    $url = "https://{0}:9440{1}" -f $sourcePc,$api_server_endpoint
                    $method = "GET"

                    $source_service_group = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -check_certificates $check_ssl_certificates

                    #Write-Host "$(Get-Date) [INFO] Checking service group $($source_service_group.service_group.name) exists in $targetPc..." -ForegroundColor Green
                    if ($source_service_group.service_group.name -notin $target_service_groups.service_group.name)
                    {#based on its name, that service group does not exist on the target
                        $missing_service_groups_list.Add($source_service_group) | Out-Null
                    }
                    else 
                    {#the service group already exists on target, let's update the uuid reference in that rule
                        $target_service_group_uuid = ($target_service_groups | Where-Object {$_.service_group.Name -eq $source_service_group.service_group.name}).uuid
                        if ($service_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                        {#that service group is used in inbound allow list
                            ForEach ($service_group_item in $service_group_inbound)
                            {
                                $service_group_item.uuid = $target_service_group_uuid
                            } 
                        }
                        if ($service_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                        {#that service group is used in outbound allow list
                            ForEach ($service_group_item in $service_group_outbound)
                            {
                                $service_group_item.uuid = $target_service_group_uuid
                            }
                        }
                    }
                }

                if ($missing_service_groups_list)
                {#there are missing service groups
                    Write-Host "$(get-date) [DATA] The following service groups need to be added on $($targetPc):" -ForegroundColor White
                    $missing_service_groups_list.service_group.name
                }
            #endregion

            #region create missing service groups on target
                [System.Collections.ArrayList]$processed_service_groups_list = New-Object System.Collections.ArrayList($null)
                foreach ($service_group in $missing_service_groups_list)
                {#process all missing service groups
                    #add service group
                    $api_server_endpoint = "/api/nutanix/v3/service_groups" -f $category,$value
                    $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                    $method = "POST"
                    $payload = (ConvertTo-Json $service_group.service_group -Depth 10)
                    Write-Host "$(Get-Date) [INFO] Adding service group $($service_group.service_group.name) to $targetPc" -ForegroundColor Green
                    try 
                    {#add service group
                        $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
                        Write-Host "$(Get-Date) [SUCCESS] Added service group $($service_group.service_group.name) to $targetPc" -ForegroundColor Cyan
                        if ($debugme) {$resp}
                        if ($service_group_inbound = $rule.spec.resources.app_rule.inbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                        {#that service group is used in inbound allow list
                            ForEach ($service_group_item in $service_group_inbound)
                            {
                                $service_group_item.uuid = $resp.uuid
                            } 
                        }
                        if ($service_group_outbound = $rule.spec.resources.app_rule.outbound_allow_list.service_group_list | Where-Object {$_.uuid -eq $source_service_group.uuid})
                        {#that service group is used in outbound allow list
                            ForEach ($service_group_item in $service_group_outbound)
                            {
                                $service_group_item.uuid = $resp.uuid
                            }
                        }
                    }
                    catch 
                    {#we couldn't add the service group
                        Throw "$($_.Exception.Message)"
                    }
                }
            #endregion
        }

        end {}
    }


    function Get-SecurityPolicies
    {#gets FNS >3.0 security policies using API v4
        param
        (
            [Parameter(Mandatory)][string]$prism_central_address,
            [Parameter(Mandatory)][pscredential]$prism_central_credentials_object
        )

        begin 
        {
            $api_endpoint = "/api/microseg/v4.0.a1/config/policies"
            $page = 0
            $limit = 100
            $url = 'https://{0}:9440{1}?$page={2}&$limit={3}' -f $prism_central_address,$api_endpoint,$page,$limit
            $method = 'GET'
            [System.Collections.ArrayList]$results = New-Object System.Collections.ArrayList($null) #this is variable we will use to keep track of entities
        }

        process 
        {
            Do 
            {
                try 
                {
                    $api_response = Invoke-PrismAPICall -method $method -url $url -credential $prism_central_credentials_object -check_certificates $check_ssl_certificates
                    
                    ForEach ($entity in $api_response.data) 
                    {                
                        $results.Add($entity) | Out-Null
                    }
                    
                    $current_page = ($api_response.metadata.links | Where-Object {$_.rel -eq "self"}).href
                    $last_page = ($api_response.metadata.links | Where-Object {$_.rel -eq "last"}).href
                    
                    $page += 1
                    $url = 'https://{0}:9440{1}?$page={2}&$limit={3}' -f $prism_central_address,$api_endpoint,$page,$limit
                }
                catch 
                {
                    <#Do this if a terminating exception happens#>
                }
            }
            While ($current_page -ne $last_page)
        }

        end 
        {
            return $results
        }
    }


    function Get-SecurityPolicyDetails
    {#given a policy extId/uuid, retrieve the detailed content for this policy and return that object
        param 
        (
            [Parameter(Mandatory)][string]$security_policy_extId,
            [Parameter(Mandatory)][string]$prism_central_address,
            [Parameter(Mandatory)][pscredential]$prism_central_credentials_object
        )

        begin
        {
            $url = 'https://{0}:9440/api/microseg/v4.0.a1/config/policies/{1}' -f $prism_central_address,$security_policy_extId
            $method = 'GET'
        }

        process 
        {
            try 
            {
                $api_response = Invoke-PrismAPICall -method $method -url $url -credential $prism_central_credentials_object -check_certificates $check_ssl_certificates
            }
            catch 
            {
                <#Do this if a terminating exception happens#>
            }
        }

        end 
        {
            return $api_response.data
        }
    }


    function Get-Categories
    {#fetch all categories from a specified Prism Central instance
        param
        (
            [Parameter(Mandatory)][string]$prism_central_address,
            [Parameter(Mandatory)][pscredential]$prism_central_credentials_object
        )

        begin 
        {
            $api_endpoint = "/api/prism/v4.0.a2/config/categories"
            $page = 0
            $limit = 100
            $url = 'https://{0}:9440{1}?$page={2}&$limit={3}' -f $prism_central_address,$api_endpoint,$page,$limit
            $method = 'GET'
            [System.Collections.ArrayList]$results = New-Object System.Collections.ArrayList($null) #this is variable we will use to keep track of entities
        }

        process 
        {
            Do 
            {
                try 
                {
                    $api_response = Invoke-PrismAPICall -method $method -url $url -credential $prism_central_credentials_object -check_certificates $check_ssl_certificates
                    
                    ForEach ($entity in $api_response.data) 
                    {                
                        $results.Add($entity) | Out-Null
                    }
                    
                    $current_page = ($api_response.metadata.links | Where-Object {$_.rel -eq "self"}).href
                    $last_page = ($api_response.metadata.links | Where-Object {$_.rel -eq "last"}).href
                    
                    $page += 1
                    $url = 'https://{0}:9440{1}?$page={2}&$limit={3}' -f $prism_central_address,$api_endpoint,$page,$limit
                }
                catch 
                {
                    <#Do this if a terminating exception happens#>
                }
            }
            While ($current_page -ne $last_page)
        }

        end 
        {
            return $results
        }        
    }

    #TODO: update code here
    function Compare-FNSSecurityPolicies
    {#given two FNS security policies, determine if they are the same or different

    }

    #! resume coding here
    function Convert-FNSSecurityPolicyExtIdsToNames 
    {#given a security policy, replace all extIds with their object names to facilitate comparison of content between policies coming from different environments
        param
        (
            [Parameter(Mandatory)]$flow_security_policy,
            [Parameter(Mandatory)]$service_groups,
            [Parameter(Mandatory)]$address_groups,
            [Parameter(Mandatory)]$categories
        )

        begin 
        {
            [System.Collections.ArrayList]$security_policy_translated_rules = New-Object System.Collections.ArrayList($null)
            $translated_flow_security_policy = $flow_security_policy.PsObject.Copy()
        }

        process 
        {
            foreach ($rule in $flow_security_policy.rules)
            {
                [System.Collections.ArrayList]$translated_securedGroup_list = New-Object System.Collections.ArrayList($null)
                foreach ($securedGroup_extId in $rule.spec.securedGroup)
                {
                    $securedGroup_matching_category = $categories | Where-Object {$_.extId -eq $securedGroup_extId}
                    $securedGroup_name = "$($securedGroup_matching_category.key):$($securedGroup_matching_category.value)"
                    Write-Host "$(get-date) [DATA] SecuredGroup with extId $($securedGroup_extId) has the following key:value: $($securedGroup_name)" -ForegroundColor White
                    $translated_securedGroup_list.Add($securedGroup_name)
                }
                $modified_rule = $rule.PsObject.Copy()
                $modified_rule.spec.securedGroup = $translated_securedGroup_list
                $security_policy_translated_rules.Add($modified_rule)
            }
        }

        end 
        {
            $translated_flow_security_policy.rules = $security_policy_translated_rules
            return $translated_flow_security_policy           
        }
    }

    #TODO: update code here
    function Convert-FNSSecurityPolicyNamesToExtIds 
    {#given a security policy, replace all object names with their extIds to enable add or update of that policy in the target environment 

    }
#endregion


#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
09/10/2021 sb   Initial release.
09/13/2021 sb   Added processing for rule(s) deletion.
09/17/2021 sb   Adding -log parameter to redirect output to log file in working
                directory as well as the console.
09/22/2021 sb   Adding service and address groups sync (issue #9).
09/23/2021 sb   Fixed an issue when categories were added to a rule in outbound
                and/or outbound.
09/26/2021 sb   Moved syncing of categories, address and service groups to
                functions to avoid code duplication between the add and update
                actions.
10/11/2021 sb   Adding processing for multiple rules with the same name (issue
                #21)
10/11/2021 sb   Closing issue #21 for remove and update of rules.
10/18/2021 sb   Fixing an issue where a rule needed both adding and removing
                but had different target groups.
10/19/2021 sb   Fixing an issue where the wrong rule would sometime get removed.
10/04/2023 sb   Adding -securedCalls parameter to enable checking SSL certs with
                every API call. Modified Invoke-PrismAPICall function to handle
                http errors correctly and show the exact error message.
                Adding the ability to pass directly a credential object to
                -prismCreds.
                Changing script name to Invoke-FNSRuleSync and replacing v3 API
                calls with v4 API calls for FNS 4.0.
10/05/2023 sb   Adding pagination to Get-SecurityPolicies function.
################################################################################
'@
    $myvarScriptName = ".\Invoke-FNSRuleSync.ps1"

    if ($log) 
    {#we want to create a log transcript
        $myvar_output_log_file = (Get-Date -UFormat "%Y_%m_%d_%H_%M_") + "Invoke-FNSRuleSync.log"
        Start-Transcript -Path ./$myvar_output_log_file
    }

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    if (!$securedCalls) 
    {#we do not want to check ssl certs with every API call
        $check_ssl_certificates = $false
        Set-PoSHSSLCerts
    }
    else 
    {#we want to check ssl certs with every API call
        $check_ssl_certificates = $true
    }
    Set-PoshTls
#endregion


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $length = 500
#endregion


#region parameters validation
    if (!$prismCreds) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
        $prismCredentials = Get-Credential -Message "Please enter Prism credentials"
    } 
    else 
    {#we are using custom credentials, so let's grab the username and password from that
        $myvar_type = $($prismCreds.GetType().Name)
        if ($myvar_type -ne "PSCredential")
        {
            try 
            {#retrieve credentials
                $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            }
            catch 
            {#could not retrieve credentials
                Set-CustomCredentials -credname $prismCreds
                $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            }
        }
        else 
        {
            $prismCredentials = $prismCreds
        }
    }
#endregion


#todo: what about service and address groups in target group?
#todo: complete scan section (does nothing at the moment)
#todo: bug: dealing with multiple apps in target group
#todo: improve: rule add/update/delete returns task uuid: check on task status: no task uuid is returned... check on status later?
#todo: improve: add export action for rules from source to json (for backup purposes)
#todo: improve: move code to figure out categories to a function
#todo: improve: implement category:value pair delete
#! does not process correctly if rule has been updated on target (exp tested: service group)

#region main

    #region GET Flow Network Security policies
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting Flow Network Security policies" -ForegroundColor Magenta
        #region process source
            Write-Host "$(get-date) [INFO] Retrieving list of Flow Network Security policies from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            $source_rules_response = Get-SecurityPolicies -prism_central_address $sourcePc -prism_central_credentials_object $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of Flow Network Security policies from the source Prism Central instance $($sourcePc)" -ForegroundColor Cyan
            $filtered_source_rules_response = $source_rules_response | Where-Object {$_.name -match "^$prefix"}
            Write-Host "$(get-date) [DATA] There are $($filtered_source_rules_response.count) Flow Network Security policies which match prefix $($prefix) on source Prism Central $($sourcePc)..." -ForegroundColor White
        #endregion

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of Flow Network Security policies from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_rules_response = Get-SecurityPolicies -prism_central_address $TargetPc -prism_central_credentials_object $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of Flow Network Security policies from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            $filtered_target_rules_response = $target_rules_response | Where-Object {$_.name -match "^$prefix"}
            Write-Host "$(get-date) [DATA] There are $($filtered_target_rules_response.count) Flow Network Security policies which match prefix $($prefix) on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion

        if (!$filtered_source_rules_response -and !$filtered_target_rules_response)
        {#we didn't find any matching rules
            Throw "$(get-date) [ERROR] There are no Flow rules on $($sourcePc) or $($targetPc) which match prefix $($prefix)!"
        }
        elseif ($filtered_source_rules_response)
        {#we have matching rules, let's retrieve details for each
            Write-Host "$(get-date) [INFO] Retrieving details of each relevant Flow Network Security policy from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            [System.Collections.ArrayList]$source_rules_details = New-Object System.Collections.ArrayList($null)
            foreach ($entity in $filtered_source_rules_response)
            {
                $entity_details = Get-SecurityPolicyDetails -security_policy_extId $entity.extId -prism_central_address $sourcePc -prism_central_credentials_object $prismCredentials
                $source_rules_details.Add($entity_details) | Out-Null
            }
        }
        elseif ($filtered_target_rules_response)
        {
            Write-Host "$(get-date) [INFO] Retrieving details of each relevant Flow Network Security policy from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            [System.Collections.ArrayList]$target_rules_details = New-Object System.Collections.ArrayList($null)
            foreach ($entity in $filtered_target_rules_response)
            {
                $entity_details = Get-SecurityPolicyDetails -security_policy_extId $entity.extId -prism_central_address $TargetPc -prism_central_credentials_object $prismCredentials
                $target_rules_details.Add($entity_details) | Out-Null
            }
        }
    #endregion GET Flow Network Security policies

    #region GET service groups
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting service groups..." -ForegroundColor Magenta

        #region process source
            Write-Host "$(get-date) [INFO] Retrieving list of service groups from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            $source_service_groups = Get-PrismCentralObjectList -pc $sourcePc -object "service_groups" -kind "service_group"
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of service groups from the source Prism Central instance $($sourcePc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($source_service_groups.count) service groups on source Prism Central $($sourcePc)..." -ForegroundColor White
        #endregion

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of service groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_service_groups = Get-PrismCentralObjectList -pc $targetPc -object "service_groups" -kind "service_group"
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of service groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($target_service_groups.count) service groups on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion
    #endregion GET service groups

    #region GET address groups
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting address groups..." -ForegroundColor Magenta

        #region process source
            Write-Host "$(get-date) [INFO] Retrieving list of address groups from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            $source_address_groups = Get-PrismCentralObjectList -pc $sourcePc -object "address_groups" -kind "address_group"
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of address groups from the source Prism Central instance $($sourcePc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($source_address_groups.count) address groups on source Prism Central $($sourcePc)..." -ForegroundColor White
        #endregion

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of address groups from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_address_groups = Get-PrismCentralObjectList -pc $targetPc -object "address_groups" -kind "address_group"
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of address groups from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($target_address_groups.count) address groups on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion
    #endregion GET address groups
    
    #region GET categories
        Write-Host ""
        Write-Host "$(get-date) [STEP] Getting categories" -ForegroundColor Magenta
        #region process source
            Write-Host "$(get-date) [INFO] Retrieving list of categories from the source Prism Central instance $($sourcePc)..." -ForegroundColor Green
            $source_categories = Get-Categories -prism_central_address $sourcePc -prism_central_credentials_object $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of categories from the source Prism Central instance $($sourcePc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($source_categories.count) categories on source Prism Central $($sourcePc)..." -ForegroundColor White
        #endregion process source

        #region process target
            Write-Host "$(get-date) [INFO] Retrieving list of categories from the target Prism Central instance $($targetPc)..." -ForegroundColor Green
            $target_categories = Get-Categories -prism_central_address $targetPc -prism_central_credentials_object $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of categories from the target Prism Central instance $($targetPc)" -ForegroundColor Cyan
            Write-Host "$(get-date) [DATA] There are $($target_categories.count) categories on target Prism Central $($targetPc)..." -ForegroundColor White
        #endregion process target
    #endregion GET categories

    #region COMPARE Flow Network Security policies
        Write-Host ""
        Write-Host "$(get-date) [STEP] Comparing Flow Network Security policies" -ForegroundColor Magenta

        #* rules to add ($add_rules_list)
        [System.Collections.ArrayList]$add_rules_list = New-Object System.Collections.ArrayList($null)
        foreach ($rule in $filtered_source_rules_response) 
        {#compare source with target
            if ($rule.name -notin $filtered_target_rules_response.name)
            {#rule exists on source but not on target
                Write-Host "$(get-date) [INFO] Flow Network Security policy $($rule.name) does not exist yet on target Prism Central $($targetPc)" -ForegroundColor Green
                $add_rules_list.Add($rule) | Out-Null
            }            
        }
        Write-Host "$(get-date) [DATA] There are $($add_rules_list.count) Flow Network Security policies to add on target Prism Central $($targetPc)" -ForegroundColor White

        #* rules to remove ($remove_rules_list)
        [System.Collections.ArrayList]$remove_rules_list = New-Object System.Collections.ArrayList($null)
        foreach ($rule in $filtered_target_rules_response) 
        {#compare target with source
            if ($rule.name -notin $filtered_source_rules_response.name)
            {#rule exists on target but not on source
                Write-Host "$(get-date) [INFO] Flow Network Security policy $($rule.name) no longer exists on source Prism Central $($sourcePc)" -ForegroundColor Green
                $remove_rules_list.Add($rule) | Out-Null
            }
        }
        Write-Host "$(get-date) [DATA] There are $($remove_rules_list.count) Flow Network Security policies to remove on target Prism Central $($targetPc)" -ForegroundColor White

        #* rules to update ($update_rules_list)
        [System.Collections.ArrayList]$update_rules_list = New-Object System.Collections.ArrayList($null)
        foreach ($source_rule in $filtered_source_rules_response) 
        {#compare source with target  
            if ($target_rule = $filtered_target_rules_response | Where-Object {$_.Name -eq $source_rule.Name})
            {#we have a matching rule on target, let's compare
                #TODO: replace code here with API v4 COMPARE code
                #compare basic attributes
                
                
                #* for each rule in this policy
                    #* compare securedGroup list on both source and target
                        #* foreach securedGroup, lookup securedGroup to see if it has already been resolved
                            #? if not, lookup entity and add it to the list
                        #* compare source and target securedGroup to see if they match
                            #? if they do not match, mark this rule to be updated and continue to next instance
                    #? based on rule type, process accordingly (functions?)
                        #* process INTRA_GROUP and TWO_ENV_ISOLATION rules: should be fairly easy
                        #* process APPLICATION rules: more complex
                        #! for both: will need to resolve extIds: maybe resolve all entities extIds in a given policy 
                        #! in a single function as orginally planned and start there: then all you have to do is lookups 
                        #! of entities at source and target and compare





                if (($source_rule.extId -notin $remove_rules_list.extId) -and ($source_rule.extId -notin $add_rules_list.extId))
                {#we haven't marked this rule for removal or addition so it needs to be updated
                    Write-Host "$(get-date) [INFO] Flow Network Security policy $($source_rule.name) needs to be updated on target Prism Central $($targetPc)" -ForegroundColor Green
                    $update_rules_list.Add($source_rule) | Out-Null
                }
            }
        }
        Write-Host "$(get-date) [DATA] There are $($update_rules_list.count) Flow Network Security policies to update on target Prism Central $($targetPc)" -ForegroundColor White

    #endregion COMPARE Flow Network Security policies

    #region ACTION
        if ($action -eq "scan")
        {#display what we would do
            foreach ($source_security_policy in $source_rules_details) 
            {
                $myvar_translated_source_security_policy = Convert-FNSSecurityPolicyExtIdsToNames -flow_security_policy $source_security_policy -service_groups $source_service_groups -address_groups $source_address_groups -categories $source_categories
            }
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
                        
                        #TODO: replace code here with API v4 code
                        Sync-Categories -rule $rule
                        Sync-ServiceGroups -rule $rule
                        Sync-AddressGroups -rule $rule

                        #TODO: replace code in this region with v4 API calls
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
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
                                Write-Host "$(Get-Date) [SUCCESS] Added Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan
                                if ($debugme) {$resp}
                                #Get-PrismCentralTaskStatus -task $resp -credential $prismCredentials -cluster $targetPc 
                            }
                            catch 
                            {#we couldn't create the network policy
                                if ($_.Exception.Message -match 'rule already exists')
                                {#the isolation rule already exists, let's just warn about this
                                    Write-Host "$(Get-Date) [WARNING] Could not add isolation rule $($rule.spec.Name) to $targetPc" -ForegroundColor Yellow
                                    Write-Host "$($_.Exception.Message)" -ForegroundColor Yellow
                                }
                                else 
                                {
                                    Throw "$($_.Exception.Message)"   
                                }
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
                        #todo: replace code in this region with v4 API calls
                        #? delete rule on target
                        $api_server_endpoint = "/api/nutanix/v3/network_security_rules/{0}" -f $rule.metadata.uuid
                        $url = "https://{0}:9440{1}" -f $targetPc,$api_server_endpoint
                        $method = "DELETE"

                        Write-Host "$(get-date) [STEP] Deleting Flow rule $($rule.spec.Name) on $($targetPc)" -ForegroundColor Green
                        try 
                        {#delete the rule
                            $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
                            Write-Host "$(Get-Date) [SUCCESS] Deleted Flow rule $($rule.spec.Name) to $targetPc" -ForegroundColor Cyan
                            
                        }
                        catch 
                        {#we couldn't delete the rule
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
                        
                        #TODO: replace code here with API v4 code
                        Sync-Categories -rule $rule
                        Sync-ServiceGroups -rule $rule
                        Sync-AddressGroups -rule $rule

                        #region update rule on target
                            $target_rule = $filtered_target_rules_response | Where-Object {$_.spec.Name -eq $rule.spec.Name}
                            #! add code here to deal with the fact that there might be multiple target rules with the same name
                            if ($target_rule.count -gt 1)
                            {#we have multiple rules with the same name on the target, let's identify which ne we are updating based on the target group   
                                Foreach ($target_rule_item in $target_rule)
                                {#compare with all rules with similar name on target
                                    #TODO: replace code here with API v4 code
                                    if (([String]::Compare(($rule.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),($target_rule_item.spec.resources.app_rule.target_group.filter.params | ConvertTo-Json -Depth 100),$true)) -eq 0)
                                    {#we found a match for the target group
                                        $target_rule = $target_rule_item
                                        continue
                                    }
                                }
                            }

                            #TODO: replace code in this region with v4 API calls
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
                                $resp = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload -check_certificates $check_ssl_certificates
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
    #endregion ACTION

#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    if ($log) 
    {#we had started a transcript to log file, so let's stop it now that we are done
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