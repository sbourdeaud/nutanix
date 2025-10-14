<#
.SYNOPSIS
  Use this script to add one or more disks to an existing VM.
.DESCRIPTION
  The script takes a VM, a size (in GiB) and a quantity of disks as input. Optionally, it can also take a storage container as input. It then adds the specified number of disks to the VM, either in the same container as disk scsi0:0, or in the specified container.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix Prism fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vm
  Specifies the name of the VM you want to power control. This can be a comma separated list of VMs.
.PARAMETER csv
  Instead of specifying vms using the -vm parameter, use this csv source file (format: stratight list of vm names).
.PARAMETER action
  What power actions you want to perform. Valid actions are: guest_shutdown, guest_reboot, acpi_shutdown, acpi_reboot, reset, power_cycle, power_off, power_on
.PARAMETER container
  Name of the container where you want the disks to be created in. If none is specified, the disks will be added in the same container as disk scsi0:0.
.EXAMPLE
.\set-AhvVmPowerState.ps1 -prism ntnxc1.local -vm myvm -action guest_shutdown
  Sends a guest shutdown command to VM myvm.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 14th 2025
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true,HelpMessage = "Enter the Nutanix Prism name or address")] [string]$prism,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $false)] [string]$vm,
        [parameter(mandatory = $false)] [string]$csv,
        [parameter(mandatory = $true)][ValidateSet("guest_shutdown", "guest_reboot", "acpi_shutdown", "acpi_reboot", "reset", "power_cycle", "power_off", "power_on")] [string]$action
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
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG')]
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
        }

        Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
        if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput


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
            Write-Host "$(Get-Date) [ERROR] $saved_error" -ForegroundColor Red
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
#endregion

#region prepwork
    #check if we need to display help and/or history
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
09/11/2018 sb   Initial release.
04/06/2020 sb   Do over with sbourdeaud module
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\new-AhvVmDisk.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    [System.Collections.ArrayList]$myvar_results = New-Object System.Collections.ArrayList($null)
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

    if (!$vm -and !$csv) {throw "$(get-date) [ERROR] You must specify a VM name or a csv file containing a list of VMs to process."}
    if ($vm) {$myvar_vms = $vm.Split(",")}
    if ($csv) {$myvar_vms = Import-Csv -Path $csv -Header "vms" -ErrorAction Stop}
#endregion

#region processing	
    #region get all vms
      #region get total number of entities
        $url = "https://{0}:9440/api/nutanix/v3/vms/list" -f $prism
        $method = "POST"
        $content = @{
            kind= "vm";
            length = 1;
        }
        $payload = (ConvertTo-Json $content -Depth 4)
        Write-Host "$(Get-Date) [INFO] Retrieving total number of VMs available from $prism..." -ForegroundColor Green
        $total_vm_entities = (Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials).metadata.total_matches
      #endregion get total number of entities
      #region retrieve all vms
        $page_size = 500
        $total_pages = [Math]::Ceiling($total_vm_entities / $page_size)
        $offsets = 0..($total_pages - 1) | ForEach-Object { $_ * $page_size }
        $headers = @{
            "Content-Type"="application/json";
            "Accept"="application/json"
        }
        Write-Host "$(Get-Date) [INFO] Retrieving $total_vm_entities entities from $prism..." -ForegroundColor Green
        $results = $offsets | ForEach-Object -ThrottleLimit 5 -Parallel {
            $offset = $_
            $url = "https://{0}:9440/api/nutanix/v3/vms/list" -f $($using:prism)
            $method = "POST"
            $content = @{
                kind= "vm";
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
      #endregion retrieve all vms
    #endregion get all vms
    #region build list of urls to process
        $urls = @()
        foreach ($result in $results) {
            if ($result.spec.name -in $myvar_vms) {
                if ($action -notin @("power_on","power_off")) {
                    $urls += "https://$($prism):9440/api/nutanix/v3/vms/$($result.metadata.uuid)/$($action)"
                }
            }
        }
    #endregion build list of urls to process

    #* foreach loop on vm urls to power them off/on/reboot
    #! add logic here to process different commands (on/off/reboot, etc...)
    Write-Host "$(Get-Date) [INFO] Sending $action command to virtual machines..." -ForegroundColor Green
    if ($action -notin @("power_on","power_off")) {
        $results = $urls | ForEach-Object -Parallel {
            $url = $_
            $method = "POST"
            $content = @{}
            $payload = (ConvertTo-Json $content -Depth 4)
            Write-Host "$(Get-Date) [INFO] Sending $($using:action) command to $url" -ForegroundColor Green
            try {
                $response = Invoke-RestMethod -Method $method -Uri $url -Headers $($using:headers) -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $($using:prismCredentials) -ErrorAction Stop
                [PSCustomObject]@{
                    Url = $url
                    Status = $response.StatusCode
                    Data = $response.Content # Or process the response as needed
                }
            }
            catch {
                [PSCustomObject]@{
                    Url = $url
                    Status = $_.Exception.Response.StatusCode
                    Error = $_.Exception.Message
                }
            }
        } -ThrottleLimit 50 #> # Adjust the throttle limit as needed
    }
    #$results | Format-Table # Or process the results as needed
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
    Remove-Variable vm -ErrorAction SilentlyContinue
    Remove-Variable csv -ErrorAction SilentlyContinue
    Remove-Variable action -ErrorAction SilentlyContinue
    Remove-Variable prism -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
#endregion