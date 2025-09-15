#Requires -Version 6.0
<#
.SYNOPSIS
  This script is meant to facilitate large scale migrations by enabling automated migration plan creation in Nutanix Move based on various input sources such as cvs, vCenter folder structure or tags and regex in vm names.
.DESCRIPTION
  This script is meant to facilitate large scale migrations by enabling automated migration plan creation in Nutanix Move based on various input sources such as cvs, vCenter folder structure or tags and regex in vm names.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER move
  Nutanix Move instance fully qualified domain name or IP address.  This can be a comma separated list if you need to take actions on multiple move instances (such as reporting plans status with -action report).
.PARAMETER moveCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER action
  Specifies what type of action the script should do. Valid actions are: migrate (to create migration plans), report (to show status of migration plans), cutover, failback, suspend, resume and validate (to check pre-reqs are in place on source vms)
.PARAMETER plans
  Name(s) (in comma separated format for multiple entries) of the migration plans you want to take action on (valid with -action report, suspend, resume, validate).  You can also specify "all" if you want to take action on all migration plans.  All is assumed if no value is given for plans.
.PARAMETER csvplans
  Specifies source csv files with the list of vms and plans to create.  Each line of that csv file must contain the following columns: migration_plan_name, vm_name, network_mappings, guest_prep_mode,	source_provider, source_cluster, target_provider, target_cluster, target_container, move_instance, start_schedule, snapshot_interval_min. In addition, the target provider, cluster and storage container for all vms within the same migration plan must be the same (if you need to specify different targets, then you will need to specify a different migration plan). Network mappings can be different per vm, must one mapping must exist for every network the vm is connected to.  Network mappings are specified in the source_network_name:target_network_name format and mutliple entries in that column are separated with a semi colon (;).
.EXAMPLE
.\invoke-MoveMigration.ps1 -move mymove.local -action report
Report the status of all migration plans from the specified Move instance:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: August 26th 2022
#>


#todo: implement migrate action capability from vcfolder and vctag
#todo: enhance report action capability (how to compute migrated data size + include csv and html reports)
#todo: implement functionality to find a specific vms amongst all migration plans and report its status
#todo: implement cutover action capability
#todo: implement failback action capability
#todo: implement validate action capability
#todo: add create providers from csv action capability
#todo: add a way to deal securely with vm credentials (exp: by fetching them from a vault instance)
#todo: need to make sure source and target types are compatible (from providers information)

#todo: enhance script to deal more elegantly (by offering choice) with csv input errors: implement silent option for schedulability
#todo: enhance script to edit existing migration plans (adding or removing vms)
#todo: enhance script to add schedule to migration plan
#todo: add functionality for log file

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] $move,
        [parameter(mandatory = $false)] $moveCreds,
        [parameter(mandatory = $true)] [string][ValidateSet("migrate","report","cutover","failback","validate","suspend","resume")]$action,
        [parameter(mandatory = $false)] $plans,
        [parameter(mandatory = $false)] $csvPlans
    )
#endregion parameters


#region functions
    #this function cleans up
    function CleanUp 
    {
        process
        {
            #let's figure out how much time this all took
            Write-Host "$(get-date) [SUM] total processing time: $($myvar_ElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

            if ($log) 
            {#we had started a transcript to log file, so let's stop it now that we are done
                Stop-Transcript
            }

            #cleanup after ourselves and delete all custom variables
            Remove-Variable myvar* -ErrorAction SilentlyContinue
            Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
            Remove-Variable username -ErrorAction SilentlyContinue
            Remove-Variable PrismSecurePassword -ErrorAction SilentlyContinue
            Remove-Variable prismCredentials -ErrorAction SilentlyContinue
        }
    }#end function CleanUp

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
    }#endfunction LoadModule

    #this function is used to create saved credentials for the current user
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
    }#endfunction Set-CustomCredentials

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
    }#endfunction Get-CustomCredentials

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
    }#endfunction Invoke-PrismAPICall

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

    #this function is used to retrieve all objects of a specific type (uses pagination)
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
            [System.Collections.ArrayList]$myvar_Results = New-Object System.Collections.ArrayList($null) #this is variable we will use to keep track of entities
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
                        $myvar_Results.Add($entity) | Out-Null
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
            return $myvar_Results
        }
    }#endfunction Get-PrismCentralObjectList

    function New-PercentageBar
    {#draws progress bar based on percentage
        
    <#
    .SYNOPSIS
        Create percentage bar.
    .DESCRIPTION
        This cmdlet creates percentage bar.
    .PARAMETER Percent
        Value in percents (%).
    .PARAMETER Value
        Value in arbitrary units.
    .PARAMETER MaxValue
        100% value.
    .PARAMETER BarLength
        Bar length in chars.
    .PARAMETER BarView
        Different char sets to build the bar.
    .PARAMETER GreenBorder
        Percent value to change bar color from green to yellow (relevant with -DrawBar parameter only).
    .PARAMETER YellowBorder
        Percent value to change bar color from yellow to red (relevant with -DrawBar parameter only).
    .PARAMETER NoPercent
        Exclude percentage number from the bar.
    .PARAMETER DrawBar
        Directly draw the colored bar onto the PowerShell console (unsuitable for calculated properties).
    .EXAMPLE
        PS C:\> New-PercentageBar -Percent 90 -DrawBar
        Draw single bar with all default settings.
    .EXAMPLE
        PS C:\> New-PercentageBar -Percent 95 -DrawBar -GreenBorder 70 -YellowBorder 90
        Draw the bar and move the both color change borders.
    .EXAMPLE
        PS C:\> 85 |New-PercentageBar -DrawBar -NoPercent
        Pipeline the percent value to the function and exclude percent number from the bar.
    .EXAMPLE
        PS C:\> For ($i=0; $i -le 100; $i+=10) {New-PercentageBar -Percent $i -DrawBar -Length 100 -BarView AdvancedThin2; "`r"}
        Demonstrates advanced bar view with custom bar length and different percent values.
    .EXAMPLE
        PS C:\> $Folder = 'C:\reports\'
        PS C:\> $FolderSize = (Get-ChildItem -Path $Folder |measure -Property Length -Sum).Sum
        PS C:\> Get-ChildItem -Path $Folder -File |sort Length -Descending |select -First 10 |select Name,Length,@{N='SizeBar';E={New-PercentageBar -Value $_.Length -MaxValue $FolderSize}} |ft -au
        Get file size report and add calculated property 'SizeBar' that contains the percent of each file size from the folder size.
    .EXAMPLE
        PS C:\> $VolumeC = gwmi Win32_LogicalDisk |? {$_.DeviceID -eq 'c:'}
        PS C:\> Write-Host -NoNewline "Volume C Usage:" -ForegroundColor Yellow; `
        PS C:\> New-PercentageBar -Value ($VolumeC.Size-$VolumeC.Freespace) -MaxValue $VolumeC.Size -DrawBar; "`r"
        Get system volume usage report.
    .NOTES
        Author      :: Roman Gelman @rgelman75
        Version 1.0 :: 04-Jul-2016 :: [Release] :: Publicly available
    .LINK
        https://ps1code.com/2016/07/16/percentage-bar-powershell
    #>
        
        [CmdletBinding(DefaultParameterSetName = 'PERCENT')]
        Param (
            [Parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName = 'PERCENT')]
            [ValidateRange(0, 100)]
            [int]$Percent
            ,
            [Parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName = 'VALUE')]
            [ValidateRange(0, [double]::MaxValue)]
            [double]$Value
            ,
            [Parameter(Mandatory, Position = 2, ParameterSetName = 'VALUE')]
            [ValidateRange(1, [double]::MaxValue)]
            [double]$MaxValue
            ,
            [Parameter(Mandatory = $false, Position = 3)]
            [Alias("BarSize", "Length")]
            [ValidateRange(10, 100)]
            [int]$BarLength = 20
            ,
            [Parameter(Mandatory = $false, Position = 4)]
            [ValidateSet("SimpleThin", "SimpleThick1", "SimpleThick2", "AdvancedThin1", "AdvancedThin2", "AdvancedThick")]
            [string]$BarView = "SimpleThin"
            ,
            [Parameter(Mandatory = $false, Position = 5)]
            [ValidateRange(50, 80)]
            [int]$GreenBorder = 60
            ,
            [Parameter(Mandatory = $false, Position = 6)]
            [ValidateRange(80, 90)]
            [int]$YellowBorder = 80
            ,
            [Parameter(Mandatory = $false)]
            [switch]$NoPercent
            ,
            [Parameter(Mandatory = $false)]
            [switch]$DrawBar
        )
        
        Begin
        {
            
            If ($PSBoundParameters.ContainsKey('VALUE'))
            {
                
                If ($Value -gt $MaxValue)
                {
                    Throw "The [-Value] parameter cannot be greater than [-MaxValue]!"
                }
                Else
                {
                    $Percent = $Value/$MaxValue * 100 -as [int]
                }
            }
            
            If ($YellowBorder -le $GreenBorder) { Throw "The [-YellowBorder] value must be greater than [-GreenBorder]!" }
            
            Function Set-BarView ($View)
            {
                Switch -exact ($View)
                {
                    "SimpleThin"	{ $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = "-"; Break }
                    "SimpleThick1"	{ $GreenChar = [char]9608; $YellowChar = [char]9608; $RedChar = [char]9608; $EmptyChar = "-"; Break }
                    "SimpleThick2"	{ $GreenChar = [char]9612; $YellowChar = [char]9612; $RedChar = [char]9612; $EmptyChar = "-"; Break }
                    "AdvancedThin1"	{ $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = [char]9476; Break }
                    "AdvancedThin2"	{ $GreenChar = [char]9642; $YellowChar = [char]9642; $RedChar = [char]9642; $EmptyChar = [char]9643; Break }
                    "AdvancedThick"	{ $GreenChar = [char]9617; $YellowChar = [char]9618; $RedChar = [char]9619; $EmptyChar = [char]9482; Break }
                }
                $Properties = [ordered]@{
                    Char1 = $GreenChar
                    Char2 = $YellowChar
                    Char3 = $RedChar
                    Char4 = $EmptyChar
                }
                $Object = New-Object PSObject -Property $Properties
                $Object
            } #End Function Set-BarView
            
            $BarChars = Set-BarView -View $BarView
            $Bar = $null
            
            Function Draw-Bar
            {
                
                Param (
                    [Parameter(Mandatory)]
                    [string]$Char
                    ,
                    [Parameter(Mandatory = $false)]
                    [string]$Color = 'White'
                    ,
                    [Parameter(Mandatory = $false)]
                    [boolean]$Draw
                )
                
                If ($Draw)
                {
                    Write-Host -NoNewline -ForegroundColor ([System.ConsoleColor]$Color) $Char
                }
                Else
                {
                    return $Char
                }
                
            } #End Function Draw-Bar
            
        } #End Begin
        
        Process
        {
            
            If ($NoPercent)
            {
                $Bar += Draw-Bar -Char "[ " -Draw $DrawBar
            }
            Else
            {
                If ($Percent -eq 100) { $Bar += Draw-Bar -Char "$Percent% [ " -Draw $DrawBar }
                ElseIf ($Percent -ge 10) { $Bar += Draw-Bar -Char " $Percent% [ " -Draw $DrawBar }
                Else { $Bar += Draw-Bar -Char "  $Percent% [ " -Draw $DrawBar }
            }
            
            For ($i = 1; $i -le ($BarValue = ([Math]::Round($Percent * $BarLength / 100))); $i++)
            {
                
                If ($i -le ($GreenBorder * $BarLength / 100)) { $Bar += Draw-Bar -Char ($BarChars.Char1) -Color 'DarkGreen' -Draw $DrawBar }
                ElseIf ($i -le ($YellowBorder * $BarLength / 100)) { $Bar += Draw-Bar -Char ($BarChars.Char2) -Color 'Yellow' -Draw $DrawBar }
                Else { $Bar += Draw-Bar -Char ($BarChars.Char3) -Color 'Red' -Draw $DrawBar }
            }
            For ($i = 1; $i -le ($EmptyValue = $BarLength - $BarValue); $i++) { $Bar += Draw-Bar -Char ($BarChars.Char4) -Draw $DrawBar }
            $Bar += Draw-Bar -Char " ]" -Draw $DrawBar
            
        } #End Process
        
        End
        {
            If (!$DrawBar) { return $Bar }
        } #End End
        
    } #EndFunction New-PercentageBar

    function Get-PrismCentralTaskStatus
    {#loops on PC task until completed
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
                    New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
                    $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 2,$Host.UI.RawUI.CursorPosition.Y
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
                    Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) status is $($taskDetails.status): $($taskDetails.progress_message)" -ForegroundColor Yellow
                } else {
                    New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2
                    Write-Host ""
                    Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
                }
            }
        }
        end
        {
            return $taskDetails.status
        }
    }

    Function Format-FileSize() 
    {#convert files sizes to human readbale form
        Param ([int64]$size)
        If     ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
        ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
        ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
        ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
        ElseIf ($size -gt 0)   {[string]::Format("{0:0.00} B", $size)}
        Else                   {""}
    }

    Function Convert-PlanState() 
    {#convert move migration plan status integer to corresponding human readable status string
        Param ([int64]$state)
        If     ($state -eq 0) {[string]"Uninitialized"}
        ElseIf ($state -eq 1) {[string]"Validation"}
        ElseIf ($state -eq 2) {[string]"Scheduled"}
        ElseIf ($state -eq 3) {[string]"Preparation"}
        ElseIf ($state -eq 4) {[string]"MigrationInProgress"}
        ElseIf ($state -eq 5) {[string]"Paused"}
        ElseIf ($state -eq 6) {[string]"Aborted"}
        ElseIf ($state -eq 7) {[string]"Completed"}
        ElseIf ($state -eq 8) {[string]"Failed"}
        ElseIf ($state -eq 9) {[string]"ValidationFailed"}
        ElseIf ($state -eq 10) {[string]"Aborting"}
        Else                  {[string]"Unknown"}
    }

    function Move-Login
    {#login the move instance and return a token
        <#
        .SYNOPSIS
        Takes a move instance ip or fqdn and a PoSH credential object, logs in the move api and returns the response (which includes the token).

        .DESCRIPTION
        Takes a move instance ip or fqdn and a PoSH credential object, logs in the move api and returns the response (which includes the token).

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER credential
        PoSH credential object that matches the move username/password with access to the move instance.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-Login -move 10.10.10.1 -credential $mycredentialobject
        Logs in to move instance 10.10.10.1.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string] 
            $move,
            
            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]
            $credential
        )

        begin 
        {
            $url = "https://{0}/move/v2/users/login" -f $move
            $method = "POST"
            $content = @{
                Spec= @{
                    UserName="{0}" -f $credential.UserName;
                    Password="{0}" -f [PSCredential]::new($moveCredentials).GetNetworkCredential().Password;
                }
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                if ($_.Exception.Source -eq "System.Net.Http")
                {
                    $saved_error_message = $_.ErrorDetails.Message
                }
                else
                {
                    $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                }
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }

    function Move-Logout
    {#login the move instance and return a token
        <#
        .SYNOPSIS
        Revokes the token on the designated move instance.

        .DESCRIPTION
        Revokes the token on the designated move instance.

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER token
        Token object to revoke.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-Logout -move 10.10.10.1 -token $mytoken
        Logs out of move instance 10.10.10.1.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string] 
            $move,
            
            [parameter(mandatory = $true)]
            [String]
            $token
        )

        begin 
        {
            $url = "https://{0}/move/v2/token/revoke" -f $move
            $method = "POST"
            $content = @{
                Spec= @{
                    Token="{0}" -f $token;
                }
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json";
                "Authorization"= "{0}" -f $token
            }
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }

    function Move-ListProviders
    {#list providers in move
        <#
        .SYNOPSIS
        Given a move instance and a valid session token, list all providers available in that move instance.

        .DESCRIPTION
        Given a move instance and a valid session token, list all providers available in that move instance.

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER token
        A valid session token string.

        .PARAMETER refresh
        If specified (no value required), then a refresh inventory will be forced on the providers.  By default, this won't happen.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-ListProviders -move 10.10.10.1 -credential $mytoken
        Lists available providers on move instance 10.10.10.1.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string] 
            $move,
            
            [parameter(mandatory = $true)]
            [string]
            $token,

            [parameter(mandatory = $false)]
            [switch]
            $refresh
        )

        begin 
        {
            $url = "https://{0}/move/v2/providers/list" -f $move
            $method = "POST"
            $content = @{
                properties= @{
                    RefreshInventory="{0}" -f $(if ($refresh) {"true"} else {"false"});
                }
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json";
                "Authorization"="$($token)";
            }
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }

    function Move-GetWorkloadInventory
    {#get workloads running in the specified source cluster
        <#
        .SYNOPSIS
        Given a move instance, a valid session token, a provider uuid and a source cluster name list all workloads available in that source cluster.

        .DESCRIPTION
        Given a move instance, a valid session token and a source cluster name list all workloads available in that source cluster.

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER token
        A valid session token string.

        .PARAMETER provider_uuid
        UUID of the Move provider which contains the source cluster.

        .PARAMETER cluster
        Source cluster name.

        .PARAMETER refresh
        If specified (no value required), then a refresh inventory will be forced on the providers.  By default, this won't happen.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-GetWorkloadInventory -move 10.10.10.1 -credential $mytoken -cluster myclustername
        Lists available workloads on source cluster myclustername on move instance 10.10.10.1.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string] 
            $move,
            
            [parameter(mandatory = $true)]
            [string]
            $token,

            [parameter(mandatory = $true)]
            [string]
            $provider_uuid,

            [parameter(mandatory = $true)]
            [string]
            $cluster,

            [parameter(mandatory = $false)]
            [switch]
            $refresh
        )

        begin 
        {
            $url = "https://{0}/move/v2/providers/{1}/workloads/list" -f $move,$provider_uuid
            $method = "POST"
            $content = @{
                Filter= @{
                    Clusters= @(
                        "$($cluster)"
                    )
                };
                RefreshInventory= if ($refresh) {true} else {false};
                ShowVMs="all"
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json";
                "Authorization"="$($token)";
            }
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }

    function Move-GetMigrationPlans
    {#get all migration plans for a given move instance
        <#
        .SYNOPSIS
        Given a move instance and a valid session token, get all migration plans.

        .DESCRIPTION
        Given a move instance and a valid session token, get all migration plans.

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER token
        A valid session token string.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-GetMigrationPlans -move 10.10.10.1 -credential $mytoken
        Gets migration plans on move instance 10.10.10.1.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string] 
            $move,
            
            [parameter(mandatory = $true)]
            [string]
            $token
        )

        begin 
        {
            $url = "https://{0}/move/v2/plans/list?IncludeVMDetails=true" -f $move
            $method = "POST"
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json";
                "Authorization"="$($token)";
            }
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }

    function Move-CreateMigrationPlan
    {#create migration plan for a given payload on the given move instance
        <#
        .SYNOPSIS
        Given a move instance and a valid session token, get all migration plans.

        .DESCRIPTION
        Given a move instance and a valid session token, get all migration plans.

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER token
        A valid session token string.

        .PARAMETER payload
        A valid json payload for a move migration plan.

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-CreateMigrationPlan -move 10.10.10.1 -credential $mytoken -payload $payload
        Create a migration plan on move instance 10.10.10.1 based on the specified payload.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string] 
            $move,
            
            [parameter(mandatory = $true)]
            [string]
            $token,

            [parameter(mandatory = $true)]
            $payload
        )

        begin 
        {
            $url = "https://{0}/move/v2/plans" -f $move
            $method = "POST"
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json";
                "Authorization"="$($token)";
            }
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop -Body $payload
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }

    function Move-StartMigrationPlan
    {#start migration plan on the given move instance
        <#
        .SYNOPSIS
        Given a move instance and a valid session token, get all migration plans.

        .DESCRIPTION
        Given a move instance and a valid session token, get all migration plans.

        .PARAMETER move
        IP address or FQDN of the move instance.

        .PARAMETER token
        A valid session token string.

        .PARAMETER plan
        A valid migration plan uuid.

        .PARAMETER snapshot_interval_min
        Interval in minutes at which replication snapshots will be created (default is 120 min).

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Move-StartMigrationPlan -move 10.10.10.1 -credential $mytoken -plan $my_plan_uuid
        Start migration plan on move instance 10.10.10.1 based on the specified plan uuid.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param 
        (
            [parameter(mandatory = $true)]
            [string]$move,
            
            [parameter(mandatory = $true)]
            [string]$token,

            [parameter(mandatory = $true)]
            [string]$plan,

            [parameter(mandatory = $false)]
            [int]$snapshot_interval_min
        )

        begin 
        {
            $url = "https://{0}/move/v2/plans/{1}/start" -f $move,$plan
            $method = "POST"
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json";
                "Authorization"="$($token)";
            }
            if (!$snapshot_interval_min) {$snapshot_interval_min = 120}
            $content = @{
                Spec=@{
                    Time=$snapshot_interval_min;
                }
            }
            $payload = (ConvertTo-Json $content -Depth 9)
        }

        process 
        {
            Write-Host "$(Get-Date) [INFO] Making a $($method) call to $($url)" -ForegroundColor Green
            try 
            {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication None -ErrorAction Stop -Body $payload
                Write-Host "$(get-date) [SUCCESS] Call $($method) to $($url) succeeded." -ForegroundColor Cyan 
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            }
            catch 
            {
                $saved_error = $_.Exception
                $saved_error_message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
                $resp_return_code = $_.Exception.Response.StatusCode.value__
                Throw "$(get-date) [ERROR] $resp_return_code $saved_error_message"
            }
            finally 
            {
                #add any last words here; this gets processed no matter what
            }
        }

        end 
        {
            return $resp
        }
    }
#endregion functions


#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
08/02/2022 sb   Initial draft.
08/24/2022 sb   Continuing work on migrate action: reading from csv, processing
                inventories from multiple source clusters.
                Adding move_instance in csv structure to enable processing of
                multiple move instances in the same csv file for central
                control/management.
08/26/2022 sb   Finished code to gather required info for plan payload.
################################################################################
'@
    $myvar_ScriptName = ".\invoke-MoveMigration.ps1"

    if ($log) 
    {#we want to create a log transcript
        $myvar_output_log_file = (Get-Date -UFormat "%Y_%m_%d_%H_%M_") + "invoke-MoveMigration.log"
        Start-Transcript -Path ./$myvar_output_log_file
    }

    if ($help) {get-help $myvar_ScriptName; exit}
    if ($History) {$HistoryText; exit}

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion prepwork


#region variables
    $myvar_ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    #[System.Collections.ArrayList]$myvar_all_available_source_workloads = New-Object System.Collections.ArrayList($null)
    $myvar_all_available_source_workloads = @()
    $myvar_vms_to_migrate_objects = @()
#endregion variables


#region parameters validation
    if (!$moveCreds) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
        $moveCredentials = Get-Credential -Message "Please enter Move credentials"
    } 
    else 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {
            $moveCredentials = Get-CustomCredentials -credname $moveCreds -ErrorAction Stop
        }
        catch 
        {
            Set-CustomCredentials -credname $moveCreds
            $moveCredentials = Get-CustomCredentials -credname $moveCreds -ErrorAction Stop
        }
    }
    $username = $moveCredentials.UserName
    $MoveSecurePassword = $moveCredentials.Password
    $moveCredentials = New-Object PSCredential $username, $MoveSecurePassword

    $move_instances = $move.Split(",")
    if (!$plans) 
    {#no value was given for plans, so assume all
        $plans = "all"
    } 
    elseif ($plans -ne "all")
    {#all was specified for plans, otherwise assume csv list of multiple plans
        $plans = $plans.Split(",")
    }
#endregion parameters validation

#! main code execution region here
#region processing
    foreach ($move in $move_instances)
    {#process all move instances specified by the user
        #region Step 1: logging in to Move and getting an authentication token
        Write-Host "$(get-date) [STEP] Logging in to Move API on instance $($move)..." -ForegroundColor Magenta
        $myvar_move_login_response = Move-Login -move $move -credential $moveCredentials
        if ($myvar_move_token = $myvar_move_login_response.Status.Token)
        {#we got an authentication token from the move instance
            Write-Host "$(get-date) [SUCCESS] Successfully logged in to Move instance $($move)!" -ForegroundColor Cyan
        }
        else 
        {#we did not get an authentication token from the move instance
            Write-Host "$(get-date) [ERROR] Could not log in to Move instance $($move)!" -ForegroundColor Red 
            exit 1
        }
        #endregion Step 1: logging in to Move and getting an authentication token
        
        #region Step 2: branch based on action selected
        if ($action -eq "migrate")
        {#user wants to create a migration plan
            #* csv read
            #region reading from csv
            if (Test-Path -Path $csvPlans) 
            {#file exists
                $myvar_csv_plans = Import-Csv -Path $csvPlans #read from the file
                #create variable with information for each plan specified
                $myvar_migration_plans = @{}
                foreach ($myvar_item in ($myvar_csv_plans | ?{$_.move_instance -eq $move}))
                {#process each line in the csv and build a variable that will keep track of specific characteristics of each migration plan required to build the json payload
                    if (!$myvar_migration_plans.($myvar_item.migration_plan_name))
                    {#we haven't processed that migration plan yet
                        if (($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_item.migration_plan_name}).start_schedule  | Select-Object -Unique)
                        {#user specified a start date and time: let's check the format is valid and let's use it
                            $myvar_migration_plan_start_date = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_item.migration_plan_name}).start_schedule  | Select-Object -Unique -First 1
                        }
                        else 
                        {#user did not specify a start date and time, so we'll assume it will start now
                            $myvar_migration_plan_start_date = "now"
                        }
                        if (($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_item.migration_plan_name}).snapshot_interval_min  | Select-Object -Unique)
                        {#user specified a snapshot interval
                            [int]$myvar_migration_plan_snapshot_interval_min = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_item.migration_plan_name}).snapshot_interval_min  | Select-Object -Unique -First 1
                        }
                        else 
                        {#user did not specify a start date and time, so we'll assume it will start now
                            [int]$myvar_migration_plan_snapshot_interval_min = 120
                        }
                        $myvar_migration_plans.($myvar_item.migration_plan_name) = @{
                            "vms" = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_item.migration_plan_name}).vm_name  | Select-Object -Unique;
                            "network_mappings" = @();
                            "vm_details" = @();
                            "start_schedule" = $myvar_migration_plan_start_date;
                            "snapshot_interval_min" = $myvar_migration_plan_snapshot_interval_min
                        }
                    }  
                }
                Write-Host "$(get-date) [DATA] There is/are $($myvar_migration_plans.count) separate migration plan(s) to create on move instance $($move)." -ForegroundColor White
            }
            else 
            {#file does not exist
                Write-Host "$(get-date) [ERROR] The specified csv file $($csvPlans) does not exist!" -ForegroundColor Red
                exit 1
            }
            #endregion reading from csv

            #* fetch providers
            #region retrieving move providers information
            Write-Host "$(get-date) [INFO] Getting providers on Move instance $($move)..." -ForegroundColor Green
            $myvar_move_providers = Move-ListProviders -move $move -token $myvar_move_token
            Write-Host "$(get-date) [DATA] There are $($myvar_move_providers.entities.count) providers on Move instance $($move)..." -ForegroundColor White
            foreach ($myvar_provider in $myvar_move_providers.entities)
            {#display information for each available provider on the move instance
                Write-Host "$(get-date) [DATA] Provider $($myvar_provider.spec.name) has uuid $($myvar_provider.spec.uuid)and is of type $($myvar_provider.spec.type) version $($myvar_provider.spec.version)" -ForegroundColor White
            }
            #endregion retrieving move providers information

            #* fetch workloads inventory
            #region fetch workloads inventory for source clusters
            foreach ($myvar_source_cluster in ($myvar_csv_plans.source_cluster | Select-Object -Unique))
            {#fetch inventory for source clusters
                if (!($myvar_source_cluster_provider_name = ($myvar_csv_plans | ?{$_.source_cluster -ieq $myvar_source_cluster}).source_provider | Select-Object -First 1))
                {#we couldn't find a provider name for the specified source cluster in the csv file
                    Write-Host "$(get-date) [ERROR] You need to specify the provider name for source cluster $($myvar_source_cluster) in the file $($csvPlans)!" -ForegroundColor Red
                    exit 1
                }
                if (!($myvar_source_cluster_provider_uuid = ($myvar_move_providers.entities | ?{$_.spec.name -ieq $myvar_source_cluster_provider_name}).spec.uuid))
                {#we couldn't find that provider name in the move instance
                    Write-Host "$(get-date) [ERROR] We couldn't find a provider called $($myvar_source_cluster_provider_name) in Move instance $($move)!" -ForegroundColor Red
                    exit 1
                }
                Write-Host "$(get-date) [INFO] Fetching workload inventory for source cluster $($myvar_source_cluster) on Move instance $($move)..." -ForegroundColor Green
                $myvar_source_cluster_workloads = Move-GetWorkloadInventory -move $move -token $myvar_move_token -provider_uuid $myvar_source_cluster_provider_uuid -cluster $myvar_source_cluster -refresh
                Write-Host "$(get-date) [DATA] There are $($myvar_source_cluster_workloads.entities.count) workloads available on source cluster $($myvar_source_cluster)..." -ForegroundColor White
                $myvar_all_available_source_workloads += $myvar_source_cluster_workloads.Entities
            }
            #endregion fetch inventory for source clusters

            #* dealing with plans
            #todo: figure out target container uuid from myvar_move_providers
            #todo: consider other job options (schedule, retain mac address, etc...)   
            #region process each migration plan
            foreach ($myvar_migration_plan in $myvar_migration_plans.keys)
            {#process each migration plan specified in the csv file
                Write-Host "$(get-date) [STEP] Creating migration plan $($myvar_migration_plan)..." -ForegroundColor Magenta
                #! need to make sure plan does not already exist (otherwise implement edit function?)

                #region making sure we have only one source provider and cluster as well as a single target provider, cluster and container for this migration plan
                $myvar_migration_plan_source_provider = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_migration_plan}).source_provider | Select-Object -Unique
                $myvar_migration_plan_source_cluster = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_migration_plan}).source_cluster | Select-Object -Unique
                $myvar_migration_plan_target_provider = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_migration_plan}).target_provider | Select-Object -Unique
                $myvar_migration_plan_target_cluster = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_migration_plan}).target_cluster | Select-Object -Unique
                $myvar_migration_plan_target_container = ($myvar_csv_plans | ?{$_.migration_plan_name -eq $myvar_migration_plan}).target_container | Select-Object -Unique
                if ($myvar_migration_plan_source_provider -is [array])
                {#more than 1 source provider for the same plan has been specified
                    Write-Host "$(get-date) [ERROR] You specified more than 1 source provider for the $($myvar_migration_plan) migration plan in $($csvPlans)!" -ForegroundColor Red
                    exit 1
                }
                elseif ($myvar_migration_plan_source_cluster -is [array]) 
                {#more than 1 source cluster for the same plan has been specified
                    Write-Host "$(get-date) [ERROR] You specified more than 1 source cluster for the $($myvar_migration_plan) migration plan in $($csvPlans)!" -ForegroundColor Red
                    exit 1
                }
                elseif ($myvar_migration_plan_target_provider -is [array]) 
                {#more than 1 target provider for the same plan has been specified
                    Write-Host "$(get-date) [ERROR] You specified more than 1 target provider for the $($myvar_migration_plan) migration plan in $($csvPlans)!" -ForegroundColor Red
                    exit 1
                }
                elseif ($myvar_migration_plan_target_cluster -is [array]) 
                {#more than 1 target cluster for the same plan has been specified
                    Write-Host "$(get-date) [ERROR] You specified more than 1 target cluster for the $($myvar_migration_plan) migration plan in $($csvPlans)!" -ForegroundColor Red
                    exit 1
                }
                elseif ($myvar_migration_plan_target_container -is [array]) 
                {#more than 1 target container for the same plan has been specified
                    Write-Host "$(get-date) [ERROR] You specified more than 1 target container for the $($myvar_migration_plan) migration plan in $($csvPlans)!" -ForegroundColor Red
                    exit 1
                }
                #endregion making sure we have only one source provider and cluster as well as a single target provider, cluster and container for this migration plan

                #* dealing with vms
                #region let's make sure all vms exist in the source cluster and get the details for each valid vm
                foreach ($myvar_vm in $myvar_migration_plans.($myvar_migration_plan).vms)
                {#looking at each individual vm specified in the csv file for this migration plan
                    if ($myvar_vm_details = $myvar_all_available_source_workloads | ?{$_.VMName -ieq $myvar_vm})
                    {#found our vm
                        Write-Host "$(get-date) [DATA] Found VM $($myvar_vm_details.VMName) on cluster $($myvar_vm_details.ClusterName) in datacenter $($myvar_vm_details.DatacenterName) running on host $($myvar_vm_details.HostName)!" -ForegroundColor Green
                        $myvar_migration_plans.($myvar_migration_plan).vm_details += $myvar_vm_details
                    }
                    else 
                    {#specified vm is not anywhere in the source providers inventory
                        Write-Host "$(get-date) [WARNING] Could not find VM $($myvar_vm) listed in migration plan $($myvar_migration_plan) in any of the source clusters on move $($move)!" -ForegroundColor Yellow
                        #$myvar_migration_plans.($myvar_migration_plan).vms = $myvar_migration_plans.($myvar_migration_plan).vms | ?{$_ -ne $myvar_vm}
                    }
                }
                if ($myvar_migration_plans.($myvar_migration_plan).vm_details.count -eq 0)
                {#we couldn't find a single vm for that migration plan: displaying an error (but continuing)
                    Write-Host "$(get-date) [ERROR] Found $($myvar_migration_plans.($myvar_migration_plan).vm_details.count) valid candidate(s) out of $($myvar_migration_plans.($myvar_migration_plan).vms.count) specified to migrate using Move instance $($move) for migration plan $($myvar_migration_plan)." -ForegroundColor Red
                    continue
                }
                elseif ($myvar_migration_plans.($myvar_migration_plan).vm_details.count -ne $myvar_migration_plans.($myvar_migration_plan).vms.count)
                {#we have less valid vms than specified for this migration plan: displaying a warning and continuing
                    Write-Host "$(get-date) [WARNING] Found $($myvar_migration_plans.($myvar_migration_plan).vm_details.count) valid candidate(s) out of $($myvar_migration_plans.($myvar_migration_plan).vms.count) specified to migrate using Move instance $($move) for migration plan $($myvar_migration_plan)." -ForegroundColor Yellow
                }
                else 
                {#we found all the vms specified for this migration plan: displaying a white data message with that information
                    Write-Host "$(get-date) [DATA] Found $($myvar_migration_plans.($myvar_migration_plan).vm_details.count) valid candidate(s) out of $($myvar_migration_plans.($myvar_migration_plan).vms.count) specified to migrate using Move instance $($move) for migration plan $($myvar_migration_plan)." -ForegroundColor White    <# Action when all if and elseif conditions are false #>
                }
                #endregion let's make sure all vms exist in the source cluster and get the details for each valid vm

                #* dealing with networks
                #region let's figure out network uuids
                foreach ($myvar_network_mapping in (($myvar_csv_plans | ?{$_.vm_name -in $myvar_migration_plans.($myvar_migration_plan).vm_details.VMName} | ?{$_.migration_plan_name -eq $myvar_migration_plan}).network_mappings))
                {#looking at each individual vm specified in the csv file for this migration plan
                    Write-Host "$(get-date) [INFO] Looking up networks on Move instance $($move)..." -ForegroundColor Green
                    foreach ($myvar_network_mapping_item in $myvar_network_mapping.split(";"))
                    {#cater for multiple network mappings specified for a single vm
                        $myvar_source_network_name = ($myvar_network_mapping_item.split(":"))[0]
                        if ($myvar_source_network_id = ($myvar_migration_plans.($myvar_migration_plan).vm_details.networks | ?{$_.Name -ieq $myvar_source_network_name}).ID)
                        {#we found our source network id
                            Write-Host "$(get-date) [DATA] Source network $($myvar_source_network_name) on source cluster $($myvar_migration_plan_source_cluster) in source provider $($myvar_migration_plan_source_provider) on Move instance $($move) has network id $($myvar_source_network_id)" -ForegroundColor White
                        }
                        else 
                        {#we could not find out source network id
                            Write-Host "$(get-date) [ERROR] Could not find source network $($myvar_source_network_name) on source cluster $($myvar_migration_plan_source_cluster) in source provider $($myvar_migration_plan_source_provider) on Move instance $($move)..." -ForegroundColor Red
                            exit 1
                        }
                        
                        $myvar_target_network_name = ($myvar_network_mapping_item.split(":"))[1]
                        if ($myvar_target_network_id = ((($myvar_move_providers.entities.spec | ?{$_.Name -ieq $myvar_migration_plan_target_provider}).AOSProperties.Clusters | ?{$_.Name -ieq $myvar_migration_plan_target_cluster}).Networks | ?{$_.Name -ieq $myvar_target_network_name}).UUID)
                        {#we found our target network uuid
                            Write-Host "$(get-date) [DATA] Target network $($myvar_target_network_name) on target cluster $($myvar_migration_plan_target_cluster) in target provider $($myvar_migration_plan_target_provider) on Move instance $($move) has network id $($myvar_target_network_id)" -ForegroundColor White
                        }
                        else 
                        {#we could not find our target network uuid
                            Write-Host "$(get-date) [ERROR] Could not find target network $($myvar_target_network_name) on target cluster $($myvar_migration_plan_target_cluster) in target provider $($myvar_migration_plan_target_provider) on Move instance $($move)..." -ForegroundColor Red
                            exit 1
                        }
                        $myvar_network_mapping_spec = @{
                            SourceNetworkID=$myvar_source_network_id;
                            TargetNetworkID=$myvar_target_network_id;
                        }
                        if ($myvar_network_mapping_spec -notin $myvar_migration_plans.($myvar_migration_plan).network_mappings)
                        {#we haven't added this network mappings spec yet
                            $myvar_migration_plans.($myvar_migration_plan).network_mappings += $myvar_network_mapping_spec
                        }
                    }
                }
                #we need to make sure that mappings have been specified for all the networks in use for each valid vm
                if (($myvar_migration_plans.($myvar_migration_plan).network_mappings.SourceNetworkID | Select-Object -Unique) -notcontains ($myvar_migration_plans.($myvar_migration_plan).vm_details.Networks.ID | Select-Object -Unique))
                {#some vm networks have no mapping specified
                    Write-Host "$(get-date) [WARNING] Some virtual machines part of migration plan $($myvar_migration_plan) are connected to networks for which no mapping has been specified!" -ForegroundColor Yellow
                }
                #endregion let's figure out network uuids
                
                #* dealing with target cluster uuid, source provider uuid and target container uuid
                #region let's figure out some uuids
                if ($myvar_migration_plan_target_cluster_uuid = ($myvar_move_providers.Entities.Spec.AOSProperties.Clusters | ?{$_.Name -ieq $myvar_migration_plan_target_cluster}).UUID)
                {#found target cluster uuid
                    Write-Host "$(get-date) [DATA] Target cluster $($myvar_migration_plan_target_cluster) UUID is $($myvar_migration_plan_target_cluster_uuid)." -ForegroundColor White
                }
                else 
                {#could not find target cluster uuid
                    Write-Host "$(get-date) [ERROR] Could not find target cluster $($myvar_migration_plan_target_cluster) UUID on $($move)!" -ForegroundColor Red
                    exit 1
                }
                if ($myvar_migration_plan_target_container_uuid = (($myvar_move_providers.Entities.Spec.AOSProperties.Clusters | ?{$_.Name -ieq $myvar_migration_plan_target_cluster}).Containers | ?{$_.Name -ieq $myvar_migration_plan_target_container}).UUID)
                {#found target container uuid
                    Write-Host "$(get-date) [DATA] Target container $($myvar_migration_plan_target_container) UUID is $($myvar_migration_plan_target_container_uuid)." -ForegroundColor White
                }
                else 
                {#could not find target cluster uuid
                    Write-Host "$(get-date) [ERROR] Could not find target container $($myvar_migration_plan_target_container) UUID on $($move)!" -ForegroundColor Red
                    exit 1
                }
                if ($myvar_migration_plan_source_provider_uuid = ($myvar_move_providers.Entities | ?{$_.Spec.Name -ieq $myvar_migration_plan_source_provider}).Metadata.UUID)
                {#found source provider uuid
                    Write-Host "$(get-date) [DATA] Source Provider $($myvar_migration_plan_source_provider) UUID is $($myvar_migration_plan_source_provider_uuid)." -ForegroundColor White
                }
                else 
                {#could not find source provider uuid
                    Write-Host "$(get-date) [ERROR] Could not find source provider $($myvar_migration_plan_source_provider) UUID on $($move)!" -ForegroundColor Red
                    exit 1
                }
                if ($myvar_migration_plan_target_provider_uuid = ($myvar_move_providers.Entities | ?{$_.Spec.Name -ieq $myvar_migration_plan_target_provider}).Metadata.UUID)
                {#found target provider uuid
                    Write-Host "$(get-date) [DATA] Target Provider $($myvar_migration_plan_target_provider) UUID is $($myvar_migration_plan_target_provider_uuid)." -ForegroundColor White
                }
                else 
                {#could not find target provider uuid
                    Write-Host "$(get-date) [ERROR] Could not find target provider $($myvar_migration_plan_target_provider) UUID on $($move)!" -ForegroundColor Red
                    exit 1
                }
                #endregion let's figure out some uuids

                #* dealing with the payload
                #region build the plan payload
                #example:
                <# {
                    "Spec": {
                      "Name": "test_auto_plan",
                      "NetworkMappings": [
                        {
                          "SourceNetworkID": "network-23685",
                          "TargetNetworkID": "81f3f8c8-0a12-4028-8cfd-1c81fc05d1a4"
                        }
                      ],
                      "Settings": {
                        "Bandwidth": null,
                        "GuestPrepMode": "manual",
                        "Schedule": {
                          "RWEndTimeAtEpochSec": 0,
                          "RWStartTimeAtEpochSec": 0,
                          "ScheduleAtEpochSec": -1
                        }
                      },
                      "SourceInfo": {
                        "ProviderUUID": "e11b52e2-8b7b-4434-a7d2-570dba97cd62"
                      },
                      "TargetInfo": {
                        "AOSProviderAttrs": {
                            "ClusterUUID": "000582c6-cf0d-e0a8-0000-000000016950",
                            "ContainerUUID": "4e2ea259-ef3a-487a-9036-3581deba5207"
                        },
                        "ProviderUUID": "ec7cab9b-c4a1-4f70-8845-1bf3ab466d29"
                      },
                      "Workload": {
                        "Type": "VM",
                        "VMs": [
                          {
                            "AllowUVMOps": false,
                            "RetainMacAddress": true,
                            "UninstallGuestTools": false,
                            "VMReference": {
                              "UUID": "d586d7b9-5f9d-5f92-9e50-ba151ee3c11d"
                            }
                          }
                        ]
                      }
                    }
                  } #>
                $myvar_migration_plan_payload = @{
                    Spec=@{
                        Name="$($myvar_migration_plan)";
                        NetworkMappings=@(foreach ($myvar_network_mapping_item in $myvar_migration_plans.($myvar_migration_plan).network_mappings) {
                            @{
                                SourceNetworkID="$($myvar_network_mapping_item.SourceNetworkID)";
                                TargetNetworkID="$($myvar_network_mapping_item.TargetNetworkID)";
                            }
                        });
                        Settings=@{
                            Bandwidth=$null;
                            GuestPrepMode="manual";
                            Schedule=@{
                                RWEndTimeAtEpochSec=0;
                                RWStartTimeAtEpochSec=0;
                                ScheduleAtEpochSec=-1;
                            };
                        };
                        SourceInfo=@{
                            ProviderUUID="$($myvar_migration_plan_source_provider_uuid)";
                        };
                        TargetInfo=@{
                            AOSProviderAttrs=@{
                                ClusterUUID="$($myvar_migration_plan_target_cluster_uuid)";
                                ContainerUUID="$($myvar_migration_plan_target_container_uuid)";
                            };
                            ProviderUUID="$($myvar_migration_plan_target_provider_uuid)"
                        };
                        Workload=@{
                            Type="VM";
                            VMs=@(foreach ($myvar_vm in $myvar_migration_plans.($myvar_migration_plan).vm_details)
                                {
                                    @{
                                        AllowUVMOps=$false;
                                        RetainMacAddress=$true;
                                        UninstallGuestTools=$false;
                                        VMReference=@{
                                            UUID="$($myvar_vm.VMUuid)"
                                        }
                                    }
                                }
                            )
                        };
                    }
                }
                $myvar_migration_plan_json_payload = (ConvertTo-Json $myvar_migration_plan_payload -Depth 9)
                #endregion build the plan payload
                
                #* dealing with plan creation
                #region create the plan
                $myvar_migration_plan_create_response = Move-CreateMigrationPlan -move $move -token $myvar_move_token -payload $myvar_migration_plan_json_payload
                Write-Host "$(get-date) [SUCCESS] Successfully created migration plan $($myvar_migration_plan)!" -ForegroundColor Cyan
                #endregion create the plan

                #* dealing with migration start
                #region start migration
                if ($myvar_migration_plan_start_date -ieq "now")
                {#we start migration immediately
                    Write-Host "$(get-date) [INFO] Starting migration plan $($myvar_migration_plan)..." -ForegroundColor Green
                    $myvar_migration_plan_start_response = Move-StartMigrationPlan -move $move -token $myvar_move_token -plan $($myvar_migration_plan_create_response.MetaData.uuid) -snapshot_interval_min $($myvar_migration_plans.($myvar_migration_plan).snapshot_interval_min)
                    Write-Host "$(get-date) [SUCCESS] Successfully started migration plan $($myvar_migration_plan)!" -ForegroundColor Cyan
                }
                #endregion start migration
            }
            #endregion process each migration plan
        }
        elseif ($action -eq "report")
        {#user wants to report migration plan(s) status
            Write-Host "$(get-date) [STEP] Reporting migration plan(s) status..." -ForegroundColor Magenta
            $myvar_move_migration_plans = Move-GetMigrationPlans -move $move -token $myvar_move_token
            Write-Host "$(get-date) [DATA] There is/are $($myvar_move_migration_plans.entities.count) migration plan(s) on Move instance $($move)..." -ForegroundColor White
            foreach ($myvar_migration_plan in $myvar_move_migration_plans.entities)
            {
                if (($plans -ieq "all") -or ($myvar_migration_plan.metadata.name -in $plans))
                {
                    Write-Host "$(get-date) [DATA] Migration plan $($myvar_migration_plan.metadata.name) with status $(Convert-PlanState($myvar_migration_plan.metadata.state)) contains $($myvar_migration_plan.metadata.numvms) VM(s) migrating from provider $($myvar_migration_plan.metadata.sourceinfo.name) of type $($myvar_migration_plan.metadata.sourceinfo.type) to $($myvar_migration_plan.metadata.targetinfo.name) of type $($myvar_migration_plan.metadata.targetinfo.type) and has a data size of $(Format-FileSize($myvar_migration_plan.metadata.datainbytes))" -ForegroundColor White
                }
                #todo: create csv/html report
            }
        }
        elseif ($action -eq "cutover")
        {#user wants to cutover vm(s)
            Write-Host "$(get-date) [STEP] Performing cutover of virtual machines..." -ForegroundColor Magenta
        }
        elseif ($action -eq "failback")
        {#user wants to failback vm(s)
            Write-Host "$(get-date) [STEP] Failing back virtual machines..." -ForegroundColor Magenta
        }
        elseif ($action -eq "validate")
        {#user wants to validate a migration plan
            Write-Host "$(get-date) [STEP] Validating pre-reqs for virtual machines..." -ForegroundColor Magenta
        }
        elseif ($action -eq "suspend")
        {#user wants to suspend migration operations for a migration plan
            Write-Host "$(get-date) [STEP] Suspending migration plan(s)..." -ForegroundColor Magenta
        }
        elseif ($action -eq "resume")
        {#user wants to resume migration operations for a migration plan
            Write-Host "$(get-date) [STEP] Resuming migration plan(s)..." -ForegroundColor Magenta
        }
        #endregion Step 2: branch based on action selected

        #region Final Step: logging out of Move to release the authentication token
        Write-Host "$(get-date) [STEP] Logging out of Move API instance $($move)..." -ForegroundColor Magenta
        $myvar_move_logout_response = Move-Logout -move $move -token $myvar_move_token
        #endregion Final Step: logging out of Move to release the authentication token
    }
#endregion processing


#region cleanup
    CleanUp
#endregion