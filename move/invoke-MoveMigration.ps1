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
  Specifies source csv files with the list of vms and plans to create.  Each line of that csv file must contain the following columns: migration_plan_name, vm_name, network_mappings, guest_prep_mode, source_provider, source_cluster, target_provider, target_cluster, target_container, move_instance, start_schedule, snapshot_interval_min. In addition, the target provider, cluster and storage container for all vms within the same migration plan must be the same (if you need to specify different targets, then you will need to specify a different migration plan). Network mappings can be different per vm, must one mapping must exist for every network the vm is connected to.  Network mappings are specified in the source_network_name:target_network_name format and mutliple entries in that column are separated with a semi colon (;).
.EXAMPLE
.\invoke-MoveMigration.ps1 -move mymove.local -action report
Report the status of all migration plans from the specified Move instance:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
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
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $false)] $move,
        [parameter(mandatory = $false)] $moveCreds,
        [parameter(mandatory = $false)] [string][ValidateSet("migrate","report","cutover","failback","validate","suspend","resume")]$action,
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

            #cleanup after ourselves and delete all custom variables
            Remove-Variable myvar* -ErrorAction SilentlyContinue
            Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
            Remove-Variable username -ErrorAction SilentlyContinue
            Remove-Variable PrismSecurePassword -ErrorAction SilentlyContinue
            Remove-Variable prismCredentials -ErrorAction SilentlyContinue
        }
    }#end function CleanUp

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
            [parameter(mandatory = $false)][string] $pc,
            [parameter(mandatory = $false)][string] $object,
            [parameter(mandatory = $false)][string] $kind
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
            [parameter(mandatory = $false)]
            [string] 
            $move,
            
            [parameter(mandatory = $false)]
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
            [parameter(mandatory = $false)]
            [string] 
            $move,
            
            [parameter(mandatory = $false)]
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
            [parameter(mandatory = $false)]
            [string] 
            $move,
            
            [parameter(mandatory = $false)]
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
            [parameter(mandatory = $false)]
            [string] 
            $move,
            
            [parameter(mandatory = $false)]
            [string]
            $token,

            [parameter(mandatory = $false)]
            [string]
            $provider_uuid,

            [parameter(mandatory = $false)]
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
#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
08/26/2022 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\invoke-MoveMigration.ps1"

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
    if ($PSVersionTable.PSVersion.Major -lt 6) {throw "$(get-date) [ERROR] Please upgrade to Powershell v6 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    #initialize variables
    $myvar_ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_MoveServers = @() #used to store the list of all the move servers we must connect to
#endregion

#region parameters validation
    if (!$move -or !$action) {
        Throw "$(Get-Date) [ERROR] You must specify -move -action!"
    }
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

    $myvar_MoveServers = $move.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#region processing
    foreach ($myvar_Move in $myvar_MoveServers) 
    {
        Write-Host "$(get-date) [INFO] Processing Move instance $myvar_Move..." -ForegroundColor Green
        
        # Login to Move
        $loginResponse = Move-Login -move $myvar_Move -credential $moveCredentials
        $token = $loginResponse.token
        
        try 
        {
            if ($action -eq "report")
            {
                # List providers and workloads
                $providers = Move-ListProviders -move $myvar_Move -token $token
                # Process providers...
                Write-Host "$(get-date) [INFO] Reporting migration plans for $myvar_Move" -ForegroundColor Green
            }
            elseif ($action -eq "migrate")
            {
                Write-Host "$(get-date) [INFO] Migration action not fully implemented yet" -ForegroundColor Yellow
            }
            elseif ($action -in @("suspend","resume","cutover","failback","validate"))
            {
                Write-Host "$(get-date) [INFO] Action $action not fully implemented yet" -ForegroundColor Yellow
            }
        }
        finally 
        {
            # Logout
            Move-Logout -move $myvar_Move -token $token
        }
    }
#endregion

#region cleanup
    CleanUp
#endregion