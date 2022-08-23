<#
.SYNOPSIS
  This script can be used to remove volume groups which do not belong to any nke cluster.
.DESCRIPTION
  This script can be used to remove volume groups which do not belong to any nke cluster.  It compares all listed volumes on all nke clusters with the list of volume groups that match a pvc name and also checks for iops activity in the last 24 hours.
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
.PARAMETER noprompt
  Switch to specify you do not want to be prompted for each volume group to be removed.  WARNING: note that pvcs could belong to other k8s clusters using the Nutanix storage class (such as an OpenShift cluster). While the script checks for activity in the last 24 hours, it is not bullet proof. use at your own risk and be warned that you will be deleting data!
.EXAMPLE
.\remove-OrphanedVolumeGroups.ps1 -prismcentral mypc.local -prismcreds mycreds
Remove all volume groups whose names match an nke pvc but which do not belong to any active nke cluster.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: August 23rd 2022
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
    [parameter(mandatory = $false)] [switch]$noprompt,
    [parameter(mandatory = $false)] $prismCreds
)
#endregion


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

function Format-FileSize() 
{
    Param ([int64]$size)
    If     ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
    ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
    ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
    ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
    ElseIf ($size -gt 0)   {[string]::Format("{0:0.00} B", $size)}
    Else                   {""}
}
#endregion


#region prepwork
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
08/23/2022 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\remove-OrphanedVolumeGroups.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

Set-PoSHSSLCerts
Set-PoshTls
#endregion


#region variables
$myvar_ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
[System.Collections.ArrayList]$myvar_nke_volumes = New-Object System.Collections.ArrayList($null)
$length = 500
$startdate = ((Get-Date).AddMinutes(-5)).AddDays(-1)
$enddate = (Get-Date).AddMinutes(-5)
$interval_end_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$interval_start_ms = $interval_end_ms - 86400000

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
#todo: get nke clusters
Write-Host "$(get-date) [INFO] Retrieving list of Nutanix Kubernetes Engine (nke) clusters from Prism Central $($prismcentral)..." -ForegroundColor Green
$url = "https://{0}:9440/karbon/acs/k8s/cluster/list" -f $prismcentral
$method = "POST"
$myvar_nke_clusters = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
Write-Host "$(get-date) [SUCCESS] Successfully retrieved nke clusters from Prism Central $($prismcentral)!" -ForegroundColor Cyan
Write-Host "$(get-date) [DATA] Found $($myvar_nke_clusters.count) nke clusters on Prism Central $($prismcentral)" -ForegroundColor White

#todo: list volumes for nke clusters
foreach ($myvar_nke_cluster in $myvar_nke_clusters)
{
    Write-Host "$(get-date) [INFO] Retrieving list of volumes for nke clusters $($myvar_nke_cluster.cluster_metadata.name) from Prism Central $($prismcentral)..." -ForegroundColor Green
    $url = "https://{0}:9440/karbon/acs/k8s/cluster/{1}/volume/list" -f $prismcentral,$myvar_nke_cluster.cluster_metadata.uuid
    $method = "POST"
    $content = @{}
    $payload = (ConvertTo-Json $content -Depth 4)
    $myvar_nke_cluster_volumes = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
    Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of volumes for nke clusters $($myvar_nke_cluster.cluster_metadata.name) from Prism Central $($prismcentral)!" -ForegroundColor Cyan
    Write-Host "$(get-date) [DATA] Found $($myvar_nke_cluster_volumes.entities.count) volumes for nke cluster $($myvar_nke_cluster.cluster_metadata.name) on Prism Central $($prismcentral)" -ForegroundColor White

    foreach ($myvar_nke_cluster_volume in $myvar_nke_cluster_volumes.entities)
    {
        $myvar_nke_volume_info = [ordered]@{
            "nke_cluster" = $myvar_nke_cluster.cluster_metadata.name;
            "name" = $myvar_nke_cluster_volume.metadata.name;
            "namespace" = $myvar_nke_cluster_volume.metadata.namespace;
            "pv_name" = $myvar_nke_cluster_volume.status.pv_name;
            "storage_class" = $myvar_nke_cluster_volume.status.storage_class_name;
            "size_gib" = $myvar_nke_cluster_volume.status.size;
        }
        $myvar_nke_volumes.Add((New-Object PSObject -Property $myvar_nke_volume_info)) | Out-Null
    }
}
Write-Host "$(get-date) [DATA] Found a total of $($myvar_nke_volumes.count) volumes on nke clusters on Prism Central $($prismcentral)" -ForegroundColor White

#todo: list volume groups and keep those that contain are nke pvcs
Write-Host "$(get-date) [INFO] Retrieving list of volume groups from Prism Central $($prismcentral)..." -ForegroundColor Green
$myvar_volume_groups = Get-PrismCentralObjectList -pc $prismcentral -object "volume_groups" -kind "volume_group"
Write-Host "$(get-date) [SUCCESS] Successfully retrieved volume groups from Prism Central $($prismcentral)!" -ForegroundColor Cyan
Write-Host "$(get-date) [DATA] Found a total of $($myvar_volume_groups.count) volume groups on Prism Central $($prismcentral)" -ForegroundColor White

$regex = '^pvc-[a-zA-Z\d]{8}-[a-zA-Z\d]{4}-[a-zA-Z\d]{4}-[a-zA-Z\d]{4}-[a-zA-Z\d]{12}$'
$myvar_orphaned_volume_groups = $myvar_volume_groups | ?{($_.spec.name -notin $myvar_nke_volumes.pv_name) -and ($_.spec.name -match $regex)}
Write-Host "$(get-date) [DATA] Found a total of $($myvar_orphaned_volume_groups.count) orphaned pvc volume groups on Prism Central $($prismcentral)" -ForegroundColor White

#todo: delete vgs which contain pvc and do not belong to any nke cluster
foreach ($myvar_orphaned_volume_group in $myvar_orphaned_volume_groups)
{  
    if (!$noprompt)
    {#let's prompt for each volume group
        Write-Host "$(Get-Date) [WARNING] Do you want to delete volume group $($myvar_orphaned_volume_group.spec.name) which does not belong to any nke cluster with size $(Format-FileSize($myvar_orphaned_volume_group.status.resources.size_bytes))?" -ForegroundColor Yellow
        $myvar_user_choice = Write-CustomPrompt
    }
    else             
    {#no need to prompt
        $myvar_user_choice = "y" 
    }
    if ($myvar_user_choice -ieq "y")
    {

        #todo: check last 24 stats to make sure there are no iops
        #https://10.68.97.150:9440/api/nutanix/v3/groups POST
        <# {
            "entity_type": "volume_group_config",
            "entity_ids": [
                "b030ad29-77d0-4402-83be-4d9f58beeb7e"
            ],
            "group_member_attributes": [
                {
                    "attribute": "controller_num_iops",
                    "operation": "AVG"
                },
                {
                    "attribute": "capacity.controller_num_iops.upper_buff",
                    "operation": "AVG"
                },
                {
                    "attribute": "capacity.controller_num_iops.lower_buff",
                    "operation": "AVG"
                }
            ],
            "interval_start_ms": 1661173069536,
            "interval_end_ms": 1661259469928,
            "downsampling_interval": 300,
            "query_name": "prism:CPStatsModel"
        } #>
        Write-Host "$(get-date) [INFO] Checking there is no iops activity in the last 24 hours on $($myvar_orphaned_volume_group.spec.name)..." -ForegroundColor Green
        $url = "https://{0}:9440/api/nutanix/v3/groups" -f $prismcentral
        $method = "POST"
        $content = @{
            entity_type="volume_group_config";
            entity_ids=@($myvar_orphaned_volume_group.metadata.uuid);
            group_member_attributes=@(@{
                attribute="controller_num_iops";
                operation="AVG";
            });
            interval_start_ms= $interval_start_ms;
            interval_end_ms= $interval_end_ms;
            downsampling_interval= 300;
            query_name="prism:CPStatsModel"
        }
        $payload = (ConvertTo-Json $content -Depth 9)
        $myvar_vg_stats = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved iops stats for volume group $($myvar_orphaned_volume_group.spec.name) from $($prismcentral)!" -ForegroundColor Cyan
        if (($myvar_vg_stats.group_results.entity_results.data | ?{$_.name -eq "controller_num_iops"}).values.count -le 0)
        {
            Write-Host "$(get-date) [DATA] There is no iops activity in the last 24 hours on $($myvar_orphaned_volume_group.spec.name)" -ForegroundColor White
        }
        else 
        {
            Write-Host "$(get-date) [WARNING] There is iops activity in the last 24 hours on $($myvar_orphaned_volume_group.spec.name)" -ForegroundColor Yellow
            continue
        }

        #todo: get iscsi attachments
        Write-Host "$(get-date) [INFO] Getting list of iscsi attachments on volume group $($myvar_orphaned_volume_group.spec.name)..." -ForegroundColor Green
        $url = "https://{0}:9440/api/storage/v4.0.a2/config/volume-groups/{1}/iscsi-client-attachments" -f $prismcentral,$myvar_orphaned_volume_group.metadata.uuid
        $method = "GET"
        $myvar_vg_iscsi_attachments = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully retrieved list of iscsi attachments on volume group $($myvar_orphaned_volume_group.spec.name) from $($prismcentral)!" -ForegroundColor Cyan
        
        #todo: remove iscsi attachments
        foreach ($myvar_vg_iscsi_attachment in $myvar_vg_iscsi_attachments)
        {
            if ($myvar_vg_iscsi_id = $myvar_vg_iscsi_attachment.data.extid)
            {
                Write-Host "$(get-date) [INFO] Removing iscsi attachments from volume group $($myvar_orphaned_volume_group.spec.name)..." -ForegroundColor Green
                $url = "https://{0}:9440/api/storage/v4.0.a2/config/volume-groups/{1}/`$actions/detach-iscsi-client/{2}" -f $prismcentral,$myvar_orphaned_volume_group.metadata.uuid,$myvar_vg_iscsi_id
                $method = "POST"
                $myvar_vg_remove_iscsi_attachments = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully removed iscsi attachments from volume group $($myvar_orphaned_volume_group.spec.name) from $($prismcentral)!" -ForegroundColor Cyan
            }
        }

        #todo: delete vg
        Write-Host "$(get-date) [INFO] Deleting volume group $($myvar_orphaned_volume_group.spec.name)..." -ForegroundColor Green
        $url = "https://{0}:9440/api/storage/v4.0.a2/config/volume-groups/{1}" -f $prismcentral,$myvar_orphaned_volume_group.metadata.uuid
        $method = "DELETE"
        $myvar_vg_delete = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        Write-Host "$(get-date) [SUCCESS] Successfully deleted volume group $($myvar_orphaned_volume_group.spec.name) from $($prismcentral)!" -ForegroundColor Cyan
    }
}

#endregion


#region cleanup
CleanUp
#endregion

