<#
.SYNOPSIS
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
.DESCRIPTION
  Use this script to connect the first vnic of the specified AHV vm(s) to the specified network.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix cluster Prism Element fully qualified domain name or IP address.  If you are using vpc_subnet, then this should be a Prism Central instance.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vms
  One or more vm name(s) (comma separated).
.PARAMETER ahv_network
  AHV network name you want to connect the specified vm(s) to.  Can't be used with -vpc_subnet.
.PARAMETER vpc_subnet
  VPC subnet name you want to connect the specified vm(s) to.  Can't be used with -ahv_network.  Note that this will remove the existing vnic and create a new one to replace it which will be connected to the specified vpc subnet.
.PARAMETER skiptaskstatuscheck
  Do not check each vm update task status.
.PARAMETER dontkeepip
  When attaching to a vpc subnet, don't try to preserve the ip configuration.
.EXAMPLE
.\set-AhvVmNetwork.ps1 -cluster ntnxc1.local -vm myvm -ahv_network mynetwork
Connect myvm to the mynetwork AHV network:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 24th 2022
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$prism,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true)] $vms,
        [parameter(mandatory = $false)] [string]$ahv_network,
        [parameter(mandatory = $false)] [string]$vpc_subnet,
        [parameter(mandatory = $false)] [switch]$skiptaskstatuscheck,
        [parameter(mandatory = $false)] [switch]$dontkeepip
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

#this function is used to compare versions of a given module
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

Function New-PercentageBar
{
	
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

Function Get-PrismTaskStatus
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
.\Get-PrismTaskStatus -Task $task
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
    {}
    process 
    {
        #region get initial task details
            Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
            $method = "GET"
            $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
        #endregion

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Sleep 5
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                $method = "GET"
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.progress_status -ine "running") 
                {
                    if ($taskDetails.progress_status -ine "succeeded") 
                    {
                        Throw "$(Get-Date) [INFO] Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        }
    }
    end
    {}
}
#endregion

#region prepwork
    $myvar_history_text = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/27/2021 sb   Initial release.
06/24/2022 sb   Adding vpc_subnet option.  Replacing external module dependency
                with local functions.
################################################################################
'@
    $myvar_script_name = ".\set-AhvVmNetwork.ps1"

    if ($help) {get-help $myvar_script_name; exit}
    if ($History) {$myvar_history_text; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvar_elapsed_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_api_server_port="9440"
    $myvar_length=100
#endregion

#region parameters validation
    if ($ahv_network -and $vpc_subnet) {Throw "$(get-date) [ERROR] You can only specify an ahv_network OR a vpc_subnet but not both! Exiting."}
    if (!$ahv_network -and !$vpc_subnet) {Throw "$(get-date) [ERROR] You must specify either an ahv_network OR a vpc_subnet! Exiting."}
    if ($ahv_network) 
    {#renamed the network variable when I added vpc subnet so to make things more simple, doing this :)
        $network = $ahv_network
        $cluster = $prism
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

    #assume vms is a list
    $myvar_vms = $vms.Split("{,}")
#endregion

#region processing
    
    if ($network) 
    {#we're updating an ahv network

        #region get cluster info, check it is AHV
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving cluster information from $($cluster)..."
            $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/cluster/" -f $cluster,$myvar_api_server_port
            $myvar_method = "GET"
            $myvar_cluster = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved cluster information from $($cluster)!"
            if ($myvar_cluster.hypervisor_types -eq "kKvm")
            {
                Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Cluster $($cluster) is an AHV cluster."
            }
            else 
            {
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Cluster $($cluster) is not an AHV cluster!"
                exit 1
            }
        #endregion

        #region get vms, make sure all specified vms exist, gather information about each vm to process
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of VMs from AHV cluster $($cluster)..."
            $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/vms/?include_vm_nic_config=true" -f $cluster,$myvar_api_server_port
            $myvar_method = "GET"
            $myvar_vm_list = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved VMs list from $($cluster)!"

            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_vm in (Compare-Object -ReferenceObject $myvar_vm_list.entities.name -DifferenceObject $myvar_vms -IncludeEqual))
            {#make sure all specified vms exist
                if ($myvar_vm.SideIndicator -eq "=>")
                {#this vm does not exist
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "VM $($myvar_vm.InputObject) does not exist on AHV cluster $($cluster)!"
                    exit 1
                }
                if ($myvar_vm.SideIndicator -eq "==")
                {#vm matches
                    $myvar_vm_info = $myvar_vm_list.entities | Where-Object -Property name -eq $myvar_vm.InputObject | Select-Object -Property name,uuid,vm_nics
                    #store the results for this entity in our overall result variable
                    $myvar_vms_details.Add($myvar_vm_info) | Out-Null
                    Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Grabbed information for vm $($myvar_vm.InputObject)..."
                }
            }
        #endregion

        #region get networks, make sure the specified network exists, get information about that network
        
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of networks from AHV cluster $($cluster)..."
            $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/networks/" -f $cluster,$myvar_api_server_port
            $myvar_method = "GET"
            $myvar_network_list = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved network list from $($cluster)!"
            
            if ($network -notin $myvar_network_list.entities.name)
            {
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Network $($network) does not exist on AHV cluster $($cluster)!"
                exit 1
            }
            #grab the uuid of the network
            $myvar_network_details = $myvar_network_list.entities | Where-Object -Property name -eq $network | Select-Object -Property name,uuid    

        #endregion

        #region process each vm
            ForEach ($myvar_vm in $myvar_vms_details)
            {
                Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Connecting vm $($myvar_vm.name) to network $($network)..."
                #figuring out vnic mac address and formatting associated url string
                $myvar_vnic_mac = ($myvar_vm.vm_nics[0]).mac_address
                $myvar_vnic_mac_url = $myvar_vnic_mac -replace ":","%3A"
                #figure out payload
                $myvar_content = @{
                    nic_spec = @{
                        is_connected= $true;
                        network_uuid= "$($myvar_network_details.uuid)"
                    }
                }
                $myvar_payload = (ConvertTo-Json $myvar_content -Depth 9)
                $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/vms/{2}/nics/{3}" -f $cluster,$myvar_api_server_port,$myvar_vm.uuid,$myvar_vnic_mac_url
                $myvar_method = "PUT"
                $myvar_vm_update_task = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
                Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully requested connection of vm $($myvar_vm.name) to network $($network)!"

                #task status check
                if (!$skiptaskstatuscheck)
                {
                    Get-PrismTaskStatus -task $myvar_vm_update_task.task_uuid -credential $prismCredentials -cluster $cluster
                }
            }
        #endregion
    }

    if ($vpc_subnet)
    {#we're attaching a vnic to a subnet in a vpc

        #region get vms, make sure all specified vms exist, gather information about each vm to process
            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of VMs from Prism Central..."
            $myvar_vm_list = Get-PrismCentralObjectList -pc $prism -object 'vms' -kind 'vm'
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved VMs list from Prism Central!"

            [System.Collections.ArrayList]$myvar_vms_details = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_vm in (Compare-Object -ReferenceObject $myvar_vm_list.spec.name -DifferenceObject $myvar_vms -IncludeEqual))
            {#make sure all specified vms exist
                if ($myvar_vm.SideIndicator -eq "=>")
                {#this vm does not exist
                    Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "VM $($myvar_vm.InputObject) does not exist on AHV cluster $($cluster)!"
                    exit 1
                }
                if ($myvar_vm.SideIndicator -eq "==")
                {#vm matches
                    $myvar_vm_info = $myvar_vm_list | Where-Object -FilterScript {$_.spec.name -eq $myvar_vm.InputObject}
                    #store the results for this entity in our overall result variable
                    $myvar_vms_details.Add($myvar_vm_info) | Out-Null
                    Write-LogOutput -Category "DATA" -LogFile $myvar_log_file -Message "Grabbed payload for vm $($myvar_vm.InputObject)..."
                }
            }
        #endregion

        #region get vpc subnets and make sure the one specified by the user exists

            Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving list of subnets from Prism Central..."
            $myvar_subnet_list = Get-PrismCentralObjectList -pc $prism -object 'subnets' -kind 'subnet'
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully retrieved subnets list from Prism Central!"
            
            if ($vpc_subnet -notin $myvar_subnet_list.spec.name)
            {
                Write-LogOutput -Category "ERROR" -LogFile $myvar_log_file -Message "Subnet $($vpc_subnet) does not exist on Prism Central $($prism)!"
                exit 1
            }
            #grab the uuid of the subnet
            $myvar_subnet_details = $myvar_subnet_list | Where-Object -FilterScript {$_.spec.name -eq $vpc_subnet}

        #endregion get vpc subnets

        #region process each vm
            #region process each vm
                ForEach ($myvar_vm in $myvar_vms_details)
                {
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Removing first vnic from vm $($myvar_vm.spec.name)..."

                    $myvar_vm.PSObject.Properties.Remove('status') #removing status section from the vm payload
                    if ($myvar_vm.spec.resources.nic_list[0].subnet_reference.uuid -eq $myvar_subnet_details.metadata.uuid)
                    {
                        Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "vnic0 on vm $($myvar_vm.spec.name) is already connected to subnet $($vpc_subnet)! Skipping..."
                        Continue
                    }
                    $myvar_vm_nic0_config = $myvar_vm.spec.resources.nic_list[0] #saving vnic0 configuration
                    if ($myvar_vm.spec.resources.nic_list.count -eq 0)
                    {#there are no vnics on this vm
                        Write-LogOutput -Category "WARNING" -LogFile $myvar_log_file -Message "There is no vnic to update on vm $($myvar_vm.spec.name)! Skipping..."
                        Continue
                    }
                    elseif ($myvar_vm.spec.resources.nic_list.count -gt 1)
                    {#we have more than 1 vnic
                        $myvar_vm.spec.resources.nic_list[0] = "" #removing existing vnic0
                    }
                    else 
                    {
                        $myvar_vm.spec.resources.nic_list = @()
                    }
                    $myvar_vm.metadata.spec_version += 1 #increasing spec version
                    $myvar_url = "https://{0}:{1}/api/nutanix/v3/vms/{2}" -f $prism,$myvar_api_server_port,$myvar_vm.metadata.uuid
                    $myvar_method = "PUT"
                    $myvar_payload = (ConvertTo-Json $myvar_vm -Depth 9)
                    $myvar_vm_update_task = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
                    
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully requested removal of vnic0 from vm $($myvar_vm.spec.name)!"
                    $myvar_vm_update_task_status = Get-PrismCentralTaskStatus -task $myvar_vm_update_task.status.execution_context.task_uuid -credential $prismCredentials -cluster $prism

                   
                    Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Connecting vm $($myvar_vm.spec.name) to subnet $($vpc_subnet)..."

                    $myvar_vm_nic0_config.subnet_reference.name = $myvar_subnet_details.spec.name #updating subnet name reference
                    $myvar_vm_nic0_config.subnet_reference.uuid = $myvar_subnet_details.metadata.uuid #updating subnet uuid reference
                    $myvar_vm_nic0_config.PSObject.Properties.Remove('uuid') #removing uuid (this is a new vnic after all)
                    $myvar_url = "https://{0}:{1}/api/nutanix/v3/vms/{2}" -f $prism,$myvar_api_server_port,$myvar_vm.metadata.uuid
                    $myvar_method = "GET"
                    $myvar_vm_payload_without_vnic0 = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials
                    $myvar_vm_payload_without_vnic0.PSObject.Properties.Remove('status') #removing status section from the vm payload
                    $myvar_vm_payload_without_vnic0.metadata.spec_version += 1 #increasing spec version
                    if ($dontkeepip)
                    {#remove the ip configuration
                        $myvar_vm_nic0_config.ip_endpoint_list = @()
                    }
                    $myvar_vm_payload_without_vnic0.spec.resources.nic_list += $myvar_vm_nic0_config #adding new vnic connected to vpc subnet
                    $myvar_method = "PUT"
                    $myvar_payload = (ConvertTo-Json $myvar_vm_payload_without_vnic0 -Depth 9)
                    $myvar_vm_update_task = Invoke-PrismAPICall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
                    
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully requested connection of vm $($myvar_vm.spec.name) to subnet $($vpc_subnet)!"
                    if (!$skiptaskstatuscheck)
                    {
                        $myvar_vm_update_task_status = Get-PrismCentralTaskStatus -task $myvar_vm_update_task.status.execution_context.task_uuid -credential $prismCredentials -cluster $prism
                    }
                }
            #endregion
        #endregion process vms
    }

    

#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(get-date) [SUM] total processing time: $($myvar_elapsed_time.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion