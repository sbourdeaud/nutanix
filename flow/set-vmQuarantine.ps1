<#
.SYNOPSIS
  This script can be used to move or remove a virtual machine in strict or forensics quarantine.
.DESCRIPTION
  Given a Prism Central instance and a virtual machine name, move or remove that virtual machine to/from quarantine in Prism Central.
.PARAMETER prism
  IP address or FQDN of Prism Central.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vm
  Name of the virtual machine to move to quarantine (as displayed in Prism Central). You can use a comman separated list.
.PARAMETER action
  Can be move or remove (to/from quarantine).
.PARAMETER type
  Can be strict or forensic (for the quarantine).
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.EXAMPLE
.\set-vmQuarantine.ps1 -prism 10.10.10.1 -prismCreds myuser -vm myvm -action move -type forensics
Move myvm to forensics quarantine.
.LINK
  http://www.nutanix.com/services
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 29th 2026
#>

#region Parameters
  Param
  (
      #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
      [parameter(mandatory = $false)] [switch]$help,
      [parameter(mandatory = $false)] [switch]$history,
      [parameter(mandatory = $false)] [switch]$debugme,
      [parameter(mandatory = $false)] [string]$prism,
      [parameter(mandatory = $false)] $prismCreds,
      [parameter(mandatory = $false)] [string]$vm,
      [parameter(mandatory = $true)] [ValidateSet("move","remove")] [string]$action,
      [parameter(mandatory = $false)] [ValidateSet("strict","forensics")] [string]$type
  )
#endregion

#region helper functions (previously from sbourdeaud module)
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
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            # PowerShell 7+ already defaults to TLS 1.2+; Invoke-PrismAPICall also sets -SslProtocol Tls12
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

function Get-PrismCentralTaskStatus
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
                Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) status is $($taskDetails.status): $($taskDetails.progress_message) $($taskDetails.error_detail)" -ForegroundColor Yellow
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
                "SimpleThin"    { $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = "-"; Break }
                "SimpleThick1"  { $GreenChar = [char]9608; $YellowChar = [char]9608; $RedChar = [char]9608; $EmptyChar = "-"; Break }
                "SimpleThick2"  { $GreenChar = [char]9612; $YellowChar = [char]9612; $RedChar = [char]9612; $EmptyChar = "-"; Break }
                "AdvancedThin1" { $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = [char]9476; Break }
                "AdvancedThin2" { $GreenChar = [char]9642; $YellowChar = [char]9642; $RedChar = [char]9642; $EmptyChar = [char]9643; Break }
                "AdvancedThick" { $GreenChar = [char]9617; $YellowChar = [char]9618; $RedChar = [char]9619; $EmptyChar = [char]9482; Break }
            }
            $Properties = [ordered]@{
                Char1 = $GreenChar
                Char2 = $YellowChar
                Char3 = $RedChar
                Char4 = $EmptyChar
            }
            $Object = New-Object PSObject -Property $Properties
            $Object
        }
        
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
#endregion

#region prep-work
  #check if we need to display help and/or history
  $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter and Write-LogOutput/LoadModule/CheckModule functions
11/10/2022 sb   Initial release.
################################################################################
'
  $myvarScriptName = ".\set-vmQuarantine.ps1"
  if ($help) {get-help $myvarScriptName; exit}
  if ($History) {$HistoryText; exit}

  Set-PoSHSSLCerts
  Set-PoshTls

#endregion

#region variables
  #initialize variables
  #misc variables
  $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
  
  $api_server_port = "9440"
  $api_server = $prism
    
  #let's initialize parameters if they haven't been specified
  if (!$prism) {$prism = read-host "Enter the hostname or IP address of Prism Central"}
  if ((!$vm) -and !($sourcecsv)) {$vm = read-host "Enter the virtual machine name"}
  $myvarListToProcess = $vm.Split(",")
  if (($action -ieq "move") -and !$action)
  {
    Write-Host "$(Get-Date) [ERROR] You must specify a quarantine type (strict or forensics) when using action move!" -ForegroundColor Red
    exit 1
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
    $vm = $item
    $category = "Quarantine"
    if ($type -ieq "strict")
    {
      $value = "Default"
    }
    elseif ($type -ieq "forensics") 
    {
      $value = "Forensics"
    }

    #* step 1: retrieve vm details
    #region retrieve the vm details

      #region prepare api call
        $api_server_endpoint = "/api/nutanix/v3/vms/list"
        $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
            $api_server_endpoint
        $method = "POST"
        $content = @{
            filter= "vm_name==$($vm)";
            kind= "vm"
        }
        $payload = (ConvertTo-Json $content -Depth 4)
      #endregion

      #region make the api call
        Write-Host "$(Get-Date) [INFO] Retrieving the configuration of vm $vm from $prism..." -ForegroundColor Green
        try {
          $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
          if ($resp.metadata.total_matches -eq 0) {
              Write-Host "$(get-date) [WARNING] VM $vm was not found on $prism" -ForegroundColor Yellow
              Continue
          }
          elseif ($resp.metadata.total_matches -gt 1) {
            Write-Host "$(get-date) [WARNING] There are multiple VMs matching name $vm on $prism" -ForegroundColor Yellow
            Continue
          }
          $vm_config = $resp.entities[0]
          $vm_uuid = $vm_config.metadata.uuid
          Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved the configuration of vm $vm from $prism" -ForegroundColor Cyan
        }
        catch {
          $saved_error = $_.Exception.Message
          Write-Host "$(get-date) [WARNING] $saved_error" -ForegroundColor Yellow
          Continue
        }
        finally {
        }

        #todo: if action is remove, we need to figure out the type of quarantine this vm was in and assign that to value
      #endregion

    #endregion

    #* step 2: prepare the json payload
    #region prepare the json payload
      $vm_config.PSObject.Properties.Remove('status')
    #endregion

    #* step 3: process action move
    #region process action move
      if ($action -ieq "move") {
        try {
          $myvarNull = $vm_config.metadata.categories_mapping | Add-Member -MemberType NoteProperty -Name $category -Value @($value) -PassThru -ErrorAction Stop
          $myvarNull = $vm_config | Add-Member -MemberType NoteProperty -Name "api_version" -Value "3.1" -PassThru -ErrorAction Stop
          $myvarNull = $vm_config.metadata | Add-Member -MemberType NoteProperty -Name "use_categories_mapping" -Value $true -PassThru -ErrorAction Stop
        }
        catch {
          Write-Host "$(Get-Date) [WARNING] Could not add category:value pair ($($category):$($value)). It may already be assigned to the vm $vm in $prism" -ForegroundColor Yellow
          $myvar_already_tagged = $true
          continue
        }
      }
    #endregion

    #* step 4: process action remove
    #region process action remove
      if ($action -ieq "remove") {
        #todo match the exact value pair here as a category could have multiple values assigned
        $myvarNull = $vm_config | Add-Member -MemberType NoteProperty -Name "api_version" -Value "3.1" -PassThru -ErrorAction Stop
        $myvarNull = $vm_config.metadata | Add-Member -MemberType NoteProperty -Name "use_categories_mapping" -Value $true -PassThru -ErrorAction Stop
        $myvarNull = $vm_config.metadata.categories_mapping.PSObject.Properties.Remove($category)
      }
    #endregion

    #* step 5: update the vm object
    #region update vm
      if (!$myvar_already_tagged)
      {
        #region prepare api call
          $api_server_endpoint = "/api/nutanix/v3/vms/{0}" -f $vm_uuid
          $url = "https://{0}:{1}{2}" -f $api_server,$api_server_port, `
              $api_server_endpoint
          $method = "PUT"

          $payload = (ConvertTo-Json $vm_config -Depth 6)
        #endregion

        #region make the api call
          Write-Host "$(Get-Date) [INFO] Updating the configuration of vm $($vm) uuid $($vm_uuid) entity version $($vm_config.metadata.entity_version) with spec version $($vm_config.metadata.spec_version) in $($prism)..." -ForegroundColor Green
          do {
            try {
              $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
              $task_status = Get-PrismCentralTaskStatus -Task $resp.status.execution_context.task_uuid -cluster $prism -credential $prismCredentials
              if ($task_status -ine "failed") 
              {
                Write-Host "$(Get-Date) [SUCCESS] Successfully updated the configuration of vm $vm from $prism" -ForegroundColor Cyan
                $resp_return_code = 200
              }
              else 
              {
                Write-Host "$(Get-Date) [ERROR] Could not update quarantine status for $($vm) on $($prism)" -ForegroundColor Red
                exit 1
              }
            }
            catch {
              $saved_error = $_.Exception
              $resp_return_code = $_.Exception.Response.StatusCode.value__
              if ($resp_return_code -eq 409) {
                Write-Host "$(Get-Date) [WARNING] VM $vm cannot be updated now. Retrying in 5 seconds..." -ForegroundColor Yellow
                sleep 5
              }
              else {
                Write-Host $payload -ForegroundColor White
                Write-Host "$(get-date) [WARNING] $($resp.status) $($saved_error.Message)" -ForegroundColor Yellow
                Break
              }
            }
            finally {
            }
          } while ($resp_return_code -eq 409)
        #endregion
      }

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
  Remove-Variable debugme -ErrorAction SilentlyContinue
  Remove-Variable prism -ErrorAction SilentlyContinue
  Remove-Variable prismCreds -ErrorAction SilentlyContinue
  Remove-Variable vm -ErrorAction SilentlyContinue
  Remove-Variable action -ErrorAction SilentlyContinue
  Remove-Variable type -ErrorAction SilentlyContinue
#endregion