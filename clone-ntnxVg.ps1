<#
.SYNOPSIS
  This script can be used to clone a volume group attached to a source vm to a target vm.
.DESCRIPTION
  The script checks that the specified source and target VMs exist, then lists the volume groups available on the source VM and prompts the user to choose (assuming there is more than one vg, otherwise it just proceeds), clones the volume group (adding a timestamp to the cloned vg name) and direct attaches it to the target vg. It then displays the disk label of the newly attached volume group.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER sourcevm
  Name of the source virtual machine as displayed in Prism.
.PARAMETER targetvm
  Name of the target virtual machine as displayed in Prism.
.EXAMPLE
 .\clone-ntnxVg.ps1 -cluster ntnxc1.local -username admin -password admin -sourcevm sqlprod1 -targetvm sqldev1
Display a list of volume groups to clone from sqlprod1 to sqldev1 and proceed with the clone operation.
.LINK
  https://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: August 30th 2018
#>

#region parameters
######################################
##   parameters and initial setup   ##
######################################
#let's start with some command line parsing
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $true)] [string]$cluster,
	[parameter(mandatory = $true)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $true)] [string]$sourcevm,
    [parameter(mandatory = $true)] [string]$targetvm
)
#endregion

#region functions
########################
##   main functions   ##
########################
Function Write-LogOutput
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
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS')]
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
	    }

	    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
	    if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput

Function Write-Menu
{
	
<#
.SYNOPSIS
	Display custom menu in the PowerShell console.
.DESCRIPTION
	The Write-Menu cmdlet creates numbered and colored menues
	in the PS console window and returns the choiced entry.
.PARAMETER Menu
	Menu entries.
.PARAMETER PropertyToShow
	If your menu entries are objects and not the strings
	this is property to show as entry.
.PARAMETER Prompt
	User prompt at the end of the menu.
.PARAMETER Header
	Menu title (optional).
.PARAMETER Shift
	Quantity of <TAB> keys to shift the menu items right.
.PARAMETER TextColor
	Menu text color.
.PARAMETER HeaderColor
	Menu title color.
.PARAMETER AddExit
	Add 'Exit' as very last entry.
.EXAMPLE
	PS C:\> Write-Menu -Menu "Open","Close","Save" -AddExit -Shift 1
	Simple manual menu with 'Exit' entry and 'one-tab' shift.
.EXAMPLE
	PS C:\> Write-Menu -Menu (Get-ChildItem 'C:\Windows\') -Header "`t`t-- File list --`n" -Prompt 'Select any file'
	Folder content dynamic menu with the header and custom prompt.
.EXAMPLE
	PS C:\> Write-Menu -Menu (Get-Service) -Header ":: Services list ::`n" -Prompt 'Select any service' -PropertyToShow DisplayName
	Display local services menu with custom property 'DisplayName'.
.EXAMPLE
	PS C:\> Write-Menu -Menu (Get-Process |select *) -PropertyToShow ProcessName |fl
	Display full info about choicen process.
.INPUTS
	Any type of data (object(s), string(s), number(s), etc).
.OUTPUTS
	[The same type as input object] Single menu item.
.NOTES
	Author      :: Roman Gelman @rgelman75
	Version 1.0 :: 21-Apr-2016 :: [Release] :: Publicly available
	Version 1.1 :: 03-Nov-2016 :: [Change] :: Supports a single item as menu entry
	Version 1.2 :: 22-Jun-2017 :: [Change] :: Throws an error if property, specified by -PropertyToShow does not exist. Code optimization
	Version 1.3 :: 27-Sep-2017 :: [Bugfix] :: Fixed throwing an error while menu entries are numeric values
.LINK
	https://ps1code.com/2016/04/21/write-menu-powershell
#>
	
	[CmdletBinding()]
	[Alias("menu")]
	Param (
		[Parameter(Mandatory, Position = 0)]
		[Alias("MenuEntry", "List")]
		$Menu
		 ,
		[Parameter(Mandatory = $false, Position = 1)]
		[string]$PropertyToShow = 'Name'
		 ,
		[Parameter(Mandatory = $false, Position = 2)]
		[ValidateNotNullorEmpty()]
		[string]$Prompt = 'Pick a choice'
		 ,
		[Parameter(Mandatory = $false, Position = 3)]
		[Alias("Title")]
		[string]$Header = ''
		 ,
		[Parameter(Mandatory = $false, Position = 4)]
		[ValidateRange(0, 5)]
		[Alias("Tab", "MenuShift")]
		[int]$Shift = 0
		 ,
		[Parameter(Mandatory = $false, Position = 5)]
		[Alias("Color", "MenuColor")]
		[System.ConsoleColor]$TextColor = 'White'
		 ,
		[Parameter(Mandatory = $false, Position = 6)]
		[System.ConsoleColor]$HeaderColor = 'Yellow'
		 ,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Alias("Exit", "AllowExit")]
		[switch]$AddExit
	)
	
	Begin
	{
		$ErrorActionPreference = 'Stop'
		if ($Menu -isnot [array]) { $Menu = @($Menu) }
		if ($Menu[0] -is [psobject] -and $Menu[0] -isnot [string])
		{
			if (!($Menu | Get-Member -MemberType Property, NoteProperty -Name $PropertyToShow)) { Throw "Property [$PropertyToShow] does not exist" }
		}
		$MaxLength = if ($AddExit) { 8 }
		else { 9 }
		$AddZero = if ($Menu.Length -gt $MaxLength) { $true }
		else { $false }
		[hashtable]$htMenu = @{ }
	}
	Process
	{
		### Write menu header ###
		if ($Header -ne '') { Write-Host $Header -ForegroundColor $HeaderColor }
		
		### Create shift prefix ###
		if ($Shift -gt 0) { $Prefix = [string]"`t" * $Shift }
		
		### Build menu hash table ###
		for ($i = 1; $i -le $Menu.Length; $i++)
		{
			$Key = if ($AddZero)
			{
				$lz = if ($AddExit) { ([string]($Menu.Length + 1)).Length - ([string]$i).Length }
				else { ([string]$Menu.Length).Length - ([string]$i).Length }
				"0" * $lz + "$i"
			}
			else
			{
				"$i"
			}
			
			$htMenu.Add($Key, $Menu[$i - 1])
			
			if ($Menu[$i] -isnot 'string' -and ($Menu[$i - 1].$PropertyToShow))
			{
				Write-Host "$Prefix[$Key] $($Menu[$i - 1].$PropertyToShow)" -ForegroundColor $TextColor
			}
			else
			{
				Write-Host "$Prefix[$Key] $($Menu[$i - 1])" -ForegroundColor $TextColor
			}
		}
		
		### Add 'Exit' row ###
		if ($AddExit)
		{
			[string]$Key = $Menu.Length + 1
			$htMenu.Add($Key, "Exit")
			Write-Host "$Prefix[$Key] Exit" -ForegroundColor $TextColor
		}
		
		### Pick a choice ###
		Do
		{
			$Choice = Read-Host -Prompt $Prompt
			$KeyChoice = if ($AddZero)
			{
				$lz = if ($AddExit) { ([string]($Menu.Length + 1)).Length - $Choice.Length }
				else { ([string]$Menu.Length).Length - $Choice.Length }
				if ($lz -gt 0) { "0" * $lz + "$Choice" }
				else { $Choice }
			}
			else
			{
				$Choice
			}
		}
		Until ($htMenu.ContainsKey($KeyChoice))
	}
	End
	{
		return $htMenu.get_Item($KeyChoice)
	}
	
} #EndFunction Write-Menu

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
        $task
    )

    begin
    {}
    process 
    {
        #region get initial task details
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving details of task $task..."
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
            $method = "GET"
            $taskDetails = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved details of task $task"
        #endregion

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Sleep 5
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                $method = "GET"
                $taskDetails = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                
                if ($taskDetails.status -ne "running") 
                {
                    if ($taskDetails.status -ne "succeeded") 
                    {
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                        Exit
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) completed successfully!"
        } 
        else 
        {
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) completed successfully!"
        }
    }
    end
    {}
}
#endregion

#region prepwork
# get rid of annoying error messages
if (!$debugme) 
{
    $ErrorActionPreference = "SilentlyContinue"
}
if ($debugme) 
{
    $VerbosePreference = "Continue"
}

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/19/2015 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\clone-ntnxVg.ps1"
 
if ($help) 
{
    get-help $myvarScriptName
    exit
}
if ($History) 
{
    $HistoryText
    exit
}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) 
{
    throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"
}

#check if we have all the required PoSH modules
Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

#region module sbourdeaud is used for facilitating Prism REST calls
    if (!(Get-Module -Name sbourdeaud)) 
    {#module is not loaded
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Importing module 'sbourdeaud'..."
        try
        {#try loading the module
            Import-Module -Name sbourdeaud -ErrorAction Stop
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported module 'sbourdeaud'!"
        }
        catch 
        {#we couldn't import the module, so let's install it
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Installing module 'sbourdeaud' from the Powershell Gallery..."
            try 
            {#install
                Install-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
            }
            catch 
            {#couldn't install
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not install module 'sbourdeaud': $($_.Exception.Message)"
                Exit
            }

            try
            {#import
                Import-Module -Name sbourdeaud -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported module 'sbourdeaud'!"
            }
            catch 
            {#we couldn't import the module
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)"
                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Please download and install from https://www.powershellgallery.com/packages/sbourdeaud/1.1"
                Exit
            }
        }
    }#endif module sbourdeaud
    if (((Get-Module -Name sbourdeaud).Version.Major -le 2) -and ((Get-Module -Name sbourdeaud).Version.Minor -le 2)) 
    {
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Updating module 'sbourdeaud'..."
        try 
        {#update the module
            Update-Module -Name sbourdeaud -ErrorAction Stop
        }
        catch 
        {#couldn't update
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not update module 'sbourdeaud': $($_.Exception.Message)"
            Exit
        }
    }
#endregion

#region module BetterTls
    $result = Set-PoshTls
#endregion

#region get ready to use the Nutanix REST API
    #Accept self signed certs
    $code = @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    if (!(([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type))
    {#make sure the type isn't already there in order to avoid annoying error messages
        $result = add-type $code -ErrorAction SilentlyContinue
    }
    
    #we also need to use the proper encryption protocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol =  [System.Security.Authentication.SslProtocols] "tls12"

#endregion

#endregion

#region variables
#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

#endregion

#region parameters validation
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
    if (!$password) 
    {#if it was not passed as an argument, let's prompt for it
        $PrismSecurePassword = Read-Host "Enter the Prism admin user password" -AsSecureString
    }
    else 
    {#if it was passed as an argument, let's convert the string to a secure string and flush the memory
        $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
        Remove-Variable password
    }

    if ($sourcevm -eq $targetvm)
    {#source and target vm are the same
        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Source VM and target VM cannot be the same!"
        exit
    }
#endregion

#region processing	
	################################
	##  Main execution here       ##
	################################
    
    #region getting VMs
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of VMs..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
        $method = "GET"
        $vmList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved VMs list from $cluster!"
        
        if ($sourceVmObject = $vmList.entities | Where-Object {$_.Name -eq $sourcevm})
        {#checking source vm exists
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details of source vm $sourcevm with uuid $($sourceVmObject.uuid)"
        }
        else 
        {#source vm does not exist
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find source vm $sourcevm on $cluster!"    
            exit
        }

        if ($targetVmObject = $vmList.entities | Where-Object {$_.Name -eq $targetvm})
        {#checking target vm exists
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details of target vm $targetvm with uuid $($targetVmObject.uuid)"
        }
        else 
        {#target vm does not exist
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find target vm $targetvm on $cluster!"    
            exit
        }
    #endregion

    #region getting cluster information
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster basic information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $clusterInfo = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information from $cluster!"

        if ($clusterInfo.hypervisor_types -eq "kVmware")
        {#cluster is running ESXi
			Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Cluster $cluster is running VMware vSphere which is not compatible yet with this script!"
			Exit
        }

        if ($clusterInfo.hypervisor_types -eq "kKvm")
        {#cluster is running ESXi
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Cluster $cluster is running AHV"
		}
		else
		{
			Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "The hypervisor running on cluster $cluster is not compatible with this script (only AHV is supported at the moment)!"
			Exit
		}
    #endregion

    #region getting volume groups attached to source vm        
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster volume groups information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information cluster volume groups!"

        if ($sourceVmVgs = $vgInfo.entities | Where-Object {$_.attachment_list.vm_uuid -eq $sourceVmObject.uuid})
        {#found one or more volume group(s) attached to the source vm
            if ($sourceVmVgs -is [array])
            {#more than one vg attached
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found $($sourceVmVgs.count) volume groups attached to the source vm $sourcevm"
            }
            else 
            {#a single vg attached
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found a single volume group attached to the source vm $sourcevm"
            }
        }
        else
        {#could not find volume groups attached to the source vm
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There were no volume groups found attached to the source vm $sourcevm on cluster $cluster"
            exit
        }
    #endregion

    #region prompting user to select volume groups to clone (if more than one vg were found)
        if ($sourceVmVgs -is [array])
        {#more than one vg attached
            $userchoice = Write-Menu -Menu $sourceVmVgs -PropertyToShow Name -Prompt "Select a volume group to clone" -Header "Available Volume Groups" -TextColor Green -HeaderColor Green -Shift 1
		}
		else
		{#only one vg attached
			$userchoice = $sourceVmVgs
		}
    #endregion

    #region cloning volume group
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Cloning volume group $($userchoice.name) with uuid $($userchoice.uuid)..."
        $timestamp = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $vgCloneName = "$($userchoice.name)-$($timestamp)clone"
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($userchoice.uuid)/clone"
        $method = "POST"
        $content = @{
            name = $vgCloneName
        }
        $body = (ConvertTo-Json $content)
        $vgCloneTaskUuid = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started task to clone volume group $($userchoice.name) with uuid $($userchoice.uuid)!"

        Start-Sleep -Seconds 5
        Get-PrismTaskStatus -Task $vgCloneTaskUuid.task_uuid
    #endregion
    
    #region retrieving details about the cloned vg
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving cluster volume groups information..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/?include_disk_size=true"
        $method = "GET"
        $vgInfo = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved information cluster volume groups!"

        if ($clonedVg = $vgInfo.entities | Where-Object {$_.name -eq $vgCloneName})
        {#found our cloned vg
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Found $($clonedVg.name) with uuid $($clonedVg.uuid)"
        }
        else
        {#could not find our cloned vg
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not find volume group $vgCloneName on cluster $cluster"
            exit
        }
    #endregion

    #region attaching volume groups to target vm
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Attaching volume group $($clonedVg.name) with uuid $($clonedVg.uuid) to vm $targetVm with uuid $($targetVmObject.uuid)..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/volume_groups/$($clonedVg.uuid)/attach"
        $method = "POST"
        $content = @{
            operation = "ATTACH"
            vm_uuid = $($targetVmObject.uuid)
        }
        $body = (ConvertTo-Json $content)
        $vgAttachTaskUuid = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started task to attach volume group $($clonedVg.name) to vm $targetVm!"

        Start-Sleep -Seconds 5
        Get-PrismTaskStatus -Task $vgAttachTaskUuid.task_uuid
    #endregion

    #region retrieving new details of target vm
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving new details of vm $targetVm..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($targetVmObject.uuid)?include_vm_disk_config=true"
        $method = "GET"
        $newTargetVmObject = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved new details of vm $targetVm!"

        $disk_label = $newTargetVmObject.vm_disk_info.disk_address | Where-Object {$_.volume_group_uuid -eq $($clonedVg.uuid)}
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Volume group $($clonedVg.name) has been attached to $targetVm as disk $($disk_label.disk_label)"
        
    #endregion

#endregion

#region cleanup
#########################
##       cleanup       ##
#########################

	#let's figure out how much time this all took
	Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar* -ErrorAction SilentlyContinue
	Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
	Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
	Remove-Variable log -ErrorAction SilentlyContinue
	Remove-Variable cluster -ErrorAction SilentlyContinue
	Remove-Variable username -ErrorAction SilentlyContinue
	Remove-Variable password -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion