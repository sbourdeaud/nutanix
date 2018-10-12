<#
.SYNOPSIS
  This script can be used to automate the failover (planned or unplanned) of Nutanix asynchronous or near-sync protection domains.
.DESCRIPTION
  This script can be used to automate the failover (planned or unplanned) of Nutanix asynchronous or near-sync protection domains.
  The script has three main workflows: (1)planned failover (migrate), (2)unplanned failover (activate) and (3)deactivate.

  A planned failover will (migrate):
    (1)Initiate migrate on the matching protection domains on the source Nutanix cluster, which will shutdown all the VMs and replicate them to the target site
    (2)Optionally, start VMs on the target cluster.
  
  An unplanned failover (activate) will:
    (1)Activate the specified protection domains on the target Nutanix cluster
    (2)Optionally, start VMs on the target cluster.

  Deactivate will:
    (1)Disable the matching protection domains on the source Nutanix cluster, which will:
    (2) DELETE ALL VMs on that cluster
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER migrate
  Specifies you want to trigger a planned failover workflow.  See the script description for more information.
.PARAMETER activate
  Specifies you want to trigger an unplanned failover workflow.  See the script description for more information.
.PARAMETER deactivate
  Specifies you want to disable a protection domain and DELETE ALL VMs on that cluster that belong to that protection domain.  See the script description for more information.
.PARAMETER pd
  Lets you specify which protection domain(s) you want to failover. If left blank, all applicable protection domains will be processed.
.PARAMETER prismCreds
  Specifies a custom credentials file name for Prism authentication (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt).
.PARAMETER powerOnVms
  Specifies you want VMs to power on after failover.
.EXAMPLE
.\Invoke-AsyncDr.ps1 -cluster <ip> -migrate -prismCreds prism_api-user -pd <protection domain name>
Trigger a planned failover workflow for the specified protection domain. Use the previously stored credentials in the %USERPROFILE%\Documents\WindowsPowerShell\Credentials\prism_api-user.txt file (use the Set-CustomCredentials function in the sbourdeaud module to create the credentials file).
.EXAMPLE
.\Invoke-AsyncDr.ps1 -cluster <ip> -activate -username admin -password <secret>
Trigger an uplanned failover for all protection domains.
.EXAMPLE
.\Invoke-AsyncDr.ps1 -cluster <ip> -deactivate -username admin -password <secret> -pd <protection domain name>
Disable the specified protection domain and delete VMs.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 5th 2018
  Version: 0.1
#>

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [switch]$migrate,
    [parameter(mandatory = $false)] [switch]$activate,
    [parameter(mandatory = $false)] [switch]$deactivate,
    [parameter(mandatory = $false)] [string]$cluster,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $pd, #don't specify type as this is sometimes a string, sometimes an array in the script
    [parameter(mandatory = $false)] $prismCreds, #don't specify type as this is sometimes a string, sometimes secure credentials
    [parameter(mandatory = $false)] [switch]$powerOnVms
)
#endregion

#TODO: add check n hypervisor at target: if vSphere, check if portgroup is on a dvswitch, if so, then reconnect vnics.

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

    function New-PercentageBar
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
    function Get-PrismTaskStatus
    {
        <#
        .SYNOPSIS
        Retrieves the status of a given task uuid from Prism and loops until it is completed.

        .DESCRIPTION
        Retrieves the status of a given task uuid from Prism and loops until it is completed.

        .PARAMETER task
        Prism task uuid.
        .PARAMETER cluster
        Prism IP or fqdn.
        .PARAMETER username
        Prism username.
        .PARAMETER password
        Prism password (as a secure string).

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Get-PrismTaskStatus -Task $task -Cluster $cluster -Username $username -Password $SecureString
        Prints progress on task $task until successfull completion. If the task fails, print the status and error code and details and exits.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param
        (
            [Parameter(Mandatory)]
            [String]
            $task,
            
            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

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
                    Start-Sleep 5
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                    $method = "GET"
                    $taskDetails = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                    
                    if ($taskDetails.progress_status -ne "Running") 
                    {
                        if ($taskDetails.progress_status -ne "Succeeded")
                        {
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                            $userChoice = Write-CustomPrompt
                            if ($userChoice -eq "n")
                            {
                                Exit
                            }
                        }
                    }
                }
                While ($taskDetails.percentage_complete -ne "100")
                
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) completed successfully!"
            } 
            else 
            {
                if ($taskDetails.progress_status -ne "Succeeded")
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                    $userChoice = Write-CustomPrompt
                    if ($userChoice -eq "n")
                    {
                        Exit
                    }
                }
                else 
                {
                    New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Task $($taskDetails.meta_request.method_name) completed successfully!"   
                }
            }
        }
        
        end
        {

        }
    }

    function Get-PrismPdTaskStatus
    {
        <#
        .SYNOPSIS
        Retrieves the status of all protection domain deactivation tasks created after a specific time.

        .DESCRIPTION
        Retrieves the status of all protection domain deactivation tasks created after a specific time.

        .PARAMETER time
        Time in epoch seconds.
        .PARAMETER cluster
        Prism IP or fqdn.
        .PARAMETER username
        Prism username.
        .PARAMETER password
        Prism password (as a secure string).

        .NOTES
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

        .EXAMPLE
        .\Get-PrismTaskStatus -Task $task -Cluster $cluster -Username $username -Password $SecureString
        Prints progress on task $task until successfull completion. If the task fails, print the status and error code and details and exits.

        .LINK
        https://github.com/sbourdeaud
        #>
        [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

        param
        (
            [Parameter(Mandatory)]
            $time,
            
            [Parameter(Mandatory)]
            [String]
            [ValidateSet('activate','deactivate')]
            $operation,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process 
        {
            Write-Host ""
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving list of tasks on the cluster $cluster ..."
            Start-Sleep 10
            
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
            $method = "GET"
            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Retrieved list of tasks on the cluster $cluster"
            
            Do
            {
                $pdTasks = $response.entities | Where-Object {$_.operation -eq $operation} | Where-Object {($_.createTimeUsecs / 1000000) -ge $time}
            }
            While (!$pdTasks)

            #let's loop now until the task status is completed and successfull. If a task fails, we'll throw an exception.
            ForEach ($pdTask in $pdTasks) 
            {
                if ($pdTask.percentageCompleted -ne "100") 
                {
                    Do 
                    {
                        Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Waiting 5 seconds for task $($pdTask.taskName) to complete : $($pdTask.percentageCompleted)%"
                        Start-Sleep 5
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                        $method = "GET"
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        $task = $response.entities | Where-Object {$_.taskName -eq $pdTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                        if ($task.status -ne "running") 
                        {#task is no longer running
                            if ($task.status -ne "succeeded") 
                            {#task failed
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Task $($pdTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)"
                                Exit
                            }
                        }
                    }
                    While ($task.percentageCompleted -ne "100")
                    
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Protection domain migration task $($pdTask.taskName) completed on the cluster $cluster"
                    Write-Host ""
                } 
                else 
                {
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Protection domain migration task $($pdTask.taskName) completed on the cluster $cluster"
                    Write-Host ""
                }
            }
        }
        
        end
        {

        }
    }

    function Invoke-NtnxPdMigration
    {
        <#
        .SYNOPSIS
        Triggers an asynchronous protection domain migration.
        .DESCRIPTION
        Triggers an asynchronous protection domain migration which (1)shuts down VMs, (2)syncs data with the remote site defined in its schedule, (3)unregisters VMs at the source and (4)registers VM on the remote site.
        .NOTES
        Author: Stephane Bourdeaud
        .PARAMETER pd
        Asynchronous protection domain name.
        .PARAMETER cluster
        FQDN or IP of Nutanix cluster.
        .PARAMETER username
        Nutanix cluster API username.
        .PARAMETER password
        Nutanix cluster API password (passed as a secure string).
        .EXAMPLE
        Invoke-NtnxPdMigration -pd <pd_name> -cluster ntnx1.local -username api-user -password $secret
        #>
        [CmdletBinding()]
        param
        (
            $pd,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password            
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process
        { 
            #region get data
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                if (!$pd) 
                {#no pd specified
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name
                } 
                else 
                {#fetch specified pd
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
                }

                if (!$pd) 
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $cluster!"
                    Exit
                }
            #endregion

            #region process
                #now let's call the migrate workflow
                ForEach ($pd2migrate in $pd) 
                {
                    #figure out if there is more than one remote site defined for the protection domain
                    $remoteSite = $PdList.entities | Where-Object {$_.name -eq $pd2migrate} | Select-Object -Property remote_site_names
                    if (!$remoteSite.remote_site_names) 
                    {#no remote site defined or no schedule on the pd with a remote site
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no remote site defined for protection domain $pd2migrate"
                        Exit
                    }
                    if ($remoteSite -is [array]) 
                    {#more than 1 remote site target defined on the pd schedule
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one remote site for protection domain $pd2migrate"
                        Exit
                    }

                    #region migrate the protection domain
                        Write-Host ""
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Migrating $pd2migrate to $($remoteSite.remote_site_names) ..."
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                        $method = "POST"
                        $content = @{
                                        value = $($remoteSite.remote_site_names)
                                    }
                        $body = (ConvertTo-Json $content -Depth 4)
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                        if ($debugme) {Write-LogOutput -Category "DEBUG" -LogFile $myvarOutputLogFile -Message "Migration request response is: $($response.metadata)"}
                        if ($response.metadata.count -ne 0)
                        {#something went wrong with our migration request
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not start migration of $pd2migrate to $($remoteSite.remote_site_names). Try to trigger it manually in Prism and see why it won't work."
                            Exit
                        }
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)"
                    #endregion

                }
            #endregion
        }

        end
        {
           return $pd #list of protection domains which were processed 
        }
    }

    function Invoke-NtnxPdActivation
    {
        <#
        .SYNOPSIS
        Activates a Nutanix asynchronous protection domain (as part of an unplanned failover).
        .DESCRIPTION
        Activates a Nutanix asynchronous protection domain (as part of an unplanned failover), which will register VMs on the Nutanix cluster.
        .NOTES
        Author: Stephane Bourdeaud
        .PARAMETER pd
        Asynchronous protection domain name.
        .PARAMETER cluster
        FQDN or IP of Nutanix cluster.
        .PARAMETER username
        Nutanix cluster API username.
        .PARAMETER password
        Nutanix cluster API password (passed as a secure string).
        .EXAMPLE
        Invoke-NtnxPdActivation -pd <pd_name> -cluster ntnx1.local -username api-user -password $secret
        #>
        [CmdletBinding()]
        param
        (
            $pd,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process
        {            
            #region get data
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                if (!$pd) 
                {#no pd specified
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name
                } 
                else 
                {#fetch specified pd
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $false} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
                }

                if (!$pd) 
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $cluster!"
                    Exit
                }
            #endregion

            #now let's call the activate workflow
            ForEach ($pd2activate in $pd) 
            {#activate each pd
                #region activate the protection domain
                    Write-Host ""
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Activating protection domain $($pd2activate) on $cluster ..."
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate)/activate"
                    $method = "POST"
                    $content = @{}
                    $body = (ConvertTo-Json $content -Depth 4)
                    $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully activated protection domain $($pd2activate) on $cluster"
                #endregion    
            }
        }

        end
        {
            return $pd #list of protection domains which were processed
        }
    }

    function Invoke-NtnxPdDeactivation
    {
        <#
        .SYNOPSIS
        Deactivates a Nutanix asynchronous protection domain (and !!!DELETES ALL VMS IN THAT PROTECTION DOMAIN!!!).
        .DESCRIPTION
        Deactivates a Nutanix asynchronous protection domain which will (1)change the status of the protection domain to inactive and (2)!!!DELETE ALL VMS IN THAT PD!!!
        .NOTES
        Author: Stephane Bourdeaud
        .PARAMETER pd
        Asynchronous protection domain name.
        .PARAMETER cluster
        FQDN or IP of Nutanix cluster.
        .PARAMETER username
        Nutanix cluster API username.
        .PARAMETER password
        Nutanix cluster API password (passed as a secure string).
        .EXAMPLE
        Invoke-NtnxPdDeactivation -pd <pd_name> -cluster ntnx1.local -username api-user -password $secret
        #>
        [CmdletBinding()]
        param
        (
            $pd,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process
        {
            #region get data
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #first, we need to figure out which protection domains need to be deactivated. If none have been specified, we'll assume all of them which are active.
                if (!$pd) 
                {#no pd specified
                    $pd = Read-Host "Enter the name of the protection domain(s) you want to deactivate on $cluster. !!!WARNING!!! All VMs in that protection domain will be deleted!"
                    $pd = $pd.Split(",") #make sure we process protection_domains as an array
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
                } 
                else 
                {#fetch specified pd
                    $pd = ($PdList.entities | Where-Object {$_.active -eq $true} | Select-Object -Property name).name | Where-Object {$pd -contains $_}
                }

                if (!$pd) 
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $cluster!"
                    Exit
                }
            #endregion

            #region process
                ForEach ($pd2deactivate in $pd) 
                {#now let's call the deactivate workflow for each pd
                    Write-Host ""
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Deactivating protection domain $pd2deactivate on $cluster ..."
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
                    $method = "POST"
                    $content = @{}
                    $body = (ConvertTo-Json $content -Depth 4)
                    $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully started deactivation of protection domain $pd2deactivate on $cluster"
                }
            #endregion
        }

        end
        {
            return $response #this is the task uuid as sent back from the API
        }
    }

    function Set-NtnxPdVmPowerOn
    {
        <#
        .SYNOPSIS
        Powers on all VMs in a given protection domain.
        .DESCRIPTION
        Powers on all VMs in a given protection domain (meant to be called after a failover).
        .NOTES
        Author: Stephane Bourdeaud
        .PARAMETER pd
        Asynchronous protection domain name.
        .PARAMETER cluster
        FQDN or IP of Nutanix cluster.
        .PARAMETER username
        Nutanix cluster API username.
        .PARAMETER password
        Nutanix cluster API password (passed as a secure string).
        .EXAMPLE
        Set-NtnxPdVmPowerOn -pd <pd_name> -cluster ntnx1.local -username api-user -password $secret
        #>
        [CmdletBinding()]
        param
        (
            $pd,

            [Parameter(Mandatory)]
            [String]
            $cluster,
            
            [Parameter(Mandatory)]
            [String]
            $username,
            
            [Parameter(Mandatory)]
            [SecureString]
            $password
        )

        begin
        {
            $PrismSecurePassword = $password #some of the code included here was imported from other scripts where this was the name of the variable used for password.
        }

        process
        {
            #region get data
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #first, we need to figure out which protection domains need to be failed over. If none have been specified, we'll assume all of them which are active.
                if (!$pd) 
                {#no pd specified
                    $pd = Read-Host "Enter the name of the protection domain(s) you want to process on $cluster."
                    $pd = $pd.Split(",") #make sure we process protection_domains as an array
                    $pd = $PdList.entities | Where-Object {$_.active -eq $active} | Where-Object {$pd -contains $_.name}
                } 
                else 
                {#fetch specified pd
                    $pd = $PdList.entities | Where-Object {$_.active -eq $true} | Where-Object {$pd -contains $_.name}
                }

                if (!$pd) 
                {
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There are no protection domains in the correct status on $cluster!"
                    Exit
                }
            #endregion
            
            Write-Host "$($pd.vms)" -ForegroundColor Red

            #region process
                ForEach ($protection_domain in $pd)
                {
                    ForEach ($vm in $protection_domain.vms)
                    {
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Powering on VM $($vm.vm_name) on $cluster ..."
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/$($vm.vm_id)/set_power_state"
                        $method = "POST"
                        $content = @{
                            transition = "ON"
                            uuid = $vm.vm_id
                        }
                        $body = (ConvertTo-Json $content -Depth 4)
                        $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) -body $body
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully created task to power on VM $($vm.vm_name) on $cluster"
                        
                        Get-PrismTaskStatus -task $response.task_uuid -cluster $cluster -username $username -password $PrismSecurePassword
                    }
                }
            #endregion
        }

        end
        {

        }
    }

#endregion

#region prepare

    #region set variables
        $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
        $StartEpochSeconds = Get-Date (Get-Date).ToUniversalTime() -UFormat %s #used to get tasks generated in Prism after the script was invoked
        $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
        $myvarOutputLogFile += "Invoke-AsyncDr_OutputLog.log"
        $remote_site_ips = @() #initialize array here to collect remote site ips
    #endregion

    Write-Host ""
    Write-LogOutput -Category "STEP" -LogFile $myvarOutputLogFile -Message "--Preparing--"

    #check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 10/08/2018 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\Invoke-AsyncDr.ps1"

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

    #region parameter validation
        if (($activate -and $migrate) -or ($activate -and $deactivate) -or ($migrate -and $deactivate))
        {#multiple actions
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You can only use -activate OR -deactivate OR -migrate. Don't try to combine them together."
            Exit
        }

        if ($deactivate -and $powerOnVms)
        {#invalid power on request
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You have used -powerOnVms and -deactivate together which is not a valid combination."
            Exit
        }

        if (!$activate -and !$migrate -and !$deactivate)
        {#no action specified
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "You must specify an action: -migrate, -activate or -deactivate."
            Exit
        }

        if (!$prismCreds) 
        {#no stored creds
            if (!$username) 
            {#no username specified
                $username = Read-Host "Enter the Prism user"
            } 

            if (!$password) #if it was not passed as an argument, let's prompt for it
            {#no password specified
                $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
            }
            else 
            {#if it was passed as an argument, let's convert the string to a secure string and flush the memory
                $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
                Remove-Variable password
            }
        } 
        else 
        {#stored creds were used
            $prismCredentials = Get-CustomCredentials -credname $prismCreds
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }

    #endregion

    #region modules
        #check if we have all the required PoSH modules
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

        #TODO: insert here PoSH version check

        #TODO: review this code region for errors
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
                    Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
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
    #endregion

#endregion

#region processing
    
    #region get stuff we'll need regardless
        
        #get cluster information
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving details of Nutanix cluster $cluster ..."
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
        $method = "GET"
        $cluster_details = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details of Nutanix cluster $cluster"

        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Hypervisor on Nutanix cluster $cluster is of type $($cluster_details.hypervisor_types)."

    #endregion

    #region migrate
        if ($migrate)
        {   
            Write-Host ""
            Write-LogOutput -Category "STEP" -LogFile $myvarOutputLogFile -Message "--Triggering protection domain migration workflow--"

            #get vms and networks if AHV (for later when we will try to reconnect to dvportgroups)
            if ($cluster_details.hypervisor_types -eq "kKvm")
            {
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving Vm details on Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true&include_vm_nic_config=true"
                $method = "GET"
                $cluster_vms = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved VM details on Nutanix cluster $cluster"

                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving networks on Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/networks/"
                $method = "GET"
                $cluster_networks = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved networks on Nutanix cluster $cluster"
            }

            $processed_pds = Invoke-NtnxPdMigration -pd $pd -cluster $cluster -username $username -password $PrismSecurePassword
            if ($debugme) {Write-LogOutput -Category "DEBUG" -LogFile $myvarOutputLogFile -Message "Processed pds: $processed_pds"}
            Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $cluster -username $username -password $PrismSecurePassword -operation "deactivate"
            
            #region check remote
                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                ForEach ($protection_domain in $processed_pds)
                {#figure out the remote site ips
                    #region figure out the remote site
                        #figure out if there is more than one remote site defined for the protection domain
                        $remoteSite = $PdList.entities | Where-Object {$_.name -eq $protection_domain} | Select-Object -Property remote_site_names
                        if (!$remoteSite.remote_site_names) 
                        {#no remote site defined or no schedule on the pd with a remote site
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no remote site defined for protection domain $protection_domain"
                            Exit
                        }
                        if ($remoteSite -is [array]) 
                        {#more than 1 remote site target defined on the pd schedule
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one remote site for protection domain $protection_domain"
                            Exit
                        }

                        #get the remote site IP address
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving details about remote site $($remoteSite.remote_site_names) ..."
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/remote_sites/$($remoteSite.remote_site_names)"
                        $method = "GET"
                        $remote_site = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details about remote site $($remoteSite.remote_site_names)"

                        if ($remote_site.remote_ip_ports.psobject.properties.count -gt 1)
                        {#there are multiple IPs defined for the remote site
                            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than 1 IP configured for the remote site $remoteSite"
                            Exit
                        }
                    #endregion
                    
                    if ($remote_site_ips -notcontains $remote_site.remote_ip_ports.psobject.properties.name)
                    {#we haven't had that remote site yet
                        $remote_site_ips += $remote_site.remote_ip_ports.psobject.properties.name #add remote site ip to an array here
                    }
                    
                }

                ForEach ($remote_site_ip in $remote_site_ips)
                {#check the protection domains have been successfully activated on each remote site
                    Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $remote_site_ip -username $username -password $PrismSecurePassword -operation "activate"
                }
            #endregion
        }
    #endregion

    #region activate
        if ($activate)
        {
            Write-Host ""
            Write-LogOutput -Category "STEP" -LogFile $myvarOutputLogFile -Message "--Triggering protection domain activation workflow--"
            $processed_pds = Invoke-NtnxPdActivation -pd $pd -cluster $cluster -username $username -password $PrismSecurePassword
            if ($debugme) {Write-LogOutput -Category "DEBUG" -LogFile $myvarOutputLogFile -Message "Processed pds: $processed_pds"}
            Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $cluster -username $username -password $PrismSecurePassword -operation "activate"
        }
    #endregion

    #region reconnect vnics to dvportgroups (vSphere only): applies only to migrate & activate. If migrate, figure out remote site ips, otherwise, use cluster
        if ($migrate -or $activate)
        {#we are either in the activate or migrate workflow
            $clusters = @()
            if ($activate)
            {#we are in the activating workflow
                $clusters += $cluster
            }
            else 
            {#we are in the migrate workflow
                $clusters = $remote_site_ips
            }

            ForEach ($prism in $clusters)
            {#check the protection domains have been successfully activated on each remote site
                #get cluster information
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving details of Nutanix cluster $prism ..."
                $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/cluster/"
                $method = "GET"
                $prism_details = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details of Nutanix cluster $prism"

                if ($prism.hypervisor_types -contains "kVMware")
                {#we have a vsphere cluster
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Nutanix cluster $prism is running VMware vSphere..."
                    
                    if ($debugme) {Write-LogOutput -Category "DEBUG" -LogFile $myvarOutputLogFile -Message "$prism.management_servers.count is $($prism.management_servers.count)"}
                    
                    if ($prism.management_servers.count -eq 1)
                    {#let's grab our vCenter IP
                        $vCenter_ip = $prism.management_servers.ip_address
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Nutanix cluster $prism is managed by vCenter server $vCenter_ip ..."
                        
                        #region load powercli
                            if (!(Get-Module VMware.PowerCLI)) 
                            {#module isn't loaded
                                try 
                                {#load powercli
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Loading VMware.PowerCLI module..."
                                    Import-Module VMware.PowerCLI -ErrorAction Stop
                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Loaded VMware.PowerCLI module"
                                }
                                catch 
                                {#couldn't load powercli
                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not load VMware.PowerCLI module! We can't check for dvPortGroups!"
                                    Exit
                                }
                            }

                            try 
                            {#configure ssl
                                $result = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction Stop
                            }
                            catch 
                            {#couldn't configure ssl
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not change the VMware.PowerCLI module configuration to accept self-signed certificates: $($_.Exception.Message)"
                                exit
                            }
                        #endregion

                        #region connect to vCenter
                            try 
                            {#connect to vCenter
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting to vCenter server $vcenter_ip ..."
                                $vCenter_Connect = Connect-VIServer -Server $vcenter_ip -ErrorAction Stop
                            }
                            catch 
                            {#couldn't connect to vCenter
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect to vCenter server $vcenter_ip : $($_.Exception.Message)"
                                Exit
                            }
                        #endregion

                        #region figure out which protection domains to process on this specific remote site
                            
                            #step 1: retrieve protection domains on this remote site
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $prism ..."
                            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                            $method = "GET"
                            $prism_PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $prism"
                            
                            #step 2: compare list of active protection domains on this remote site with the list of processed protection domains returned by the activate or migrate workflow in $processed_pds
                            $prism_processed_pds = $prism_PdList.entities | Where-Object {$processed_pds -contains $_.name} | Where-Object {$_.active -eq $true}
                            if ($debugme) {Write-LogOutput -LogFile $myvarOutputLogFile -Category "DEBUG" -Message "List of active protection domains which were processed on this site: $prism_processed_pds"}
                            if (!$prism_processed_pds)
                            {
                                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not find applicable protection domains on Nutanix cluster $prism ..."
                                Continue
                            }
                        #endregion
                        
                        #region process vms inside protection domains
                            
                            #step 1: foreach protection domain loop
                            ForEach ($prism_processed_pd in $prism_processed_pds)
                            {#process each applicable protection domain
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing VMs for protection domain $($prism_processed_pd.name) on $prism ..."
                                #step 2: process each vm inside the protection domain
                                ForEach ($prism_processed_pd_vm in $prism_processed_pd.vms)
                                {#process all vms in the applicable protection domain
                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Processing VM $($prism_processed_pd_vm.name) ..."
                                    try
                                    {#get vm object from vCenter
                                        $vm_vCenter_object = Get-VM -Name $prism_processed_pd_vm.Name -ErrorAction Stop
                                    }
                                    catch
                                    {#couldn't get vm object from vCenter
                                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not get VM object from vCenter server $vcenter_ip : $($_.Exception.Message)"
                                        Continue
                                    }
                                    try
                                    {#get the vnics for that vm from vCenter
                                        $vm_vCenter_vnics = $vm_vCenter_object | Get-NetworkAdapter -ErrorAction Stop
                                    }
                                    catch
                                    {#couldn't get vnics for that vm from vCenter
                                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not vNICs for that VM object from vCenter server $vcenter_ip : $($_.Exception.Message)"
                                        Continue
                                    }
                                    
                                    #step 3: if migrate, and if source was AHV, based on vm name, figure out the list of vnics and which portgroup they are connected to at the source
                                    if (($cluster_details.hypervisor_types -eq "kKvm") -and ($migrate))
                                    {#source was AHV and we are migrating, so there is a chance that VMs will end up without vnics if those are connected to a network mapped to a dvportgroup
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "We are migrating from an AHV cluster."
                                        #step 4: get remote site details and figure out network mappings
                                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving network mappings for remote site $($cluster) on $prism ..."
                                        $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/remote_sites/$cluster"
                                        $method = "GET"
                                        $cluster_remote_site = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved network mappings for remote site $($cluster) on $prism"
                                        
                                        #step 5: foreach vm vnic defined at the source, figure out if the vnic already exists on the target. if not, add it and connect it to the right dvportgroup
                                        #get the vnics on the vm
                                        $vm_ahv_cluster_vnics = ($cluster_vms.entities | Where-Object {$_.name -eq $prism_processed_pd_vm.name}).vm_nics
                                        ForEach ($vm_ahv_cluster_vnic in $vm_ahv_cluster_vnics)
                                        {#foreach vnic that existed at the source on AHV
                                            #figure out network name
                                            $cluster_network_name = ($cluster_networks.entities | Where-Object {$_.uuid -eq $vm_ahv_cluster_vnic.network_uuid}).name
                                            #figure out the mapped network name
                                            $prism_mapped_network_name = ($cluster_remote_site.network_mapping.l2_network_mappings | Where-Object {$_.src_network_name -eq $cluster_network_name}).dest_network_name
                                            
                                            #figure out if this is a dvportgroup
                                            try 
                                            {#get vdportgroup
                                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Searching for $prism_mapped_network_name ..."
                                                $mapped_network_vdportgroup = Get-VDPortgroup -Name $prism_mapped_network_name -ErrorAction Stop
                                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "$prism_mapped_network_name is a VDPortGroup."
                                            }
                                            catch 
                                            {#no vdportgroup
                                                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "$prism_mapped_network_name is not a VDPortGroup or we could not retrieve it from vCenter. Skipping this vnic."
                                                Continue
                                            }
                                            #if it is a dvportgroup, add a vnic and map it to the correct dvportgroup
                                            if ($mapped_network_vdportgroup)
                                            {#got a vdportgroup
                                                try 
                                                {#add vnic
                                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Connecting $($prism_processed_pd_vm.name) to VDPortGroup $prism_mapped_network_name ..."
                                                    $add_vnic = new-networkadapter -vm $vm_vCenter_object -type vmxnet3 -StartConnected -PortGroup $mapped_network_vdportgroup -ErrorAction Stop
                                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully connected $($prism_processed_pd_vm.name) to VDPortGroup $prism_mapped_network_name ..."
                                                }
                                                catch 
                                                {#couldn't add vnic
                                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not connect $($prism_processed_pd_vm.name) to VDPortGroup $prism_mapped_network_name : $($_.Exception.Message)"
                                                }
                                            }
                                        }
                                    }
                                    else 
                                    {#source was not AHV and we could be migrate or activate, but we're on vSphere
                                        #foreach vnic, figure out if the connected portgroup is a dvportgroup.  If it is, reconnect it via vCenter
                                        ForEach ($vm_vCenter_vnic in $vm_vCenter_vnics)
                                        {
                                            try 
                                            {#get vdportgroup
                                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Searching for $($vm_vCenter_vnic.NetworkName) ..."
                                                $vdportgroup = Get-VDPortgroup -Name $vm_vCenter_vnic.NetworkName -ErrorAction Stop
                                                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "$($vm_vCenter_vnic.NetworkName) is a VDPortGroup."
                                            }
                                            catch 
                                            {#no vdportgroup
                                                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "$($vm_vCenter_vnic.NetworkName) is not a VDPortGroup or we could not retrieve it from vCenter. Skipping this vnic."
                                                Continue
                                            }
                                            if ($vdportgroup)
                                            {#got a vdportgroup
                                                try 
                                                {#add vnic
                                                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Reconnecting $($prism_processed_pd_vm.name) to VDPortGroup $($vm_vCenter_vnic.NetworkName) ..."
                                                    $connect_vnic = Set-NetworkAdapter -NetworkAdapter $vm_vCenter_vnic -StartConnected -PortGroup $vdportgroup -Connected $true -ErrorAction Stop
                                                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully reconnected $($prism_processed_pd_vm.name) to VDPortGroup $($vm_vCenter_vnic.NetworkName) ..."
                                                }
                                                catch 
                                                {#couldn't add vnic
                                                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not reconnect $($prism_processed_pd_vm.name) to VDPortGroup $($vm_vCenter_vnic.NetworkName) : $($_.Exception.Message)"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        #endregion
                    
                        #region disconnect from vCenter
                            try 
                            {
                                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disconnecting from vCenter server..."
                                $vCenter_Disconnect = Disconnect-VIServer * -Confirm:$false -ErrorAction Stop 
                            }
                            catch 
                            {
                                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not disconnect from vCenter server : $($_.Exception.Message)"
                            }
                        #endregion
                    }
                    else 
                    {#we have either no or multiple management servers...
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no or more than one management server(s) defined on $prism"
                        Exit
                    }
                }
            }
            
        }
    #endregion

    #region powerOnVms
        if ($migrate -or $activate)
        {#we migrated or activated, so there are vms to power on
            if ($powerOnVms)
            {#user wants to power on vms
                Write-Host ""
                Write-LogOutput -Category "STEP" -LogFile $myvarOutputLogFile -Message "--Triggering VM power on workflow--"

                #let's retrieve the list of protection domains
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving protection domains from Nutanix cluster $cluster ..."
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $PdList = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved protection domains from Nutanix cluster $cluster"

                #region process
                    ForEach ($protection_domain in $processed_pds)
                    {
                        #region figure out the remote site
                            #figure out if there is more than one remote site defined for the protection domain
                            $remoteSite = $PdList.entities | Where-Object {$_.name -eq $protection_domain} | Select-Object -Property remote_site_names
                            if (!$remoteSite.remote_site_names) 
                            {#no remote site defined or no schedule on the pd with a remote site
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is no remote site defined for protection domain $protection_domain"
                                Exit
                            }
                            if ($remoteSite -is [array]) 
                            {#more than 1 remote site target defined on the pd schedule
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than one remote site for protection domain $protection_domain"
                                Exit
                            }

                            #get the remote site IP address
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving details about remote site $($remoteSite.remote_site_names) ..."
                            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/remote_sites/$($remoteSite.remote_site_names)"
                            $method = "GET"
                            $remote_site = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details about remote site $($remoteSite.remote_site_names)"

                            if ($remote_site.remote_ip_ports.psobject.properties.count -gt 1)
                            {#there are multiple IPs defined for the remote site
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "There is more than 1 IP configured for the remote site $remoteSite"
                                Exit
                            }
                        #endregion

                        if ($migrate)
                        {#we are migrating, so the cluster where we power on vms is the remote site
                            $powerOn_cluster = $remote_site.remote_ip_ports.psobject.properties.name
                        }
                        if ($activate)
                        {#we are activating, so the cluster where we power on is the same cluster where we activated
                            $powerOn_cluster = $cluster
                        }

                        
                        #region check the protection domain is active
                            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Retrieving details about protection domain $($protection_domain) on cluster $powerOn_cluster ..."
                            $url = "https://$($powerOn_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/?names=$($protection_domain)"
                            $method = "GET"
                            $response = Invoke-PrismRESTCall -method $method -url $url -username $username -password ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword)))
                            Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully retrieved details about protection domain $($protection_domain) on cluster $powerOn_cluster"

                            if ($response.entities.active -ne "true")
                            {#pd is not active
                                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Protection domain $protection_domain is not active on cluster $($powerOn_cluster)"
                                Exit
                            }
                        #endregion

                        Write-Host ""
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Powering on VMs in protection domain $($protection_domain) on cluster $powerOn_cluster ..."
                        Set-NtnxPdVmPowerOn -pd $protection_domain -cluster $powerOn_cluster -username $username -password $PrismSecurePassword
                    }
                #endregion
            }
        }
    #endregion 

    #region deactivate
        if ($deactivate)
        {
            Write-Host ""
            Write-LogOutput -Category "STEP" -LogFile $myvarOutputLogFile -Message "--Triggering protection domain deactivation workflow--"
            $response = Invoke-NtnxPdDeactivation -pd $pd -cluster $cluster -username $username -password $PrismSecurePassword
            Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $cluster -username $username -password $PrismSecurePassword -operation "deactivate"
        }
    #endregion

#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-LogOutput -Category "SUM" -LogFile $myvarOutputLogFile -Message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion