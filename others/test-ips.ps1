<#
.SYNOPSIS
  Use this script to test a range of IPs.
.DESCRIPTION
  You can test IPs with ping as well as any tcp port you want to add.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Display additional debugging output.
.PARAMETER subnet
  Subnet in CIDR notation you want to test (exp: 192.168.0.0/24). By default, all IPs in that subnet will be tested, unless you specify a range.
.PARAMETER range
  Range of IPs you want to test. Example: 30-50
.PARAMETER ports
  Comma separated list of additional tcp ports you want to test.
.PARAMETER timeout
  Timeout for TCP ports tests (default is 1 second).
.PARAMETER onlyavailable
  Only display a list of available IPs.
.PARAMETER onlyunavailable
  Only display a list of unavailable IPs.
.EXAMPLE
.\test-ips.ps1 -subnet 192.168.0.0/24 -tcp 22,3389,80,443 -timeout 5
Ping all IP addresses in subnet 192.168.0.0/24 and apply a timeout of 5 seconds for tcp port tests (22,3389,80,443)
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 25th 2021
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true, HelpMessage="Enter subnet in CIDR format (exp:192.168.0.0/24)")][string]$subnet,
        [parameter(mandatory = $false)] [string]$range,
        [parameter(mandatory = $false)] [string[]]$ports,
        [parameter(mandatory = $false)] [int]$timeout,
        [parameter(mandatory = $false)] [switch]$onlyavailable,
        [parameter(mandatory = $false)] [switch]$onlyunavailable
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
    Function LoadModule
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
#endregion

#region prepwork
    #check if we need to display help and/or history
    $myvar_history_text = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
02/25/2021 sb   Initial release.
################################################################################
'@
    $myvar_script_name = ".\test-ips.ps1"

    if ($help) {get-help $myvar_script_name; exit}
    if ($History) {$myvar_history_text; exit}

    LoadModule -module PSNetAddressing
#endregion

#region variables
    $myvar_elapsed_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_available_ips=@()
    $myvar_unavailable_ips=@()
#endregion

#region parameters validation
    if ($subnet -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
    {#specified subnet is in valid cidr format
        Write-LogOutput -Category "INFO" -Message "Specified subnet is valid."
        $myvar_network_id = ($subnet.Split("/"))[0]
        $myvar_network_prefix_length = ($subnet.Split("/"))[1]
        $myvar_network_information = Get-IPNetwork -IPAddress $myvar_network_id -PrefixLength $myvar_network_prefix_length -ReturnAllIPs
    }
    else 
    {#specified subnet is not valid
        Write-LogOutput -Category "ERROR" -Message "Specified subnet is not in valid CIDR notation. Please use something like 192.168.0.0/24"
        Exit 1
    }

    if (!$timeout) {$timeout = 1}
    if ($ports)
    {#tcp ports were specified
        $myvar_tcp_ports = $ports.Split(",")
    }
#endregion

#region processing	
    if (!$range)
    {#no range was specified, we ping all IP addresses
        $myvar_ips = $myvar_network_information.AllIPs
    }
    else 
    {
        if ($range -match '\d+[-]\d+')
        {#range is in valid format
            $myvar_range = ($range.Split("-"))[0]..($range.Split("-"))[1]
            $myvar_range_invalid_numbers = $myvar_range | ?{$_ -notmatch '^0*(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-5][0-5]|2[0-4][0-9])$'}
            if ($myvar_range_invalid_numbers)
            {#specified range is invalid
                Write-LogOutput -Category "ERROR" -Message "Range contains numbers less than 0 or greater than 255!"
                Exit 1
            }
            $myvar_ips = $myvar_range | %{((($myvar_network_information.FirstIP).Split(".")[0,1,2]) -join ".")+"."+$_}
        }
        else 
        {#range is not in valid format
            Write-LogOutput -Category "ERROR" -Message "Range must be specified in a valid format. Example: 10-20"
            Exit 1
        }
    }

    ForEach ($myvar_ip in $myvar_ips)
    {#process each ip
        if ($debugme) {Write-LogOutput -Category "DEBUG" -Message "Pinging $($myvar_ip)..."}
        $myvar_ping_result = Test-Connection -IPv4 -Ping -Count 2 -TargetName $myvar_ip -Quiet -TimeoutSeconds $timeout

        if ($myvar_ping_result)
        {#ping was positive so the IP is not available
            if ($onlyunavailable)
            {
                $myvar_unavailable_ips += $myvar_ip
            }
            else 
            {
                Write-Host "IP $($myvar_ip) is not available" -ForeGroundColor Red
            }
            continue
        }

        $myvar_tcp_result = $false
        ForEach ($myvar_tcp_port in $myvar_tcp_ports)
        {#process each tcp port
            if ($debugme) {Write-LogOutput -Category "DEBUG" -Message "Testing TCP port $($myvar_tcp_port) for IP $($myvar_ip)..."}
            $myvar_tcp_result = Test-Connection -IPv4 -TcpPort $myvar_tcp_port -Timeout $timeout -TargetName $myvar_ip
            if ($myvar_tcp_result) 
            {#a port tested positive, so we break out of the loop
                break
            }
        }

        if ($myvar_tcp_result)
        {#one test was positive so the IP is not available
            if ($onlyunavailable)
            {
                $myvar_unavailable_ips += $myvar_ip
            }
            else 
            {
                Write-Host "IP $($myvar_ip) is not available" -ForeGroundColor Red
            }
        }
        else
        {
            if ($onlyavailable)
            {
                $myvar_available_ips += $myvar_ip
            }
            elseif (!$onlyunavailable)
            {
                Write-Host "IP $($myvar_ip) is available" -ForeGroundColor Green   
            }
        }
    }

    if ($onlyavailable)
    {
        if ($myvar_available_ips)
        {
            Write-LogOutput -Category "DATA" -Message "List of available IPs: $($myvar_available_ips)"
        }
        else 
        {
            Write-LogOutput -Category "WARNING" -Message "There are no available IPs!"
        }
    }
    elseif ($onlyunavailable)
    {
        if ($myvar_unavailable_ips)
        {
            Write-LogOutput -Category "DATA" -Message "List of unavailable IPs: $($myvar_unavailable_ips)"
        }
        else 
        {
            Write-LogOutput -Category "INFO" -Message "All IPs are available!"
        }
    }
#endregion

#region cleanup
    #let's figure out how much time this all took
    Write-LogOutput -category "SUM" -message "total processing time: $($myvar_elapsed_time.Elapsed.ToString())"

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable subnet -ErrorAction SilentlyContinue
    Remove-Variable range -ErrorAction SilentlyContinue
    Remove-Variable ports -ErrorAction SilentlyContinue
    Remove-Variable timeout -ErrorAction SilentlyContinue
#endregion