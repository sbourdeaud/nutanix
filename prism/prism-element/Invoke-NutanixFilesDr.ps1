<#
.SYNOPSIS
  Start a Nutanix Files failover (planned or unplanned) from one Nutanix cluster to another.
.DESCRIPTION
  Given a file server name, assuming protection domain and replication to another site is already in place, do a planned or unplanned failover of a Nutanix Files file server instance from one site to another.  The script will migrate or activate the protection domain, activate the file server and can also trigger DNS update.  The script is designed to be able to work also with a reference file so that it can be used to facilitate DR automation.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prism
  Nutanix cluster fully qualified domain name or IP address (source or target; the script will figure out which is which).
.PARAMETER username
  Username used to connect to the Nutanix cluster.
.PARAMETER password
  Password used to connect to the Nutanix cluster.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER failover
  Specifies the type of failover (valid entries are planned or unplanned).
.PARAMETER fsname
  Name of the file server instance you want to failover.
.PARAMETER reference
  (Optional) Path to the reference file containing the following information in csv format: fsname,prism-primary,prism-dr,primary-client-network-name,primary-client-network-subnet,primary-client-network-gateway,primary-client-network-startip,primary-client-network-endip,primary-storage-network-name,primary-storage-network-subnet,primary-storage-network-gateway,primary-storage-network-startip,primary-storage-network-endip,dr-client-network-name,dr-client-network-subnet,dr-client-network-gateway,dr-client-network-startip,dr-client-network-endip,dr-storage-network-name,dr-storage-network-subnet,dr-storage-network-gateway,dr-storage-network-startip,dr-storage-network-endip,prismcreds,adcreds,pd,smtp,email,primary-dns-servers,primary-ntp-servers,dr-dns-servers,dr-ntp-servers,vcentercreds
  If any of the client or storage networks are AHV managed, you do not need to specify values for the network name, subnet, gateway, startip and endip.
  The script will always look for a reference file in the current directory called <fsname>-reference.csv and use it if available.  Otherwise, it will prompt the user for the necessary information.
.PARAMETER pd
  (Optional) Name of protection domain for the file server instance (assumed name if NTNX-<file-server-name>).
.PARAMETER dns
  (Optional) Specifies that you want to trigger a DNS update after the file server has been activated (works only if your DNS server is a Microsoft DNS server).
.PARAMETER adcreds
  (Required if -dns) Name of credentials file for Active Directory (required for DNS update).  If the credentials file does not exist, you will be prompted for credentials.
.PARAMETER mail
  (Optional) Specifies that you want to notify by email when the script takes action.
.PARAMETER smtp
  (Required if -mail) FQDN or IP of the SMTP server to use for sending emails.
.PARAMETER email
  (Required if -mail) Comma separated list of email addresses to notify.
.PARAMETER dvswitch
  (Optional) If the File server you are failing over uses distributed virtual switches on VMware vSphere, use this switch to reconnect the network interface after the Protection Domain has failed over and before File Server activation, otherwise the FSVMs will start without network connectivity.
.EXAMPLE
.\Invoke-NutanixFilesDr.ps1 -fsname myfileserver -failover unplanned
Do an unplanned failover of a file server called myfileserver.  All reference information will be obtained from myfileserver.csv in the current directory:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 25th 2020
#>

#! when you run an unplanned failover on an esx cluster with metro availability using a dvswitch, things may not work as expected during file server activation.

#region parameters
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$prism,
    [parameter(mandatory = $false)] [string]$username,
    [parameter(mandatory = $false)] [string]$password,
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $true)] [ValidateSet("planned","unplanned","deactivate")] [string]$failover,
    [parameter(mandatory = $false)] [string]$fsname,
    [parameter(mandatory = $false)] [string]$reference,
    [parameter(mandatory = $false)] [string]$pd,
    [parameter(mandatory = $false)] [switch]$dns,
    [parameter(mandatory = $false)] $adCreds,
    [parameter(mandatory = $false)] [switch]$mail,
    [parameter(mandatory = $false)] [string]$smtp,
    [parameter(mandatory = $false)] [string]$email,
    [parameter(mandatory = $false)] [switch]$force,
    [parameter(mandatory = $false)] [switch]$dvswitch
)
#endregion

#region functions
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
    .PARAMETER credential
    PowerShell credential object for Nutanix cluster API user.
    .EXAMPLE
    Invoke-NtnxPdMigration -pd <pd_name> -cluster ntnx1.local -credential $credential
    #>
    [CmdletBinding()]
    param
    (
        $pd,

        [Parameter(Mandatory)]
        [String]
        $cluster,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential            
    )

    begin
    {
        
    }

    process
    { 
        #region get data
            #let's retrieve the list of protection domains
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

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
                Write-Host "$(get-date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
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
                    Write-Host "$(get-date) [ERROR] There is no remote site defined for protection domain $pd2migrate" -ForegroundColor Red
                    Exit
                }
                if ($remoteSite -is [array]) 
                {#more than 1 remote site target defined on the pd schedule
                    Write-Host "$(get-date) [ERROR] There is more than one remote site for protection domain $pd2migrate" -ForegroundColor Red
                    Exit
                }

                #region migrate the protection domain
                    Write-Host ""
                    Write-Host "$(get-date) [INFO] Migrating $pd2migrate to $($remoteSite.remote_site_names) ..." -ForegroundColor Green
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2migrate/migrate"
                    $method = "POST"
                    $content = @{
                                    value = $($remoteSite.remote_site_names)
                                }
                    $body = (ConvertTo-Json $content -Depth 4)
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                    if ($debugme) {Write-Host "$(get-date) [DEBUG] Migration request response is: $($response.metadata)" -ForegroundColor White}
                    if ($response.metadata.count -ne 0)
                    {#something went wrong with our migration request
                        Write-Host "$(get-date) [ERROR] Could not start migration of $pd2migrate to $($remoteSite.remote_site_names). Try to trigger it manually in Prism and see why it won't work (this could be caused ny NGT being disabled on some VMs, or by delta disks due to old snapshots)." -ForegroundColor Red
                        Exit
                    }
                    Write-Host "$(get-date) [SUCCESS] Successfully started migration of $pd2migrate to $($remoteSite.remote_site_names)" -ForegroundColor Cyan
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
    .PARAMETER credential
    PowerShell credential object for Nutanix cluster API user.
    .EXAMPLE
    Invoke-NtnxPdActivation -pd <pd_name> -cluster ntnx1.local -credential $prism_credential
    #>
    [CmdletBinding()]
    param
    (
        $pd,

        [Parameter(Mandatory)]
        [String]
        $cluster,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential  
    )

    begin
    {
        
    }

    process
    {            
        #region get data
            #let's retrieve the list of protection domains
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

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
                Write-Host "$(get-date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
                Exit
            }
        #endregion

        #now let's call the activate workflow
        ForEach ($pd2activate in $pd) 
        {#activate each pd
            #region activate the protection domain
                Write-Host ""
                Write-Host "$(get-date) [INFO] Activating protection domain $($pd2activate) on $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$($pd2activate)/activate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                Write-Host "$(get-date) [SUCCESS] Successfully activated protection domain $($pd2activate) on $cluster" -ForegroundColor Cyan
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
    .PARAMETER credential
    PowerShell credential object for Nutanix cluster API user.
    .EXAMPLE
    Invoke-NtnxPdDeactivation -pd <pd_name> -cluster ntnx1.local -credential $credential
    #>
    [CmdletBinding()]
    param
    (
        $pd,

        [Parameter(Mandatory)]
        [String]
        $cluster,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential   
    )

    begin
    {
        
    }

    process
    {
        #region get data
            #let's retrieve the list of protection domains
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $cluster ..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $PdList = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $cluster" -ForegroundColor Cyan

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
                Write-Host "$(get-date) [ERROR] There are no protection domains in the correct status on $cluster!" -ForegroundColor Red
                Exit 1
            }
        #endregion

        #region process
            ForEach ($pd2deactivate in $pd) 
            {#now let's call the deactivate workflow for each pd
                Write-Host ""
                Write-Host "$(get-date) [INFO] Deactivating protection domain $pd2deactivate on $cluster ..." -ForegroundColor Green
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/$pd2deactivate/deactivate"
                $method = "POST"
                $content = @{}
                $body = (ConvertTo-Json $content -Depth 4)
                $response = Invoke-PrismAPICall -method $method -url $url -credential $credential -payload $body
                Write-Host "$(get-date) [SUCCESS] Successfully started deactivation of protection domain $pd2deactivate on $cluster" -ForegroundColor Cyan
            }
        #endregion
    }

    end
    {
        return $response #this is the task uuid as sent back from the API
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
    .PARAMETER credential
    PowerShell credential object for Nutanix cluster API user.

    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

    .EXAMPLE
    .\Get-PrismTaskStatus -Task $task -Cluster $cluster -credential $prism_credential
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
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential   
    )

    begin
    {
        
    }

    process 
    {
        Write-Host ""
        Write-Host "$(get-date) [INFO] Retrieving list of tasks on the cluster $cluster ..." -ForegroundColor Green
        Start-Sleep 10
        
        $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
        $method = "GET"
        $response = Invoke-PrismAPICall -method $method -url $url -credential $credential
        Write-Host "$(get-date) [SUCCESS] Retrieved list of tasks on the cluster $cluster" -ForegroundColor Cyan
        
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
                    Write-Host "$(get-date) [WARNING] Waiting 5 seconds for task $($pdTask.taskName) to complete : $($pdTask.percentageCompleted)%" -ForegroundColor Yellow
                    Start-Sleep 5
                    $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/progress_monitors"
                    $method = "GET"
                    $response = Invoke-PrismAPICall -method $method -url $url -credential $credential
                    $task = $response.entities | Where-Object {$_.taskName -eq $pdTask.taskName} | Where-Object {($_.createTimeUsecs / 1000000) -ge $StartEpochSeconds}
                    if ($task.status -ne "running") 
                    {#task is no longer running
                        if ($task.status -ne "succeeded") 
                        {#task failed
                            Write-Host "$(get-date) [ERROR] Task $($pdTask.taskName) failed with the following status and error code : $($task.status) : $($task.errorCode)" -ForegroundColor Red
                            Exit
                        }
                    }
                }
                While ($task.percentageCompleted -ne "100")
                
                Write-Host "$(get-date) [SUCCESS] Protection domain migration task $($pdTask.taskName) completed on the cluster $cluster" -ForegroundColor Cyan
                Write-Host ""
            } 
            else 
            {
                Write-Host "$(get-date) [SUCCESS] Protection domain migration task $($pdTask.taskName) completed on the cluster $cluster" -ForegroundColor Cyan
                Write-Host ""
            }
        }
    }
    
    end
    {

    }
}

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
    .PARAMETER credential
    PowerShell credential object for Nutanix cluster API user.

    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

    .EXAMPLE
    .\Get-PrismTaskStatus -Task $task -Cluster $cluster -credential $prism_credential
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
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential   
    )

    begin
    {
        
    }

    process 
    {
        #region get initial task details
            Write-Host "$(get-date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
            $method = "GET"
            $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(get-date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
        #endregion

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Start-Sleep 5
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                $method = "GET"
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.progress_status -ne "Running") 
                {
                    if ($taskDetails.progress_status -ne "Succeeded")
                    {
                        Write-Host "$(get-date) [ERROR] Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)" -ForegroundColor Red
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
            Write-Host "$(get-date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            if ($taskDetails.progress_status -ne "Succeeded")
            {
                Write-Host "$(get-date) [ERROR] Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)" -ForegroundColor Red
                $userChoice = Write-CustomPrompt
                if ($userChoice -eq "n")
                {
                    Exit
                }
            }
            else 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Write-Host "$(get-date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
            }
        }
    }
    
    end
    {

    }
}

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
        Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
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

#this function is used to prompt the user for a yes/no/skip response in order to control the workflow of a script
function Write-CustomPrompt 
{
<#
.SYNOPSIS
Creates a user prompt with a yes/no/skip response. Returns the response.

.DESCRIPTION
Creates a user prompt with a yes/no/skip response. Returns the response in lowercase. Valid responses are "y" for yes, "n" for no, "s" for skip.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Write-CustomPrompt
Creates the prompt.

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

param 
(
    [Switch]$skip
)

begin 
{
    [String]$userChoice = "" #initialize our returned variable
}
process 
{
    if ($skip)
    {
        do {$userChoice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o]/S[kip])"} #display the user prompt
        while ($userChoice -notmatch '[ynsYNS]') #loop until the user input is valid
    }
    else 
    {
        do {$userChoice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o])"} #display the user prompt
        while ($userChoice -notmatch '[ynYN]') #loop until the user input is valid
    }
    $userChoice = $userChoice.ToLower() #change to lowercase
}
end 
{
    return $userChoice
}

} #end Write-CustomPrompt function

#endregion

#region prepwork
$HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
06/08/2020 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\Invoke-NutanixFilesDr.ps1"

if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

Set-PoSHSSLCerts
Set-PoshTls
#endregion

#region variables
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$StartEpochSeconds = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s)) #used to get tasks generated in Prism after the script was invoked
$remote_site_ips = @() #initialize array here to collect remote site ips
#endregion

#region parameters validation
if ($failover -eq "deactivate") {
    if (!$prism) {$prism = Read-Host "Enter the FQDN or IP address of a Nutanix cluster"}
    if (!$prismCreds) 
    {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
        if (!$username) 
        {#if Prism username has not been specified ask for it
            $username = Read-Host "Enter the Prism username"
        } 

        if (!$password) 
        {#if password was not passed as an argument, let's prompt for it
            $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
        }
        else 
        {#if password was passed as an argument, let's convert the string to a secure string and flush the memory
            $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
            Remove-Variable password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    } 
    else 
    { #we are using custom credentials, so let's grab the username and password from that
        try 
        {
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        catch 
        {
            $credname = Read-Host "Enter the credentials name"
            Set-CustomCredentials -credname $credname
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }
    if (!$pd) {$pd = Read-Host "Enter the name of the protection domain you want to deactivate (WARNING! This will delete VMs and destroy data!"}
} else {
    if (!$reference) {
        if (!$fsname) {$fsname = Read-Host "Enter the name of the file server you want to failover"}
        #check if there is a default reference file for this file server in the current directory
        if ((Test-Path ./$($fsname)-reference.csv -PathType Leaf) -and !$prism) {
            Write-Host "$(get-date) [INFO] Found a reference file called $($fsname)-reference.csv in the current directory." -ForegroundColor Green
            $reference_data = Import-Csv -Path ./$($fsname)-reference.csv
        } else {
            Write-Host "$(get-date) [WARN] Could not find a reference file for file server $($fsname) in the current directory or you specified a Prism cluster." -ForegroundColor Yellow
            if (!$prism) {$prism = Read-Host "Enter the FQDN or IP address of a Nutanix cluster"}
            if (!$prismCreds) 
            {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
                if (!$username) 
                {#if Prism username has not been specified ask for it
                    $username = Read-Host "Enter the Prism username"
                } 

                if (!$password) 
                {#if password was not passed as an argument, let's prompt for it
                    $PrismSecurePassword = Read-Host "Enter the Prism user $username password" -AsSecureString
                }
                else 
                {#if password was passed as an argument, let's convert the string to a secure string and flush the memory
                    $PrismSecurePassword = ConvertTo-SecureString $password –asplaintext –force
                    Remove-Variable password
                }
                $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
            } 
            else 
            { #we are using custom credentials, so let's grab the username and password from that
                try 
                {
                    $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
                    $username = $prismCredentials.UserName
                    $PrismSecurePassword = $prismCredentials.Password
                }
                catch 
                {
                    $credname = Read-Host "Enter the credentials name"
                    Set-CustomCredentials -credname $credname
                    $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
                    $username = $prismCredentials.UserName
                    $PrismSecurePassword = $prismCredentials.Password
                }
                $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
            }
            if (!$pd) {$pd = "NTNX-$($fsname)"}
        }
    } else {
        $reference_data = Import-Csv -Path ./$($reference)
    }
    if ($dns) {
        if (!$reference_data) {
            if (!$adCreds) 
            {#we are not using custom credentials, so let's ask for a username and password if they have not already been specified
                $ad_username = Read-Host "Enter the Active Directory username for DNS updates"
                $ad_secure_password = Read-Host "Enter the Active Directory user $ad_username password" -AsSecureString
                $ad_credentials = New-Object PSCredential $ad_username, $ad_secure_password
            } 
            else 
            { #we are using custom credentials, so let's grab the username and password from that
                try 
                {
                    $ad_credentials = Get-CustomCredentials -credname $adCreds -ErrorAction Stop
                    $ad_username = $ad_credentials.UserName
                    $ad_secure_password = $ad_credentials.Password
                }
                catch 
                {
                    $credname = Read-Host "Enter the credentials name"
                    Set-CustomCredentials -credname $credname
                    $ad_credentials = Get-CustomCredentials -credname $adCreds -ErrorAction Stop
                    $ad_username = $ad_credentials.UserName
                    $ad_secure_password = $ad_credentials.Password
                }
                $ad_credentials = New-Object PSCredential $ad_username, $ad_secure_password
            }
        }
    }
    if ($mail) {
        if (!$smtp) {$smtp = Read-Host "Enter the FQDN or IP address of an SMTP server"}
        if (!$email) {$email = Read-Host "Enter a comma separated list of email addresses to notify"}
    }
    if ($dvswitch) {
        if (!$reference_data) {
            $vcenter_username = Read-Host "Enter the vCenter username"
            $vcenter_secure_password = Read-Host "Enter the vCenter user $vcenter_username password" -AsSecureString
            $vcenter_credentials = New-Object PSCredential $vcenter_username, $vcenter_secure_password
        }
    }
}
#endregion

#region processing
#TODO enhance deactivate workflow to require fsname instead of pd
#region check reference_data and validate entries
    if ($reference_data) {
        if (!$reference_data.fsname) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute fsname" -ForegroundColor Red; exit 1}
        if (!$reference_data.{prism-primary}) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute prism-primary" -ForegroundColor Red; exit 1}
        if (!$reference_data.{prism-dr}) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute prism-dr" -ForegroundColor Red; exit 1}
        if (!$reference_data.{primary-client-network-name}) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute primary-client-network-name" -ForegroundColor Red; exit 1}
        if (!$reference_data.{primary-storage-network-name}) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute primary-storage-network-name" -ForegroundColor Red; exit 1}
        if (!$reference_data.{dr-client-network-name}) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute dr-client-network-name" -ForegroundColor Red; exit 1}
        if (!$reference_data.{dr-storage-network-name}) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute dr-storage-network-name" -ForegroundColor Red; exit 1}
        if (!$reference_data.prismcreds) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute prismcreds" -ForegroundColor Red; exit 1}
        if ($dns -and !$reference_data.adcreds) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute adcreds" -ForegroundColor Red; exit 1}
        if ($mail -and (!$smtp -or !$email)) {Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute smtp and/or email" -ForegroundColor Red; exit 1}
        if ($dvswitch -and !$reference_data.vcentercreds) {{Write-Host "$(get-date) [ERROR] Reference file is missing a value for attribute vcentercreds" -ForegroundColor Red; exit 1}}

        #import prismcredentials
        try {
            $prismCredentials = Get-CustomCredentials -credname $reference_data.prismcreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        catch 
        {
            $credname = Read-Host "Enter the Prism credentials name"
            Set-CustomCredentials -credname $credname
            $prismCredentials = Get-CustomCredentials -credname $reference_data.prismcreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
        
        #import adcredentials
        if ($dns -and $reference_data.adcreds) {
            try {
                $ad_credentials = Get-CustomCredentials -credname $reference_data.adcreds -ErrorAction Stop
                $ad_username = $ad_credentials.UserName
                $ad_secure_password = $ad_credentials.Password
            }
            catch 
            {
                $credname = Read-Host "Enter the AD credentials name"
                Set-CustomCredentials -credname $credname
                $ad_credentials = Get-CustomCredentials -credname $reference_data.adcreds -ErrorAction Stop
                $ad_username = $ad_credentials.UserName
                $ad_secure_password = $ad_credentials.Password
            }
            $ad_credentials = New-Object PSCredential $ad_username, $ad_secure_password
        }

        #import vcenter_credentials
        if ($dvswitch -and $reference_data.vcentercreds) {
            try {
                $vcenter_credentials = Get-CustomCredentials -credname $reference_data.vcentercreds -ErrorAction Stop
                $vcenter_username = $vcenter_credentials.UserName
                $vcenter_secure_password = $vcenter_credentials.Password
            }
            catch 
            {
                $credname = Read-Host "Enter the vCenter credentials name"
                Set-CustomCredentials -credname $credname
                $vcenter_credentials = Get-CustomCredentials -credname $reference_data.vcentercreds -ErrorAction Stop
                $vcenter_username = $vcenter_credentials.UserName
                $vcenter_secure_password = $vcenter_credentials.Password
            }
            $vcenter_credentials = New-Object PSCredential $vcenter_username, $vcenter_secure_password
        }

        $fsname = $reference_data.fsname
        if ($reference_data.pd) {
            $pd = $reference_data.pd
        } else {
            $pd = "NTNX-$($reference_data.fsname)"
        }
    }
#endregion

#region check prism connectivity and get additional data
    Write-Host ""
    Write-Host "$(get-date) [STEP] --Verifying Connectivity to Prism(s)--" -ForegroundColor Magenta
    if ($reference_data) {#we have a reference data file with all the info we need
        if ($failover -eq "planned") {
            #region GET cluster (PRIMARY)
                #check if primary site is available
                Write-Host "$(get-date) [INFO] Retrieving details of PRIMARY Nutanix cluster $($reference_data.{prism-primary}) ..." -ForegroundColor Green
                $url = "https://$($reference_data.{prism-primary}):9440/PrismGateway/services/rest/v2.0/cluster/"
                $method = "GET"
                $primary_cluster_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of PRIMARY Nutanix cluster $($reference_data.{prism-primary})" -ForegroundColor Cyan
                Write-Host "$(get-date) [INFO] Hypervisor on PRIMARY Nutanix cluster $($reference_data.{prism-primary}) is of type $($primary_cluster_details.hypervisor_types)." -ForegroundColor Green

                #grab cluster name and ntp servers if they have not been specified in the reference data
                if (!$reference_data.{primary-dns-servers}) {
                    $primary_dns_servers = $primary_cluster_details.name_servers
                } else {
                    $primary_dns_servers = ($reference_data.{primary-dns-servers}).split(",")
                }
                if (!$reference_data.{primary-ntp-servers}) {
                    $primary_ntp_servers = $primary_cluster_details.ntp_servers
                } else {
                    $primary_ntp_servers = ($reference_data.{primary-ntp-servers}).split(",")
                }
            #endregion
            
            #region GET vfiler (PRIMARY)
                #check status of file server on primary
                Write-Host "$(get-date) [INFO] Retrieving details of file server $fsname status from PRIMARY Nutanix cluster $($reference_data.{prism-primary})..." -ForegroundColor Green
                $url = "https://$($reference_data.{prism-primary}):9440/PrismGateway/services/rest/v1/vfilers/"
                $method = "GET"
                $primary_cluster_vfilers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                $primary_cluster_vfiler = $primary_cluster_vfilers.entities | Where-Object {$_.Name -eq $fsname}
                if (!$primary_cluster_vfiler) {Write-Host "$(get-date) [ERROR] Could not find a file server called $fsname on PRIMARY Nutanix cluster $($reference_data.{prism-primary})!" -ForegroundColor Red; Exit 1}
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of file server $fsname status from PRIMARY Nutanix cluster $($reference_data.{prism-primary})" -ForegroundColor Cyan
                Write-Host "$(get-date) [INFO] File server $fsname on PRIMARY Nutanix cluster $($reference_data.{prism-primary}) has the following status: $($primary_cluster_vfiler.fileServerState)" -ForegroundColor Green
            #endregion

            #region GET protection domains (PRIMARY)
                #get protection domains from primary
                Write-Host "$(get-date) [INFO] Retrieving protection domains from PRIMARY Nutanix cluster $($reference_data.{prism-primary})..." -ForegroundColor Green
                $url = "https://$($reference_data.{prism-primary}):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $primary_pd_list = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from PRIMARY Nutanix cluster $($reference_data.{prism-primary})" -ForegroundColor Cyan
                $primary_vfiler_pd = $primary_pd_list.entities | Where-Object {$_.name -eq $pd}
                if (!$primary_vfiler_pd) {Write-Host "$(get-date) [ERROR] Could not find a protection domain called $pd on PRIMARY Nutanix cluster $($reference_data.{prism-primary})!" -ForegroundColor Red; Exit 1}
            #endregion

            #region GET networks (PRIMARY)
                #get available networks from primary (/PrismGateway/services/rest/v2.0/networks/)
                #TODO check this works the same with esxi (testing on ahv for now)
                Write-Host "$(get-date) [INFO] Retrieving available networks from PRIMARY Nutanix cluster $($reference_data.{prism-primary})..." -ForegroundColor Green
                $url = "https://$($reference_data.{prism-primary}):9440/PrismGateway/services/rest/v2.0/networks/"
                $method = "GET"
                $primary_cluster_networks = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved networks from PRIMARY Nutanix cluster $($reference_data.{prism-primary})" -ForegroundColor Cyan
                $primary_client_network_uuid = ($primary_cluster_networks.entities | Where-Object {$_.name -eq $reference_data.{primary-client-network-name}}).uuid
                $primary_storage_network_uuid = ($primary_cluster_networks.entities | Where-Object {$_.name -eq $reference_data.{primary-storage-network-name}}).uuid
                $primary_client_netwok_name = $reference_data.{primary-client-network-name}
                $primary_storage_netwok_name = $reference_data.{primary-storage-network-name}
                if (!$primary_client_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($reference_data.{primary-client-network-name}) on PRIMARY Nutanix cluster $($reference_data.{prism-primary})!" -ForegroundColor Red; Exit 1}
                if (!$primary_storage_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($reference_data.{primary-storage-network-name}) on PRIMARY Nutanix cluster $($reference_data.{prism-primary})!" -ForegroundColor Red; Exit 1}
                Write-Host "$(get-date) [INFO] Client network uuid on primary cluster is $($primary_client_network_uuid)" -ForegroundColor Green
                Write-Host "$(get-date) [INFO] Storage network uuid on primary cluster is $($primary_storage_network_uuid)" -ForegroundColor Green
            #endregion
        }
        #region GET cluster (DR)
            #check if dr site is available (IF not, error out)
            Write-Host "$(get-date) [INFO] Retrieving details of DR Nutanix cluster $($reference_data.{prism-dr}) ..." -ForegroundColor Green
            $url = "https://$($reference_data.{prism-dr}):9440/PrismGateway/services/rest/v2.0/cluster/"
            $method = "GET"
            $dr_cluster_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of DR Nutanix cluster $($reference_data.{prism-dr})" -ForegroundColor Cyan
            Write-Host "$(get-date) [INFO] Hypervisor on DR Nutanix cluster $($reference_data.{prism-dr}) is of type $($dr_cluster_details.hypervisor_types)." -ForegroundColor Green

            #grab cluster name and ntp servers if they have not been specified in the reference data
            if (!$reference_data.{dr-dns-servers}) {
                $dr_dns_servers = $dr_cluster_details.name_servers
            } else {
                $dr_dns_servers = ($reference_data.{dr-dns-servers}).split(",")
            }
            if (!$reference_data.{dr-ntp-servers}) {
                $dr_ntp_servers = $dr_cluster_details.ntp_servers
            } else {
                $dr_ntp_servers = ($reference_data.{dr-ntp-servers}).split(",")
            }
        #endregion
        
        #region GET vfiler (DR)
            #check status of file server on dr
            Write-Host "$(get-date) [INFO] Retrieving details of file server $fsname status from DR Nutanix cluster $($reference_data.{prism-dr})..." -ForegroundColor Green
            $url = "https://$($reference_data.{prism-dr}):9440/PrismGateway/services/rest/v1/vfilers/"
            $method = "GET"
            $dr_cluster_vfilers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            $dr_cluster_vfiler = $dr_cluster_vfilers.entities | Where-Object {$_.Name -eq $fsname}
            if (!$dr_cluster_vfiler) {Write-Host "$(get-date) [ERROR] Could not find a file server called $fsname on DR Nutanix cluster $($reference_data.{prism-dr})!" -ForegroundColor Red; Exit 1}
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of file server $fsname status from DR Nutanix cluster $($reference_data.{prism-dr})" -ForegroundColor Cyan
            Write-Host "$(get-date) [INFO] File server $fsname on DR Nutanix cluster $($reference_data.{prism-dr}) has the following status: $($dr_cluster_vfiler.fileServerState)" -ForegroundColor Green
        #endregion

        #region GET protection domains (DR)
            #get protection domains from dr
            Write-Host "$(get-date) [INFO] Retrieving protection domains from DR Nutanix cluster $($reference_data.{prism-dr})..." -ForegroundColor Green
            $url = "https://$($reference_data.{prism-dr}):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $dr_pd_list = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from DR Nutanix cluster $($reference_data.{prism-dr})" -ForegroundColor Cyan
            $dr_vfiler_pd = $dr_pd_list.entities | Where-Object {$_.name -eq $pd}
            if (!$dr_vfiler_pd) {Write-Host "$(get-date) [ERROR] Could not find a protection domain called $pd on DR Nutanix cluster $($reference_data.{prism-dr})!" -ForegroundColor Red; Exit 1}
        #endregion
        
        #region GET networks (DR)
            #get available networks from primary (/PrismGateway/services/rest/v2.0/networks/)
            #TODO check this works the same with esxi (testing on ahv for now)
            Write-Host "$(get-date) [INFO] Retrieving available networks from DR Nutanix cluster $($reference_data.{prism-dr})..." -ForegroundColor Green
            $url = "https://$($reference_data.{prism-dr}):9440/PrismGateway/services/rest/v2.0/networks/"
            $method = "GET"
            $dr_cluster_networks = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved networks from DR Nutanix cluster $($reference_data.{prism-dr})" -ForegroundColor Cyan
            $dr_client_network_uuid = ($dr_cluster_networks.entities | Where-Object {$_.name -eq $reference_data.{dr-client-network-name}}).uuid
            $dr_storage_network_uuid = ($dr_cluster_networks.entities | Where-Object {$_.name -eq $reference_data.{dr-storage-network-name}}).uuid
            $dr_client_netwok_name = $reference_data.{dr-client-network-name}
            $dr_storage_netwok_name = $reference_data.{dr-storage-network-name}
            if (!$dr_client_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($reference_data.{dr-client-network-name}) on DR Nutanix cluster $($reference_data.{prism-dr})!" -ForegroundColor Red; Exit 1}
            if (!$dr_storage_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($reference_data.{dr-storage-network-name}) on DR Nutanix cluster $($reference_data.{prism-dr})!" -ForegroundColor Red; Exit 1}
            Write-Host "$(get-date) [INFO] Client network uuid on dr cluster is $($dr_client_network_uuid)" -ForegroundColor Green
            Write-Host "$(get-date) [INFO] Storage network uuid on dr cluster is $($dr_storage_network_uuid)" -ForegroundColor Green
        #endregion
        
        #* figuring out here source and target for failover operations
        #if planned failover, based on pd status, determine the direction of the failover and set variable accordingly
        if ($failover -eq "planned") {
            if ($primary_vfiler_pd.active -and $dr_vfiler_pd.active) {
                Write-Host "$(get-date) [ERROR] Protection domain $pd is active on both PRIMARY and DR clusters. We cannot do a planned migration. Aborting." -ForegroundColor Red
                Exit 1
            } elseif ($primary_vfiler_pd.active) {#protection domain is active on primary, so this is where we'll trigger migrate. Filer activation will be done on dr.
                Write-Host "$(get-date) [INFO] Protection domain $pd is active on PRIMARY cluster, so migrating from PRIMARY to DR and doing file server activation on DR." -ForegroundColor Green
                $migrate_from_cluster = $reference_data.{prism-primary}
                $migrate_from_cluster_name = $primary_cluster_details.name
                $filer_activation_cluster = $reference_data.{prism-dr}
                $filer_activation_cluster_name = $dr_cluster_details.name
                $filer_pd_vms = $primary_vfiler_pd.vms.vm_name
                $myvarvCenter = ($dr_cluster_details.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
            } elseif ($dr_vfiler_pd.active) {
                Write-Host "$(get-date) [INFO] Protection domain $pd is active on DR cluster, so migrating from DR to PRIMARY and doing file server activation on PRIMARY." -ForegroundColor Green
                $migrate_from_cluster = $reference_data.{prism-dr}
                $migrate_from_cluster_name = $dr_cluster_details.name
                $filer_activation_cluster = $reference_data.{prism-primary}
                $filer_activation_cluster_name = $primary_cluster_details.name
                $filer_pd_vms = $dr_vfiler_pd.vms.vm_name
                $myvarvCenter = ($primary_cluster_details.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
            }
        } elseif ($failover -eq "unplanned") {
            Write-Host "$(get-date) [INFO] We are doing an unplanned failover, so protection domain $pd will be activated on DR. File server activation will also be done on DR." -ForegroundColor Green
            $filer_activation_cluster = $reference_data.{prism-dr}
            $filer_activation_cluster_name = $dr_cluster_details.name
            #! move this to after pd migration otherwise I won't get the vm list
            $filer_pd_vms = $dr_vfiler_pd.vms.vm_name
            $myvarvCenter = ($dr_cluster_details.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
            if ($dr_vfiler_pd.active) {
                Write-Host "$(get-date) [ERROR] Protection domain $pd is already active on DR cluster. We cannot do an unplanned migration. Aborting." -ForegroundColor Red
                Exit 1
            }
        }
    } else {#we don't have a reference data file and thus we must rely on user input
        #region GET cluster (-prism)
            #check connectivity to prism
            Write-Host "$(get-date) [INFO] Retrieving details of Nutanix cluster $($prism) ..." -ForegroundColor Green
            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/cluster/"
            $method = "GET"
            $prism_cluster_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of Nutanix cluster $($prism) ($($prism_cluster_details.name))" -ForegroundColor Cyan
            Write-Host "$(get-date) [INFO] Hypervisor on Nutanix cluster $($prism) ($($prism_cluster_details.name)) is of type $($prism_cluster_details.hypervisor_types)." -ForegroundColor Green
        #endregion

        #region GET vfiler (-prism)
            if ($failover -ne "deactivate") {
                #check status of file server on prism
                Write-Host "$(get-date) [INFO] Retrieving details of file server $fsname status from Nutanix cluster $($prism) ($($prism_cluster_details.name))..." -ForegroundColor Green
                $url = "https://$($prism):9440/PrismGateway/services/rest/v1/vfilers/"
                $method = "GET"
                $prism_cluster_vfilers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                $prism_cluster_vfiler = $prism_cluster_vfilers.entities | Where-Object {$_.Name -eq $fsname}
                if (!$prism_cluster_vfiler) {Write-Host "$(get-date) [ERROR] Could not find a file server called $fsname on Nutanix cluster $($prism) ($($prism_cluster_details.name))!" -ForegroundColor Red; Exit 1}
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of file server $fsname status from Nutanix cluster $($prism) ($($prism_cluster_details.name))" -ForegroundColor Cyan
                Write-Host "$(get-date) [INFO] File server $fsname on Nutanix cluster $($prism) ($($prism_cluster_details.name)) has the following status: $($prism_cluster_vfiler.fileServerState)" -ForegroundColor Green
                $pd = $prism_cluster_vfiler.protectionDomainName
            }
        #endregion

        #region GET protection domains (PRISM)
            #get protection domains from prism
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $($prism) ($($prism_cluster_details.name))..." -ForegroundColor Green
            $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $prism_pd_list = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $($prism) ($($prism_cluster_details.name))" -ForegroundColor Cyan
            
            $prism_vfiler_pd = $prism_pd_list.entities | Where-Object {$_.name -eq $pd}
            if (!$prism_vfiler_pd) {Write-Host "$(get-date) [ERROR] Could not find a protection domain called $pd on Nutanix cluster $($prism) ($($prism_cluster_details.name))!" -ForegroundColor Red; Exit 1}

            $remoteSite = $prism_vfiler_pd | Select-Object -Property remote_site_names
            if (!$remoteSite.remote_site_names) 
            {#no remote site defined or no schedule on the pd with a remote site
                Write-Host "$(get-date) [ERROR] There is no remote site defined for protection domain $pd" -ForegroundColor Red
                Exit 1
            }
            if ($remoteSite -is [array]) 
            {#more than 1 remote site target defined on the pd schedule
                Write-Host "$(get-date) [ERROR] There is more than one remote site for protection domain $pd" -ForegroundColor Red
                Exit 1
            }
        #endregion

        #region GET networks (-prism)
            if ($failover -ne "deactivate") {
                #get available networks from primary (/PrismGateway/services/rest/v2.0/networks/)
                Write-Host "$(get-date) [INFO] Retrieving available networks from Nutanix cluster $($prism)..." -ForegroundColor Green
                $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/networks/"
                $method = "GET"
                $prism_cluster_networks = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved networks from Nutanix cluster $($prism)" -ForegroundColor Cyan

                #TODO enhance this to show list of networks available + capture other network details (gateway, pool, subnet mask)  Also this should be asking/checking on target cluster, not prism
                $prism_client_network_name = Read-Host "Enter the name of the client network to use for the file server"
                $prism_storage_network_name = Read-Host "Enter the name of the storage network to use for the file server"
            }
        #endregion
        
        #region GET remote site details (PRISM)
            if ($failover -ne "deactivate") {
                #get the remote site IP address
                Write-Host "$(get-date) [INFO] Retrieving details about remote site $($remoteSite.remote_site_names) ..." -ForegroundColor Green
                $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/remote_sites/$($remoteSite.remote_site_names)"
                $method = "GET"
                $remote_site_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details about remote site $($remoteSite.remote_site_names)" -ForegroundColor Cyan

                if ($remote_site_details.remote_ip_ports.psobject.properties.count -gt 1)
                {#there are multiple IPs defined for the remote site
                    Write-Host "$(get-date) [ERROR] There is more than 1 IP configured for the remote site $remoteSite" -ForegroundColor Red
                    Exit 1
                }

                $remote_site_ip = $remote_site_details.remote_ip_ports.psobject.properties.name
            }    
        #endregion

        if ($failover -eq "planned") {
            $migrate_from_cluster = $prism
            $migrate_from_cluster_name = $prism_cluster_details.name
            $filer_activation_cluster = $remote_site_ip
            $filer_activation_cluster_name = $remote_cluster_details.name

            #region GET remote cluster details
                #check if remote site is available (IF not, error out)
                Write-Host "$(get-date) [INFO] Retrieving details of remote Nutanix cluster $($filer_activation_cluster) ..." -ForegroundColor Green
                $url = "https://$($filer_activation_cluster):9440/PrismGateway/services/rest/v2.0/cluster/"
                $method = "GET"
                $remote_cluster_details = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of remote Nutanix cluster $($filer_activation_cluster)" -ForegroundColor Cyan
                Write-Host "$(get-date) [INFO] Hypervisor on remote Nutanix cluster $($filer_activation_cluster) is of type $($remote_cluster_details.hypervisor_types)." -ForegroundColor Green

                #grab cluster name dns and ntp servers if they have not been specified in the reference data
                $remote_dns_servers = $remote_cluster_details.name_servers
                $remote_ntp_servers = $remote_cluster_details.ntp_servers
                $filer_activation_cluster_name = $remote_cluster_details.name
            #endregion

            $myvarvCenter = ($remote_cluster_details.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address

            #region GET remote cluster networks
                #get available networks from remote cluster (/PrismGateway/services/rest/v2.0/networks/)
                Write-Host "$(get-date) [INFO] Retrieving available networks from remote Nutanix cluster $($filer_activation_cluster)..." -ForegroundColor Green
                $url = "https://$($filer_activation_cluster):9440/PrismGateway/services/rest/v2.0/networks/"
                $method = "GET"
                $remote_cluster_networks = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved networks from remote Nutanix cluster $($filer_activation_cluster)" -ForegroundColor Cyan
                $remote_client_network_uuid = ($remote_cluster_networks.entities | Where-Object {$_.name -eq $prism_client_network_name}).uuid
                $remote_storage_network_uuid = ($remote_cluster_networks.entities | Where-Object {$_.name -eq $prism_storage_network_name}).uuid
                if (!$remote_client_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($prism_client_network_name) on remote Nutanix cluster $($filer_activation_cluster)!" -ForegroundColor Red; Exit 1}
                if (!$remote_storage_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($prism_storage_network_name) on remote Nutanix cluster $($filer_activation_cluster)!" -ForegroundColor Red; Exit 1}
                Write-Host "$(get-date) [INFO] Client network uuid on dr cluster is $($remote_client_network_uuid)" -ForegroundColor Green
                Write-Host "$(get-date) [INFO] Storage network uuid on dr cluster is $($remote_storage_network_uuid)" -ForegroundColor Green
            #endregion

            #region GET remote cluster vfiler
                #check status of file server on remote prism
                Write-Host "$(get-date) [INFO] Retrieving details of file server $fsname status from remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))..." -ForegroundColor Green
                $url = "https://$($filer_activation_cluster):9440/PrismGateway/services/rest/v1/vfilers/"
                $method = "GET"
                $remote_cluster_vfilers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                $remote_cluster_vfiler = $remote_cluster_vfilers.entities | Where-Object {$_.Name -eq $fsname}
                if (!$remote_cluster_vfiler) {Write-Host "$(get-date) [ERROR] Could not find a file server called $fsname on remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))!" -ForegroundColor Red; Exit 1}
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of file server $fsname status from remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))" -ForegroundColor Cyan
                Write-Host "$(get-date) [INFO] File server $fsname on remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name)) has the following status: $($prism_cluster_vfiler.fileServerState)" -ForegroundColor Green
            #endregion

            #region GET remote cluster protection domain
                #get protection domains from prism
                Write-Host "$(get-date) [INFO] Retrieving protection domains from remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))..." -ForegroundColor Green
                $url = "https://$($prism):9440/PrismGateway/services/rest/v2.0/protection_domains/"
                $method = "GET"
                $remote_pd_list = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))" -ForegroundColor Cyan
                
                $remote_vfiler_pd = $remote_pd_list.entities | Where-Object {$_.name -eq $pd}
                if (!$remote_vfiler_pd) {Write-Host "$(get-date) [ERROR] Could not find a protection domain called $pd on remote Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))!" -ForegroundColor Red; Exit 1}
            #endregion

            $filer_pd_vms = $prism_vfiler_pd.vms.vm_name
        }

        if ($failover -eq "unplanned") {
            $prism_dns_servers = $prism_cluster_details.name_servers
            $prism_ntp_servers = $prism_cluster_details.ntp_servers
            $filer_activation_cluster = $prism
            $filer_activation_cluster_name = $prism_cluster_details.name
            #! move this to after pd migration otherwise I won't get the vm list
            $filer_pd_vms = $prism_vfiler_pd.vms.vm_name
            $myvarvCenter = ($prism_cluster_details.management_servers | Where-Object {$_.management_server_type -eq "vcenter"}).ip_address
            $prism_client_network_uuid = ($prism_cluster_networks.entities | Where-Object {$_.name -eq $prism_client_network_name}).uuid
            $prism_storage_network_uuid = ($prism_cluster_networks.entities | Where-Object {$_.name -eq $prism_storage_network_name}).uuid
            if (!$prism_client_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($prism_client_network_name) on Nutanix cluster $($prism)!" -ForegroundColor Red; Exit 1}
            if (!$prism_storage_network_uuid) {Write-Host "$(get-date) [ERROR] Could not find a network named $($prism_storage_network_name) on Nutanix cluster $($prism)!" -ForegroundColor Red; Exit 1}
            Write-Host "$(get-date) [INFO] Client network uuid on cluster is $($prism_client_network_uuid)" -ForegroundColor Green
            Write-Host "$(get-date) [INFO] Storage network uuid on cluster is $($prism_storage_network_uuid)" -ForegroundColor Green
        }
    }

    #* Figuring out vfiler uuid and networks
    #get file servers uuids and other network configuration details required for activation
    if ($reference_data) {#we have a reference data file with all the info we need
        $fsname = "$($reference_data.fsname)"
        if ($filer_activation_cluster -eq $reference_data.{prism-primary}) {
            $vfiler_uuid = $primary_cluster_vfiler.uuid

            $client_network_name = $reference_data.{primary-client-network-name}
            $storage_network_name = $reference_data.{primary-storage-network-name}

            $internalNetwork_subnetMask = "$($reference_data.{primary-storage-network-subnet})"
            $internalNetwork_defaultGateway = "$($reference_data.{primary-storage-network-gateway})"
            $internalNetwork_uuid = "$($primary_storage_network_uuid)"
            if ($reference_data.{primary-storage-network-startip} -and $reference_data.{primary-storage-network-endip}) {
                $internalNetwork_pool = "$($reference_data.{primary-storage-network-startip}) $($reference_data.{primary-storage-network-endip})"
            } else {
                $internalNetwork_pool = $null
            }

            $externalNetwork_subnetMask = "$($reference_data.{primary-client-network-subnet})"
            $externalNetwork_defaultGateway = "$($reference_data.{primary-client-network-gateway})"
            $externalNetwork_uuid = "$($primary_client_network_uuid)"
            if ($reference_data.{primary-client-network-startip} -and $reference_data.{primary-client-network-endip}) {
                $externalNetwork_pool = "$($reference_data.{primary-client-network-startip}) $($reference_data.{primary-client-network-endip})"
            } else {
                $externalNetwork_pool = $null
            }

            $dns_servers = $primary_dns_servers
            $ntp_servers = $primary_ntp_servers
        } elseif ($filer_activation_cluster -eq $reference_data.{prism-dr}) {
            $vfiler_uuid = $dr_cluster_vfiler.uuid

            $client_network_name = $reference_data.{dr-client-network-name}
            $storage_network_name = $reference_data.{dr-storage-network-name}

            $internalNetwork_subnetMask = "$($reference_data.{dr-storage-network-subnet})"
            $internalNetwork_defaultGateway = "$($reference_data.{dr-storage-network-gateway})"
            $internalNetwork_uuid = "$($dr_storage_network_uuid)"
            $internalNetwork_pool = "$($reference_data.{dr-storage-network-startip}) $($reference_data.{dr-storage-network-endip})"

            $externalNetwork_subnetMask = "$($reference_data.{dr-client-network-subnet})"
            $externalNetwork_defaultGateway = "$($reference_data.{dr-client-network-gateway})"
            $externalNetwork_uuid = "$($dr_client_network_uuid)"
            $externalNetwork_pool = "$($reference_data.{dr-client-network-startip}) $($reference_data.{dr-client-network-endip})"

            $dns_servers = $dr_dns_servers
            $ntp_servers = $dr_ntp_servers
        }
    } else {#we don't have a reference data file and thus we must rely on user input
        #figure out which cluster we are activating this on and what the filer uuid is (this will vary based on planned or unplanned)
        if ($failover -eq "planned") {
            $vfiler_uuid = $remote_cluster_vfiler.uuid
            $dns_servers = $remote_dns_servers
            $ntp_servers = $remote_ntp_servers

            $client_network_name = $prism_client_network_name
            $storage_network_name = $prism_storage_network_name

            $internalNetwork_subnetMask = Read-Host "Enter the subnet mask (exp:255.255.255.0) for the storage network (leave blank if the network is managed)"
            $internalNetwork_defaultGateway = Read-Host "Enter the gateway ip for the storage network (leave blank if the network is managed)"
            $internalNetwork_uuid = "$($remote_storage_network_uuid)"
            $internalNetworkStartIp = Read-Host "Enter the start ip for the storage network (leave blank if the network is managed)"
            $internalNetworkEndIp = Read-Host "Enter the last ip for the storage network (leave blank if the network is managed)"
            $internalNetwork_pool = "$($internalNetworkStartIp) $($internalNetworkEndIp)"

            $externalNetwork_subnetMask = Read-Host "Enter the subnet mask (exp:255.255.255.0) for the client network (leave blank if the network is managed)"
            $externalNetwork_defaultGateway = Read-Host "Enter the gateway ip for the client network (leave blank if the network is managed)"
            $externalNetwork_uuid = "$($remote_client_network_uuid)"
            $externalNetworkStartIp = Read-Host "Enter the start ip for the client network (leave blank if the network is managed)"
            $externalNetworkEndIp = Read-Host "Enter the last ip for the client network (leave blank if the network is managed)"
            $externalNetwork_pool = "$($externalNetworkStartIp) $($externalNetworkEndIp)"
        }
        if ($failover -eq "unplanned") {
            $vfiler_uuid = $prism_cluster_vfiler.uuid
            $dns_servers = $prism_dns_servers
            $ntp_servers = $prism_ntp_servers

            $internalNetwork_subnetMask = Read-Host "Enter the subnet mask (exp:255.255.255.0) for the storage network (leave blank if the network is managed)"
            $internalNetwork_defaultGateway = Read-Host "Enter the gateway ip for the storage network (leave blank if the network is managed)"
            $internalNetwork_uuid = "$($prism_storage_network_uuid)"
            $internalNetworkStartIp = Read-Host "Enter the start ip for the storage network (leave blank if the network is managed)"
            $internalNetworkEndIp = Read-Host "Enter the last ip for the storage network (leave blank if the network is managed)"
            $internalNetwork_pool = "$($internalNetworkStartIp) $($internalNetworkEndIp)"

            $externalNetwork_subnetMask = Read-Host "Enter the subnet mask (exp:255.255.255.0) for the client network (leave blank if the network is managed)"
            $externalNetwork_defaultGateway = Read-Host "Enter the gateway ip for the client network (leave blank if the network is managed)"
            $externalNetwork_uuid = "$($prism_client_network_uuid)"
            $externalNetworkStartIp = Read-Host "Enter the start ip for the client network (leave blank if the network is managed)"
            $externalNetworkEndIp = Read-Host "Enter the last ip for the client network (leave blank if the network is managed)"
            $externalNetwork_pool = "$($externalNetworkStartIp) $($externalNetworkEndIp)"
        }
    }
#endregion

#region check vcenter connectivity (if dvswitch)
    if ($dvSwitch) {#user has specified dvswitch, so wee need to check connectivity to vcenter
        #region Load/Install VMware.PowerCLI
            if (!(Get-Module VMware.PowerCLI)) 
            {#module VMware.PowerCLI is not loaded
                try 
                {#load module VMware.PowerCLI
                    Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                    Import-Module VMware.PowerCLI -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
                }
                catch 
                {#couldn't load module VMware.PowerCLI
                    Write-Host "$(get-date) [WARNING] Could not load VMware.PowerCLI module!" -ForegroundColor Yellow
                    try 
                    {#install module VMware.PowerCLI
                        Write-Host "$(get-date) [INFO] Installing VMware.PowerCLI module..." -ForegroundColor Green
                        Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Installed VMware.PowerCLI module" -ForegroundColor Cyan
                        try 
                        {#loading module VMware.PowerCLI
                            Write-Host "$(get-date) [INFO] Loading VMware.PowerCLI module..." -ForegroundColor Green
                            Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] Loaded VMware.PowerCLI module" -ForegroundColor Cyan
                        }
                        catch 
                        {#couldn't load module VMware.PowerCLI
                            throw "$(get-date) [ERROR] Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
                        }
                    }
                    catch 
                    {#couldn't install module VMware.PowerCLI
                        throw "$(get-date) [ERROR] Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"
                    }
                }
            }
            
            if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
            {#check PowerCLI version
                try 
                {#update module VMware.PowerCLI
                    Update-Module -Name VMware.PowerCLI -ErrorAction Stop
                } 
                catch 
                {#couldn't update module VMware.PowerCLI
                    throw "$(get-date) [ERROR] Could not update the VMware.PowerCLI module : $($_.Exception.Message)"
                }
            }
            if ((Get-PowerCLIConfiguration | where-object {$_.Scope -eq "User"}).InvalidCertificateAction -ne "Ignore") {
                Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false
            }
        #endregion

        #region connect to vCenter
            try {
                Write-Host "$(get-date) [INFO] Connecting to vCenter server $myvarvCenter..." -ForegroundColor Green
                $myvarvCenterObject = Connect-VIServer $myvarvCenter -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Connected to vCenter server $myvarvCenter" -ForegroundColor Cyan
            }
            catch {throw "$(get-date) [ERROR] Could not connect to vCenter server $myvarvCenter : $($_.Exception.Message)"}
        #endregion
    }
#endregion

#region deactivate
    if ($failover -eq "deactivate") {
        Write-Host ""
        Write-Host "$(get-date) [STEP] --Deactivating Protection Domain Migration $($pd) on Nutanix cluster $($prism) ($($prism_cluster_details.name))--" -ForegroundColor Magenta

        Write-Host "$(get-date) [WARN] You are about to deactivate the protection domain $($pd) on Nutanix cluster $($prism_cluster_details.name). This will delete all the virtual machines and volume groups listed below and their associated data." -ForegroundColor Yellow
        Write-Host "$($prism_vfiler_pd.vms.vm_name)"
        Write-Host "$($prism_vfiler_pd.volume_groups.name)"
        $user_choice = Write-CustomPrompt

        if ($user_choice -eq "y") {
            $response = Invoke-NtnxPdDeactivation -pd $pd -cluster $prism -credential $prismCredentials
            Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $prism -credential $prismCredentials -operation "deactivate"
        }
    }
#endregion

#region failover pd
    if ($failover -eq "planned") {#doing a planned failover

        Write-Host ""
        Write-Host "$(get-date) [STEP] --Triggering Protection Domain Migration from $($migrate_from_cluster_name)--" -ForegroundColor Magenta 

        $processed_pds = Invoke-NtnxPdMigration -pd $pd -cluster $migrate_from_cluster -credential $prismCredentials
        if ($debugme) {Write-Host "$(get-date) [DEBUG] Processed pds: $processed_pds" -ForegroundColor White}
        Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $migrate_from_cluster -credential $prismCredentials -operation "deactivate"

        #check status of activation on remote site
        #region check remote
            #let's retrieve the list of protection domains
            Write-Host "$(get-date) [INFO] Retrieving protection domains from Nutanix cluster $migrate_from_cluster ..." -ForegroundColor Green
            $url = "https://$($migrate_from_cluster):9440/PrismGateway/services/rest/v2.0/protection_domains/"
            $method = "GET"
            $PdList = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved protection domains from Nutanix cluster $migrate_from_cluster" -ForegroundColor Cyan

            ForEach ($protection_domain in $processed_pds)
            {#figure out the remote site ips
                #region figure out the remote site
                    #figure out if there is more than one remote site defined for the protection domain
                    $remoteSite = $PdList.entities | Where-Object {$_.name -eq $protection_domain} | Select-Object -Property remote_site_names
                    if (!$remoteSite.remote_site_names) 
                    {#no remote site defined or no schedule on the pd with a remote site
                        Write-Host "$(get-date) [ERROR] There is no remote site defined for protection domain $protection_domain" -ForegroundColor Red
                        Exit
                    }
                    if ($remoteSite -is [array]) 
                    {#more than 1 remote site target defined on the pd schedule
                        Write-Host "$(get-date) [ERROR] There is more than one remote site for protection domain $protection_domain" -ForegroundColor Red
                        Exit
                    }

                    #get the remote site IP address
                    Write-Host "$(get-date) [INFO] Retrieving details about remote site $($remoteSite.remote_site_names) ..." -ForegroundColor Green
                    $url = "https://$($migrate_from_cluster):9440/PrismGateway/services/rest/v2.0/remote_sites/$($remoteSite.remote_site_names)"
                    $method = "GET"
                    $remote_site = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                    Write-Host "$(get-date) [SUCCESS] Successfully retrieved details about remote site $($remoteSite.remote_site_names)" -ForegroundColor Cyan

                    if ($remote_site.remote_ip_ports.psobject.properties.count -gt 1)
                    {#there are multiple IPs defined for the remote site
                        Write-Host "$(get-date) [ERROR] There is more than 1 IP configured for the remote site $remoteSite" -ForegroundColor Red
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
                Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $remote_site_ip -credential $prismCredentials -operation "activate"
            }
        #endregion

        #TODO check remote site configured on PD matches dr site in reference file
    }

    if ($failover -eq "unplanned") {#doing an unplanned failover (disaster)
        #region dvswitch shenanigans (removing disconnected fsvms from vcetner inventory)
            if ($dvswitch) {
                #get fsvms (name will be NTNX-fsname-*)
                $existing_filer_vms = Get-VM -Name "NTNX-$($fsname)-*" -ErrorAction SilentlyContinue
                if ($existing_filer_vms) {
                    if ($existing_filer_vms.ExtensionData.Summary.OverallStatus -eq "green") {#checking their status is not OK
                        Write-Host "$(get-date) [WARN] There are existing FSVMs for file server $($fsname) but their status is green. Skipping removal from inventory..." -ForegroundColor Yellow
                    } else {
                        Write-Host ""
                        Write-Host "$(get-date) [STEP] --Cleaning vCenter inventory--" -ForegroundColor Magenta
                        Write-Host "$(get-date) [INFO] There are existing FSVMs for file server $($fsname) and their status is not green. Removing them from vCenter inventory..." -ForegroundColor Green
                        Foreach ($existing_filer_vm in $existing_filer_vms) {#processing each fsvm and removing it from inventory
                            try
                            {
                                Write-Host "$(get-date) [INFO] Removing FSVM $($existing_filer_vm.Name) from the vCenter inventory..." -ForegroundColor Green
                                $result = Remove-Vm -VM $existing_filer_vm -DeletePermanently -Confirm:$false -ErrorAction Stop
                                Write-Host "$(get-date) [SUCCESS] Successfully removed FSVM $($existing_filer_vm.Name) from the vCenter inventory..." -ForegroundColor Cyan
                            }
                            catch
                            {
                                Write-Host "$(get-date) [WARN] Could not clean up vCenter inventory for FSVM $($existing_filer_vm.Name)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
            }
        #endregion

        #region protection domain activation
            Write-Host ""
            Write-Host "$(get-date) [STEP] --Triggering Protection Domain Activation--" -ForegroundColor Magenta

            if ($reference_data) {
                $cluster = $reference_data.{prism-dr}              
                if ($reference_data.pd) {
                    $pd = $reference_data.pd
                } else {
                    $pd = "NTNX-$($reference_data.fsname)"
                }
                
                #safeguard here to check if primary cluster is responding to ping before triggering activation
                Write-Host "$(get-date) [INFO] Trying to ping IP $($reference_data.{prism-primary}) ..." -ForegroundColor Green
                if ((Test-Connection $reference_data.{prism-primary} -Count 5))
                {#ping was successfull
                    if ($force) {
                        Write-Host "$(get-date) [WARN] Can ping primary site Nutanix cluster IP $($reference_data.{prism-primary}). Continuing with protection domain activation since you used -force..." -ForegroundColor Yellow
                        #TODO add prompt here to continue and enhance warning text
                    } else {
                        Write-Host "$(get-date) [ERROR] Can ping primary site Nutanix cluster IP $($reference_data.{prism-primary}). Aborting protection domain activation!" -ForegroundColor Red
                        Exit 1
                    }
                } 
                else 
                {#ping failed
                    Write-Host "$(get-date) [SUCCESS] Cannot ping primary site Nutanix cluster IP $($reference_data.{prism-primary}). Proceeding with protection domain activation on DR." -ForegroundColor Cyan
                }                
            } else {
                $cluster = $prism
                #TODO: add safeguard here to check if primary cluster is responding to ping before triggering activation

                #safeguard here to check if primary cluster is responding to ping before triggering activation
                Write-Host "$(get-date) [INFO] Trying to ping IP $($reference_data.{prism-primary}) ..." -ForegroundColor Green
                if ((Test-Connection $remote_site_ip -Count 5))
                {#ping was successfull
                    if ($force) {
                        Write-Host "$(get-date) [WARN] Can ping remote site Nutanix cluster IP $($remote_site_ip). Continuing with protection domain activation since you used -force..." -ForegroundColor Yellow
                        #TODO add prompt here to continue and enhance warning text
                    } else {
                        Write-Host "$(get-date) [ERROR] Can ping remote site Nutanix cluster IP $($remote_site_ip). Aborting protection domain activation!" -ForegroundColor Red
                        Exit 1
                    }
                } 
                else 
                {#ping failed
                    Write-Host "$(get-date) [SUCCESS] Cannot ping remote site Nutanix cluster IP $($remote_site_ip). Proceeding with protection domain activation on DR."
                }
            }

            $processed_pds = Invoke-NtnxPdActivation -pd $pd -cluster $cluster -credential $prismCredentials
            if ($debugme) {Write-Host "$(get-date) [DEBUG] Processed pds: $processed_pds" -ForegroundColor White}
            Get-PrismPdTaskStatus -time $StartEpochSeconds -cluster $cluster -credential $prismCredentials -operation "activate"
        #endregion
    }
    #TODO if MAIL, send notification email
#endregion

#region post pd migration actions (dvswitch shenanigans, file server activation and dns updates)
    if ($failover -ne "deactivate") {#nothing to do if this was a deactivation
        #region more dvswitch shenanigans (remapping network interfaces)
            if ($dvswitch) {
                if ($failover -eq "unplanned") {
                    #* querying the vfiler to extract the exact fsvm names (as they could have changed if this is a metro cluster)
                    #region GET vfiler (DR)
                        #check status of file server on dr
                        Write-Host "$(get-date) [INFO] Retrieving details of file server $fsname status from Nutanix cluster $($cluster)..." -ForegroundColor Green
                        $url = "https://$($cluster):9440/PrismGateway/services/rest/v1/vfilers/"
                        $method = "GET"
                        $cluster_vfilers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
                        $cluster_vfiler = $cluster_vfilers.entities | Where-Object {$_.Name -eq $fsname}
                        if (!$cluster_vfiler) {Write-Host "$(get-date) [ERROR] Could not find a file server called $fsname on Nutanix cluster $($cluster)!" -ForegroundColor Red; Exit 1}
                        Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of file server $fsname status from Nutanix cluster $($cluster)" -ForegroundColor Cyan
                        $filer_pd_vms = $cluster_vfiler.nvms.name
                    #endregion

                }

                ForEach ($filer_vm in $filer_pd_vms) {

                    #region check vm and vmnics
                        Write-Host "$(get-date) [INFO] Processing VM $($filer_vm) ..." -ForegroundColor Green
                        try
                        {#get vm object from vCenter
                            $vm_vCenter_object = Get-VM -Name $filer_vm -ErrorAction Stop
                        }
                        catch
                        {#couldn't get vm object from vCenter
                            Write-Host "$(get-date) [ERROR] Could not get VM object from vCenter server $myvarvCenter : $($_.Exception.Message)" -ForegroundColor Red
                            Exit 1
                        }
                        try
                        {#get the vnics for that vm from vCenter
                            $vm_vCenter_vnics = $vm_vCenter_object | Get-NetworkAdapter -ErrorAction Stop
                        }
                        catch
                        {#couldn't get vnics for that vm from vCenter
                            Write-Host "$(get-date) [ERROR] Could not vNICs for that VM object from vCenter server $myvarvCenter : $($_.Exception.Message)"
                            Exit 1
                        }
                    #endregion

                    #region reconnect vnics
                    ForEach ($vm_vCenter_vnic in $vm_vCenter_vnics)
                    {
                        #! this is a workaround for the bug where vdportgroups are not correctly mapped after the pd activation
                        if ($failover -eq "unplanned") {
                            if ($vm_vCenter_vnic -eq $vm_vCenter_vnics[0]) {
                                $target_vdportgroup = $reference_data.{dr-storage-network-name}
                            }
                            if ($vm_vCenter_vnic -eq $vm_vCenter_vnics[1]) {
                                $target_vdportgroup = $reference_data.{dr-client-network-name}
                            }
                        } else {
                            $target_vdportgroup = $vm_vCenter_vnic.NetworkName
                        }

                        try 
                        {#get vdportgroup
                            Write-Host "$(get-date) [INFO] Searching for $($vm_vCenter_vnic.NetworkName) ..." -ForegroundColor Green
                            $vdportgroup = Get-VDPortgroup -Name $target_vdportgroup -ErrorAction Stop
                            Write-Host "$(get-date) [SUCCESS] $($vm_vCenter_vnic.NetworkName) is a VDPortGroup." -ForegroundColor Cyan
                        }
                        catch 
                        {#no vdportgroup
                            Write-Host "$(get-date) [WARNING] $($vm_vCenter_vnic.NetworkName) is not a VDPortGroup or we could not retrieve it from vCenter. Skipping this vnic." -ForegroundColor Yellow
                            Continue
                        }
                        if ($vdportgroup)
                        {#got a vdportgroup
                            try 
                            {#reconnect vnic
                                Write-Host "$(get-date) [INFO] Reconnecting $($prism_processed_pd_vm.vm_name) to VDPortGroup $($vm_vCenter_vnic.NetworkName) ..." -ForegroundColor Green
                                $connect_vnic = Set-NetworkAdapter -NetworkAdapter $vm_vCenter_vnic -PortGroup $vdportgroup -ErrorAction Stop -Confirm:$false
                                $connect_vnic = Set-NetworkAdapter -NetworkAdapter $vm_vCenter_vnic -StartConnected:$true -ErrorAction Stop -Confirm:$false
                                Write-Host "$(get-date) [SUCCESS] Successfully reconnected $($prism_processed_pd_vm.vm_name) to VDPortGroup $($vm_vCenter_vnic.NetworkName) ..." -ForegroundColor Cyan
                            }
                            catch 
                            {#couldn't reconnect vnic
                                Write-Host "$(get-date) [ERROR] Could not reconnect $($prism_processed_pd_vm.vm_name) to VDPortGroup $($vm_vCenter_vnic.NetworkName) : $($_.Exception.Message)" -ForegroundColor Red
                                Exit 1
                            }
                        }
                    }
                    #endregion
                }

                #disconnect from vcenter
                Disconnect-viserver * -Confirm:$False
            }
        #endregion

        #region activate file server
            Write-Host ""
            Write-Host "$(get-date) [STEP] --Activating vFiler $($fsname) on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))--" -ForegroundColor Magenta
            
            #build the json payload here
            $content = @{
                name = $fsname;
                internalNetwork = @{
                    subnetMask = $internalNetwork_subnetMask;
                    defaultGateway = $internalNetwork_defaultGateway;
                    uuid = $internalNetwork_uuid;
                    pool = @(
                        $(if ($internalNetwork_pool) {$internalNetwork_pool})
                    )
                };
                externalNetworks = @(
                    @{
                        subnetMask = $externalNetwork_subnetMask;
                        defaultGateway = $externalNetwork_defaultGateway;
                        uuid = $externalNetwork_uuid;
                        pool = @(
                            $(if ($externalNetwork_pool) {$externalNetwork_pool})
                        )
                    }
                );
                dnsServerIpAddresses = @(
                    $dns_servers
                );
                ntpServers = @(
                    $ntp_servers
                )
            }
            $payload = (ConvertTo-Json $content -Depth 4)

            #* activate (POST /v1/vfilers/{$vfiler_uuid}/activate): response is a taskUuid
            Write-Host "$(get-date) [INFO] Activating file server $($fsname) on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))..." -ForegroundColor Green
            $url = "https://$($filer_activation_cluster):9440/PrismGateway/services/rest/v1/vfilers/$($vfiler_uuid)/activate"
            $method = "POST"
            $vfiler_activation_task_uuid = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
            Write-Host "$(get-date) [SUCCESS] Successfully triggered activation of file server $($fsname) on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name)) (task: $($vfiler_activation_task_uuid.taskUuid))" -ForegroundColor Cyan

            #check on file server activation task status
            Get-PrismTaskStatus -task $vfiler_activation_task_uuid.taskUuid -cluster $filer_activation_cluster -credential $prismCredentials
            
            #TODO if MAIL, send notification email
        #endregion
        
        #region update DNS
            if ($dns) {
                Write-Host ""
                Write-Host "$(get-date) [STEP] --Updating DNS records for vFiler $($fsname) on cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))--" -ForegroundColor Magenta
                #if DNS, send API call to update DNS            
                $content = @{
                    dnsOpType = "MS_DNS";
                    dnsServer= "";
                    dnsUserName= $ad_credentials.UserName;
                    dnsPassword= $ad_credentials.GetNetworkCredential().password
                }
                $payload = (ConvertTo-Json $content -Depth 4)
        
                #* activate (POST /v1/vfilers/$($file_server_uuid)/addDns): response is a taskUuid
                Write-Host "$(get-date) [INFO] Updating DNS records for file server $($fsname) on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))..." -ForegroundColor Green
                $url = "https://$($filer_activation_cluster):9440/PrismGateway/services/rest/v1/vfilers/$($vfiler_uuid)/addDns"
                $method = "POST"
                $vfiler_dns_update_task_uuid = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials -payload $payload
                Write-Host "$(get-date) [SUCCESS] Successfully triggered update of DNS records for file server $($fsname) on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name)) (task: $($vfiler_activation_task_uuid.taskUuid))" -ForegroundColor Cyan

                #check on DNS update task status
                Get-PrismTaskStatus -task $vfiler_dns_update_task_uuid.taskUuid -cluster $filer_activation_cluster -credential $prismCredentials

                #TODO if MAIL, send notification email
            }
        #endregion

        #region print final file server status
            Write-Host ""
            Write-Host "$(get-date) [STEP] --Getting final status for vFiler $($fsname) on cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))--" -ForegroundColor Magenta
            #check status of file server
            Write-Host "$(get-date) [INFO] Retrieving details of file server $fsname status from Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))..." -ForegroundColor Green
            $url = "https://$($filer_activation_cluster):9440/PrismGateway/services/rest/v1/vfilers/"
            $method = "GET"
            $vfilers = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            $vfiler = $vfilers.entities | Where-Object {$_.Name -eq $fsname}
            if (!$vfiler) {Write-Host "$(get-date) [ERROR] Could not find a file server called $fsname on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))!" -ForegroundColor Red; Exit 1}
            Write-Host "$(get-date) [SUCCESS] Successfully retrieved details of file server $fsname status from Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name))" -ForegroundColor Cyan
            Write-Host "$(get-date) [INFO] File server $fsname on Nutanix cluster $($filer_activation_cluster) ($($filer_activation_cluster_name)) has the following status: $($vfiler.fileServerState)" -ForegroundColor Green
            #TODO if MAIL, send notification email
        #endregion
    }
#endregion

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
Remove-Variable username -ErrorAction SilentlyContinue
Remove-Variable password -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion