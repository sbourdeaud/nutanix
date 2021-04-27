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
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER vms
  One or more vm name(s) (comma separated).
.PARAMETER network
  AHV network name you want to connect the specified vm(s) to.
.PARAMETER skiptaskstatuscheck
  Do not check each vm update task status.
.EXAMPLE
.\set-AhvVmNetwork.ps1 -cluster ntnxc1.local -vm myvm -network mynetwork
Connect myvm to the mynetwork AHV network:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: April 27th 2021
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$log,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $false)] $prismCreds,
        [parameter(mandatory = $true)] [string]$vms,
        [parameter(mandatory = $true)] [string]$network,
        [parameter(mandatory = $false)] [switch]$skiptaskstatuscheck
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
#endregion

#region prepwork
    $myvar_history_text = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/27/2021 sb   Initial release.
################################################################################
'@
    $myvar_script_name = ".\set-AhvVmNetwork.ps1"

    if ($help) {get-help $myvar_script_name; exit}
    if ($History) {$myvar_history_text; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    #region module sbourdeaud is used for facilitating Prism REST calls
        if (!(Get-Module -Name sbourdeaud)) {
            Write-Host "$(get-date) [INFO] Importing module 'sbourdeaud'..." -ForegroundColor Green
            try
            {
                Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
                Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
            }#end try
            catch #we couldn't import the module, so let's install it
            {
                Write-Host "$(get-date) [INFO] Installing module 'sbourdeaud' from the Powershell Gallery..." -ForegroundColor Green
                try {Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop}
                catch {throw "$(get-date) [ERROR] Could not install module 'sbourdeaud': $($_.Exception.Message)"}

                try
                {
                    Import-Module -Name sbourdeaud -MinimumVersion $required_version -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Imported module 'sbourdeaud'!" -ForegroundColor Cyan
                }#end try
                catch #we couldn't import the module
                {
                    Write-Host "$(get-date) [ERROR] Unable to import the module sbourdeaud.psm1 : $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/sbourdeaud/1.1" -ForegroundColor Yellow
                    Exit
                }#end catch
            }#end catch
        }#endif module sbourdeaud
        if (!(CheckModule -module "sbourdeaud" -version "3.1")) 
        {
            do 
            { 
                $askyesno = (Read-Host "Do you want to update Module sbourdeaud (Y/N)").ToLower() 
            } while ($askyesno -notin @('y','n'))

            if ($askyesno -eq 'y') 
            {
                Write-Host "$(get-date) [INFO] Selected YES Updating module sbourdeaud" -ForegroundColor Green
                Update-Module -Name sbourdeaud -Verbose -Force
            } 
            else 
            {
                Write-Host "$(get-date) [WARNING] Selected NO , no updates to Module sbourdeaud were done" -ForegroundColor Yellow
            }
        }
    #endregion
    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvar_elapsed_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $myvar_api_server_port="9440"
    $myvar_length=100
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
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        catch 
        {
            Set-CustomCredentials -credname $prismCreds
            $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
            $username = $prismCredentials.UserName
            $PrismSecurePassword = $prismCredentials.Password
        }
        $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
    }

    #assume vms is a list
    $myvar_vms = $vms.Split("{,}")
#endregion

#region processing
    #region get cluster info, check it is AHV
        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving cluster information from $($cluster)..."
        $myvar_url = "https://{0}:{1}/PrismGateway/services/rest/v2.0/cluster/" -f $cluster,$myvar_api_server_port
        $myvar_method = "GET"
        $myvar_cluster = Get-PrismRESTCall -method $myvar_method -url $myvar_url -credential $prismCredentials
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
        $myvar_vm_list = Get-PrismRESTCall -method $myvar_method -url $myvar_url -credential $prismCredentials
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
        $myvar_network_list = Get-PrismRESTCall -method $myvar_method -url $myvar_url -credential $prismCredentials
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
            $myvar_vm_update_task = Get-PrismRESTCall -method $myvar_method -url $myvar_url -credential $prismCredentials -payload $myvar_payload
            Write-LogOutput -Category "SUCCESS" -LogFile $myvar_log_file -Message "Successfully requested connection of vm $($myvar_vm.name) to network $($network)!"

            #task status check
            if (!$skiptaskstatuscheck)
            {
                Get-PrismTaskStatus -task $myvar_vm_update_task.task_uuid -credential $prismCredentials -cluster $cluster
            }
        }
    #endregion

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