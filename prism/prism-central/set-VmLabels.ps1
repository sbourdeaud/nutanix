<#
.SYNOPSIS
  Use this script to add one or more labels to virtual machines managed by Prism Central.
.DESCRIPTION
  Use this script to add one or more labels to virtual machines managed by Prism Central.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central instance fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ for more details.
.PARAMETER action
  Can be add or remove.
.PARAMETER vms
  One or more vm name (comma separated) to which you want to add or remove labels.
.PARAMETER labels
  One or more label that you want to apply to the specified vm(s). If the label does not exist, you will be prompted to create it.
.EXAMPLE
.\set-VmLabels.ps1 -prismcentral ntnxc1.local -labels "mylabel1,mylabel2" -vms "myvm1,myvm2" -action add
Connect to a Nutanix cluster of your choice:
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: October 26th 2022
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
    [parameter(mandatory = $false)] $prismCreds,
    [parameter(mandatory = $true)] [string][ValidateSet("add","remove")]$action,
    [parameter(mandatory = $true)] [string]$vms,
    [parameter(mandatory = $true)] [string]$labels
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
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
04/26/2021 sb   Initial release.
10/26/2022 sb   Tested version for add action.
################################################################################
'@
    $myvarScriptName = ".\set-VmLabels.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #check if we have all the required PoSH modules
    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Checking for required Powershell modules..."

    #region module sbourdeaud is used for facilitating Prism REST calls
        $required_version = "3.0.8"
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
        $MyVarModuleVersion = Get-Module -Name sbourdeaud | Select-Object -Property Version
        if (($MyVarModuleVersion.Version.Major -lt $($required_version.split('.')[0])) -or (($MyVarModuleVersion.Version.Major -eq $($required_version.split('.')[0])) -and ($MyVarModuleVersion.Version.Minor -eq $($required_version.split('.')[1])) -and ($MyVarModuleVersion.Version.Build -lt $($required_version.split('.')[2])))) {
            Write-Host "$(get-date) [INFO] Updating module 'sbourdeaud'..." -ForegroundColor Green
            Remove-Module -Name sbourdeaud -ErrorAction SilentlyContinue
            Uninstall-Module -Name sbourdeaud -ErrorAction SilentlyContinue
            try {
                Update-Module -Name sbourdeaud -Scope CurrentUser -ErrorAction Stop
                Import-Module -Name sbourdeaud -ErrorAction Stop
            }
            catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
        }
    #endregion
    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $api_server_port="9440"
    $length=100
    [System.Collections.ArrayList]$myvar_clusters_list = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$myvar_vms_list = New-Object System.Collections.ArrayList($null)
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
    $vms = $vms.Split(",")
    $labels = $labels.Split(",")
#endregion

#region processing

    #todo: get all vms from prism central
    #! need to use a v2 call as v3 only lists ahv vms: does v2 call from PC work?
    #todo: get all labels from prism central
    #todo: check specified vm(s) exist
    #todo: check specified label(s) exist, if not, prompt for creation and create
    #todo: apply all specified labels to all specified vms

    #! below: reusable code

    #* get clusters (results stored in $myvar_cluster_list)
    #region get clusters
        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving information about managed clusters..."
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/clusters/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            # this is used to capture the content of the payload
            $content = @{
                kind="cluster";
                offset=0;
                length=$length;
                sort_order="ASCENDING";
                sort_attribute="name"
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make api call
            Do {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials

                #region deal with offset for v3 API
                    $listLength = 0
                    if ($resp.metadata.offset) {
                        $firstItem = $resp.metadata.offset
                    } else {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                        $listLength = $resp.metadata.length
                    } else {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
                #endregion

                ForEach ($entity in $resp.entities) {
                    $myvar_cluster_info = [ordered]@{
                        "name" = $entity.status.name;
                        "uuid" = $entity.metadata.uuid
                    }
                    $myvar_clusters_list.Add((New-Object PSObject -Property $myvar_cluster_info)) | Out-Null
                }

                #prepare the json payload for the next batch of entities/response
                $content = @{
                    kind="cluster";
                    offset=($resp.metadata.length + $offset);
                    length=$length;
                    sort_order="ASCENDING";
                    sort_attribute="name"
                }
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)
        #endregion
    #endregion

    #* get vms (results stored in $myvar_vm_results)
    #region get vms
        Write-LogOutput -Category "INFO" -LogFile $myvar_log_file -Message "Retrieving information about AHV vms..."
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/vms/list"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"
            # this is used to capture the content of the payload
            $content = @{
                kind="vm";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
        #endregion

        #region make api call
            Do 
            {
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials

                #region deal with offset for v3 API
                    $listLength = 0
                    if ($resp.metadata.offset) {
                        $firstItem = $resp.metadata.offset
                    } else {
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) {
                        $listLength = $resp.metadata.length
                    } else {
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
                #endregion

                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) {
                    $myvar_vm_info = [ordered]@{
                        "name" = $entity.spec.name;
                        "power_state" = $entity.spec.resources.power_state;
                        "cluster" = $entity.spec.cluster_reference.name;
                        "uuid" = $entity.metadata.uuid
                    }
                    #store the results for this entity in our overall result variable
                    $myvar_vms_list.Add((New-Object PSObject -Property $myvar_vm_info)) | Out-Null
                }

                #prepare the json payload for the next batch of entities/response
                $content = @{
                    kind="vm";
                    offset=(($resp.entities).count + $resp.metadata.offset);
                    length=$length
                }
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)

            if (!$myvar_vms_list) 
            {
                Write-Host "$(Get-Date) [ERROR] Query did not return any results/vms on Prism Central $($prismcentral)" -ForegroundColor Red
                Exit 1
            } 
            else 
            {
                Write-Host "$(Get-Date) [SUCCESS] Retrieved list of virtual machines from Prism Central $($prismcentral)" -ForegroundColor Cyan
            }

            if ($debugme) 
            {
                Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
                ForEach ($vm in $myvar_vms_list) {
                    Write-Host "$vm" -ForegroundColor White
                }
            }
        #endregion
    #endregion

    #* get existing tags (results stored in $pc_tags)
    #region get tags
        #region prepare api call
            $api_server_endpoint = "/PrismGateway/services/rest/v1/tags"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "GET"
        #endregion

        #region making the api call
            $myvar_pc_tags = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
        #endregion
    #endregion

    #* creating default tags if necessary
    #region creating tags
        #region prepare api call
            $api_server_endpoint = "/PrismGateway/services/rest/v1/tags"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"
        #endregion

        #region make the api call
            Foreach ($myvar_label in $labels)
            {
                # this is used to capture the content of the payload
                $content = @{
                    name=$myvar_label;
                    entityType="vm";
                    description=$null
                }
                $payload = (ConvertTo-Json $content -Depth 4)

                if (($myvar_pc_tags.entities.name) -contains $myvar_label) 
                {
                    Write-Host "$(Get-Date) [INFO] Tag $($myvar_label) already exists on Prism Central $($prismcentral)" -ForegroundColor Green
                } 
                else 
                {
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                }
            }
        #endregion
    #endregion

    #* refresh existing tags (results stored in $pc_tags)
    #region get tags
        #region prepare api call
        $api_server_endpoint = "/PrismGateway/services/rest/v1/tags"
        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
        $method = "GET"
    #endregion

    #region making the api call
        $myvar_pc_tags = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
    #endregion
#endregion

    #* tagging vms
    #region tagging vms
        #build list of vm uuids
        #$myvar_vms_to_process = Compare-Object -ReferenceObject $myvar_vms_list -DifferenceObject $tagRef -Property name -IncludeEqual -PassThru | Where-Object -Property SideIndicator -eq "=="
        $myvar_vms_to_process = $myvar_vms_list | ?{$_.name -in $vms}
        #build list of tag uuids
        $myvar_tags_to_process = $myvar_pc_tags.entities | ?{$_.name -in $labels}

        ForEach ($myvar_tag in $myvar_tags_to_process) {
            #region prepare api call
                $vm_uuid_list = $myvar_vms_to_process.uuid                
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] List of uuids for Vms to process: $($vm_uuid_list)" -ForegroundColor White}
                if (!$vm_uuid_list) {continue}

                #build json payload
                $content = @{
                    tagUuid=$myvar_tag.uuid;
                    entitiesList=@(ForEach ($vm_uuid in $vm_uuid_list) {
                        @{
                            entityUuid=$vm_uuid;
                            entityType="vm"
                        }
                    }
                    )
                }
                $payload = (ConvertTo-Json $content -Depth 4)
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Payload: $($payload)" -ForegroundColor White}

                $api_server_endpoint = "/PrismGateway/services/rest/v1/tags/add_entities/fanout?async=true"
                $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                $method = "POST"
            #endregion
            
            #region make api call to add entities to tag
                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
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
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion