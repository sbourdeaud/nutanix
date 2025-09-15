<#
.SYNOPSIS
  This script can be used to retrieve Prism Central audit entries for one or multiple virtual machines or for all VMs belonging to a given category for a given period of time specified in days.
.DESCRIPTION
  This script can be used to retrieve Prism Central audit entries for one or multiple virtual machines or for all VMs belonging to a given category for a given period of time specified in days. Output can be console text, csv and/or html.  Html report produces a searchable table which can also be exported to Excel.
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
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt). These credentials can be created using the Powershell command 'Set-CustomCredentials -credname <credentials name>'. See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0#how-secure-is-securestring for more details.
.PARAMETER vm
  Specifies the name of one or more virtual machine which you want to audit.  Multiple names can be specified in a comma separated list.  You can also specify 'all' to audit all virtual machines.
.PARAMETER category
  Specified the category:value pair for which you want to retrieve audit entries.  Multiple category:value pairs can be specified in a comma separated list.
.PARAMETER days
  Specifies as an integer the number of days you want the audit entries for.  Note that Prism Central maximum retention is 365 days.
.PARAMETER csv
  Specifies you want a csv file with all the audit entries.  You can specify the directory (default will be current directory) with the -dir parameter.
.PARAMETER html
  Specifies you want an html report with all the audit entries.  You can specify the directory (default will be current directory) with the -dir parameter.
.PARAMETER dir
  Use this parameter to specify the path where you want csv and/or html files to be saved.  By default, the script will save those in the current directory.
.EXAMPLE
.\get-audits.ps1 -prismcentral ntnxc1.local -category mycategory:myvalue -days 3 -html -dir d:\reports
Retrieves all audit entries for all VMs categorized with mycategory:myvalue for the last 3 days and produces an html report which will be saved in the d:\reports directory.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 15th 2021
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
        [parameter(mandatory = $false)] [string]$vm,
        [parameter(mandatory = $false)] [string]$category,
        [parameter(mandatory = $false)] [int]$days,
        [parameter(mandatory = $false)] [switch]$csv,
        [parameter(mandatory = $false)] [switch]$html,
        [parameter(mandatory = $false)] [string]$dir
    )
#endregion

#region functions

#endregion

#region prepwork
    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
02/15/2021 sb   Initial release.
################################################################################
'@
    $myvarScriptName = ".\get-audits.ps1"

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

    #region module PSWriteHTML
        if ($html)
        {#we need html output, so let's load the PSWriteHTML module
            if (!(Get-Module -Name PSWriteHTML)) 
            {#we could not get the module, let's try to load it
                try
                {#import the module
                    Import-Module -Name PSWriteHTML -ErrorAction Stop
                    Write-Host "$(get-date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
                }#end try
                catch 
                {#we couldn't import the module, so let's install it
                    Write-Host "$(get-date) [INFO] Installing module 'PSWriteHTML' from the Powershell Gallery..." -ForegroundColor Green
                    try {Install-Module -Name PSWriteHTML -Scope CurrentUser -Force -ErrorAction Stop}
                    catch {throw "$(get-date) [ERROR] Could not install module 'PSWriteHTML': $($_.Exception.Message)"}

                    try
                    {#now that it is intalled, let's import it
                        Import-Module -Name PSWriteHTML -ErrorAction Stop
                        Write-Host "$(get-date) [SUCCESS] Imported module 'PSWriteHTML'!" -ForegroundColor Cyan
                    }#end try
                    catch 
                    {#we couldn't import the module
                        Write-Host "$(get-date) [ERROR] Unable to import the module PSWriteHTML.psm1 : $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "$(get-date) [WARNING] Please download and install from https://www.powershellgallery.com/packages/PSWriteHTML/0.0.132" -ForegroundColor Yellow
                        Exit
                    }#end catch
                }#end catch
            }
        }
    #endregion
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
    $length = 200 #this is used to specify how many objects are returned for v3 Prism REST API calls
    $api_server_port = 9440 #this is the default Prism Central TCP port for the REST API
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
    
    if ((!$vm) -and (!$category))
    {#no vm or category was specified
        Throw "$(Get-Date) [ERROR] You must specify a vm or a category!"
    }
    elseif ($vm -and $category) 
    {#both a vm and category were specified
        Throw "$(Get-Date) [ERROR] You must specify a vm or a category but not both!"
    }

    if ($category)
    {#one or more categories were specified
        $myvar_category_list = $category.Split(",")
    }

    if ($vm)
    {#a vm was specified
        $myvar_vm_list = $vm.Split(",")
    }

    if ($dir)
    {#a path was specified to save files into

    }
#endregion

#region processing
    #region get information from Prism Central
        #region get audits
            Write-Host "$(Get-Date) [INFO] Retrieving audit entries from Prism Central $($prismcentral)" -ForegroundColor Green
            [System.Collections.ArrayList]$myvar_audit_results = New-Object System.Collections.ArrayList($null)
            $content = @{
                kind="audit";
                offset=0;
                length=$length
            }
            $payload = (ConvertTo-Json $content -Depth 4)
            Do 
            {#loop on v3 API call until there are no more objects
                try 
                {
                    $api_server_endpoint = "/api/nutanix/v3/audits/list"
                    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                    $method = "POST"
                    $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                    $listLength = 0
                    if ($resp.metadata.offset) 
                    {#gifuring out which object page we are looking at
                        $firstItem = $resp.metadata.offset
                    } 
                    else 
                    {#this is the first page of objects retrieved
                        $firstItem = 0
                    }
                    if (($resp.metadata.length -le $length) -and ($resp.metadata.length -ne 1)) 
                    {#there are more objects to retrieve
                        $listLength = $resp.metadata.length
                    } 
                    else 
                    {#there are no more objects to retrieve
                        $listLength = $resp.metadata.total_matches
                    }
                    Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.metadata.total_matches)" -ForegroundColor Green
                    if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
        
                    #grab the information we need in each entity
                    ForEach ($entity in $resp.entities) 
                    {#process each entity in the result
                        $myvar_entity_info = [ordered]@{
                            "audit_message" = $entity.status.audit_message;
                            "entity_type" = $entity.staus.source_entity_reference.type;
                            "entity_name" = $entity.staus.source_entity_reference.name;
                            "operation_date" = $entity.status.operation_complete_time;
                            "operation_status" = $entity.status.state;
                            "operation_type" = $entity.status.operation_type;
                            "user" = $entity.status.initiated_user.name;
                        }
                    }
                    #store the results for this entity in our overall result variable
                    $myvar_audit_results.Add((New-Object PSObject -Property $myvar_entity_info)) | Out-Null
        
                    #prepare the json payload for the next batch of entities/response
                    $content = @{
                        kind="audit";
                        offset=($resp.metadata.length + $resp.metadata.offset);
                        length=$length
                    }
                    $payload = (ConvertTo-Json $content -Depth 4)
                }
                catch 
                {
                    $saved_error = $_.Exception.Message
                    # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                    Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                    Throw "$(get-date) [ERROR] $saved_error"
                }
            }
            While ($resp.metadata.length -eq $length)
        #endregion

        #region query category
        if ($category)
        {#we are filtering based on category membership
            [System.Collections.ArrayList]$myvar_audit_filtered_results = New-Object System.Collections.ArrayList($null)
            ForEach ($myvar_category in $myvar_category_list)
            {#process each category
                Write-Host "$(Get-Date) [INFO] Processing entries for category $($category) from Prism Central $($prismcentral)" -ForegroundColor Green
                [System.Collections.ArrayList]$myvar_members_results = New-Object System.Collections.ArrayList($null)
                $myvar_category = $myvar_category.Split(":")
                if ($myvar_category.count -ne 2) 
                {#category was incorrectly specified
                    Throw "$(Get-Date) [ERROR] Categories must be specifed as a key:value pair. For example: mycategoryname:myvalue"
                }
                $content = @{
                    api_version= "3.1.0";
                    group_member_count= $length;
                    usage_type= "APPLIED_TO";
                    category_filter= @{
                        type= "CATEGORIES_MATCH_ANY";
                        params= @{
                            $myvar_category[0]= @($myvar_category[1])
                        }
                    }
                }
                $payload = (ConvertTo-Json $content -Depth 9)
                Do 
                {#loop on v3 API call until there are no more objects
                    try 
                    {
                        $api_server_endpoint = "/api/nutanix/v3/category/query"
                        $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                        $method = "POST"
                        $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                        $listLength = 0
                        if ($resp.metadata.group_member_offset) 
                        {#gifuring out which object page we are looking at
                            $firstItem = $resp.metadata.group_member_offset
                        } 
                        else 
                        {#this is the first page of objects retrieved
                            $firstItem = 0
                        }
                        if (($resp.metadata.total_matches -le $length) -and ($resp.metadata.total_matches -ne 1)) 
                        {#there are more objects to retrieve
                            $listLength = $resp.metadata.total_matches
                        } 
                        else 
                        {#there are no more objects to retrieve
                            $listLength = $resp.results.total_entity_count
                        }
                        Write-Host "$(Get-Date) [INFO] Processing results from $($firstItem) to $($firstItem + $listLength) out of $($resp.results.total_entity_count)" -ForegroundColor Green
                        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
            
                        #grab the information we need in each entity
                        ForEach ($entity in $resp.entities) 
                        {#process each entity in the result
                            $myvar_entity_info = [ordered]@{
                                "audit_message" = $entity.status.audit_message;
                                "entity_type" = $entity.staus.source_entity_reference.type;
                                "entity_name" = $entity.staus.source_entity_reference.name;
                                "operation_date" = $entity.status.operation_complete_time;
                                "operation_status" = $entity.status.state;
                                "operation_type" = $entity.status.operation_type;
                                "user" = $entity.status.initiated_user.name;
                            }
                        }
                        #store the results for this entity in our overall result variable
                        $myvar_members_results.Add((New-Object PSObject -Property $myvar_entity_info)) | Out-Null
            
                        #prepare the json payload for the next batch of entities/response
                        $content = @{
                            api_version= "3.1.0";
                            group_member_count= $length;
                            group_member_offset= ($resp.metadata.total_matches + $resp.metadata.group_member_offset);
                            usage_type= "APPLIED_TO";
                            category_filter= @{
                                type= "CATEGORIES_MATCH_ANY";
                                params= @{
                                    $myvar_category[0]= @($myvar_category[1])
                                }
                            }
                        }
                        $payload = (ConvertTo-Json $content -Depth 4)
                    }
                    catch 
                    {
                        $saved_error = $_.Exception.Message
                        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
                        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
                        Throw "$(get-date) [ERROR] $saved_error"
                    }
                }
                While ($resp.results.filtered_entity_count -eq $length)
                $myvar_member_vms = ($myvar_members_results | Where-Object {$_.kind -eq "vm"}).Name
                ForEach ($myvar_audit_entry in $myvar_audit_results)
                {#process each audit entry in the results list
                    if ($myvar_audit_entry.entity_name -in $myvar_member_vms)
                    {#the entity name in the audit entry matches a vm name in the category:value members
                        $myvar_audit_filtered_results.Add((New-Object PSObject -Property $myvar_audit_entry)) | Out-Null
                    }
                }
            }
        }
        $myvar_audit_filtered_results
        #endregion
    
        #region filter vms

        #endregion
    #endregion

    #region generate output
        #region console output
        #endregion

        #region csv output
        #endregion

        #region html output
        #endregion
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