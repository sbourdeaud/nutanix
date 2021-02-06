<#
.SYNOPSIS
  This script powers on virtual machines using the Prism Central v3 API in a 
  specific sequence.
.DESCRIPTION
  The power on sequence is specified using labels/groups in Prism Central, or 
  by specifying a reference file.  
  The script can also be used to do the inital tagging by using a reference 
  csv file.
  Only VMs specified or tagged with the specified labels will be powered on.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart 
  enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as 
  well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER prismcentral
  Nutanix Prism Central fully qualified domain name or IP address.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for 
  %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on 
  Windows or in $home/$prismCreds.txt on Mac and Linux).
.PARAMETER labels
  By default, the script will use boot_priority_1, boot_priority_2 up to 5.  
  If you want to use different labels, you can use this parameter and specify 
  the label names, in order, separated by commas.  VMs with no labels will 
  remain untouched.
.PARAMETER delay
  By default, the script waits for 180 seconds (3 minutes) between each 
  sequence. You can customize this delay in seconds by using this parameter.
.PARAMETER sequence
  By default, the script will use labels to determine the power on sequence.  
  If -sequence is used, you can specify a reference csv file name which 
  contains the vm name followed by an integer (1,2,3, etc...) to determine the 
  sequence yourself.
.PARAMETER tag
  Use this parameter, followed by a csv file name (with name[string], 
  boot_priority[int]) to tag initially your vms. It will label them with 
  boot_priority_1, 2 up to 5 based on that csv file content.
.PARAMETER cluster
  Limit processing VMs to the specified cluster.
.EXAMPLE
.\Invoke-PcVmPowerOnSequence.ps1 -prismCentral pc.domain.com
Power on all VMs in the specified Prism Central based on their labels: boot_priority_1 labelled Vms will power on first, then boot_priority_2 labelled Vms, etc... up to boot_priority_5 labelled VMs.  All remaining Vms (with no label) will remain untouched.  The script will wait 180 seconds between each group/sequence of VMs.
.EXAMPLE
.\Invoke-PcVmPowerOnSequence.ps1 -prismCentral pc.domain.com -labels group1,group2 -delay 60 -leaveOtherVmsOff
Power on VMs labeled group1 and group2 in the specified order. All other Vms will remain untouched.  The script will wait 60 seconds between each group/sequence of VMs.
.EXAMPLE
.\Invoke-PcVmPowerOnSequence.ps1 -prismCentral pc.domain.com -tag .\vm-sequence.csv
Tag VMs listed in the specified csv file (csv file content is vm_name;integer): VMs will be labeled boot_priority_1, boot_priority_2, etc...
.LINK
  http://github.com/sbourdeaud/nutanix
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 6th 2021
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
        [parameter(mandatory = $false)] [string]$prismCreds,
        [parameter(mandatory = $false)] [array]$labels,
        [parameter(mandatory = $false)] [int]$delay,
        [parameter(mandatory = $false)] [string]$sequence,
        [parameter(mandatory = $false)] [string]$tag,
        [parameter(mandatory = $false)] [string]$cluster
    )
#endregion

#TODO: enhance the script to check on power on task status after a batch has been processed
#TODO: add an option to interrupt power on operations when a vm has not successfully powered on (will continue by default)

#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
07/10/2019 sb   Initial release.
07/11/2019 sb   First tested version. Missing -sequence still (wip).
07/12/2019 sb   Implementing -sequence
04/21/2020 sb   Do over with sbourdeaud module.
02/06/2021 sb   Replaced username with get-credential
################################################################################
'@
    $myvarScriptName = ".\Invoke-PcVmPowerOnSequence.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

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
            Install-Module -Name sbourdeaud -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module -Name sbourdeaud -ErrorAction Stop
        }
        catch {throw "$(get-date) [ERROR] Could not update module 'sbourdeaud': $($_.Exception.Message)"}
        }
    #endregion
    Set-PoSHSSLCerts
    Set-PoshTls
#endregion

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
    #prepare our overall VM results variable
    [System.Collections.ArrayList]$myvarVmResults = New-Object System.Collections.ArrayList($null)
    [System.Collections.ArrayList]$cluster_list = New-Object System.Collections.ArrayList($null)
    $cluster_exists = $false
    $length=100 #this specifies how many entities we want in the results of each API query
    $api_server_port = "9440"
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

    #if no delay was specified so we'll use the default 180
    if (!$delay) {$delay = 180}
    #if no custom labels were specified, we'll use the default labels
    if (!$labels) {$labels = @("boot_priority_1","boot_priority_2","boot_priority_3","boot_priority_4","boot_priority_5")}

    #if a custom sequence file was specified, let's make sure the file can be read
    if ($sequence) {
        Write-Host "$(Get-Date) [INFO] Reading file $($sequence)..." -ForegroundColor Green
        try {        
            $sequenceRef = Import-Csv -Path $sequence -ErrorAction Stop -Delimiter ";"
            Write-Host "$(Get-Date) [SUCCESS] Successfully read file $($sequence)." -ForegroundColor Cyan
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Host "$(Get-Date) [ERROR] Could not read file $($sequence)" -ForegroundColor Red
            Throw "$(get-date) [ERROR] $saved_error"
        }
        if ((($sequenceRef | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name') -contains "boot_priority") -and (($sequenceRef | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name') -contains "name")) {
            Write-Host "$(Get-Date) [INFO] $($sequence) content is valid" -ForegroundColor Green
        } else {
            Write-Host "$(Get-Date) [ERROR] $($sequence) content is invalid. Make sure it contains the following headers: 'vm' and 'boot_priority'" -ForegroundColor Red
            Exit 1
        }
    }

    #if a custom sequence file was specified, let's make sure the file can be read
    if ($tag) {
        Write-Host "$(Get-Date) [INFO] Reading file $($tag)..." -ForegroundColor Green
        try {        
            $tagRef = Import-Csv -Path $tag -ErrorAction Stop -Delimiter ";"
            Write-Host "$(Get-Date) [SUCCESS] Successfully read file $($tag)." -ForegroundColor Cyan
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Host "$(Get-Date) [ERROR] Could not read file $($tag)" -ForegroundColor Red
            Throw "$(get-date) [ERROR] $saved_error"
        }
        if ((($tagRef | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name') -contains "boot_priority") -and (($tagRef | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name') -contains "name")) {
            Write-Host "$(Get-Date) [INFO] $($tag) content is valid" -ForegroundColor Green
        } else {
            Write-Host "$(Get-Date) [ERROR] $($tag) content is invalid. Make sure it contains the following headers: 'name' and 'boot_priority'" -ForegroundColor Red
            Exit 1
        }
    }
#endregion

#! processing starts here
#region processing

    #* get clusters (results stored in $cluster_list)
    #region get clusters
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
                    $myvarClusterInfo = [ordered]@{
                        "name" = $entity.status.name;
                        "uuid" = $entity.metadata.uuid
                    }
                    $cluster_list.Add((New-Object PSObject -Property $myvarClusterInfo)) | Out-Null
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
            While ($cluster_list.metadata.length -eq $length)
        #endregion

        if ($cluster) {#a specific cluster was specified, so we need to make sure it exists in Prism Central before we do anything else 
            ForEach ($entity in $cluster_list) {
                #grab the uuid of the specified cluster
                if ($entity.spec.name -eq $cluster) {
                    $cluster_exists = $true
                    break
                }
            }

            if (!$cluster_exists) {
                Write-Host "$(Get-Date) [ERROR] There is no cluster named $($cluster) on Prism Central $($prismcentral)" -ForegroundColor Red
                Exit 1
            } else {
                Write-Host "$(Get-Date) [SUCCESS] Cluster $($cluster) found on Prism Central $($prismcentral)" -ForegroundColor Cyan
            }
        }
    #endregion

    #* get vms (results stored in $myvarVmResults)
    #region get vms
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

                #grab the information we need in each entity
                ForEach ($entity in $resp.entities) {
                    $myvarVmInfo = [ordered]@{
                        "name" = $entity.spec.name;
                        "power_state" = $entity.spec.resources.power_state;
                        "cluster" = $entity.spec.cluster_reference.name;
                        "uuid" = $entity.metadata.uuid
                    }
                    #store the results for this entity in our overall result variable
                    $myvarVmResults.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
                }

                #prepare the json payload for the next batch of entities/response
                $content = @{
                    kind="vm";
                    offset=($resp.metadata.length + $offset);
                    length=$length
                }
                $payload = (ConvertTo-Json $content -Depth 4)
            }
            While ($resp.metadata.length -eq $length)

            if ($cluster) {
                $myvarVmResults = $myvarVmResults | Where-Object -Property cluster -eq $cluster
            }

            if (!$myvarVmResults) {
                Write-Host "$(Get-Date) [ERROR] Query did not return any results/vms on Prism Central $($prismcentral)" -ForegroundColor Red
                Exit 1
            } else {
                Write-Host "$(Get-Date) [SUCCESS] Retrieved list of virtual machines from Prism Central $($prismcentral)" -ForegroundColor Cyan
            }

            if ($debugme) {
                Write-Host "$(Get-Date) [DEBUG] Showing results:" -ForegroundColor White
                ForEach ($vm in $myvarVmResults) {
                    Write-Host "$vm" -ForegroundColor White
                }
            }
        #endregion
    #endregion

    #* get existing tags (results stored in $pc_tags)
    #region get tags
        if (!$sequence) {
            #region prepare api call
                $api_server_endpoint = "/PrismGateway/services/rest/v1/tags"
                $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                $method = "GET"
            #endregion

            #region making the api call
                $pc_tags = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
            #endregion
        }
    #endregion

    #* -tag
    #region tag
        if ($tag) {
            if ($debugme) {
                Write-Host "$(Get-Date) [DEBUG] Reference for tag:" -ForegroundColor White
                foreach ($vm in $tagRef) {
                    Write-Host "$($vm.vm);$($vm.boot_priority)" -ForegroundColor White
                }
            }

            #* creating default tags if necessary
            #region creating tags
                #region prepare api call
                    $api_server_endpoint = "/PrismGateway/services/rest/v1/tags"
                    $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                    $method = "POST"
                #endregion

                #region make the api call
                    $count = 1
                    While ($count -le 5) {
                        $tag_name = "boot_priority_{0}" -f $count
                        # this is used to capture the content of the payload
                        $content = @{
                            name=$tag_name;
                            entityType="vm";
                            description=$null
                        }
                        $payload = (ConvertTo-Json $content -Depth 4)

                        if (($pc_tags.entities.name) -contains $tag_name) {
                            Write-Host "$(Get-Date) [INFO] Tag $($tag_name) already exists on Prism Central $($prismcentral)" -ForegroundColor Green
                        } else {
                            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                        }

                        $count++
                    }
                #endregion
            #endregion


            #* tagging vms
            #region tagging vms
                #build list of vm uuids
                $vms_to_process = Compare-Object -ReferenceObject $myvarVmResults -DifferenceObject $tagRef -Property name -IncludeEqual -PassThru | Where-Object -Property SideIndicator -eq "=="
                #build list of tag uuids
                $tag_uuids = $pc_tags.entities | where-object -Property name -Like "boot_priority_*" | Select-Object -Property name,uuid | Sort-Object -Property name

                ForEach ($tag_uuid in $tag_uuids) {
                    #region prepare api call
                        #build list of vms with the matching boot_priority
                        $priority = $tag_uuid.name.Substring($tag_uuid.name.length - 1)
                        $vm_uuid_list = @()
                        ForEach ($vm in $vms_to_process) {
                            $vm_priority = ($tagRef | Where-Object {$_.name -eq $vm.name}).boot_priority
                            if ($vm_priority -eq $priority) {$vm_uuid_list += $vm.uuid}
                        }
                        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] List of uuids for Vms with priority $($priority): $($vm_uuid_list)" -ForegroundColor White}
                        if (!$vm_uuid_list) {continue} #if there are no entities to tag, proceed to the next priority

                        #build json payload
                        $content = @{
                            tagUuid=$tag_uuid.uuid;
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
        }
    #endregion

    #* get groups/labels (results stored in $poweron_list)
    #region get groups/labels
    if ((!$tag) -and (!$sequence)) {
        #region prepare api call
            $api_server_endpoint = "/api/nutanix/v3/groups"
            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
            $method = "POST"

            [System.Collections.ArrayList]$tag_uuids = New-Object System.Collections.ArrayList($null)
            ForEach ($label in $labels) {
                $label_uuid = $pc_tags.entities | where-object -Property name -match $label | Select-Object -Property name,uuid | Sort-Object -Property name
                $myvarLabelInfo = [ordered]@{
                    "name" = $label_uuid.name;
                    "uuid" = $label_uuid.uuid
                }
                $tag_uuids.Add((New-Object PSObject -Property $myvarLabelInfo)) | Out-Null
            }
            if (!$tag_uuids) {
                Write-Host "$(Get-Date) [ERROR] Could not find any labels/tags from the specified list ($($labels)) in Prism Central $($prismcentral)" -ForegroundColor Red
                Exit 1
            }
        #endregion

        #region make the api call
            [System.Collections.ArrayList]$poweron_list = New-Object System.Collections.ArrayList($null)
            ForEach ($tag_entry in $labels) {
                $tag_uuid = ($tag_uuids | Where-Object -Property name -Eq $tag_entry).uuid
                if (!$tag_uuid) {
                    Write-Host "$(Get-Date) [WARN] Could not find uuid for tag $($tag_entry) in Prism Central $($prismcentral)" -ForegroundColor Yellow
                    Continue
                }

                # this is used to capture the content of the payload
                $content = [ordered]@{
                    entity_type="vm";
                    group_member_sort_attribute="vm_name";
                    group_member_sort_order="ASCENDING";
                    group_member_attributes=@(
                        @{
                            attribute="vm_name"
                        };
                        @{
                            attribute="power_state"
                        };
                        @{
                            attribute="cluster_name"
                        }
                    );
                    filter_criteria="tag_list==.*"+$tag_uuid+".*"
                }
                $payload = (ConvertTo-Json $content -Depth 4)

                $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved the list of VMs with label $($tag_entry)" -ForegroundColor Cyan
                ForEach ($result in $resp.group_results[0].entity_results) {
                    if (($result.data | Where-Object -Property name -eq "power_state").values.values -eq "on") {
                        Write-Host "$(Get-Date) [WARN] Virtual machine $(($result.data | Where-Object -Property name -eq "vm_name").values.values) is already powered on!" -ForegroundColor Yellow
                        Continue
                    }
                    $myvarVmInfo = [ordered]@{
                        "name" = ($result.data | Where-Object -Property name -eq "vm_name").values.values;
                        "uuid" = $result.entity_id;
                        "tag" = $tag_entry;
                        "cluster_name" = ($result.data | Where-Object -Property name -eq "cluster_name").values.values;
                    }
                    $poweron_list.Add((New-Object PSObject -Property $myvarVmInfo)) | Out-Null
                }
            }
            if ($debugme) {
                Write-Host "$(Get-Date) [DEBUG] Showing results: " -ForegroundColor White
                ForEach ($vm in $poweron_list) {
                    Write-Host "$vm" -ForegroundColor White
                }
            }
        #endregion
    }
    #endregion

    #* power on vms
    #region power on
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Tag: $($tag)" -ForegroundColor White}
        if (!$tag) {
            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Sequence: $($sequence)" -ForegroundColor White}
            if ($sequence) {
                #process boot sequences from 1 to 5
                $count = 1
                While ($count -le 5) {
                    Write-Host "$(Get-Date) [STEP] Processing boot sequence number $($count)" -ForegroundColor Magenta
                    #process each vm with the same sequence number
                    $vms_to_process = $sequenceRef | Where-Object -Property boot_priority -eq $count
                    if (!$vms_to_process) {
                        Write-Host "$(Get-Date) [WARN] No Vms to process in boot sequence number $($count)!" -ForegroundColor Yellow
                        $count++
                        Continue
                    }
                    $vms_processed = 0
                    ForEach ($vm in $vms_to_process) {
                        #determine if the vm is already powered on and if it is, skip ahead to the next vm
                        $vm_details = $myvarVmResults | Where-Object -Property name -eq $vm.name
                        if (!$vm_details) {
                            Write-Host "$(Get-Date) [WARN] Could not find VM $($vm.name)!" -ForegroundColor Yellow
                            Continue
                        }
                        if ($vm_details.power_state -eq "ON") {
                            Write-Host "$(Get-Date) [WARN] Virtual machine $($vm.name) is already powered on!" -ForegroundColor Yellow
                            Continue
                        }
                        
                        #region prepare the api call
                            $api_server_endpoint = "/api/nutanix/v0.8/vms/set_power_state/fanout"
                            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                            $method = "POST"

                            #determine the cluster uuid for the vm to power on
                            $cluster_uuid = ($cluster_list | Where-Object -Property name -Eq $vm_details.cluster).uuid
                            if (!$cluster_uuid) {#couldn't figure out the cluster uuid, so let's skip to the next vm
                                Write-Host "$(Get-Date) [WARN] Could not get uuid of the cluster $($vm_details.cluster) for vm $($vm.name). Skipping this VM!" -ForegroundColor Yellow
                                Continue
                            }
                            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Cluster $($vm_details.cluster) uuid is $($cluster_uuid)" -ForegroundColor White}

                            #build json payload
                            $content = @(
                                @{
                                    generic_dto=@{
                                        transition="on";
                                        uuid=$vm_details.uuid
                                    };
                                    cluster_uuid = $cluster_uuid
                                }
                            )
                            $payload = (ConvertTo-Json $content -Depth 4)
                            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Payload: $($payload)" -ForegroundColor White}
                        #endregion

                        #region make the api call
                            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                            Write-Host "$(Get-Date) [SUCCESS] Successfully sent power on request for VM $($vm.name). Task uuid is $($resp.taskUuid)" -ForegroundColor Cyan
                            $vms_processed++
                        #endregion
                    }
                    if ($vms_processed -ge 1) {
                        Write-Host "$(Get-Date) [INFO] Waiting $($delay) seconds before processing the next group..." -ForegroundColor Green
                        Start-Sleep $delay
                    }
                    $count++
                }
            } else {
                if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Labels: $($labels)" -ForegroundColor White}
                #process each label
                ForEach ($label in $labels) {
                    Write-Host "$(Get-Date) [STEP] Powering on virtual machines labeled with $($label)" -ForegroundColor Magenta
                    #find applicable vms with that label
                    $vm_list = $poweron_list | Where-Object -Property tag -Eq $label
                    if (!$vm_list) {#no applicable vm was found, so let's skip ahead to the next label
                        Write-Host "$(Get-Date) [WARN] No Vms to process with label $($label)!" -ForegroundColor Yellow
                        Continue 
                    }
                    $vms_processed = 0
                    ForEach ($vm in $vm_list) {#process each applicable vm
                        Write-Host "$(Get-Date) [INFO] Powering on virtual machine $($vm.name)" -ForegroundColor Green
                        #region prepare api call
                            $api_server_endpoint = "/api/nutanix/v0.8/vms/set_power_state/fanout"
                            $url = "https://{0}:{1}{2}" -f $prismcentral,$api_server_port, $api_server_endpoint
                            $method = "POST"
                            
                            #figure out the cluster uuid for that vm
                            $cluster_uuid = ($cluster_list | Where-Object -Property name -Eq $vm.cluster_name).uuid
                            if (!$cluster_uuid) {#couldn't figure out the cluster uuid, so let's skip to the next vm
                                Write-Host "$(Get-Date) [WARN] Could not get uuid of the cluster $($vm.cluster_name) for vm $($vm.name). Skipping this VM!" -ForegroundColor Yellow
                                Continue
                            }
                            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Cluster $($vm.cluster_name) uuid is $($cluster_uuid)" -ForegroundColor White}
                            
                            #build json payload
                            $content = @(
                                @{
                                    generic_dto=@{
                                        transition="on";
                                        uuid=$vm.uuid
                                    };
                                    cluster_uuid = $cluster_uuid
                                }
                            )
                            $payload = (ConvertTo-Json $content -Depth 4)
                            if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Payload: $($payload)" -ForegroundColor White}
                        #endregion

                        #region make api call
                            $resp = Invoke-PrismAPICall -method $method -url $url -payload $payload -credential $prismCredentials
                            Write-Host "$(Get-Date) [SUCCESS] Successfully sent power on request for VM $($vm.name). Task uuid is $($resp.taskUuid)" -ForegroundColor Cyan
                            $vms_processed++
                        #endregion
                    }
                    if ($vms_processed -ge 1) {
                        Write-Host "$(Get-Date) [INFO] Waiting $($delay) seconds before processing the next group..." -ForegroundColor Green
                        Start-Sleep $delay
                    }
                }
            }
        }
    #endregion

#endregion
#! processing ends here

#region cleanup
    #let's figure out how much time this all took
    Write-Host "$(Get-Date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable prismcentral -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
#endregion