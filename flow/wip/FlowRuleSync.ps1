<#
  .SYNOPSIS
  AHV Sync Rep with flow, this script makes sure the categories, including its values and Flow Rules exist on the target prism.
  .DESCRIPTION
  Syncs Security Policys / Rules between 2 PCs. single direction. Target rules are overwritten only when changed on the source within an interval.
  All categories on the source will be created on the target.
  If target category exists, values are not overwritten, but only added if missing.
  Target Categories / Values are not renamed for compatibilty reasons.
  Requires credentials to be installed in a working dir. Use Mode InstallCreds to install the credentials.
  Sources are synced, Rule state is synced.
  Changing the rule on the source will automatically delete / create the rule on the target, if the change is within the time interval set.
  Synced rules on target side should not be changed while the sync is active.
  DR Relationship is not required for testing this script.
  Identity based security rules cannot be synced to a random target, it needs to have the identical AD Connected.
  This is however untested.
  
  .PARAMETER SourcePCIP
  Source IP address of the Prism Central Instance.
  .PARAMETER TargetPCIP
  Target IP address of the Prism Central Instance.
  .PARAMETER Mode
  Scan, Scans source, and target and shows the differences or possible changes to be made.
  Execute, Scan + make the changes needed on the target.
  .PARAMETER SourceRuleSearchStr
  This is a regular expression search string. Rules that should be synchronized should follow this naming convention.
  .PARAMETER TargetRulePrefix
  This is prefix that is inserted before the target rule name.
  .PARAMETER RuleSyncHourChanged
  This value should be in negative notation "-1", but also greater than the interval in which the script is scheduled.
  Rules that are changed in this interval will be overwritten.
  Rules are not compared. Source always wins.
  We do not overwrite the rule unless its changed within this time period.
  .PARAMETER EULA
  Use at your own risk, not Nutanix owned software.
  .INPUTS
  This tool does not support pipeline input operations
  .OUTPUTS
  Not applicable.
  .EXAMPLE
  .\Flow_Rule_Sync.ps1 -mode installcreds
  Installs the credentials for Source and Target PCs. Stores the secure credential files in a working dir.
  These credential files can only be decryped on this pc, and by the same user that created them.
  .EXAMPLE
  .\Flow_Rule_Sync.ps1 -mode execute -SourcePCIP 10.10.0.32 -TargetPCIP 10.42.17.40 -EULA $true
  Example for scheduled task
  .EXAMPLE
  .\Flow_Rule_Sync.ps1 -mode execute
  Installs the credentials for Source and Target PCs. Stores the secure credential files in a working dir.
  These credential files can only be decryped on this pc, and by the same user that created them.
#>


#region parameter
  Param 
  (        
    [String] $SourcePCIP               = "Enter Me",
    [String] $TargetPCIP               = "Enter Me",
    [String][ValidateSet("Scan","Execute","InstallCreds")] $Mode = "Scan",      # Scan, Execute, InstallCreds
    [bool]   $EULA                     = $false,
    [string] $workingdir               = "~\appdata\local\temp\",
    [string] $SourceRuleSearchStr      = "AZ01",
    [string] $TargetRulePrefix         = "AZ02",
    [int]    $RuleSyncHourChanged      = -5 # Only Replace rules if they were edited in the source PC within the past x hours. Value should be greater than the script interval, negative value please
  )
#endregion


#region prompt section
  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
  Add-Type -AssemblyName PresentationFramework
  $global:debug = 1
#endregion


#region functions
Function PSR-SSL-Fix {

  try {
  add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
                                          WebRequest request, int certificateProblem) {
            return true;
        }
     }
"@

  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

  write-log -message "SSL Certificate has been loaded." 

  } catch {

    write-log -message "SSL Certificate fix is already loaded." -sev "WARN"

  }
}

Function write-log {
  param (
  $message,
  $sev = "INFO",
  $D = 0
  ) 
  ## This write log module is designed for nutanix calm output
  if ($sev -eq "INFO" -and $Debug -ge $D){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' | INFO  | $message "
  } elseif ($sev -eq "WARN"){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | $message " -ForegroundColor  Yellow
  } elseif ($sev -eq "ERROR"){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| $message " -ForegroundColor  Red
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.MessageBox]::Show($message,"GuestVM Tools stopped", 'OK' , 'ERROR')
    sleep 5
    [Environment]::Exit(1)
  } elseif ($sev -eq "CHAPTER"){
    write-host ""
    write-host "####################################################################"
    write-host "#                                                                  #"
    write-host "#     $message"
    write-host "#                                                                  #"
    write-host "####################################################################"
    write-host ""
  }
} 

function Get-FunctionName {
  param (
    [int]$StackNumber = 1
  ) 
    return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
}

function Test-IsGuid{
  [OutputType([bool])]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]$ObjectGuid
  )
  
  # Define verification regex
  [regex]$guidRegex = '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$'

  # Check guid against regex
  return $ObjectGuid -match $guidRegex
}

Function REST-Query-PrismCentral {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Getting PC Object."

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/prism_central"

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
  }

  write-log -message "We found '$($task.entities.count)' clusters"

  Return $task
}

Function REST-Query-Security-Rules {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Query all security rules"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/network_security_rules/list"
  $Payload= @{
    kind="network_security_rule"
    offset=0
    length=99999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  if ($task.entities.count -eq 0){
    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting Security Rules, current items found is '$($task.entities.count)'"
    } until ($count -ge 10 -or $task.entities.count -ge 1)
  }
  write-log -message "We found '$($task.entities.count)' Security Rules"

  Return $task
} 

Function REST-Add-Security-Rule {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $Rule,
    [string] $NewName,
    [string] $NewDescription
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Preparing rule for upload."

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/network_security_rules"
  $Rule.psobject.members.remove("Status")
  $rule.metadata.psobject.members.remove("uuid")
  $rule.spec.name = $NewName
  $rule.spec.description = $NewDescription
  $rule.spec.resources.app_rule.outbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
  $rule.spec.resources.app_rule.outbound_allow_list | %{$_.PSObject.Properties.Remove("service_group_list")}
  $rule.spec.resources.app_rule.inbound_allow_list | %{$_.PSObject.Properties.remove("rule_id")}
  $rule.spec.resources.app_rule.inbound_allow_list | %{$_.PSObject.Properties.Remove("service_group_list")}

  $JSON = $Rule | convertto-json -depth 100

  try{
 #   Write-Host $JSON
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Delete-Security-Rule {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $Rule
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Deleting Rule '$($Rule.status.name)' with uuid '$($Rule.metadata.uuid)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/network_security_rules/$($Rule.metadata.uuid)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "DELETE" -headers $headers
  }

  Return $task
} 

Function REST-Category-Value-Create {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [object] $CatObj,
    [string] $Value
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating Value '$Value' on Category '$($CatObj.name)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$($CatObj.name)/$($Value)"

  $Payload= @"
{
      "value": "$Value",
      "description": "$($CatObj.description)"
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    ;$FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Category-Create {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Creating / Updating Category '$($Name)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$($Name)"
  ## What is cardinality.. Do we care.. We only create once. We dont update.
  $Payload= @"
{
  "api_version": "3.1.0",
  "description": "Created by 1-click-flow-Sync.",
  "capabilities": {
    "cardinality": 64
  },
  "name": "$($Name)"
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    ;$FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "PUT" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 


Function REST-Category-List {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Query all categories on '$PCClusterIP'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/groups"

  $Payload= @"
{
  "entity_type": "category",
  "query_name": "eb:data-1599312145673",
  "grouping_attribute": "abac_category_key",
  "group_sort_attribute": "name",
  "group_sort_order": "ASCENDING",
  "group_count": 20,
  "group_offset": 0,
  "group_attributes": [{
    "attribute": "name",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "immutable",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "cardinality",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "description",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "total_policy_counts",
    "ancestor_entity_type": "abac_category_key"
  }, {
    "attribute": "total_entity_counts",
    "ancestor_entity_type": "abac_category_key"
  }],
  "group_member_count": 5,
  "group_member_offset": 0,
  "group_member_sort_attribute": "value",
  "group_member_sort_order": "ASCENDING",
  "group_member_attributes": [{
    "attribute": "name"
  }, {
    "attribute": "value"
  }, {
    "attribute": "entity_counts"
  }, {
    "attribute": "policy_counts"
  }, {
    "attribute": "immutable"
  }]
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Payload -ContentType 'application/json' -headers $headers -ea:4;
  } catch {
    ;$FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $Payload -ContentType 'application/json' -headers $headers
  }

  Return $task
} 

Function REST-Category-Query {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Finding Category with Name '$($Name)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$Name"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {
    write-log "Category '$Name' does not exist."
  }

  Return $task
}

Function REST-Category-Value-Query {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $Name,
    [string] $value
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  write-log -message "Finding Category Value with Name '$($Name)' and value '$($value)'"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/categories/$($Name)/$($value)"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {
    write-log -message "Category with Name '$($Name)' and value '$($value)' does not exist."
  }

  Return $task
} 

Function 1FRS-Create-Categories{
  Param (
    [string] $PCIP,
    [object] $PCCreds,
    [object] $delta
  )
  $change = 0
  foreach ($Category in $delta){
    $CategoryName = $Category.name
    $valarr = $Category.values -split ","

    write-log -message "Working on Category '$CategoryName'"
  
    $CatObj = REST-Category-Query `
      -PCClusterIP $PCIP `
      -PxClusterUser $PCCreds.getnetworkcredential().username `
      -PxClusterPass $PCCreds.getnetworkcredential().password `
      -name $CategoryName

    if (!$CatObj){
      $change++
      write-log -message "Category '$CategoryName' does not exist, creating"
      write-log -message "This Parent PC is not prepared with all Categories."
      write-log -message "Creating Category with general description."

      REST-Category-Create `
        -PCClusterIP $PCIP `
        -PxClusterUser $PCCreds.getnetworkcredential().username `
        -PxClusterPass $PCCreds.getnetworkcredential().password `
        -Name $CategoryName

      write-log -message "Getting object after creating."  

      $CatObj = REST-Category-Query `
        -PCClusterIP $PCIP `
        -PxClusterUser $PCCreds.getnetworkcredential().username `
        -PxClusterPass $PCCreds.getnetworkcredential().password `
        -name $CategoryName

      write-log -message "Getting object after creating."

    }

    write-log -message "Working on '$($valarr.count)' values for this category."

    foreach ($value in $valarr){

      write-log -message "Checking Value '$value'"

      $ValueObj = REST-Category-Value-Query `
          -PCClusterIP $PCIP `
          -PxClusterUser $PCCreds.getnetworkcredential().username `
          -PxClusterPass $PCCreds.getnetworkcredential().password `
        -Name $CategoryName `
        -Value $Value 
  
      if (!$ValueObj){
        $change++
        write-log -message "Value does not exist yet in '$CategoryName', creating.." 
  
        REST-Category-Value-Create `
          -PCClusterIP $PCIP `
          -PxClusterUser $PCCreds.getnetworkcredential().username `
          -PxClusterPass $PCCreds.getnetworkcredential().password `
          -Catobj $CatObj `
          -Value $Value
  
        write-log -message "Value Created." 
      }
    }
  }
  write-log -message "We made '$($change)' changes in categories."
}
#endregion


#region execution logic
  if ($PSVersionTable.PSVersion.Major -lt 5){

    write-log -message "You need to run this on Powershell 5 or greater...." -sev "ERROR"

  } elseif ($PSVersionTable.PSVersion.Major -match 5 ){

    write-log -message "Disabling SSL Certificate Check for PowerShell 5"

    PSR-SSL-Fix

  }

  if (!$eula -and !$commandline){
    $License = [System.Windows.Forms.MessageBox]::Show("Use at your own risk, do you accept?`nThis software is NOT linked to Nutanix.", "Nutanix License" , 4)
    if ($license -eq "Yes"){
    
      write "User accepted the license"
    
    } else {
    
      [System.Windows.Forms.MessageBox]::Show($message,"User did not accept the license!","STOP",0,16)
      sleep 5
      [Environment]::Exit(1)
    
    }
  } elseif (!$eula) {
    [System.Windows.Forms.MessageBox]::Show($message,"User did not accept the license!","STOP",0,16)
    sleep 5
    [Environment]::Exit(1) 
  }

  write-log -message "Getting some data"
  write-log -message "Validating Input" -sev "Chapter"

  if ($SourcePCIP -eq "Enter Me"){

    write-log -message "PC Source Cluster IP is not specified, prompting" -sev "WARN"

    $SourcePCIP = [Microsoft.VisualBasic.Interaction]::InputBox("Enter PC Source Cluster IP", "Prism Central IP address", "")

  }
  if ($TargetPCIP -eq "Enter Me"){

    write-log -message "PC Target Cluster IP is not specified, prompting" -sev "WARN"

    $TargetPCIP = [Microsoft.VisualBasic.Interaction]::InputBox("Enter PC Target Cluster IP", "Prism Central IP address", "")
  }
#endregion execution logic


#region main
  #region creds & scan
    if ($mode -eq "InstallCreds")
    {#dealiong with storing credentials in files

      if (!(Get-item "$workingdir\SecureFiles\" -ea:4)){
        $null = mkdir "$workingdir\SecureFiles\" -force
      }

      write-log -message "Installing Credential files."
      write-log -message "Working on Target PC first."

      if (get-item "$workingdir\SecureFiles\TargetPC.xml" -ea 4){

        write-log -message "Target Credential file already exists, removing"

        remove-item "$workingdir\SecureFiles\TargetPC.xml" -force -confirm:0
      }

      $credential = Get-Credential -message "Please enter the Target PC Credentials"
      $credential | Export-CliXml -Path "$workingdir\SecureFiles\TargetPC.xml"

      write-log -message "Installing Source PC Credentials."

      if (get-item "$workingdir\SecureFiles\SourcePC.xml" -ea 4){

        write-log -message "Target Credential file already exists, removing"

        remove-item "$workingdir\SecureFiles\SourcePC.xml" -force -confirm:0
      }

      $credential = Get-Credential -message "Please enter the Source PC Credentials"
      $credential | Export-CliXml -Path "$workingdir\SecureFiles\SourcePC.xml"

      write-log -message "Credentials are installed, Please run in scan or execute mode."

    } elseif ($mode -match "Scan|Execute") 
    {#scan

      ### Loading Credentials

      write-log -message "Loading Credential files.." -sev "Chapter"

      $SourcePCCreds = Import-CliXml -Path "$workingdir\SecureFiles\SourcePC.xml"
      $TargetPCCreds = Import-CliXml -Path "$workingdir\SecureFiles\TargetPC.xml"

      $sourcePCVersion = REST-Query-PrismCentral `
        -PCClusterIP $SourcePCIP `
        -PxClusterUser $SourcePCCreds.getnetworkcredential().username `
        -PxClusterPass $SourcePCCreds.getnetworkcredential().password

      $TargetPCVersion = REST-Query-PrismCentral `
        -PCClusterIP $TargetPCIP `
        -PxClusterUser $TargetPCCreds.getnetworkcredential().username `
        -PxClusterPass $TargetPCCreds.getnetworkcredential().password
      
      write-log -message "Source PC is running version '$($sourcePCVersion.resources.version)'"
      write-log -message "Target PC is running version '$($TargetPCVersion.resources.version)'"

      if ($sourcePCVersion.resources.version -ne $TargetPCVersion.resources.version){

        write-log -message "PC Version Mismatch!!" -sev "Warn"

      } else {

        write-log -message "PC Version Match"

      }

      write-log -message "Using username '$($SourcePCCreds.username)' as username for the source PC"
      write-log -message "Using username '$($TargetPCCreds.username)' as username for the target PC"

      write-log -message "Getting Categories from Source PC" -sev "Chapter"

      $SourceCategories = REST-Category-List `
        -PCClusterIP $SourcePCIP `
        -PxClusterUser $SourcePCCreds.getnetworkcredential().username `
        -PxClusterPass $SourcePCCreds.getnetworkcredential().password

      write-log -message "Creating Readable Category object"

      $SCategoryList = $null
      foreach ($Category in $SourceCategories.group_results){
        $Entity = [PSCustomObject]@{
          Name         = ($Category.group_summaries.'sum:name').values.values
          Values       = ($Category.entity_results.data | where {$_.name -eq "value"}).values.values -join ","
          ValueCount   = ($Category.total_entity_count)
        }
        [array]$SCategoryList += $entity     
      }
      $SourcetotalValues = 0    
      $SCategoryList.Valuecount |% {[int]$SourcetotalValues += [int]$_ }

      write-log -message "We have '$($SCategoryList.count)' categories on the source PC."
      write-log -message "We have '$($SourcetotalValues)' values in these categories."
      write-log -message "Getting Categories from Target PC" -sev "Chapter"

      $TargetCategories = REST-Category-List `
        -PCClusterIP $TargetPCIP `
        -PxClusterUser $TargetPCCreds.getnetworkcredential().username `
        -PxClusterPass $TargetPCCreds.getnetworkcredential().password

      write-log -message "Creating Readable Category object"

      $TCategoryList = $null
      foreach ($Category in $TargetCategories.group_results){
        $Entity = [PSCustomObject]@{
          Name         = ($Category.group_summaries.'sum:name').values.values
          Values       = ($Category.entity_results.data | where {$_.name -eq "value"}).values.values -join ","
          ValueCount   = ($Category.total_entity_count)
        }
        [array]$TCategoryList += $entity     
      }
      $TargettotalValues = 0    
      $TCategoryList.Valuecount |% {[int]$TargettotalValues += [int]$_ }

      write-log -message "We have '$($TCategoryList.count)' categories on the source PC."
      write-log -message "We have '$($TargettotalValues)' values in these categories."


      [array] $CatValueSyncRequired = $null
      [array] $NewCat = $null
      foreach ($category in $SCategoryList){
        if ($category.name -notin $TCategoryList.name){

          write-log -message "Category '$($category.name)' does not exist yet."

          $NewCat += $category

        } else {

          $sourcevalarr = $category.values -split "," |sort
          $targetvalarr = ($TCategoryList | where {$_.name -eq $category.name}).values -split "," |sort
          $addArr = $false
          foreach ($sourceval in $sourcevalarr){
            if ($sourceval -in $targetvalarr){

              write-log -message "The value '$sourceval' is present in category '$($category.name)' on the target PC" 

            } else {

              write-log -message "The value '$sourceval' is not present in '$($category.name)' on the target PC" 

              $addArr = $true
            }
          }
          if ($addArr -eq $true){ 

              write-log -message "Category '$($category.name)' is missing values on the target PC."

              [array] $CatValueSyncRequired += $category
          } else {

              write-log -message "Category '$($category.name)' has its values in sync, no change needed."

          }
        }
      }

      write-log -message "Checking Security rules on the source." -sev "Chapter"

      $SourceRules = REST-Query-Security-Rules `
        -PCClusterIP $SourcePCIP `
        -PxClusterUser $SourcePCCreds.getnetworkcredential().username `
        -PxClusterPass $SourcePCCreds.getnetworkcredential().password

      write-log -message "We are filtering rules matching filter string: '$SourceRuleSearchStr'"

      $SourceSyncRules = $SourceRules.entities | where {$_.spec.name -match $SourceRuleSearchStr -and $_.spec.name -ne "Quarantine"}

      write-log -message "We have '$($SyncRules.count)' rules to sync after filtering."
      write-log -message "Checking Security rules on the target."

      $TargetRules = REST-Query-Security-Rules `
        -PCClusterIP $TargetPCIP `
        -PxClusterUser $TargetPCCreds.getnetworkcredential().username `
        -PxClusterPass $TargetPCCreds.getnetworkcredential().password

      write-log -message "We are only checking rules with prefix '$TargetRulePrefix'"

      [array] $TargetRulelist = $null
      [array] $AlreadyExists = $null
      [array] $NewRules = $null
      [array] $AlreadyExistsSyncRequired = $null
      $TargetSyncRules = $TargetRules.entities | where {$_.spec.name -match "^$($TargetRulePrefix)"}
      
      write-log -message "Comparing Rules based on name."

      foreach ($rule in $SourceSyncRules){

        [string]$DestName =  $TargetRulePrefix + $rule.spec.name 

        write-log -message "Checking if we have '$DestName' in our target PC already.."

        if ($destname -in $TargetSyncRules.spec.name){

          write-log -message "Destination Rule '$($destname)' already exists."

          [array] $AlreadyExists += $rule

          foreach ($rule in $AlreadyExists){
            if (([datetime] $rule.metadata.last_update_time) -gt $(get-date).addhours($RuleSyncHourChanged)){

              write-log -message "This rule is changed in the (last) '$RuleSyncHourChanged' hours"

              $AlreadyExistsSyncRequired += $rule

            } else {

              write-log -message "This rule was modified '$(([datetime] $rule.metadata.last_update_time))', its old, not replacing this one."

            }
          }
        } else {

          [array] $NewRules += $rule

        }
      }

      if ($mode -eq "Scan"){

        write-log -message "Scan Summary" -sev "Chapter"
        $prefix = "Scan mode, this setup would"

      } elseif ($mode -eq "execute") {

        $prefix = "Execute mode, this setup will"

      }

      write-log -message "$prefix create '$($NewCat.count)' new categories on '$($TargetPCIP)'"
      write-log -message "$prefix update '$($CatValueSyncRequired.count)' categories that need value alignment on '$($TargetPCIP)'"
      write-log -message "$prefix create '$($NewRules.count)' new rules on '$($TargetPCIP)'"
      write-log -message "$prefix replace '$($AlreadyExistsSyncRequired.count)' existing rules on '$($TargetPCIP)' which are changed in the (last) '$RuleSyncHourChanged' hours"

      sleep 10 

    }
  #endregion

  #region execute
    if ($mode -eq "Execute"){

      write-log -message "New Categories first"

      if ($NewCat.count -ge 1){

        1FRS-Create-Categories -PCCreds $TargetPCCreds -PCIP $TargetPCIP -delta $NewCat
      
      } else {

        write-log -message "Category sync not required for new categories."

      }

      write-log -message "Syncing Existing Categories"

      if ($CatValueSyncRequired.count -ge 1){

        1FRS-Create-Categories -PCCreds $TargetPCCreds -PCIP $TargetPCIP -delta $CatValueSyncRequired
      
      } else {

        write-log -message "Category sync not required for existing categories."

      }

      write-log -message "Working on Security Rules"
      
      if ($AlreadyExistsSyncRequired.count -ge 1){

        write-log -message "Cleanup required, Existing changed Rules will be deleted first."

        foreach ($rule in $AlreadyExistsSyncRequired){

          $targetRule = $TargetSyncRules | where {$_.spec.name -eq [string]($TargetRulePrefix + $Rule.spec.name)}

          if ($targetrule){ 

            write-log -message "Found the target rule to delete."

            REST-Delete-Security-Rule `
              -PCClusterIP $TargetPCIP `
              -PxClusterUser $TargetPCCreds.getnetworkcredential().username `
              -PxClusterPass $TargetPCCreds.getnetworkcredential().password `
              -Rule $targetRule
          }
        } 
      }

      [array]$rulestocreate = $null
      if ($AlreadyExistsSyncRequired.count -ge 1){
        $rulestocreate += $AlreadyExistsSyncRequired
      }
      if ($NewRules.count -ge 1){
        $rulestocreate += $NewRules
      }

      write-log -message "Creating Rules" -sev "Chapter"
      write-log -message "Creating '$($rulestocreate.count)' rules on '$TargetPCIP'"

      foreach ($rule in $rulestocreate){

        [string] $DRRuleName        = $TargetRulePrefix + $rule.spec.name
        [string] $DRRuleDescription = "Please do not edit here, synced rule, edit on '$SourcePCIP'" + $rule.spec.description

        write-log -message "Creating Rule '$DRRuleName'"

        REST-Add-Security-Rule `
          -PCClusterIP $TargetPCIP `
          -PxClusterUser $TargetPCCreds.getnetworkcredential().username `
          -PxClusterPass $TargetPCCreds.getnetworkcredential().password `
          -Rule $Rule `
          -NewName $DRRuleName `
          -NewDescription $DRRuleDescription
      }
    }
  #endregion
#endregion