# Invoke-FlowRulesSync.ps1:

The Invoke-FlowRulesSync.ps1 script can be used to synchronize Nutanix Flow Security policies and their related entities (categories, service groups and addresses) from one Prism Central instance to another.
This is useful when you replicate virtual machines from one availability zone to another and you want the Flow Security policies to apply immediately after failover without having to re-create them manually.

## What the script does

The script starts by retrieving objects from each Prism Central (PC) instance.  One PC instance is the source, and the other PC instance is the target. Synchronization occurs one way, from source to target.

The objects it retrieves in order are:

1. Flow Security policies (aka rules): from the `/api/nutanix/v3/network_security_rules/list` Prism Central v3 API endpoint
2. Flow Security service groups (aliases that contain one or more network ports which are used in rules): from the `/api/nutanix/v3/service_groups/list` Prism Central v3 API endpoint
3. Flow Security address groups (aliases that contain one or more IP addresses which are used in rules): from the `/api/nutanix/v3/address_groups/list` Prism Central v3 API endpoint

Note that to retrieve those objects, the script uses a function (Get-PrismCentralObjectList) which processes correctly pagination in the v3 API.  This means that it is not limited to the first 50 items of each object type but can scale to whatever PC supports.  This function also attempts to retrieve the API error code if the payload is not successfully returned.

Once all objects have been retrieved from both source and target and stored in variables, the script determines which rules must be:

1. _added_: because they exist on the source but not on the target
2. _removed_: because they exist on the target but no longer exist on the source
3. _updated_: because the contents of the rule (apart from object uuids) are different from the source and the target. Note that the reference is the source, so if an update is done manually on the target, it will get overwritten when the script runs.

Note that the only rules which are being considered are the ones that match the prefix specified with the **prefix** parameter.

Once the _add_, _remove_ and _update_ lists have been figured out, it proceeds to do just that in that exact order.

When rules are _added_, the script synchronized _categories_, _services groups_ and _address groups_ in that order by:

1. Figuring out which of those objects are being used in the rule (by looking at its payload content),
2. Finding out if that objects already exists on the target,
3. If the object does not already exist on the target, it creates it and figures out what the uuid of the resulting object is now on the target so that references can be updated in the payload of the rule to be created on that target PC instance.
4. If the object already exists, the uuid reference is also updated in the payload of the rule to be created on that target PC instance.

When rule are _removed_, any categories, service groups and address groups it was using are left behind on the target.

Rules are _updated_ when the source and target payloads do not match (other than uuids), so any type of change should be processed as the payload is updated with the correct uuid references and then applied as it is from source.

Note that thoughout execution, the script display timestamped output entries which are green for informational output, yellow for warning output, red for error output (which usually interrupt script execution), white for data and debug output (debug output can be triggered with the **debugme** script parameter) and light blue for things which are successfull (such as an API call).

## Technical requirements

While technically the script should work on any system running PowerShell 5.1 or above, it is strongly recommended to run PowerShell Core (v6 or above) as many cmdlets the script uses have enhanced functionality in PoSH core.
This means that the script can run on any Windows, Linux or MacOSX system which is running PowerShell core.

In this GitHub repository, the script does not require any external PowerShell module to run correctly. In other GitHub repositories, older versions of the script may require the installation of the _sbourdeaud_ PowerShell gallery module which contains the functions used in the script to make API calls.

## Script syntax

Syntax for the script can be shown using the `Get-Help ./Invoke-FlowRuleSync.ps1` command from a PowerShell prompt.

To handle scheduling and safe storage of credentials, the script uses PowerShell secure strings stored in the user profile directory. The secure string stored in the resulting text file can only be decrypted by the same user on that same workstation and therefore credential files are not transferrable from one workstation to another or from one user to another on the same workstation.
The script output shows where those files are stored (which varies based on the platform your workstation uses).

## Troubleshooting

The script can be ran with the **debugme** parameter to create additional output.
There is also a **log** parameter to create a log file in the working directory with the same output as displayed on the console.

When the script simply won't execute, this can be caused by various things:
1. Running the wrong PowerShell version (suggesting you use PowerShell core v6 or above)
2. Not being able to install dependencies (applies to some versions of the script) from the PowerShell gallery
3. Not being able to accept the Prism Central self-signed certificates (it should by default, but in some rare instances, it may be necessary to re-generate those self-signed certificates as they are perceived as invalid by the dotnet library)

Most of those reasons will be PowerShell or DotNet specific and may require troubleshooting those components.  PowerShell and DotNet troubleshooting is too vast a topic to cover here.

If the script runs correctly but does not produce the expected output, then the steps taken by the script should be reproduced manually to determine if there is an issue with Flow Security (for example, the rules and their objects are created successfully but not applied to virtual machines after failover). If you can create them manually and they still don't work as expected, then it is obviously not a script issue.

Between multiple script executions, it may be necessary to re-initialize your PowerShell session (by closing and re-opening your PowerShell prompt).  The script tries to clear variables once it is done executing, but when execution fails for whatever reason, some variables may be left behind in memory which may affect any subsequent execution.

# Sync-FlowRules.ps1:

## Export/Import Flow rules from one Prism Central instance to another

You use _SyncFlowRules.ps1_ to export and import a number of Flow rules which follow a specified naming convention from/to Prism Central.
The rules, but also their related categories, addresses and service groups (all Prism Central objects which are used in Flow rule definitions) are exported to **json** format.
That **json** file can then be edited manually if required, then re-imported in the same or another Prism Central instance.

To export all Flow rules that start with _openshift_, run:

 `SyncFlowRules.ps1 -pc pc1.local -prismCreds myadcreds -export -rules openshift*`

 Where **_pc_** is the IP address or fully qualified domain name of the Prism Central instance and **_prismCred_** is the name of the encrypted credential file (if that file does not already exist, you will be prompted for the credentials you want to use and the file will get created automatically for subsequent uses).  If you do not specify a credentials file name, you will simply be prompted for credentials.
 The script will display where the **json** export file was created (in the current directory).

To import Flow rules from a **json** file called _openshift.json_, run:

`SyncFlowRules.ps1 -pc pc2.local -prismCreds myadcreds -import -rules openshift*`

If the required categories, addresses or service groups are missing from the target Prism Central instance, they will get created automatically so that the Flow rules can then be created successfully.
If the rules already exist but have changed, they will get updated.

To learn more about the script syntax and usage, you can use `get-help ./SyncFlowRules.ps1`