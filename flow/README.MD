# SyncFlowRules.ps1:

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