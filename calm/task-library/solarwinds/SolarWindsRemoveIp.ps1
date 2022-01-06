 #requires -version 4 -Module SwisPowerShell
 
<#
    .SYNOPSIS
        Code sample for Solarwinds IPAM to remove reservation
    .DESCRIPTION
        requires solarwinds module - https://www.powershellgallery.com/packages/SwisPowerShell
        the solarwinds rest api is not well documented, so the best solution
        is to use the powershell commandlets and execute them from the
        IPAM server.

        Note - An active directory account can not be used with the solarwinds API
        It must be a solarwinds 'sql' account.

        In Calm, this task should be executed against a Windows Endpoint (possibly the SWIS host)

    .NOTES
        Version:        1.0
        Author:         Dusty Lane
        Creation Date:  05/10/2021
        Purpose/Change: 
  
#>

$ip_address = "@@{vm_ip}@@"
$swhost = "@@{solarwinds_ip}@@"
$swuser = "@@{solarwinds.username}@@"
$swpasswd = "@@{solarwinds.secret}@@"

#------------------ no changes below here -----------#
try 
{
    $swis = Connect-Swis -Hostname $swhost -username $swuser -Password $swpasswd
    invoke-swisverb $swis IPAM.SubnetManagement ChangeIpStatus @($ip_address, "Available")
}
catch 
{
    #displaying error
    $_
}
