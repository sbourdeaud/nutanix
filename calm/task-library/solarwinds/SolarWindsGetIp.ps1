 #requires -version 4 -Module SwisPowerShell
 
<#
    .SYNOPSIS
        Code sample for Solarwinds IPAM
    .DESCRIPTION
        requires solarwinds module - https://www.powershellgallery.com/packages/SwisPowerShell
        the solarwinds rest api is not well documented, so the best solution
        is to use the powershell commandlets and execute them from the
        IPAM server.

        Note - An active directory account can not be used with the solarwinds API
        It must be a solarwinds 'sql' account.

        All of the def_net* macros must be defined in the blueprint, in the script variables, and in
        the script's switch block.

        In Calm, this task should be executed against a Windows Endpoint (possibly the SWIS host)

    .NOTES
        Version:        1.0.1
        Author:         Dusty Lane
        Creation Date:  03/25/2021
        Purpose/Change: add some error handling and change logic.

  
#>


$ErrorActionPreference = "Stop"
 
$network = "@@{network}@@"
$swhost = "@@{solarwinds_ip}@@"
$swuser = "@@{solarwinds.username}@@"
$swpasswd = "@@{solarwinds.secret}@@"
$reservetime = "240" # in minutes

# to minimize the amount of user input, we need to define
# the network, mask, and gateway variables.
# We will need to define this for every network that we want to be able to provision 
# virtual machines to.  Add to the switch loop.

$def_net1 = "@@{def_net1}@@"
$def_net1_mask = "@@{def_net1_mask}@@"
$def_net1_gw = "@@{def_net1_gw}@@"
$def_net2 = "@@{def_net2}@@"
$def_net2_mask = "@@{def_net2_mask}@@"
$def_net2_gw = "@@{def_net2_gw}@@"

#------------------ no changes below here -----------#

#region Functions

Function Convert-IPInt64 { 
 
    [CmdletBinding()]
    Param(
      [parameter(Mandatory=$true)]
      [string]$IP
      )
 
    $IPSPLIT = $IP.Split('.') # IP to it's octets 
 
    # Return 
    [int64]([int64]$IPSPLIT[0] * 16777216 + 
            [int64]$IPSPLIT[1] * 65536 + 
            [int64]$IPSPLIT[2] * 256 + 
            [int64]$IPSPLIT[3]) 
} 
 
Function Convert-SMtoCIDR
{ 

   [CmdletBinding()]
    Param(
      [parameter(Mandatory=$true)]
      [string]$SUBNET_MASK
      )
 
    [int64]$SMINT64 = Convert-IPInt64 -IP $SUBNET_MASK 
 
    $Cidr32Int = 2147483648 
 
    $MaskCidr = 0 
    for ($i = 0; $i -lt 32; $i++) 
    { 
        if (!($SMINT64 -band $Cidr32Int) -eq $Cidr32Int) { break } # Bitwise and operator - Same as "&" in C# 
 
        $MaskCidr++ 
        $Cidr32Int = $Cidr32Int -shr 1 
    } 
 
    # Return 
    $MaskCidr 
}
#endregion

# using the switch block to create a powershell object to hold the values.
switch ($network)
{
    $def_net1
    {
        $mask = $def_net1_mask
        $gateway = $def_net1_gw
    }
    $def_net2
    {
        $mask = $def_net2_mask
        $gateway = $def_net2_gw
    }
}

Write-Host "Network is: $network"
Write-Host "Subnet mask is: $($mask)"
Write-Host "Default gateway is: $($gateway)"
# create connection to the solarwinds ipam server
$swis = Connect-Swis -Hostname $swhost -UserName $swuser -Password $swpasswd

# using the subnet mask to generate the cidr.  cidr Code contributed by Matthew.Foster@nutanix.com
$cidr = Convert-SMtoCIDR -SUBNET_MASK $mask

# DNS & Ping Test to double check the reservation.  This may or maynot be needed depending on
# how well the customer is leveraging their IPAM solution.
$Test = $true
while ($test -eq $true)
{
    # do some checks (ping and nslookup) to make sure that the IPs are truly available
    # get an IP from the IPAM
    $ip_address = Invoke-SwisVerb $swis IPAM.SubnetManagement StartIpReservation @("$network", "$cidr", "$reservetime") -Verbose | 
      Select-Object -expand '#text'
    
      # test-netconnection is really just a ping to the IP we received from the IPAM.
    $Test = Test-NetConnection -InformationLevel Quiet $ip_address -ErrorAction Continue
    
    # if the ping 'fails', the ip is not in use.  next step we need to check dns...
    if ($test -eq $false)
    {
        try
        {
            # now let's check DNS with resolve-dns.  if this command errors, drop to catch block.
            # if it resolves successfully, let's reset the $test variable back to true 
            # and try again.
            Resolve-DnsName -Name $ip_address
            $Test = $true
        }
        catch
        {
            $test = $false
            # we need to clear the error from the resolve-dnsname command so that calm
            # will not fail due to the error.
            $error.Clear()
        }
    }
}

try
{
    # we are putting this in a try catch - just because....  The current version of the API does not appear to throw error messages.
    $capture_ipam1 = Invoke-SwisVerb -SwisConnection $swis -EntityName IPAM.SubnetManagement -Verb ChangeIpStatus @($ip_address, "Blocked") -Verbose
    $capture_ipam2 = Invoke-SwisVerb -SwisConnection $swis -EntityName IPAM.SubnetManagement -Verb FinishIpReservation @($ip_address, "Reserved") -Verbose     
}
catch
{
    #displaying error
    $_ 
}

Write-Host "vm_ip=$ip_address"
Write-Host "subnet_mask=$mask"
Write-Host "gateway=$gateway"
Write-Host "subnet_mask_bits=$cidr"