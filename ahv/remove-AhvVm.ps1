<#
.SYNOPSIS
  This script can be used to delete one or more vms from AHV.
.DESCRIPTION
  Removes all specified VMs from AHV cluster. Prompts if VMs are powered on. Confirmed deletes run in parallel.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER cluster
  Nutanix cluster fully qualified domain name or IP address.
.PARAMETER vm
  Name(s) of VM(s) to delete (use a comma separated strings for multiple VMs)
.PARAMETER allowWildcards
  Specifies you want to use wildcards when specifying the VM name. This will automatically prompt before each deletion to avoid errors.
.PARAMETER Force
  Skip confirmation prompts and delete matching VMs without asking (including powered-on VMs).
.PARAMETER ThrottleLimit
  Maximum number of concurrent delete operations. Default is 10. Requires PowerShell 7+.
.PARAMETER prismCreds
  Specifies a custom credentials file name (will look for %USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$prismCreds.txt on Windows or in $home/$prismCreds.txt on Mac and Linux).
.EXAMPLE
.\remove-AhvVm.ps1 -cluster ntnxc1.local -vm "steph-vm1,steph-vm2"
Deletes 2 specified VMs from ntnxc1.local:
.EXAMPLE
.\remove-AhvVm.ps1 -cluster ntnxc1.local -vm "steph-vm*" -allowWildcards -Force -ThrottleLimit 20
Deletes all VMs matching steph-vm* without prompting, using up to 20 concurrent delete requests.
.LINK
  http://www.nutanix.com/services
.NOTES
  Author(s): Stephane Bourdeaud (sbourdeaud@nutanix.com), Jeremie Moreau (jeremie.moreau@nutanix.com)
  Revision: October 29th 2026
#>

#region parameters
    Param
    (
        #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
        [parameter(mandatory = $false)] [switch]$help,
        [parameter(mandatory = $false)] [switch]$history,
        [parameter(mandatory = $false)] [switch]$debugme,
        [parameter(mandatory = $true)] [string]$cluster,
        [parameter(mandatory = $true)] $vm,
        [parameter(mandatory = $false)] [switch]$allowWildcards,
        [parameter(mandatory = $false)] [switch]$Force,
        [parameter(mandatory = $false)] [ValidateRange(1, 50)] [int]$ThrottleLimit = 10,
        [parameter(mandatory = $false)] $prismCreds
    )
#endregion


#region prepwork

    $HistoryText = @'
Maintenance Log
Date       By   Updates (newest updates at the top)
---------- ---- ---------------------------------------------------------------
10/29/2026 sb   Modernized: removed sbourdeaud module dependency; inlined helpers; fixed SSL for PS7+; removed -log parameter
08/26/2026 sb   Added -Force to skip delete confirmation, A[ll] prompt option, and parallel deletes.
02/22/2021 sb   Initial release, with JM's help.
################################################################################
'
    $myvarScriptName = ".\remove-AhvVm.ps1"

    if ($help) {get-help $myvarScriptName; exit}
    if ($History) {$HistoryText; exit}

    #check PoSH version
    if ($PSVersionTable.PSVersion.Major -lt 5) {throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)"}

    #region helper functions (previously from sbourdeaud module)
    function Invoke-PrismAPICall {
        param (
            [parameter(mandatory = $true)]
            [ValidateSet("POST","GET","DELETE","PUT")]
            [string]$method,

            [parameter(mandatory = $true)]
            [string]$url,

            [parameter(mandatory = $false)]
            [string]$payload,

            [parameter(mandatory = $true)]
            [System.Management.Automation.PSCredential]$credential
        )

        Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
        try {
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json"
                    "Accept"       = "application/json"
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
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))))
                    "Content-Type"  = "application/json"
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                } else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
            Write-Host "$(Get-Date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan
            if ($debugme) { Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White }
        }
        catch {
            Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
            throw "$(Get-Date) [ERROR] $($_.Exception.Message)"
        }
        return $resp
    }

    function Set-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $true)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Set path to $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
        $user = $credentials.UserName
        $securePassword = $credentials.Password

        try {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        if (!(Test-Path $path)) {
            try {
                New-Item -Type Directory $path -ErrorAction Stop | Out-Null
            }
            catch {
                throw "$(Get-Date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
        }

        try {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        }
        catch {
            throw "$(Get-Date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(Get-Date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan
    }

    function Get-CustomCredentials {
        param (
            [parameter(mandatory = $false)]
            [string]$path,

            [parameter(mandatory = $true)]
            [string]$credname
        )

        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            } else {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(Get-Date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        }

        $credentialsFilePath = "$path\$credname.txt"
        if (!(Test-Path $credentialsFilePath)) {
            throw "$(Get-Date) [ERROR] Could not access file $credentialsFilePath"
        }

        $credFile = Get-Content $credentialsFilePath
        $user = $credFile[0]
        $securePassword = $credFile[1] | ConvertTo-SecureString
        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(Get-Date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan
        return $customCredentials
    }

    function Set-PoshTls {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            # PowerShell 7+ already defaults to TLS 1.2+; Invoke-PrismAPICall also sets -SslProtocol Tls12
            return
        }
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = (
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        )
    }

    function Set-PoSHSSLCerts {
        # PowerShell 6+ uses -SkipCertificateCheck on Invoke-RestMethod (see Invoke-PrismAPICall).
        # The old ServicePointManager Add-Type path is obsolete on modern .NET and fails to compile (SYSLIB0014).
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates (SkipCertificateCheck)" -ForegroundColor Green
            return
        }

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
        if (ServicePointManager.ServerCertificateValidationCallback == null)
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                delegate (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                {
                    return true;
                };
        }
    }
}
"@
            Add-Type $certCallback
        }
        [ServerCertificateValidationCallback]::Ignore()
    }
    #endregion

    Set-PoSHSSLCerts
    Set-PoshTls
#endregion


#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
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
      }
      catch 
      {
          Set-CustomCredentials -credname $prismCreds
          $prismCredentials = Get-CustomCredentials -credname $prismCreds -ErrorAction Stop
      }
  }
  $username = $prismCredentials.UserName
  $PrismSecurePassword = $prismCredentials.Password
  $prismCredentials = New-Object PSCredential $username, $PrismSecurePassword
  
  $myvar_vms = $vm.Split(",") #make sure we parse the argument in case it contains several entries
#endregion

#todo: filter out cvms (and maybe fsvms as well as any agent vms)
#region processing	
    #region GET VMs
      Write-Host "$(get-date) [INFO] Retrieving list of VMs..." -ForegroundColor Green
      $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/"
      $method = "GET"
      $myvar_vm_list = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
      Write-Host "$(get-date) [SUCCESS] Successfully retrieved VMs list from $($cluster)!" -ForegroundColor Cyan
    #endregion

    #region build list of VMs to delete
      [array]$myvar_vm_list_to_delete=@()
      ForEach ($myvar_vm in $myvar_vms)
      {
        if ($allowWildcards)
        {#we are using wildcards
          if ($myvar_item = $myvar_vm_list.entities | Where-Object {$_.name -like $myvar_vm})
          {#found a vm to delete
            $myvar_vm_list_to_delete += $myvar_item
          }
        }
        else 
        {#we are using explicit vm names
          if ($myvar_item = $myvar_vm_list.entities | Where-Object {$_.name -eq $myvar_vm})
          {#found a vm to delete
            $myvar_vm_list_to_delete += $myvar_item
          }
        }
      }
      if (!$myvar_vm_list_to_delete)
      {#could not find any of the vms specified
        Throw "$(Get-Date) [ERROR] Could not find any VM on cluster $($cluster) from the specified list!"
      }
    #endregion
    
    #region DELETE VMs
      [array]$myvar_confirmed_vms_to_delete = @()
      $myvar_skip_remaining_prompts = $Force.IsPresent

      ForEach ($myvar_vm_to_delete in $myvar_vm_list_to_delete)
      {#confirm each vm before queuing it for deletion
        if ($myvar_skip_remaining_prompts)
        {#Force was specified, or the user already answered A[ll]
          $myvar_user_choice = "y"
        }
        elseif ($myvar_vm_to_delete.power_state -eq "on")
        {#vm is powered on, prompt user for confirmation
          Write-Host "$(Get-Date) [WARNING] VM $($myvar_vm_to_delete.name) is powered on: are you sure you want to delete it?" -ForegroundColor Yellow
          do {$myvar_user_choice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o]/A[ll])"}
          while ($myvar_user_choice -notmatch '[ynaYNA]')
          $myvar_user_choice = $myvar_user_choice.ToLower()
        }
        elseif ($allowWildcards)
        {#we are using wildcards, so we prompt for confirmation
          Write-Host "$(Get-Date) [WARNING] Are you sure you want to delete VM $($myvar_vm_to_delete.name)?" -ForegroundColor Yellow
          do {$myvar_user_choice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o]/A[ll])"}
          while ($myvar_user_choice -notmatch '[ynaYNA]')
          $myvar_user_choice = $myvar_user_choice.ToLower()
        }
        else
        {#we are using explicit names, so no need to prompt
          $myvar_user_choice = "y"
        }

        if ($myvar_user_choice -ieq "a")
        {#user chose to skip remaining prompts
          $myvar_skip_remaining_prompts = $true
          $myvar_user_choice = "y"
        }

        if ($myvar_user_choice -ieq "y")
        {
          $myvar_confirmed_vms_to_delete += $myvar_vm_to_delete
        }
      }

      if (!$myvar_confirmed_vms_to_delete)
      {#nothing was confirmed for deletion
        Write-Host "$(Get-Date) [WARNING] No VMs were confirmed for deletion." -ForegroundColor Yellow
      }
      else
      {#delete confirmed VMs, in parallel on PowerShell 7+
        $myvar_ps_version = [decimal]($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor -join ".")
        Write-Host "$(Get-Date) [INFO] Deleting $($myvar_confirmed_vms_to_delete.Count) VM(s) from $($cluster)..." -ForegroundColor Green

        if ($myvar_ps_version -ge 7.0)
        {#PowerShell 7+: parallel REST deletes
          $headers = @{
            "Content-Type" = "application/json"
            "Accept" = "application/json"
          }
          $myvar_confirmed_vms_to_delete | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $myvar_vm_to_delete = $_
            $url = "https://{0}:9440/PrismGateway/services/rest/v2.0/vms/{1}" -f $($using:cluster), $myvar_vm_to_delete.uuid
            Write-Host "$(Get-Date) [INFO] Deleting VM $($myvar_vm_to_delete.name)..." -ForegroundColor Green
            try
            {
              $null = Invoke-RestMethod -Method DELETE -Uri $url -Headers $($using:headers) -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $($using:prismCredentials) -ErrorAction Stop
              Write-Host "$(Get-Date) [SUCCESS] Successfully deleted VM $($myvar_vm_to_delete.name) from $($using:cluster)!" -ForegroundColor Cyan
            }
            catch
            {
              Write-Host "$(Get-Date) [ERROR] Failed to delete VM $($myvar_vm_to_delete.name): $($_.Exception.Message)" -ForegroundColor Red
            }
          }
        }
        else
        {#PowerShell 5: sequential deletes
          ForEach ($myvar_vm_to_delete in $myvar_confirmed_vms_to_delete)
          {
            Write-Host "$(get-date) [INFO] Deleting VM $($myvar_vm_to_delete.name)..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/vms/{0}" -f $myvar_vm_to_delete.uuid
            $method = "DELETE"
            try
            {
              $myvar_vm_delete = Invoke-PrismAPICall -method $method -url $url -credential $prismCredentials
              Write-Host "$(get-date) [SUCCESS] Successfully deleted VM $($myvar_vm_to_delete.name) from $($cluster)!" -ForegroundColor Cyan
            }
            catch
            {
              Write-Host "$(Get-Date) [ERROR] Failed to delete VM $($myvar_vm_to_delete.name): $($_.Exception.Message)" -ForegroundColor Red
            }
          }
        }
      }
    #endregion
#endregion


#region cleanup
    #let's figure out how much time this all took
    Write-Host ""
    Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

    #cleanup after ourselves and delete all custom variables
    Remove-Variable myvar* -ErrorAction SilentlyContinue
    Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
    Remove-Variable help -ErrorAction SilentlyContinue
    Remove-Variable history -ErrorAction SilentlyContinue
    Remove-Variable log -ErrorAction SilentlyContinue
    Remove-Variable cluster -ErrorAction SilentlyContinue
    Remove-Variable debugme -ErrorAction SilentlyContinue
    Remove-Variable Force -ErrorAction SilentlyContinue
    Remove-Variable ThrottleLimit -ErrorAction SilentlyContinue
    Remove-Variable prismCreds -ErrorAction SilentlyContinue
    Remove-Variable vm -ErrorAction SilentlyContinue
    Remove-Variable allowWildcards -ErrorAction SilentlyContinue
#endregion