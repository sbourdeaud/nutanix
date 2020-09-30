#*run remote powershell session
enter-pssession -computername hostname

#*run script on remote machine
Invoke-Command -ComputerName gso-mgt-vm-dc01 -Scriptblock {Get-Process}

#*join domain
Rename-Computer -NewName RDSH1
Restart-Computer
add-computer -domainname gso.lab -Credential (get-credential)
restart-computer

#*change service configuration and start service
 set-service -name msiscsi -startuptype automatic
 start-service msiscsi

#*add windows features and roles
import-module servermanager
add-windowsfeature file-services,fs-resource-manager
add-windowsfeature Failover-Clustering,RSAT-Clustering
add-windowsfeature fs-dfs-namespace
add-windowsfeature fs-dfs-replication

#*disable signed scripts
set-executionpolicy unrestricted -scope localmachine

#*scheduling powershell script in windows server 2003 with environment variable and arguments
C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -command "& $env:mq_java_data_path\Qmgrs\BackupQM\backupQM.ps1 -qmanager QCARW01"

#*Win2008: Show process information based on PID (useful after netstat -ano):
get-process | where{$_.Id -eq 3496} | select ProcessName,Product,Path |ft -autosize -wrap

#*Windows: List top 5 CPU consumers:
Get-WmiObject Win32_PerfFormattedData_PerfProc_Process | where-object{ $_.Name -ne "_Total" -and $_.Name -ne "Idle"} | Sort-Object PercentProcessorTime -Descending | select -First 5 | Format-Table Name,IDProcess,PercentProcessorTime -AutoSize
get-process | where {$_.CPU -ne $null} | select -Property ProcessName,Id,CPU | sort-object -Property CPU -Descending | Select -First 5

#*Windows: List all CPU using processes and sort:
get-process | where {$_.CPU -ne $null} | sort-object -Property CPU -Descending

#*Windows: List hotfixes installed
Get-wmiobject -Query "SELECT HotFixID FROM Win32_QuickFixEngineering" | ft HotFixID
Get-wmiobject -Query "SELECT HotFixID FROM Win32_QuickFixEngineering" | where {$_.HotFixID -eq "KB3161561"}

#*Windows: Get basic operating system information
Get-wmiobject -Query "SELECT CSName, Caption, CSDVersion, OSArchitecture, PAEEnabled, ServicePackMajorVersion FROM Win32_OperatingSystem" | Format-List CSName, Caption, ServicePackMajorVersion, CSDVersion, OSArchitecture, PAEEnabled

#*Windows: Find large files on the c: drive
get-childitem -Path "C:\" -recurse | ? { $_.GetType().Name -eq "FileInfo" } | where-Object {$_.Length -gt 134217728}| sort-Object -property length -Descending | select Directory,Name,@{Name="SizeMB"; Expression={"{0:N0}" -f ([math]::Round(($_.Length/1024/1024)))}} | ft -wrap

#*Windows: retrieve errors from system log for the last 24 hours
get-eventlog -LogName System -EntryType Error -Before (Get-Date -Hour 0 -Minute 0 -Second 0) -After ((Get-Date -Hour 0 -Minute 0 -Second 0).AddDays(-1)) | select TimeGenerated,EventID,Source,Message | ft -autosize -wrap
get-eventlog -LogName System -EntryType Error,Warning -After ([DateTime]((Get-CimInstance -ClassName win32_operatingsystem).lastbootuptime)) | select TimeGenerated,EventID,Source,Message | ft -autosize -wrap
get-eventlog -LogName System -EntryType Error,Warning -After ((Get-WmiObject win32_operatingsystem | select @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime) | select TimeGenerated,EventID,Source,Message | ft -autosize -wrap


#*Windows: get last boot time
Get-CimInstance -ClassName win32_operatingsystem | select lastbootuptime
[DateTime]((Get-CimInstance -ClassName win32_operatingsystem).lastbootuptime)
(Get-WmiObject win32_operatingsystem | select @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime


#*Windows: get information on the most recent 5 processes
Get-Process | Sort-Object StartTime -ea 0 -desc | select-object ProcessName,Description,Path,Id,StartTime -First 5

#*Windows: get a history of all USB devices
Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object -ExpandProperty FriendlyName | Sort-Object

#*Windows: find out which groups you belong to
([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value } | Sort-Object

#*Windows: list domain controllers
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers

#*Windows: count number of applied updates per day
Get-Content $env:windir\windowsupdate.log | Where-Object { $_ -like '*successfully installed*' } | Group-Object { $_.SubString(0,10) } -NoElement | Sort-Object Count -Descending | Select-Object Count, Name

#*Windows: list driver information
driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select-Object 'Display Name','Start Mode','State','Paged Pool(bytes)',Path | ft -wrap

#*Windows: list services by start mode
Get-WMIObject Win32_Service | Select-Object Name, StartMode | Sort-Object StartMode

#*windows: configure an ip interface
New-NetIPAddress -InterfaceAlias "Wired Ethernet Connection" -IPv4Address 10.0.0.6 -PrefixLength 24

Set-DnsClientServerAddress -InterfaceAlias "Wired Ethernet Connection" -ServerAddresses 10.0.0.1
&{$adapter = Get-NetAdapter -Name Ethernet;New-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -IPAddress 192.168.1.55 -PrefixLength 24 -DefaultGateway 192.168.1.1; Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ("192.168.1.2","192.168.1.3")}
&{$adapter = (get-netadapter | where {$_.status -eq "up"});New-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -IPAddress 10.1.175.250 -PrefixLength 22 -DefaultGateway 10.1.174.1; Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ("10.1.174.5","10.4.89.111")}
&{$adapter = (get-netadapter | where {$_.status -eq "up"});New-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -IPAddress 10.4.92.200 -PrefixLength 22 -DefaultGateway 10.4.92.1; Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ("10.4.89.111","10.4.89.112")}

$script = '&{$adapter = (get-netadapter | where {$_.status -eq "up"});New-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -IPAddress 10.4.92.200 -PrefixLength 22 -DefaultGateway 10.4.92.1; Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ("10.4.89.111","10.4.89.112")}'
Invoke-VMScript -ScriptText $script -ScriptType Powershell -VM corevm_1 -GuestUser administrator -GuestPassword nutanix/4u

http://www.adminarsenal.com/admin-arsenal-blog/using-powershell-to-set-static-and-dhcp-ip-addresses-part-1/

#*Windows: convert to server core
Uninstall-WindowsFeature -Name Server-Gui-Mgmt-Infra, Server-Gui-Shell -Restart
#*(See more at: http://www.technig.com/convert-server-core-to-full-gui-and-vice-versa/#sthash.mir33zX5.dpuf)
Install-WindowsFeature -Name Server-Gui-Mgmt-Infra, Server-Gui-Shell -Source:E:\sources\install.wim

#*General: Ping range of IP addresses
1..254 | %{ping -n 1 -w 15 192.168.1.$_ | select-string "reply from"}

#*Ping a URL ($url)
if ((new-object net.webclient).DownloadString($url)) {write-host Passed -foregroundcolor "green"}

#*nslookup (host:ip and ip:host)
[System.Net.Dns]::GetHostAddresses("www.msn.com") | select IPAddressToString
[System.Net.Dns]::GetHostbyAddress("207.46.198.30")

#*Windows: get ntfs allocation size
Get-WmiObject -Query "SELECT Label, Blocksize, Name FROM Win32_Volume WHERE FileSystem='NTFS'" -ComputerName '.' | Select-Object Label, Blocksize, Name
