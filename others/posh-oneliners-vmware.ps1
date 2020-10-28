Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope All

#*VMware: show vSwitches and remaining ports:
get-virtualswitch | select Name,NumPortsAvailable,@{Name="Host";Expression={(get-vmhost -Id $_.VMHostId)}} |ft -autosize

#*VMware: set all disks to roundrobin multipath policy
Get-VMhost | Get-ScsiLun -LunType disk |  where {$_.MultiPathPolicy -ne "RoundRobin"} | Set-ScsiLun -MultipathPolicy "RoundRobin" | ft -autosize
get-cluster "Farm E" | get-vmhost | get-datastore -Name "DS808A_E_Thin_21" | Get-ScsiLun -LunType disk |  where {$_.MultiPathPolicy -ne "RoundRobin"} | Set-ScsiLun -MultipathPolicy "RoundRobin" | ft -autosize

#*VMware: view all connected CD-ROM drives
Get-vm | Select-Object @{ Name="Status"; Expression={(Get-CDDrive -VM $_).ConnectionState.Connected}}, @{ Name="Name"; Expression={$_.Name}} | ft -autosize

#*VMware: get list of LUN IDs on a given cluster
get-cluster "Farm E" | get-vmhost | select -first 1 | get-datastore -Name "DS804A_E_Thick*" | get-scsilun | export-csv c:\temp\farme_luns.csv

#*VMware: get vm with a specific MAC@
Get-vm | Select Name, @{N="Network";E={$_ | Get-networkAdapter | ? {$_.macaddress -eq "00:50:56:84:00:0A"}}} |Where {$_.Network -ne $null}

#*VMware: move storage for VMs that are in a given datastore based on their name
get-datastore DS804A_E_Thin_04 | get-vm | where-object {$_.Name -match "^MIAVM"} | move-vm -Datastore DS808A_E_Thin_01 -DiskStorageFormat Thin
get-datastore DS808A_E_Thin_18 | get-vm | move-vm -Datastore DS809A_E_Thin_13 -DiskStorageFormat Thin

#*VMware: list all LUN IDs for a given datastore:
get-datastore -Name "DS809A_E_Thick_27" | get-scsilun |sort-object CanonicalName |get-unique |select CanonicalName

#*VMware: remove a datastore from all hosts in a given cluster
get-cluster "Farm E" | get-vmhost | Remove-Datastore -Datastore DS804A_E_Thin_02

#*VMware: rescan HBAs for all hosts in a given cluster
get-cluster "Farm E" | get-vmhost | get-vmhoststorage -RescanAllHba

#*VMware: count total number of LUNs on a given host
(get-vmhost miavs957.mia.michelin.com | get-scsilun | sort-object CanonicalName | get-unique).count

#*VMware: update vmware tools
Get-VM | Update-Tools -NoReboot

#*VMware: list and remove snapshots
Get-VM | Get-Snapshot | where {$_.Created -lt "mm/dd/yyyy"} | fl *
Get-VM | Get-Snapshot | where {$_.Created -lt "mm/dd/yyyy"} | Remove-Snapshot

#*VMware: basic inventory of vm > cluster > host > datastore
get-VM | Select Name,@{N="Cluster";E={Get-Cluster -VM $_}},@{N="ESX Host";E={Get-VMHost -VM $_}},@{N="Datastore";E={Get-Datastore -VM $_}}

#*VMware: provision 2 VM(s) from the same template
new-vm -Template "Windows 2008 R2 - TIM Build" -Datastore "Virtual Machine Datastores" -Location "veeam" -OSCustomizationSpec "Win 2008 R2 - DHCP, No Domain" -ResourcePool "veeam" -Name SB_veeam3
1..50 | Foreach {new-vm -Template "Windows Server 2008 R2 Enterprise - TIM" -Datastore "Virtual Machine Datastores" -Location "tests" -OSCustomizationSpec "Win 2008 R2 - DHCP, No Domain" -ResourcePool "tests" -Name SB_sqlvm_$_}
1..3 | Foreach {new-vm -Template "c09-w2k12r2-core" -Datastore "c09-ct1" -Location "HQ-Stephane" -OSCustomizationSpec "w2k12r2-dhcp-domain" -ResourcePool "c09-rp" -Name SB_MAVM_$_}

#*VMware: shutdown all VMs in a cluster
get-cluster "Citrix" | get-vm | shutdown-vmguest -Confirm:$false

#*VMware: change CPU allocation to 2 for all VMs in a given cluster
get-cluster "Citrix" | get-vm | set-vm -NumCpu 2

#*Create multiple clones of a vm
1..10 | foreach {new-vm -vm vm1 -name vm$_ -resourcepool Test}
41..45 | foreach {new-vm -vm vm31 -name vm$_ -datastore c15-metro2 -vmhost c15nodea.gso.lab -location HQ-Stephane}

#*Start all the VMs in a given resource pool
Get-ResourcePool Test | get-vm | start-vm

#*Change VM portgroup
Get-VM |Get-NetworkAdapter |Where {$_.NetworkName -eq $OldNetwork } |Set-NetworkAdapter -NetworkName $NewNetwork -Confirm:$false

#*Get IP address of VM
Get-VM | Select Name, @{N="IP Address";E={@($_.guest.IPAddress[0])}}

#*Get WWN for cluster
Get-Cluster clustername | Get-VMhost | Get-VMHostHBA -Type FibreChannel | Select VMHost,Device,@{N="WWN";E={"{0:X}" -f $_.PortWorldWideName}} | Sort VMhost,Device

#*Get WWN by single host
Get-VMhost -Name Host | Get-VMHostHBA-Type FibreChannel | Select VMHost,Device,@{N="WWN";E={"{0:X}" -f $_.PortWorldWideName}} | Sort VMhost,Device

#* http://www.virtu-al.net/script-list/

#*Remove greyed out vms
Get-VM | where {$_.ExtensionData.Summary.OverallStatus -eq 'gray'} | remove-vm -Confirm:$false

#*Start PowerCLI core on Mac
Get-Module -ListAvailable PowerCLI* | Import-Module

#*Export all VM MAC addresses
Get-View -Viewtype VirtualMachine -Property Name, Config.Hardware.Device | Select name, @{n="MAC(s)"; e={($_.Config.Hardware.Device | ?{($_ -is [VMware.Vim.VirtualEthernetCard])} | %{$_.MacAddress}) -join ","}} | Export-Csv c:\temp\VMMACsInfo.csv -UseCulture -NoTypeInformation

#*VMware: Remove physical network adapter uplinks on a given host
Get-VMhost "tiana-3.gso.lab" | Get-VMHostNetworkAdapter -Physical | where {$_.Name -ne "vmnic2"} | Remove-VirtualSwitchPhysicalNetworkAdapter -Confirm:$false

#*VMware: share nothing migration
Get-VM $vmname | Move-VM -Destination $vmhost -Datastore (get-datastore “$datastorename”) -confirm:$false -RunAsync:$true

#*VMware: get cpu oversubscription ratio
Get-Cluster | Sort-Object -Property Name | Select Name, @{N="CpuOversubscriptionRatio";E={[math]::Round((($_|get-VM|measure numcpu -sum).Sum)/(($_|get-vmhost|measure numcpu -sum).sum),2)}}

Get-Cluster | Sort-Object -Property Name | Select Name, @{N="Cores";E={($_|get-vmhost|measure numcpu -sum).sum/2}}, @{N="vCPUs";E={($_|get-VM|where {$_.PowerState -eq "PoweredOn"}|measure numcpu -sum).Sum}}, @{N="Ratio";E={[math]::Round((($_|get-VM|where {$_.PowerState -eq "PoweredOn"}|measure numcpu -sum).Sum)/(($_|get-vmhost|measure numcpu -sum).sum/2),2)}}

#*VMware: get memory oversubscription ratio
Get-Cluster | Sort-Object -Property Name | Select Name, @{N="RAM";E={[math]::Round(($_|get-vmhost|measure MemoryTotalGB -sum).sum,2)}}, @{N="Allocated";E={($_|get-VM|where {$_.PowerState -eq "PoweredOn"}|measure MemoryGB -sum).Sum}}, @{N="Ratio";E={[math]::Round((($_|get-VM|where {$_.PowerState -eq "PoweredOn"}|measure MemoryGB -sum).Sum)/(($_|get-vmhost|measure MemoryTotalGB -sum).sum),2)}}

#*Vmware: add to inventory all vmx in a datastore:
dir 'vmstores:\<nom du vCenter>@443\<nom du datacenter>\<nom du datastore>\restore\*\*.vmx' | % {New-VM -Host "esxihostname" -VMFilePath $_.DatastoreFullPath}
