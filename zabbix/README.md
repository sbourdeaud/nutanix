# Configuration instructions for configuring SNMP traps from Prism to Zabbix
This document explains how to configure SNMP traps forwarding from Nutanix Prism to Zabbix v4 and above.  
It specifically covers:  
<a id="ToC"></a>
1. [How to configure SNMPv3 in Prism](#PrismConfiguration)  
2. [How to configure the Zabbix proxy or server for receiving SNMPv3 traps](#ZabbixServerConfiguration)  
3. [How to test SNMP traps from Prism to Zabbix](#SNMPTest)  
4. [How to configure a host object in Zabbix to match the Nutanix cluster and automate the creation of Zabbix items and triggers in a template for the SNMP traps you want](#ZabbixMonitoringConfiguration)  

## <a id="PrismConfiguration"></a>How to configure Nutanix Prism to send SNMPv3 traps to Zabbix

1. **Adding the SNMPv3 user in Nutanix Prism**:
   1. Log into Prism and navigate to the "*Settings* > *SNMP* > *Users*" page
   2. Click on "*New User*"
   3. Enter a username (exp: zabbix) and type the same password in AES and SHA. Note that you will configure the same password later on, so make sure to note it down somewhere.  It is recommended to avoid special Unix characters such as ^ or \ or /.
   4. Click "*Save*"
2. **Configuring the trapper in Nutanix Prism**:
   1. Log into Prism and navigate to the "*Settings* > *SNMP* > *Traps*" page
   2. Click on "*New Trap Receiver*"
   3. Enter the following information:
      1. `Receiver Name` : this can be anything you want that is meaningful to you to designate your Zabbix server or proxy.
      2. `SNMP Version` : v3
      3. `Trap Username` : select the user you created in the previous list from the drop down menu
      4. `Address` : enter the IP address or FQDN of your Zabbix server or proxy. Note that if you use an FQDN, you'll need to make sure that it can be resolved from all CVMs (in other words, that the DNS server they point to can resolve that FQDN)
      5. Leave everything else blank or default and click "*Save*"
      6. Copy the Engine ID string that was assigned to the SNMP Trap Receiver entry you just created as you will need it later

Note that you don't need to create an SNMP transport, unless you want to also pull information from SNMP polling from the Zabbix server. This topic is not covered in this document.

[*<<back to ToC*](#ToC)

## <a id="ZabbixServerConfiguration"></a>How to configure the Zabbix proxy or server for SNMPv3 traps
The official Zabbix documentation is available here: [Zabbix Documentation 5.4 - SNMP Traps](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/snmptrap)  
However, this documentation is not super explicit and does not explain the fine details of how to get SNMPv3 working.  
Before we detail the steps, note that additional helpful references are:
- [Zabbix SNMP – What You Need to Know and How to Configure It](https://blog.zabbix.com/zabbix-snmp-what-you-need-to-know-and-how-to-configure-it/10345/)
- [SNMPv3 Configuration and Troubleshooting](https://assets.zabbix.com/files/events/meetup_20200813/Arturs_Lontons_Zabbix_SNMPv3.pdf)
- [SNMPTT installation on CentOS 7 for Zabbix integration](https://gist.github.com/TEH30P/9e29a05de7d3ffd5e4f51e2bb4fab385)
- [SNMP Traps in Zabbix](https://blog.zabbix.com/snmp-traps-in-zabbix/8210/)

Based on information from all the above sources, here are detailed steps for a Zabbix proxy running on RHEL7:  
1. **Installing the required packages**: assuming you are running Zabbix (proxy and/or server) on CentOS or RHEL 7, use the following command to install all pre-requisite packages:  
   ``sudo yum install -y net-snmp net-snmp-utils perl-Net-SNMP net-snmp-perl``  
   Note that for the Perl packages, you may have to use the EPEL repositories which can be installed with the following command:  
   ``sudo yum install -y epel-release``
2. **Adding the Nutanix MIB**: the Nutanix MIB can be downloaded from Nutanix Prism interface by navigating to the "*Settings* > *SNMP*" page and clicking on "*View MIB*". You can then save that file with a `.txt` extension and copy it on your Zabbix proxy/server in the `/usr/share/snmp/mibs/` directory with the other MIBs.
3. **Adding the Zabbix Perl script (and customizing it for name resolution)**: the SNMP trap service/daemon on Linux needs something to interpret the incoming traps and make sense out of them.  This could be something generic such as SNMPTT, but for Zabbix, there is a Perl script supplied by Zabbix to do that job.  This script will process incoming traps and format them in a shape that is understood and can be exploited by Zabbix.  
The script name is `zabbix_trap_receiver.pl` and is available from Zabbix sources. This is explained in the following Zabbix [blog](https://blog.zabbix.com/snmp-traps-in-zabbix/8210/).  
For convenience, to retrieve the Zabbix source code and get a copy of the script, follow these instructions (replace the Zabbix version numbers with yours or refer to the blog article if the links are not working for you):
   - From a temporary directory:  
     ``wget https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/4.4.0/zabbix-4.4.0.tar.gz``
   - Extract the sources:  
     ``tar −zxvf zabbix _._._.tar.gz``   
   - Copy the Perl script in a location of your choice:  
     ``cp zabbix-_._._/misc/snmptrap/zabbix_trap_receiver.pl /usr/lib/zabbix/zabbix_trap_receiver.pl``
   - Assign execute permissions for the script:  
     ``chmod +x /usr/lib/zabbix/zabbix_trap_receiver.pl``  

    Now by default, the script will identify any source of SNMP traps with its IP address. Because our Nutanix cluster has multiple IP addresses (one per CVM as any CVM at any point in time could run the SNMP daemon that sends traps), and to make the Zabbix configuration simpler, it is preferable that we identify our SNMP traps sources by their resolved hostname.  
    Note that this requires that you set up PTR entries in the reverse lookup zone in your DNS server for each CVM IP address to resolve to whatever the Nutanix cluster name is (exp: *mynutanixcluster.mydomain.local*).  
    To change the its default behavior, we must modify the Zabbix supplied Perl script by changing the code within the `zabbix_receiver` procedure and adding the following lines after the line that reads `$hostname = $1 || 'unknown';`:  
    ```perl
    if ($hostname ne 'unknown')
    {
        $hostname = `nslookup $hostname | awk '{print substr(\$4, 1, length(\$4)-1)}'` || $hostname;
    }
    ```
    This code will attempt to resolve the IP address to a hostname.

5. **Configuring the snmptrapd service**: now that everything is in place for snmptrapd to work, we need to change a couple of things:
   1. First, we need to change the default behavior of the service by editing the `/etc/sysconfig/snmptrapd` file and adding the following line at the end:  
   ``OPTIONS="-OS -m-/usr/share/snmp/mibs/NUTANIX-MIB.txt -Lsd -Lf /var/log/snmptrapd.log"``  
   This will create a log file for the service (which will help with troubleshooting) and will make sure that the OIDs are properly resolved using the Nutanix MIB file when variables are parsed in the trap.
   2. Then we need to configure the SNMPv3 user as well as the Perl interpreter for the snmptrapd service/daemon by editing the `/etc/snmp/snmptrapd.conf` file.  
   Add the following lines to the end of that file:  
   ```
   createUser -e "replace_this_with_your_engine_id_string" zabbix SHA key2thedoor AES replace_this_with_your_password
   authUser execute zabbix
   perl do "/usr/lib/zabbix/zabbix_trap_receiver.pl";
   ```
   Note that in this example, the SNMPv3 user name is *zabbix* (but it could be whatever you want).  
   The engine ID, you got from Nutanix Prism when you configured the SNMP receiver earlier.  If you forgot to write it down, don't panic and go back to Prism to copy the weird looking string.  
   If you intend to get traps from multiple Nutanix Prism instances with different engines ID, you will need to repeat the first line for each Nutanix Prism instance.  

   You will then need to enable the snmptrapd service and start it with the following commands:  
   ```
   sudo systemctl enable snmptrapd  
   sudo systemctl start snmptrapd
   ```  
   You can use ``sudo systemctl status snmptrapd`` to see if there are any errors being reported and to verify that the service is started and active.

   Note that if you have the firewall service enabled on your RHEL or CentOS 7 system, you will need to open UDP port 162 with the following commands:  
   ```
   firewall-cmd --add-port=162/udp --permanent
   firewall-cmd --reload
   ```
   At this point, we'll assume SELinux is disabled. If not, you will probably have to authorize that Perl handler script somehow.
6. **Configuring the Zabbix trapper**  
Ok, now that our snmptrapd service is configured, it is time to let Zabbix know about it.  
This is done by editing the `/etc/zabbix/zabbix_server.conf` file if you are not using a proxy, or the `/etc/zabbix/zabbix_proxy.conf` file if you are using a proxy.
Within this file, you will need to make sure that the two following lines are present and not commented:
```
SNMPTrapperFile=/tmp/zabbix_traps.tmp
StartSNMPTrapper=1
```
Note that you can use a different directory for writing your traps, but you will then need to make sure the `/usr/lib/zabbix/zabbix_trap_receiver.pl` file points to the same location (as it also contains a reference to that file) and that the zabbix user used to execute the script has permissions to write in that directory and file.  
You can then restart the Zabbix server or proxy with one of the following commands:  
```
sudo systemctl restart zabbix_server
sudo systemctl restart zabbix_proxy
```

The overall idea is that the snmptrapd service receives traps over UDP 162 from a sender (in our case Nutanix Prism). When it does, it will run the Perl handler script which will parse the trap and write information in the `/tmp/zabbix_traps.tmp` file.  This is then picked up by the Zabbix trapper and accessible to be used in Zabbix monitoring configuration.

[*<<back to ToC*](#ToC)

## <a id="SNMPTest"></a>How to test SNMPv3 traps from Nutanix to Zabbix

So we are now ready to test that what was just described actually works.  
Log into Prism and navigate to the "*Settings* > *SNMP* > *Traps*" page and click on "*Test all*".  
This will send a test trap to the configured receivers.

Back on the Zabbix server or proxy, you should see content inside the `/tmp/zabbix_traps.tmp` file similar to the following:  
```
13:10:21 2021/12/11 ZBXTRAP lancelot.emeagso.lab


PDU INFO:
  contextEngineID                0x80001f8880458bc8123da3b46100000000
  notificationtype               TRAP
  version                        3
  receivedfrom                   UDP: [10.68.97.37]:48600->[10.68.99.70]:162
  errorstatus                    0
  messageid                      646221619
  securitylevel                  3
  securityEngineID               0x8000a12f04372080d7526e4b9ebedbd453a71435af
  securityName                   zabbix
  contextName
  securitymodel                  3
  transactionid                  17
  errorindex                     0
  requestid                      305493060
VARBINDS:
  DISMAN-EVENT-MIB::sysUpTimeInstance type=67 value=Timeticks: (78067120) 9 days, 0:51:11.20
  SNMPv2-MIB::snmpTrapOID.0      type=6  value=OID: NUTANIX-MIB::ntxTrapResolved
  NUTANIX-MIB::ntxTrapName       type=4  value=STRING: "ntxTrapTestAlertTitle"
  NUTANIX-MIB::ntxAlertResolvedTime type=70 value=Counter64: 1639053634
  NUTANIX-MIB::ntxAlertDisplayMsg type=4  value=STRING: "AlertUuid:2406cfa7-4b7a-4233-93fd-5e1d25fe3960: Test Alert is generated on Controller VM 10.68.97.32."
  NUTANIX-MIB::ntxAlertTitle     type=4  value=STRING: "Test Alert Title"
  NUTANIX-MIB::ntxAlertSeverity  type=2  value=INTEGER: 1
  NUTANIX-MIB::ntxAlertClusterName type=4  value=""
  NUTANIX-MIB::ntxAlertUuid      type=4  value=STRING: "2406cfa7-4b7a-4233-93fd-5e1d25fe3960"
```

You will want to make sure that:
1. The first line displays the cluster hostname (as opposed to the CVM IP address): if not, DNS is not setup with the correct PTR records.
2. The VARBINDS section displays NUTANIX-MIB entries on not OIDs: if not, you have not put the Nutanix MIB in the correct directory, or the file has incorrect permissions, or the `/etc/sysconfig/snmptrapd` file is not pointing to the correct MIB file.

If you are not getting any content inside the `/tmp/zabbix_traps.tmp` file, try restarting your snmptrapd service, looking at its log file, or retracing all the configuration steps.  Keep in mind that it could also be a firewall or network routing issue between your Nutanix cluster and your Zabbix proxy or server (try testing port UDP 162 from a Nutanix CVM using nc or curl for example).

[*<<back to ToC*](#ToC)

## <a id="ZabbixMonitoringConfiguration"></a>Zabbix server monitoring configuration

1. **Configuring the Zabbix server with the host object**: this is done from the Zabbix server UI. You should create one host entry for each Nutanix cluster you intend to monitor. For each host, you will need to add an SNMP interface with type DNS and put in the cluster FQDN to which the CVM IP addresses resolve in DNS.
2. **Creating the Nutanix SNMP template using PowerShell scripts for the items and triggers in Zabbix**: still in the Zabbix UI, create a new template named "Nutanix Template" (or any name that makes sense to you).  We will now need to create items and triggers for all the SNMP traps you want to alert on.  
To figure out all possible alerts, you can use [this](https://github.com/sbourdeaud/nutanix/blob/master/prism/prism-element/get-ntnxAlertPolicy.ps1) PowerShell script which will produce a csv file with all possible alerts.  Edit that file and keep in it only the alerts you are interested in (exp: all critical and warnings).  Then use [this](https://github.com/sbourdeaud/nutanix/blob/master/zabbix/set-ZabbixNutanixTemplate.ps1) script to create the items and triggers in the Nutanix template on the Zabbix server based on the csv input.  
Note that you may get some errors when there are funky characters in some of the messages or description fields, so you may have to edit the csv file to remove those characters, then simply run the script again. Any existing item or trigger will be skipped.  
An example file containing all storage related alerts which are either a Warning or Critical is included in this repository ([zabbix_template_nutanix_smb.xml](https://raw.githubusercontent.com/sbourdeaud/nutanix/master/zabbix/zabbix_template_nutanix_smb.xml))

Now apply the Nutanix template to your cluster hosts.  
That's it! You should now receive traps and alerts from Prism into Zabbix.

[*<<back to ToC*](#ToC)