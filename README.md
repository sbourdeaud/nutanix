
NAME
    C:\Users\user\Documents\GitHub\nutanix\set-ipconfig.ps1
    
SYNOPSIS
    This script is used to deal with IP changes in DR scenarios.  It saves static IP configuration (ipconfig.csv and previous_ipconfig.csv), allows for 
    alternative DR IP configuration (dr_ipconfig.csv) and reconfigures an active interface accordingly. The script only works with 2 DNS servers (no suffix 
    or search list). Each configuration file is appended with a numerical index starting at 1 to indicate the number of the interface (sorted using the 
    ifIndex parameter).
    
    
SYNTAX
    C:\Users\user\Documents\GitHub\nutanix\set-ipconfig.ps1 [-help] [-history] [-log] [-debugme] [[-path] <String>] [-dhcp] [[-interface] <String>] 
    [<CommonParameters>]
    
    
DESCRIPTION
    This script is meant to be run at startup of a Windows machine, at which point it will list all active network interfaces (meaning they are connected).  
    If it finds no active interface, it will display an error and exit, otherwise it will continue.  If the active interface is using DHCP, it will see if 
    there is a previously saved configuration and what was the last previous state (if any).  If there is a config file and the previous IP state is the 
    same, if there is a DR config, it will apply it, otherwise it will reapply the static config. If the IP is static and there is no previously saved 
    config, it will save the configuration.  It records the status every time it runs so that it can detect regular static to DR changes.  A change is 
    triggered everytime the interface is in DHCP, and there is a saved config.  If the active interface is already using a static IP address and there is a 
    dr_ipconfig.csv file, the script will try to ping the default gateway and apply the dr_ipconfig if it does NOT ping. If the gateway still does not ping, 
    it will revert back to the standard ipconfig.
    

PARAMETERS
    -help [<SwitchParameter>]
        Displays a help message (seriously, what did you think this was?)
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -history [<SwitchParameter>]
        Displays a release history for this script (provided the editors were smart enough to document this...)
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -log [<SwitchParameter>]
        Specifies that you want the output messages to be written in a log file as well as on the screen.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -debugme [<SwitchParameter>]
        Turns off SilentlyContinue on unexpected error messages.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -path <String>
        Specify the path where you want config files and last state to be saved.  By default, this is in c:\
        
        Required?                    false
        Position?                    1
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -dhcp [<SwitchParameter>]
        Use this switch if you want to configure one or more interfaces with dhcp
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -interface <String>
        Specify the interface you want to configure with -dhcp using an index number.  Use 1 for the first interface, 2 for the second, etc... or all for 
        all interfaces.
        
        Required?                    false
        Position?                    2
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216). 
    
INPUTS
    
OUTPUTS
    
NOTES
    
    
        Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
        Revision: November 7th 2016
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Simply run the script and save to c:\windows:
    
    PS> .\set-ipconfig.ps1 -path c:\windows\
    
    
    
    
    
RELATED LINKS
    http://www.nutanix.com/services
