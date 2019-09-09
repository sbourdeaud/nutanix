#region authentication
    variable "prismUser" {
        default = "admin"
    }
    variable "prismSecret" {
        default = "Nutanix/4u"
    }
    variable "prismEndpoint" {}
    variable "prismPort" {
        default = "9440"
    }
#endregion

#region cluster information
    variable nutanix_image {
        default = "CentOS_7_Cloud"
    }
    variable nutanix_network {}
#endregion

#region vm configuration
    variable "cpu" { 
        default = "1"
    }
    variable "ram" {
        default = "2048"
    }
    variable "qty" {
        default = "1"
    }
    variable "dataDiskSizeMib" {
        default = 51200
    }
#endregion

#region vm customization
    variable "vmName" {
        default = "terraform-vm"
    }
    variable "ips" {
        type    = list(string)
    }
    variable "domain" {}
    variable "subnetMask" {
        default = "255.255.255.0"
    }
    variable "gw" {}
    variable "dns1" {}
    variable "dns2" {}
    variable "publicKey" {}
#endregion