#region authentication
    variable "prismUser" {
        type = string
    }
    variable "prismSecret" {
        type = string
    }
    variable "prismEndpoint" {
        type = string
    }
    variable "prismPort" {
        type = string
        default = "9440"
    }
#endregion

#region cluster information
    variable nutanix_image {
        default = "rhel8-cloud-image.qcow2"
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
        default = 102400
    }
#endregion

#region vm customization
    variable "vmName" {
        default = "tf-vm"
    }
    variable "ips_file" {
        type = string
        default = "ips.csv"
    }
    variable "domain" {
        type = string
    }
    variable "subnetMask" {
        default = "24"
    }
    variable "gw" {
        type = string
    }
    variable "dns1" {
        type = string
    }
    variable "dns2" {
        type = string
    }
    variable "publicKey" {
        type = string
    }
#endregion