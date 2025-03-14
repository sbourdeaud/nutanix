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
        default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9GE/gov8gOPsSkKVeejG5NYTJTQGNFCsJOXFcszhd1s1ixS1ClVZs3MduB1fWSvY8Vjzs+jD5VkW7SdwxEQQmOvyF8sHGNM1s4FGNgnRIvKXlPaXQSe9TUEl52xJa7G0JwggiG4kNgCtJmunK9cXZMj+iTQqSwdGvidOFdMxTbmSjlTNEE4kMIP4jiyZEKztVbz4i9+bI/Sq8cQVX+pNF6XTjxqUgDH15KIejnXw6QDH26yv6KWbSjtRl+8HvE1yNtJh9yXDEJ1pt4jcvE2SHNfFYlY8HM9qyymeVkL7SzL3u6dmkN7ospqiNgJVEW/iOATUHICLZpSXj1kr73xFB"
        type = string
    }
#endregion