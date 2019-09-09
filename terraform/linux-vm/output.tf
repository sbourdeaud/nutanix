output "vmUuid" {
    value = ["${nutanix_virtual_machine.vm.*.id}"]
}
output "vmName" {
    value = ["${nutanix_virtual_machine.vm.*.name}"]
}