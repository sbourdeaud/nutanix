#cloud-config
cloud_config_modules:
  - runcmd
hostname: ${name}
fqdn: ${name}.${domain}
users:
  - name: nutanix
    ssh-authorized-keys:
      - ${publicKey}
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
runcmd:
  - nmcli connection migrate
  - nmcli con down "System eth0"
  - nmcli con del "System eth0"
  - nmcli con add con-name "System eth0" ifname eth0 type ethernet ip4 ${ip}/${subnetMask} gw4 ${gw} ipv4.dns "${dns1} ${dns2}"
  - nmcli con up "System eth0"
  - nmcli general reload
  - nmcli connection reload
  - [eject]

package_upgrade: false