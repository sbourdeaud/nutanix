#cloud-config
cloud_config_modules: 
  - resolv_conf
  - runcmd
hostname: ${name}
fqdn: ${name}.${domain}
users:
  - name: centos
    ssh-authorized-keys:
      - ${publicKey}
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
write_files:
  - path: /etc/sysconfig/network-scripts/ifcfg-eth0
    content: |
      IPADDR="${ip}"
      NETMASK="${subnetMask}"
      GATEWAY="${gw}"
      BOOTPROTO=none
      ONBOOT=yes
      DEVICE=eth0
runcmd:
  - [ifdown, eth0]
  - [ifup, eth0]
  - [eject]
manage_resolv_conf: true
resolv_conf:
  nameservers: ['${dns1}', '${dns2}']
  domain: ${domain}
  options:
    rotate: true
    timeout: 1