# region headers
"""
# TODO Fill in this section with your information
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v1.0/20210511 - cita-starter version
# task_name:    InfobloxSetMask
# description:  Given a network cidr, compute the mask bits, subnet mask,
# 				network address and broadcast address.               
# outputvars:   InfobloxSetMask
"""
# endregion

# region capture Calm variables
# * Capture variables here. This makes sure Calm macros are not referenced
# * anywhere else in order to improve maintainability.
network = "@@{network}@@"
# endregion

(addrString, cidrString) = network.split('/')

# Split address into octets and turn CIDR into int
addr = addrString.split('.')
cidr = int(cidrString)

# Initialize the netmask and calculate based on CIDR mask
mask = [0, 0, 0, 0]
for i in range(cidr):
	mask[i/8] = mask[i/8] + (1 << (7 - i % 8))

# Initialize net and binary and netmask with addr to get network
net = []
for i in range(4):
	net.append(int(addr[i]) & mask[i])

# Duplicate net into broad array, gather host bits, and generate broadcast
broad = list(net)
brange = 32 - cidr
for i in range(brange):
	broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))

# Print information, mapping integer lists to strings for easy printing
print("subnet_mask_bits={0}".format(cidr))
print("net_ip_address={0}".format(addrString))
print("subnet_mask={0}".format(".".join(map(str, mask))))
print("network={0}".format(".".join(map(str, net))))
print("broadcast={0}".format(".".join(map(str, broad))))