"""Description here.
    Args:
    Returns:  
"""


import argparse
import socket
from datetime import datetime
import ipaddress
import netflow


class BColors:
    """Description here.
        Attributes:
        Methods:  
    """
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR


class NetflowPacket:
    """Description here.
        Attributes:
        Methods:  
    """
    def __init__(
        self,timestamp,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        size_bytes):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.size_bytes = size_bytes


    def print(self):
        """Description here.
            Args:
            Returns:  
        """
        print(f"{self.timestamp},{self.protocol},{self.size_bytes},\
            {self.source_ip}:{self.source_port} --> {self.destination_ip}:{self.destination_port}")


def main(port,buffer,nslookup):
    """Description here.
        Args:
        Returns:  
    """
    parsed_netflow_data = collect_netflow(port,buffer,nslookup)
    return parsed_netflow_data


def define_protocols(protocol_number):
    """Description here.
        Args:
        Returns:  
    """
    prefix = "IPPROTO_"
    table = {num:name[len(prefix):]
        for name,num in vars(socket).items()
           if name.startswith(prefix)}
    return table[protocol_number]


def collect_netflow(port,buffer,nslookup):
    """Description here.
        Args:
        Returns:  
    """
    print(f"{BColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}\
        [INFO] Listening for NetFlow IPFIX (v10) data on UDP:{port} with a buffer size of {buffer} bytes.\
        {BColors.RESET}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    templates = {"netflow": {}, "ipfix": {}}
    while True:
        payload, client = sock.recvfrom(buffer)
        try:
            parsed_netflow_data = netflow.parse_packet(payload, templates)
            if nslookup:
                try:
                    client_ip = socket.gethostbyaddr(client[0])[0]
                except socket.herror:
                    client_ip = client[0]
            else:
                client_ip = client[0]
            print(f"{BColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} \
                [INFO] Received {buffer} bytes of data and {parsed_netflow_data.header.size} packets from {client_ip}.\
                {BColors.RESET}")
            if parsed_netflow_data.header.version != 10:
                print(f"{BColors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} \
                    [ERROR] Received data from {client_ip} was not in NetFlow IPFIX v10 format but in NetFlow v{parsed_netflow_data.header.version}. Exiting!\
                    {BColors.RESET}")
                exit(1)
            decoded_netflow_data = decode_netflow_data(parsed_netflow_data,nslookup)
            send_data_to_influxdb(decoded_netflow_data)
        except netflow.ipfix.IPFIXTemplateNotRecognized:
            #print(f"{BColors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} \
                # [WARNING] Could not parse received packets because no template was received yet.\
                # {BColors.RESET}")
            continue
    return parsed_netflow_data


def decode_netflow_data(parsed_netflow_data,nslookup):
    """Description here.
        Args:
        Returns:  
    """
    #print(f"{BColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} \
        # [INFO] Decoding {parsed_netflow_data.header.size} packets in parsed netflow data.\
        # {BColors.RESET}")
    decoded_netflow_data=[]
    for packet in parsed_netflow_data.flows:
        if 'sourceIPv4Address' in packet.data:
            timestamp=datetime.fromtimestamp(packet.data['flowEndSeconds'])
            if nslookup:
                try:
                    source_ip = socket.gethostbyaddr(
                        ipaddress.ip_address(packet.data['sourceIPv4Address']).exploded)[0]
                except socket.herror:
                    source_ip = ipaddress.ip_address(packet.data['sourceIPv4Address']).exploded
                try:
                    destination_ip = socket.gethostbyaddr(
                        ipaddress.ip_address(packet.data['destinationIPv4Address']).exploded)[0]
                except socket.herror:
                    destination_ip = ipaddress.ip_address(
                        packet.data['destinationIPv4Address']).exploded
            else:
                source_ip = ipaddress.ip_address(packet.data['sourceIPv4Address']).exploded
                destination_ip = ipaddress.ip_address(
                    packet.data['destinationIPv4Address']).exploded

            if 'protocolIdentifier' in packet.data:
                protocol = define_protocols(packet.data['protocolIdentifier'])
            else:
                protocol = 'unknown'
            if 'sourceTransportPort' in packet.data:
                source_port = packet.data['sourceTransportPort']
                if protocol != 'unknown':
                    try:
                        source_port = socket.getservbyport(source_port, protocol.lower())
                    except OSError:
                        source_port = packet.data['sourceTransportPort']
            else:
                source_port = 0
            if 'destinationTransportPort' in packet.data:
                destination_port = packet.data['destinationTransportPort']
                if protocol != 'unknown':
                    try:
                        destination_port = socket.getservbyport(destination_port, protocol.lower())
                    except OSError:
                        destination_port = packet.data['destinationTransportPort']
            else:
                destination_port = 0

            size_bytes = packet.data['octetDeltaCount']

            decoded_netflow_packet = NetflowPacket(
                timestamp,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
                size_bytes)
            decoded_netflow_data.append(decoded_netflow_packet)
    return decoded_netflow_data


def send_data_to_influxdb(decoded_netflow_data):
    """Description here.
        Args:
        Returns:  
    """
    #print(f"{BColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} \
        # [INFO] Sending decoded data to influxdb.{BColors.RESET}")
    bandwidth = 0
    for packet in decoded_netflow_data:
        packet.print()
        bandwidth = bandwidth + packet.size_bytes
    print(f"{BColors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} \
        [INFO] Total Bandwidth: {sizeof_fmt(bandwidth)}{BColors.RESET}")
    return


def sizeof_fmt(num, suffix="B"):
    """Description here.
        Args:
        Returns:  
    """
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


if __name__ == '__main__':
    #region parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", 
        "--port", 
        default=2055,
        type=int,
        help="UDP port our netflow listener will use to receive data. Defaults to UDP:2055")
    parser.add_argument(
        "-b",
        "--buffer",
        default=2048,
        type=int,
        help="Size in bytes of the listener buffer. Defaults to 2048.")
    parser.add_argument(
        "-n",
        "--nslookup", nargs='?',
        const=1,
        default=1,
        type=int,
        help="Specifies if IP addresses should be resolved to hostnames. \
            Set to 0 if you do not want to lookup names.")
    args = parser.parse_args()
    #endregion parsing arguments
    main(port=args.port,buffer=args.buffer,nslookup=args.nslookup)
