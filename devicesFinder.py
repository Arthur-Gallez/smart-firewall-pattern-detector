"""Devices finder module. Contains Device class and functions to find devices in packets.

Made by: Gallez Arthur & Zhang Zexin
"""
from scapy.all import rdpcap, Ether, IP, IPv6, ARP
import manuf
import ipaddress
from progressBar import printProgressBar
import yaml

class Device:
    """Device class to store device information.
    
    Attributes:
        name (str): Device name.
        ipv4 (str): Device IPv4 address.
        ipv6 (str): Device IPv6 address.
        mac (str): Device MAC address
    """
    def __init__(self, name: str = "Unknown", ipv4: str = "", ipv6: str = "", mac: str = ""):
        self.name = name
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.mac = mac

    def __str__(self):
        return f"Device {self.name} with ipv4 {self.ipv4}, ipv6 {self.ipv6} and mac {self.mac}"
    
    def complete(self):
        """Check if all fields are populated."""
        return self.ipv4 and self.ipv6 and self.mac and self.name
    
    def find(self, data: str):
        """Check if the given data matches any field."""
        return data in [self.name, self.ipv4, self.ipv6, self.mac]
    
    def update(self, mac=None, ipv4=None, ipv6=None, name=None):
        """Update device attributes only if not already set."""
        if mac and not self.mac:
            self.mac = mac
        if ipv4 and not self.ipv4:
            self.ipv4 = ipv4
        if ipv6 and not self.ipv6:
            self.ipv6 = ipv6
        if name and not self.name:
            self.name = name
    
    def get_yaml(self):
        """Return device information in YAML format."""
        yaml_dict = {}
        info = {}
        if self.name:
            info["name"] = self.name
        if self.ipv4:
            info["ipv4"] = self.ipv4
        if self.ipv6:
            info["ipv6"] = self.ipv6
        if self.mac:
            info["mac"] = self.mac
        yaml_dict["device-info"] = info
        return yaml.dump(yaml_dict)
        

def isInList(devices, data: str):
    """Check if a device with matching data exists in the list."""
    for d in devices:
        if d.find(data):
            return d
    return None

def findDevices(packets, number_of_packets: int, print_progress: bool):
    """
    Find devices in the given packets.
    
    Args:
        packets (PacketList): List of packets.
        number_of_packets (int): Number of packets.
        
    Returns:
        list: List of devices (Device objects).
    """
    filtered_ipv4 = ["0.0.0.0", "255.255.255.255"]
    filtered_ipv6 = ["::"]  # TODO fill in with broadcast addresses
    devices = []

    print("Finding devices...")
    i_packet = 1
    for packet in packets:

        if print_progress:
            printProgressBar(i_packet, number_of_packets, prefix='Progress:', suffix='Complete', length=50)
        i_packet += 1
        mac = ipv4 = ipv6 = None
        name = None

        # Extract Ethernet (MAC) layer
        if Ether in packet:
            mac = packet[Ether].src

        # Extract IPv4 layer
        if IP in packet:
            ipv4 = packet[IP].src
            if ipv4 in filtered_ipv4:
                continue
            # Check if ip is local
            addr = ipaddress.ip_address(ipv4)
            prefix1 = ipaddress.ip_network("10.0.0.0/8")
            prefix2 = ipaddress.ip_network("172.16.0.0/12")
            prefix3 = ipaddress.ip_network("192.168.0.0/16")
            if addr not in prefix1 and addr not in prefix2 and addr not in prefix3:
                continue

        # Extract IPv6 layer
        if IPv6 in packet:
            ipv6 = packet[IPv6].src
            if ipv6 in filtered_ipv6:
                continue
            # check if ip is local
            addr = ipaddress.ip_address(ipv6)
            prefix = ipaddress.ip_network("fe80::/10")
            if addr not in prefix:
                continue

        if ARP in packet:
            mac = packet[ARP].hwsrc
            ipv4 = packet[ARP].psrc
            # Check if ip is not default
            if ipv4 in filtered_ipv4:
                continue

        # Skip empty data
        if not mac and not ipv4 and not ipv6:
            continue

        existing_device = None
        if mac:
            existing_device = isInList(devices, mac)
        if not existing_device and ipv4:
            existing_device = isInList(devices, ipv4)
        if not existing_device and ipv6:
            existing_device = isInList(devices, ipv6)

        if existing_device:
            existing_device.update(mac=mac, ipv4=ipv4, ipv6=ipv6, name=name)
        else:
            name = manuf.MacParser().get_manuf_long(mac)
            new_device = Device(mac=mac, ipv4=ipv4, ipv6=ipv6, name=name)
            devices.append(new_device)
    devices.sort(key=lambda x: "0.0.0.0" if x.ipv4 is None else x.ipv4)
    return devices