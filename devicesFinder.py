import pyshark
from progressBar import printProgressBar

class Device:
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

def isInList(devices, data: str):
    """Check if a device with matching data exists in the list."""
    for d in devices:
        if d.find(data):
            return d
    return None

def findDevices(cap: pyshark.FileCapture, number_of_packets: int):
    filtered_ipv4 = ["0.0.0.0", "255.255.255.255"]
    filtered_ipv6 = ["::"] # TODO fill in with broadcast adresses
    devices = []

    print("Finding devices...")
    i_packet = 0
    for packet in cap:
        printProgressBar(i_packet, number_of_packets, prefix = 'Progress:', suffix = 'Complete', length = 50)
        i_packet += 1
        mac = ipv4 = ipv6 = None

        # Extract Ethernet (MAC) layer
        if hasattr(packet, 'eth'):
            mac = packet.eth.src
            name = packet.eth.src_oui_resolved

        # Extract IPv4 layer
        if hasattr(packet, 'ip'):
            ipv4 = packet.ip.src
            if ipv4 in filtered_ipv4:
                continue

        # Extract IPv6 layer
        if hasattr(packet, 'ipv6'):
            ipv6 = packet.ipv6.src
            if ipv6 in filtered_ipv6:
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
            new_device = Device(mac=mac, ipv4=ipv4, ipv6=ipv6, name=name)
            devices.append(new_device)

    print()
    for device in devices:
        print(device)


