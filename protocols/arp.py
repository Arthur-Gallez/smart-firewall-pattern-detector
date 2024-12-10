import ipaddress

class arp:
    type = ""
    sha = ""
    spa = ""
    tha = ""
    tpa = ""

    mac_addrs = {
        "gateway": "c0:56:27:73:46:0b",
        "default": "00:00:00:00:00:00",
        "broadcast": "ff:ff:ff:ff:ff:ff",
        "phone": "3c:cd:5d:a2:a9:d7"
    }
    ip_addrs = {
        "gateway": "192.168.1.1",
        "phone": "192.168.1.222"
    }
    local_range = "192.168.1.0/24"

    def __init__(self, type, sha, spa, tha, tpa):
        self.type = type
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa

    def __str__(self):
        return "ARP: type=%s, sha=%s, spa=%s, tha=%s, tpa=%s" % (self.type, self.sha, self.spa, self.tha, self.tpa)
    
    def __eq__(self, value: object) -> bool:
        return self.type == value.type and self.sha == value.sha and self.spa == value.spa and self.tha == value.tha and self.tpa == value.tpa
    
    def simplify(self, device_ip, device_mac):
        # Known lac addresses
        for key, value in self.mac_addrs.items():
            if value == self.sha:
                self.sha = key
            if value == self.tha:
                self.tha = key
        # Known ip addresses
        for key, value in self.ip_addrs.items():
            if value == self.spa:
                self.spa = key
            if value == self.tpa:
                self.tpa = key

        # self ip address
        if self.spa == device_ip:
            self.spa = "self"
        if self.tpa == device_ip:
            self.tpa = "self"
        if self.sha == device_mac:
            self.sha = "self"
        if self.tha == device_mac:
            self.tha = "self"

        # Local detection
        ip_range = ipaddress.ip_network(self.local_range, strict=False)
        try:
            ip_source = ipaddress.ip_address(self.spa)
            if ip_source in ip_range:
                self.spa = "local"
        except ValueError:
            # Adress has already been chaged to text
            pass
        try:
            ip_target = ipaddress.ip_address(self.tpa)
            if ip_target in ip_range:
                self.tpa = "local"
        except ValueError:
            # Adress has already been chaged to text
            pass

        