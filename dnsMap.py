"""DNSMap class.

Made by: Gallez Arthur & Zhang Zexin
"""

class DNSMap:
    """DNSMap class stores the mapping between domains and IPs."""
    def __init__(self):
        """Initialize an empty map."""
        self.map = {}
        
    def add_ipv4(self, domain, ip, device_name=None):
        """add a domain with an IPv4 address to the map.

        Args:
            domain (str): Domain name.
            ip (str): IPv4 address.
            device_name (str, optional): Name of the device. Defaults to None.
        """
        if domain not in self.map:
            self.map[domain] = {"ipv4": [], "ipv6": [], "device_name": device_name}
        if ip not in self.map[domain]["ipv4"]:
            self.map[domain]["ipv4"].append(ip)
        
    def add_ipv6(self, domain, ip, device_name=None):
        """add a domain with an IPv6 address to the map.

        Args:
            domain (str): Domain name.
            ip (str): IPv6 address.
            device_name (str, optional): Name of the device. Defaults to None.
        """
        if domain not in self.map:
            self.map[domain] = {"ipv4": [], "ipv6": [], "device_name": device_name}
        if ip not in self.map[domain]["ipv6"]:
            self.map[domain]["ipv6"].append(ip)

    def get_device_name(self, domain):
        """Geth the device name of a domain.

        Args:
            domain (str): Domain name.

        Returns:
            str: Device name.
        """
        if domain in self.map:
            return self.map[domain]["device_name"]
        return domain
        
    def get_ipv4(self, domain):
        """Get the IPv4 addresses of a domain.

        Args:
            domain (str): Domain name.

        Returns:
            list: List of IPv4 addresses.
        """
        if domain in self.map:
            return self.map[domain]["ipv4"]
        return None
    
    def get_ipv6(self, domain):
        """Get the IPv6 addresses of a domain.

        Args:
            domain (str): Domain name.

        Returns:
            list: List of IPv6 addresses.
        """
        if domain in self.map:
            return self.map[domain]["ipv6"]
        return None
    
    def get_domain_by_ipv4(self, ip):
        """Get the domain of an IPv4 address.

        Args:
            ip (str): IPv4 address.

        Returns:
            str: Domain name.
        """
        for domain in self.map:
            for ipv4 in self.map[domain]["ipv4"]:
                if ipv4 == ip:
                    return domain
        return None
    
    def get_domain_by_ipv6(self, ip):
        """Get the domain of an IPv6 address.

        Args:
            ip (str): IPv6 address.

        Returns:
            str: Domain name.
        """
        for domain in self.map:
            for ipv6 in self.map[domain]["ipv6"]:
                if ipv6 == ip:
                    return domain
        return None
    
    def print_map(self):
        """Print the map. For each domain, print the IPv4 and IPv6 addresses."""
        for domain in self.map:
            print("Domain: " + domain)
            print("     IPv4: " + str(self.map[domain]["ipv4"]))
            print("     IPv6: " + str(self.map[domain]["ipv6"]))
            print()
            