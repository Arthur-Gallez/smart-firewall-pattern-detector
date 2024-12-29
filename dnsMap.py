import pyshark

class DNSMap:
    def __init__(self):
        self.map = {}
        
    def add_ipv4(self, domain, ip, device_name=None):
        if domain not in self.map:
            self.map[domain] = {"ipv4": [], "ipv6": [], "device_name": device_name}
        if ip not in self.map[domain]["ipv4"]:
            self.map[domain]["ipv4"].append(ip)
        
    def add_ipv6(self, domain, ip, device_name=None):
        if domain not in self.map:
            self.map[domain] = {"ipv4": [], "ipv6": [], "device_name": device_name}
        if ip not in self.map[domain]["ipv6"]:
            self.map[domain]["ipv6"].append(ip)

    def get_device_name(self, domain):
        if domain in self.map:
            return self.map[domain]["device_name"]
        return domain
        
    def get_ipv4(self, domain):
        if domain in self.map:
            return self.map[domain]["ipv4"]
        return None
    
    def get_ipv6(self, domain):
        if domain in self.map:
            return self.map[domain]["ipv6"]
        return None
    
    def get_domain_by_ipv4(self, ip):
        for domain in self.map:
            for ipv4 in self.map[domain]["ipv4"]:
                if ipv4 == ip:
                    return domain
        return None
    
    def get_domain_by_ipv6(self, ip):
        for domain in self.map:
            for ipv6 in self.map[domain]["ipv6"]:
                if ipv6 == ip:
                    return domain
        return None
    
    def print_map(self):
        for domain in self.map:
            print("Domain: " + domain)
            print("     IPv4: " + str(self.map[domain]["ipv4"]))
            print("     IPv6: " + str(self.map[domain]["ipv6"]))
            print()
            
            

if __name__ == "__main__":
    # Example of use of the DNSMap from a pcap file
    dns_map = DNSMap()

    # Read the PCAP file
    cap = pyshark.FileCapture('traces/philips-hue.pcap')

    counter = 0
    # Analyze packets
    for packet in cap:
        counter += 1
        
        # Get the DNS packets
        if hasattr(packet, 'dns'):
            dns = packet.dns
            # Check if the packet is a DNS response
            if hasattr(dns, 'a'):
                # Get the domain and the IP
                domain = dns.qry_name
                ip = dns.a
                # Add the domain and the IP to the map
                dns_map.add_ipv4(domain, ip)
            if hasattr(dns, 'aaaa'):
                # Get the domain and the IP
                domain = dns.qry_name
                ip = dns.aaaa
                # Add the domain and the IP to the map
                dns_map.add_ipv6(domain, ip)
    
    print("Number of packets: " + str(counter))
    print()
    dns_map.print_map()
            