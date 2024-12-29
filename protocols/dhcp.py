class dhcp:
    dhcp_type = ""
    client_mac = ""
    
    def __init__(self, dhcp_type, client_mac):
        self.dhcp_type = dhcp_type
        self.client_mac = client_mac
        
    def __str__(self):
        return "DHCP Type: " + self.dhcp_type + ", Client MAC: " + self.client_mac
    
    def __eq__(self, value):
        return self.dhcp_type == value.dhcp_type and self.client_mac == value.client_mac
    
    def __dict__(self):
        return {
            "type": self.dhcp_type,
            "client-mac": self.client_mac
        }