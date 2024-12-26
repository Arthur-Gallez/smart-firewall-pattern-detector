class igmp:
    igmp_version = 0
    igmp_type = ""
    igmp_group = ""
    
    groups = {
        "all" : "224.0.0.2",
        "mdns" : "224.0.0.251",
        "ssdp" : "239.255.255.250",
        "coap" : "224.0.1.187"
    }
    
    def __init__(self, igmp_version, igmp_type, igmp_group):
        self.igmp_version = igmp_version
        self.igmp_type = igmp_type
        self.igmp_group = igmp_group
    
    def __str__(self):
        return "IGMP Version: " + str(self.igmp_version) + ", IGMP Type: " + self.igmp_type + ", IGMP Group: " + self.igmp_group
    
    def __eq__(self, value):
        return self.igmp_version == value.igmp_version and self.igmp_type == value.igmp_type and self.igmp_group == value.igmp_group
    
    def simplify(self):
        for key, value in self.groups.items():
            if self.igmp_group == value:
                self.igmp_group = key
                break
    
    def __dict__(self):
        return {
            "version": self.igmp_version,
            "type": self.igmp_type,
            "group": self.igmp_group
        }