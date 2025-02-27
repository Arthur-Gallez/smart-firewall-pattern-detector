class icmp:
    icmp_type = None
    
    def __init__(self, type):
        if type == 0:
            name = "echo-reply"
        elif type == 3:
            name = "destination-unreachable"
        elif type == 8:
            name = "echo-request"
        elif type == 11:
            name = "time-exceeded"
        elif type == 13:
            name = "timestamp-request"
        else:
            name = "unknown"
        self.icmp_type = name
        
    def __eq__(self, value):
        return self.icmp_type == value.icmp_type
    
    def __str__(self):
        return f"ICMP: type={self.icmp_type}"
    
    def __dict__(self):
        return {
            "type": self.icmp_type
        }