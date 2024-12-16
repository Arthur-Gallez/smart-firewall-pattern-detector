class dns:
    qtype = []
    domain_name = []
    
    def __init__(self, qtype, domain_name):
        self.qtype = [qtype]
        self.domain_name = [domain_name]
        
    def __str__(self):
        return f"{self.qtype} {self.domain_name}"
    
    def __eq__(self, value):
        return self.qtype == value.qtype and self.domain_name == value.domain_name
    
    def merge(self, other):
        self.domain_name.extend(other.domain_name)
        self.qtype = list(set(self.qtype + other.qtype))
        return True