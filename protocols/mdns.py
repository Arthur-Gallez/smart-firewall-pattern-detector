class mdns:
    response = False
    qtype = ""
    domain_name = []
    
    def __init__(self, response:bool, qtype:str, domain_name:list):
        self.response = response
        self.qtype = qtype
        self.domain_name = domain_name
        
    def __str__(self):
        return f"response:{self.response} type:{self.qtype} domain-names{self.domain_name}"
    
    def __eq__(self, value):
        return self.response == value.response and self.qtype == value.qtype and self.domain_name == value.domain_name