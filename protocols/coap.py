class coap:
    type = ""
    method = ""
    uri = ""
    
    def __init__(self, type:str, method:str, uri:str):
        self.type = type
        self.method = method
        self.uri = uri
    
    def __str__(self):
        return f"CoAP {self.type} {self.method} {self.uri}"
    
    def __eq__(self, value):
        return self.type == value.type and self.method == value.method and self.uri == value.uri
    
    def __dict__(self):
        return {
            "type": self.type,
            "method": self.method,
            "uri": self.uri
        }