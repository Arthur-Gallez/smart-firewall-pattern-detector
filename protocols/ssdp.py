class ssdp:
    method = ""
    response = False
    
    def __init__(self, method:str, response:bool):
        self.method = method
        self.response = response
        
    def __str__(self):
        if self.response:
            return "SSDP response"
        else:
            return "SSDP request (method: {})".format(self.method)
        
    def __eq__(self, value):
        if self.response and value.response:
            return True
        return self.method == value.method and self.response == value.response
    
    def __dict__(self):
        if self.response:
            return {
                "response": self.response
            }
        return {
            "method": self.method,
        }