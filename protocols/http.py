class http:
    method = ""
    uri = ""
    
    def __init__(self, method, uri):
        self.method = method
        self.uri = uri
        
    def __str__(self):
        return f"{self.method} {self.uri}"
    
    def __eq__(self, value):
        return self.method == value.method and self.uri == value.uri
    
    def __hash__(self):
        return hash(self.method + self.uri)
    
    def __dict__(self):
        return {
            "method": self.method,
            "uri": self.uri
        }