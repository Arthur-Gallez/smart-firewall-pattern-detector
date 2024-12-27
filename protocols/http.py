class http:
    method = ""
    uri = ""
    response = False
    
    def __init__(self, method, uri, response):
        self.method = method
        self.uri = uri
        self.response = response
    def __str__(self):
        return f"{self.method} {self.uri}"
    
    def __eq__(self, value):
        return self.method == value.method and self.uri == value.uri
    
    def __hash__(self):
        return hash(self.method + self.uri)
    
    def __dict__(self):
        if self.response:
            return {
                "response": self.response
            }
        return {
            "method": self.method,
            "uri": self.uri
        }