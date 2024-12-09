class ipv4:
    src = None
    dst = None
    
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        
    def __eq__(self, value):
        return self.src == value.src and self.dst == value.dst
    
    def __str__(self):
        return "IPv4: " + self.src + " -> " + self.dst