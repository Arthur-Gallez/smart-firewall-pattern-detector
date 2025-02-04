class udp:
    src_port = None
    dst_port = None
    
    def __init__(self, src_port, dst_port):
        self.src_port = src_port
        self.dst_port = dst_port
        
    def __eq__(self, value):
        return self.src_port == value.src_port and self.dst_port == value.dst_port
    
    def __str__(self):
        return "UDP: " + str(self.src_port) + " -> " + str(self.dst_port)
    
    def __dict__(self):
        if self.src_port is None:
            return {"dst-port": self.dst_port}
        elif self.dst_port is None:
            return {"src-port": self.src_port}
        else:
            return {
                "src-port": self.src_port,
                "dst-port": self.dst_port
            }