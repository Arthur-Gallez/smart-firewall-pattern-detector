"""Pattern class.

Made by: Gallez Arthur & Zhang Zexin
"""
class Pattern:
    """Pattern class. Store all information of a pattern.
    
    The patterns correspond the the patterns directly used in the firewall (after transformed in YAML).
    """
    def __init__(self, layer_0, layer_1, layer_2, 
                 packet_number_0=0, packet_number_1=0, packet_number_2=0,
                 is_bidirectional=False):
        self.layer_0 = layer_0
        self.layer_1 = layer_1
        self.layer_2 = layer_2
        self.packet_number_0 = packet_number_0  # first layer packet number
        self.packet_number_1 = packet_number_1  # second layer packet number
        self.packet_number_2 = packet_number_2  # third layer packet number
        self.is_bidirectional = is_bidirectional
        