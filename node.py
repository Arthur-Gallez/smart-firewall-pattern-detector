"""Node class.

Made by: Gallez Arthur & Zhang Zexin
"""
class Node:
    """Node class used for representing the pattern tree.

    Returns:
        Node: Node object.
    """
    element = None
    layer = 0
    protocol = ""
    childrens = []
    packet_number = 0
    stat_count = 0
    
    def __init__(self, element, protocol, childrens=[], layer=0, packet_number=0):
        """Initialize the Node object.

        Args:
            element (Protocol): protocol object.
            protocol (str): protocol name.
            childrens (list, optional): initial list of Node children. Defaults to [].
            layer (int, optional): Number of the layer of the tree (representing the Depth in the tree). Defaults to 0.
            packet_number (int, optional): Number of the packet. Defaults to 0.
        """
        self.element = element
        self.layer = layer
        self.protocol = protocol
        self.childrens = childrens
        self.packet_number = packet_number
        self.last_seen_time = 0
        self.rate = 0
        self.stat_count = 1
    
    def last_seen(self, time):
        old = self.last_seen_time
        self.last_seen_time = time
        if old != 0 and time > old:
            new_rate = 1 / (time - old)
            self.rate = max(self.rate, new_rate)
    
    def print_tree(self):
        """Print the tree."""
        spacer = "  " * self.layer
        print(spacer + "Element: " + str(self.element))
        print(spacer + "Layer: " + str(self.layer))
        print(spacer + "Protocol: " + str(self.protocol))
        print(spacer + "Packet #: " + str(self.packet_number))
        print(spacer + "Stat count: " + str(self.stat_count))
        for child in self.childrens:
            child.print_tree()
            
    def __eq__(self, value):
        """Check if two nodes are equal. Nodes are equal if their element, layer, protocol and childrens are equal.
        
        Args:
            value (Node): Node to compare.
            
        Returns:
            bool: True if the nodes are equal, False otherwise.
        """
        return (self.element == value.element and 
                self.layer == value.layer and 
                self.protocol == value.protocol and 
                self.childrens == value.childrens)
    
    def is_leaf(self):
        """Check if the node is a leaf."""
        return len(self.childrens) == 0