class Node:
    element = None
    layer = 0
    protocol = ""
    childrens = []
    
    def __init__(self, element, protocol, childrens=[], layer=0):
        self.element = element
        self.layer = layer
        self.protocol = protocol
        self.childrens = childrens
        
    
    def print_tree(self):
        spacer = "  " * self.layer
        print(spacer + "Element: " + str(self.element))
        print(spacer + "Layer: " + str(self.layer))
        print(spacer + "Protocol: " + str(self.protocol))
        for child in self.childrens:
            child.print_tree()
            
    def __eq__(self, value):
        return self.element == value.element and self.layer == value.layer and self.protocol == value.protocol and self.childrens == value.childrens