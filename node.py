class Node:
    element = None
    layer = 0
    protocol = ""
    childrens = []
    
    
    def print_tree(self):
        print("Element: " + str(self.element))
        print("Layer: " + str(self.layer))
        print("Protocol: " + str(self.protocol))
        for child in self.childrens:
            child.print_tree()