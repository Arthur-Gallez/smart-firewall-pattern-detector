from yaml import safe_load, dump

class Interaction:
    def __init__(self, name: str, patterns: list, domain: str = None):
        """Instantiates an Interaction object.

        Args:
            name (str): Name of the interaction.
            patterns (list): List of patterns.
        """
        self.name = name
        self.patterns = patterns
        self.domain = domain

    def getYAML(self, n):
        """Generates YAML representation of the interaction.
        
        Args:
            n (int): If positive, number of characters to remove from the pattern name. Else, special case for different naming.
            
        Returns:
            str: YAML representation of the interaction.
        """
        d = {}
        d[self.name] = {}
        if n == -1:
            for pattern in self.patterns:
                if "discover" in pattern:
                    d[self.name]["dhcp-discover"] = f"!include patterns.{pattern}"
                elif "offer" in pattern:
                    d[self.name]["dhcp-offer"] = f"!include patterns.{pattern}"
                elif "request" in pattern:
                    d[self.name]["dhcp-request"] = f"!include patterns.{pattern}"
                elif "ack" in pattern:
                    d[self.name]["dhcp-ack"] = f"!include patterns.{pattern}"
        elif n == -2:
            for pattern in self.patterns:
                if pattern.startswith("dns"):
                    d[self.name]["dns"] = f"!include patterns.{pattern} protocols.dns.domain-name:{self.domain}" 
                else:
                    d[self.name]["then_" + pattern] = f"!include patterns.{pattern}"
        else:
            for pattern in self.patterns:
                d[self.name][pattern[n:]] = f"!include patterns.{pattern}"
        return dump(d, sort_keys=False).replace("'", "")

def find_interactions(YAML):
    """Find the interactions in the given yaml patterns list.

    Args:
        YAML (str): YAML representation of the patterns.

    Returns:
        List: List of interactions in YAML format (string).
    """
    suggestions = []
    suggestions.extend(arp_interaction_finder(YAML))
    suggestions.extend(dhcp_interaction_finder(YAML))
    suggestions.extend(dns_dependency_interaction_finder(YAML))
    return suggestions

def dns_dependency_interaction_finder(YAML):
    YAML = safe_load(YAML)
    domain_list = []
    for pattern_name in YAML:
        if pattern_name.startswith("dns") and not pattern_name.endswith("template"):
            dns_data = YAML[pattern_name]["protocols"]["dns"]
            sub_list = []
            for sub in dns_data["domain-name"]:
                sub_list.append((pattern_name, sub))
            domain_list.extend(sub_list)
    interaction_list = []
    for pattern_name in YAML:
        for domain in domain_list:
            if domain[1] in pattern_name:
                interaction = Interaction ("dns_and_" + pattern_name, [domain[0] + "_template", pattern_name], domain=domain[1])
                interaction_list.append(interaction)
    suggestions = []
    for interaction in interaction_list:
        suggestions.append(interaction.getYAML(-2))
    return suggestions

def arp_interaction_finder(YAML):
    """
    Find ARP interactions in the given packets.
    
    Args:
        patternList (list): List of patterns to find.
    
    Returns:
        list: List of arp interactions in YAML format (string).
    """
    YAML = safe_load(YAML)
    arp_request_list = []
    arp_reply_list = []
    for pattern_name in YAML:
        if pattern_name.startswith("arp"):
            arp_data = YAML[pattern_name]["protocols"]["arp"]
            if arp_data["type"] == "request":
                arp_request_list.append((pattern_name, arp_data))
            elif arp_data["type"] == "reply":
                arp_reply_list.append((pattern_name, arp_data))
    # Find interactions
    interactions = []
    for request in arp_request_list:
        for reply in arp_reply_list:
            if arp_is_reply_of_request(request[1], reply[1]):
                interactions.append((request[0], reply[0]))
                break
    interactions_objects = []
    for interaction in interactions:
        name = "arp_" + interaction[0][12:]
        l = [interaction[0], interaction[1]]
        interactions_objects.append(Interaction(name, l))
    suggestions = []
    for interaction in interactions_objects:
        suggestions.append(interaction.getYAML(4))
    return suggestions
    
def arp_is_reply_of_request(request, reply):
    """
    Check if an ARP reply is a reply to an ARP request.
    
    Args:
        request (dict): ARP request pattern.
        reply (dict): ARP reply pattern.
        
    Returns:
        bool: True if the reply is a reply to the request, False otherwise.
    """
    try:
        # Check if types are correct
        if request["type"] != "request" or reply["type"] != "reply":
            raise ValueError("Invalid ARP patterns")
        # Check if fields are swapped
        if request["spa"] == reply["tpa"] and request["tpa"] == reply["spa"]:
            return True
        if request["sha"] == reply["tha"] and request["tha"] == reply["sha"]:
            return True
        return False
    except KeyError:
        raise ValueError("Invalid ARP patterns")
    
def dhcp_interaction_finder(YAML):
    """Check if the given DHCP patterns interact.

    Args:
        YAML (str): YAML representation of the patterns.

    Returns:
        List: List of dhcp interactions in YAML format (string).
    """
    YAML = safe_load(YAML)
    dhcp_discover_list = []
    dhcp_offer_list = []
    dhcp_request_list = []
    dhcp_ack_list = []
    for pattern_name in YAML:
        if pattern_name.startswith("dhcp"):
            dhcp_data = YAML[pattern_name]["protocols"]["dhcp"]
            if dhcp_data["type"] == "discover":
                dhcp_discover_list.append((pattern_name, dhcp_data))
            elif dhcp_data["type"] == "offer":
                dhcp_offer_list.append((pattern_name, dhcp_data))
            elif dhcp_data["type"] == "request":
                dhcp_request_list.append((pattern_name, dhcp_data))
            elif dhcp_data["type"] == "ack":
                dhcp_ack_list.append((pattern_name, dhcp_data))
    
    interactions = []
    for discover in dhcp_discover_list:
        for offer in dhcp_offer_list:
            if dhcp_same_client(discover[1], offer[1]):
                for request in dhcp_request_list:
                    if dhcp_same_client(offer[1], request[1]):
                        for ack in dhcp_ack_list:
                            if dhcp_same_client(request[1], ack[1]):
                                interactions.append((discover[0], offer[0], request[0], ack[0], discover[1]["client-mac"]))
                                break
                        break
                break
    interactions_objects = []
    for interaction in interactions:
        name = "ip-allocation-" + interaction[4]
        l = [interaction[0], interaction[1], interaction[2], interaction[3]]
        interactions_objects.append(Interaction(name, l))
    
    suggestions = []
    for interaction in interactions_objects:
        suggestions.append(interaction.getYAML(-1))
    return suggestions
            
def dhcp_same_client(packet1, packet2):
    """Check if two DHCP packets are from the same client.

    Args:
        packet1 (dict): DHCP packet information dictionary.
        packet2 (dict): DHCP packet information dictionary.

    Raises:
        ValueError: Invalid DHCP patterns.

    Returns:
        bool: True if the packets are from the same client, False otherwise.
    """
    try:
        return packet1["client-mac"] == packet2["client-mac"]
    except KeyError:
        raise ValueError("Invalid DHCP patterns")