from yaml import dump

def remove_duplicates(obj_list):
    """
    Removes duplicates from a list of objects.

    Args:
        obj_list: List of objects to process.

    Returns:
        List: List of objects without duplicates.
    """
    unique_list = []
    for obj in obj_list:
        if obj not in unique_list:
            unique_list.append(obj)
    return unique_list

def generate_pattern_name(pattern, dns_map):
    """
    Generate a meaningful name for a pattern based on its characteristics
    
    Args:
        pattern: A Pattern object containing layer information
        
    Returns:
        str: A descriptive name for the pattern
    """
    name_parts = []
    if pattern.layer_0:
        if pattern.layer_0.__class__.__name__ == "arp":
            name_parts.append("arp")
            name_parts.append(pattern.layer_0.type)
            name_parts.append(dns_map.get_device_name(pattern.layer_0.spa))
            name_parts.append(dns_map.get_device_name(pattern.layer_0.tpa))
        elif pattern.layer_0.__class__.__name__ == "ipv6":
            if dns_map.get_device_name(pattern.layer_0.src) is None:
                src_name = pattern.layer_0.src
            else:
                src_name = dns_map.get_device_name(pattern.layer_0.src)
            if dns_map.get_device_name(pattern.layer_0.dst) is None:
                dst_name = pattern.layer_0.dst
            else:
                dst_name = dns_map.get_device_name(pattern.layer_0.dst) 
            if pattern.layer_1 is None:
                name_parts.append("ipv6")
                name_parts.append(src_name)
                if pattern.layer_0.dst == "ff02::16":
                    dst_name = "MLDv2-broadcast"
                name_parts.append(dst_name)
            else:
                if pattern.layer_2 is None:
                    name_parts.append(pattern.layer_1.__class__.__name__)
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
                    name_parts.append(pattern.layer_1.src_port)
                    name_parts.append(pattern.layer_1.dst_port)
                else:
                    name_parts.append(pattern.layer_2.__class__.__name__)
                    if pattern.layer_2.__class__.__name__ == "mdns":
                        name_parts.append(pattern.layer_2.qtype)
                        if src_name != "mdns": 
                            name_parts.append(src_name)
                        if dst_name != "mdns": 
                            name_parts.append(dst_name)
        elif pattern.layer_0.__class__.__name__ == "ipv4":
            if dns_map.get_device_name(pattern.layer_0.src) is None:
                src_name = pattern.layer_0.src
            else:
                src_name = dns_map.get_device_name(pattern.layer_0.src)
            if dns_map.get_device_name(pattern.layer_0.dst) is None:
                dst_name = pattern.layer_0.dst
            else:
                dst_name = dns_map.get_device_name(pattern.layer_0.dst) 
            if pattern.layer_1 is None:
                name_parts.append("ipv4")
                name_parts.append(src_name)
                name_parts.append(dst_name)
            else:
                if pattern.layer_2 is None:
                    if pattern.layer_1.__class__.__name__ == "tcp":
                        if pattern.layer_1.src_port == 443:
                            name_parts.append("https-response")
                        elif pattern.layer_1.dst_port == 443:
                            name_parts.append("https-request")
                    elif pattern.layer_1.__class__.__name__ == "udp":
                        if pattern.layer_1.src_port == 123:
                            name_parts.append("ntp-response")
                        elif pattern.layer_1.dst_port == 123:
                            name_parts.append("ntp-request")
                    else:
                        name_parts.append(pattern.layer_1.__class__.__name__)
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
                elif pattern.layer_2.__class__.__name__ == "dhcp":
                    name_parts.append("dhcp")
                    name_parts.append(pattern.layer_2.dhcp_type)
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
                elif pattern.layer_2.__class__.__name__ == "coap":
                    name_parts.append("coap")
                    name_parts.append(pattern.layer_2.type)
                    #name_parts.append(pattern.layer_2.method)   
                    name_parts.append(pattern.layer_2.uri)
                    name_parts.append(src_name)
                    name_parts.append(dst_name) 
                elif pattern.layer_2.__class__.__name__ == "ssdp":
                    name_parts.append("ssdp")
                    name_parts.append(pattern.layer_2.method)
                    if pattern.layer_2.response:
                        name_parts.append("response")
                    else:
                        name_parts.append("request")
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
                elif pattern.layer_2.__class__.__name__ == "dns":
                    name_parts.append("dns")
                    #name_parts.append(pattern.layer_2.qtype)
                    #name_parts.append(pattern.layer_2.domain_name)
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
                elif pattern.layer_2.__class__.__name__ == "http":
                    name_parts.append("http")
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
                    if pattern.layer_2.uri:
                        name_parts.append(pattern.layer_2.uri.strip('/').split('/')[0])
                elif pattern.layer_2.__class__.__name__ == "mdns":
                    name_parts.append("mdns")
                    if pattern.layer_2.qtype is not None or pattern.layer_2.qtype != "": 
                        name_parts.append(pattern.layer_2.qtype)
                    name_parts.append(src_name)
                    name_parts.append(dst_name)
    name_parts = remove_duplicates(name_parts)
    name_parts = [part for part in name_parts if part is not None]
    name_parts = [part for part in name_parts if part != ""]
    return "_".join(name_parts)

def patterns_to_dict(patterns, dns_map):
    """
    Convert a list of patterns to a dictionary with meaningful names as keys.
    If duplicate names exist, append numbering (-1, -2, etc.)
    
    Args:
        patterns: List of Pattern objects
        dns_map: DNS mapping information
        
    Returns:
        dict: Dictionary with unique pattern names as keys and Pattern objects as values
    """
    pattern_dict = {}
    name_count = {} 
    
    for pattern in patterns:
        base_name = generate_pattern_name(pattern, dns_map)
        
        if base_name in pattern_dict:
            # First time encountering a duplicate name
            if base_name not in name_count:
                name_count[base_name] = 2
                # Rename the previous entry
                old_pattern = pattern_dict[base_name]
                pattern_dict[f"{base_name}-1"] = old_pattern
                del pattern_dict[base_name]
                # Add current entry
                pattern_dict[f"{base_name}-{name_count[base_name]}"] = pattern
            else:
                # Already encountered duplicates before
                pattern_dict[f"{base_name}-{name_count[base_name]}"] = pattern
                name_count[base_name] += 1
        else:
            # No duplicate, use original name
            pattern_dict[base_name] = pattern
    
    return pattern_dict


def patternToYAML(patterns, dns_map):
    # Get dictionary with meaningful names as keys
    pattern_dict = patterns_to_dict(patterns, dns_map)
    
    # Convert to YAML format
    yaml_dict = {}
    for name, pattern in pattern_dict.items():
        yaml_dict[name] = {
            'protocols': {},
            'bidirectionnal': pattern.is_bidirectional
        }
        if pattern.layer_0:
            yaml_dict[name]['protocols'][pattern.layer_0.__class__.__name__] = dict(pattern.layer_0.__dict__())
        if pattern.layer_1:
            yaml_dict[name]['protocols'][pattern.layer_1.__class__.__name__] = dict(pattern.layer_1.__dict__())
        if pattern.layer_2:
            yaml_dict[name]['protocols'][pattern.layer_2.__class__.__name__] = dict(pattern.layer_2.__dict__())
    
    d = dump(yaml_dict)
    return d

