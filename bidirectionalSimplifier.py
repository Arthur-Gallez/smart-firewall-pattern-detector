from patternClass import Pattern

def merge_bidirectional_patterns(pattern_list):
    """Merge patterns representing bidirectional traffic"""
    merged_patterns = []
    used_patterns = set()
    used_patterns_obj = []
    
    def _check_reverse_pattern(pattern1, pattern2):
        """Check if pattern2 is the reverse traffic of pattern1"""
        # Skip protocols that don't need bidirectional check
        if pattern1.layer_2 and pattern1.layer_2.__class__.__name__ in [
            'coap', 'dhcp', 'mdns', 'ssdp']:
            return False
            
        if pattern1.layer_1 and pattern1.layer_1.__class__.__name__ == 'igmp':
            return False
            
        if pattern1.layer_0 and pattern1.layer_0.__class__.__name__ == 'arp':
            return False
            
        # Check if protocol layers match
        if ((pattern1.layer_0 is None) != (pattern2.layer_0 is None) or
            (pattern1.layer_1 is None) != (pattern2.layer_1 is None) or
            (pattern1.layer_2 is None) != (pattern2.layer_2 is None)):
            return False
            
        # Check specific attributes for each protocol layer
        if pattern1.layer_0:
            if pattern1.layer_0.__class__ != pattern2.layer_0.__class__:
                return False
            if pattern1.layer_0.__class__.__name__ in ['ipv4', 'ipv6']:
                if (pattern1.layer_0.src != pattern2.layer_0.dst or 
                    pattern1.layer_0.dst != pattern2.layer_0.src):
                    return False
                    
        if pattern1.layer_1:
            if pattern1.layer_1.__class__ != pattern2.layer_1.__class__:
                return False
            if pattern1.layer_1.__class__.__name__ in ['tcp', 'udp']:
                if (pattern1.layer_1.src_port != pattern2.layer_1.dst_port or 
                    pattern1.layer_1.dst_port != pattern2.layer_1.src_port):
                    return False
                    
        if pattern1.layer_2:
            if pattern1.layer_2.__class__ != pattern2.layer_2.__class__:
                return False
                
        return True

    def _get_pattern_with_earlier_highest_layer(pattern1, pattern2):
        """
        Compare the highest layer packet_number of two Patterns and return the one with smaller number
        """
        # First determine the highest layer
        if pattern1.layer_2 is not None and pattern2.layer_2 is not None:
            # If both have third layer, compare packet_number_2
            return pattern1 if pattern1.packet_number_2 <= pattern2.packet_number_2 else pattern2
        elif pattern1.layer_1 is not None and pattern2.layer_1 is not None:
            # If both have second layer, compare packet_number_1
            return pattern1 if pattern1.packet_number_1 <= pattern2.packet_number_1 else pattern2
        else:
            # Only first layer, compare packet_number_0
            return pattern1 if pattern1.packet_number_0 <= pattern2.packet_number_0 else pattern2

    # Find and merge bidirectional patterns
    for i, pattern1 in enumerate(pattern_list):
        if i in used_patterns:
            continue
            
        found_reverse = False
        for j, pattern2 in enumerate(pattern_list[i+1:], i+1):
            if j in used_patterns:
                continue
                
            if _check_reverse_pattern(pattern1, pattern2):
                # Select pattern with earlier highest layer packet_number
                base_pattern = _get_pattern_with_earlier_highest_layer(pattern1, pattern2)
                # Create merged pattern
                merged = Pattern(
                    layer_0=base_pattern.layer_0,
                    layer_1=base_pattern.layer_1,
                    layer_2=base_pattern.layer_2,
                    packet_number_0=base_pattern.packet_number_0,
                    packet_number_1=base_pattern.packet_number_1,
                    packet_number_2=base_pattern.packet_number_2,
                    is_bidirectional=True  # Set bidirectional flag
                )
                merged_patterns.append(merged)
                used_patterns.add(i)
                used_patterns.add(j)
                used_patterns_obj.append(pattern1)
                used_patterns_obj.append(pattern2)
                found_reverse = True
                break
                
        if not found_reverse and i not in used_patterns:
            # No reverse pattern found, add original pattern
            merged_patterns.append(pattern1)
            
    return merged_patterns