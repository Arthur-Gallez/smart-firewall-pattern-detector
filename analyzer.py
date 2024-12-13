import pyshark
from dnsMap import DNSMap
from protocols.ipv4 import ipv4
from protocols.ipv6 import ipv6
from protocols.tcp import tcp
from protocols.udp import udp
from protocols.arp import arp
from protocols.http import http
from protocols.dns import dns
from protocols.mdns import mdns
from node import Node

GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "c0:56:27:73:46:0b"
GATEWAY_IPV6 = "fddd:ed18:f05b::1"
GATEWAY_LOCAL_IPV6 = "fe80::c256:27ff:fe73:460b"
DEFAULT = "00:00:00:00:00:00"
BROADCAST = "ff:ff:ff:ff:ff:ff"
PHONE = "3c:cd:5d:a2:a9:d7"

def remove_duplicates(obj_list):
    unique_list = []
    for obj in obj_list:
        if obj not in unique_list:
            unique_list.append(obj)
    return unique_list


def merge_nodes_on_port(children, port_attr, merge_attr):
    """
    Merges nodes in a list based on a port attribute.
    
    Args:
        children: List of child nodes to process.
        port_attr: Attribute name to compare for merging (e.g., 'src_port' or 'dst_port').
        merge_attr: Attribute name to modify when merging (e.g., 'dst_port' or 'src_port').
    """
    i = 0
    while i < len(children):
        j = i + 1
        while j < len(children):
            if (
                getattr(children[i].element, port_attr) == getattr(children[j].element, port_attr)
                and children[i].protocol == children[j].protocol
            ):
                # Merge child nodes
                children[i].childrens.extend(children[j].childrens)
                if getattr(children[i].element, merge_attr) != getattr(children[j].element, merge_attr):
                    setattr(children[i].element, merge_attr, None)
                children.pop(j)
            else:
                j += 1
        i += 1
    # Deduplicate children of children[i] (last layer so no need to merge, only deduplicate)
    for node in children:
        node.childrens = remove_duplicates(node.childrens)


def analyser(cap, device_ipv4, device_ipv6, device_mac):
    counter = 0
    # create list of patterns
    patterns = []
    dns_map = DNSMap()
    # Adding special cases to the DNS map
    dns_map.add_ipv4("self", device_ipv4)
    dns_map.add_ipv6("self", device_ipv6)
    dns_map.add_ipv4("gateway", GATEWAY_IP)
    dns_map.add_ipv6("gateway", GATEWAY_IPV6)
    dns_map.add_ipv6("gateway-local", GATEWAY_LOCAL_IPV6)
    # mdns broadcast
    dns_map.add_ipv4("mdns", "224.0.0.251")
    dns_map.add_ipv6("mdns", "ff02::fb")
    
    # MAIN LOOP
    for packet in cap:
        # parse the dns packets for the future dns map
        # Get the DNS packets
        if hasattr(packet, 'dns'):
            dns_data = packet.dns
            # Check if the packet is a DNS response
            if hasattr(dns_data, 'a'):
                # Get the domain and the IP
                domain = dns_data.qry_name
                ip = dns_data.a
                # Add the domain and the IP to the map
                dns_map.add_ipv4(domain, ip)
            if hasattr(dns_data, 'aaaa'):
                # Get the domain and the IP
                domain = dns_data.qry_name
                ip = dns_data.aaaa
                # Add the domain and the IP to the map
                dns_map.add_ipv6(domain, ip)
        
        
        try:
            try:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
            except AttributeError as e:
                ip_src = packet.ipv6.src
                ip_dst = packet.ipv6.dst
            if ip_src == device_ipv4 or ip_dst == device_ipv4 or ip_src == device_ipv6 or ip_dst == device_ipv6:
                # Packet is linked to our device
                counter += 1
                
                # ----------------------------------------
                # First layer (ipv4, ipv6, arp, etc)
                # ----------------------------------------
                if '.' in ip_src or '.' in ip_dst:
                    ip = ipv4(ip_src, ip_dst)
                else:
                    ip = ipv6(ip_src, ip_dst)
                
                my_node_0 = None
                for node in patterns:
                    if node.protocol == "ipv4":
                        if node.element == ip:
                            # We found a node with the same IP data
                            my_node_0 = node
                            break
                    if node.protocol == "ipv6":
                        if node.element == ip:
                            # We found a node with the same IP data
                            my_node_0 = node
                            break
                if my_node_0 is None:
                    # No firt layer found
                    my_node_0 = Node(ip, "ipv4" if isinstance(ip, ipv4) else "ipv6", childrens=[], layer=0)
                    patterns.append(my_node_0)
                    
                # ----------------------------------------
                # Second layer (tcp, udp, etc)
                # ----------------------------------------
                my_node_1 = None
                try:
                    src_port = int(packet.tcp.srcport.show)
                    dst_port = int(packet.tcp.dstport.show)
                    tcp_info = tcp(src_port, dst_port)
                    for node in my_node_0.childrens:
                        if node.protocol == "tcp":
                            if node.element == tcp_info:
                                # We found a node with the same TCP data
                                my_node_1 = node
                                break
                    if my_node_1 is None:
                        # No second layer found
                        my_node_1 = Node(tcp_info, "tcp", layer=1, childrens=[])
                        my_node_0.childrens.append(my_node_1)
                except AttributeError as e:
                    # Not a TCP packet
                    pass
                if my_node_1 is None:
                    try:
                        src_port = int(packet.udp.srcport.show)
                        dst_port = int(packet.udp.dstport.show)
                        udp_info = udp(src_port, dst_port)
                        for node in my_node_0.childrens:
                            if node.protocol == "udp":
                                if node.element == udp_info:
                                    # We found a node with the same UDP data
                                    my_node_1 = node
                                    break
                        if my_node_1 is None:
                            # No second layer found
                            my_node_1 = Node(udp_info, "udp", layer=1, childrens=[])
                            my_node_0.childrens.append(my_node_1)
                    except AttributeError as e:
                        # Not a UDP packet
                        pass
                
                # ----------------------------------------
                # Third layer (http, dns, etc)
                # ----------------------------------------
                # Check http case
                if "HTTP" in str(packet.layers):
                    try:
                        # Get the method and the request URI
                        method = packet.http.request_method.show
                        uri = packet.http.request_uri.show
                        # To simplify queries/answers, we will not fill in the "response" field
                        http_packet = http(method, uri)
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "http":
                                if node.element == http_packet:
                                    # We found a node with the same HTTP data
                                    my_node_2 = node
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(http_packet, "http", layer=2, childrens=[])
                            my_node_1.childrens.append(my_node_2)
                    except AttributeError as e:
                        # HTTP packet is a response
                        pass
                elif "DNS" in str(packet.layers):
                    try:
                        type_name = None
                        dns_type = int(packet.dns.qry_type.show)
                        if dns_type == 1:
                            type_name = "A"
                        elif dns_type == 28:
                            type_name = "AAAA"
                        elif dns_type == 5:
                            type_name = "CNAME"
                        elif dns_type == 2:
                            type_name = "NS"
                        elif dns_type == 12:
                            type_name = "PTR"
                        request_name = packet.dns.qry_name.show
                        dns_packet = dns(type_name, request_name)
                        
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "dns":
                                if node.element == dns_packet:
                                    # We found a node with the same DNS data
                                    my_node_2 = node
                                    break
                                elif node.element.merge(dns_packet):
                                    # We found a node with the same domain name
                                    my_node_2 = node
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(dns_packet, "dns", layer=2, childrens=[])
                            my_node_1.childrens.append(my_node_2)
                    except AttributeError as e:
                        # Error in the DNS packet process. It could be a mDNS packet
                        if "MDNS" in str(packet.layers):
                            try:
                                is_response = True if packet.mdns.get_field_value("dns.flags.response") == "1" else False
                                mdns_packets = []
                                if is_response:
                                    mdns_packet = mdns(True, "", [])
                                    mdns_packets.append(mdns_packet)
                                else:
                                    qtypes = []
                                    qnames = []
                                    for querry in packet.mdns.dns_qry_name.fields:
                                        qnames.append(querry.show)
                                    for querry_type in packet.mdns.dns_qry_type.fields:
                                        type_name = querry_type.showname_value.split(" ")[0]
                                        qtypes.append(type_name)
                                    mdns_dict = {}
                                    for i in range(len(qtypes)):
                                        if qtypes[i] in mdns_dict:
                                            mdns_dict[qtypes[i]].append(qnames[i])
                                        else:
                                            mdns_dict[qtypes[i]] = [qnames[i]]
                                    # Create a node for each querry type
                                    for key, values in mdns_dict.items():
                                        mdns_packet = mdns(False, key, values)
                                        mdns_packets.append(mdns_packet)
                                
                                for mdns_packet in mdns_packets:
                                    my_node_2 = None
                                    for node in my_node_1.childrens:
                                        if node.protocol == "mdns":
                                            if node.element == mdns_packet:
                                                # We found a node with the same mDNS data
                                                my_node_2 = node
                                                break
                                    if my_node_2 is None:
                                        # No third layer found
                                        my_node_2 = Node(mdns_packet, "mdns", layer=2, childrens=[])
                                        my_node_1.childrens.append(my_node_2)
                                    
                            except AttributeError as e:
                                # Error in the mDNS packet process
                                #print(packet)
                                pass
                        else:
                            # Dns packet with error (ex: DNS in a icmp destination unreachable packet)
                            #print(packet)
                            pass
                else:
                    # packet have no third layer handled before
                    # print(packet.layers)
                    pass
                
                # TODO: Handle igmp, ssdp, dhcp, ntp
                            
        except AttributeError as e:
            # Packet is not an IP Packet
            try:
                # Parse the ARP packets
                arp_type_number = int(packet.arp.opcode.show)
                sha = packet.arp.src_hw_mac.show
                spa = packet.arp.src_proto_ipv4.show
                tha = packet.arp.dst_hw_mac.show
                tpa = packet.arp.dst_proto_ipv4.show
                arp_type = "request" if arp_type_number == 1 else "reply"
                arp_packet = arp(arp_type, sha, spa, tha, tpa)
                arp_packet.simplify(device_ipv4, device_mac)
                my_node_0 = None
                for node in patterns:
                    if node.protocol == "arp":
                        if node.element == arp_packet:
                            # We found a node with the same ARP data
                            my_node_0 = node
                            break
                if my_node_0 is None:
                    # No firt layer found
                    my_node_0 = Node(arp_packet, "arp", childrens=[], layer=0)
                    patterns.append(my_node_0)
            except AttributeError as e:
                # Packet is not an ARP Packet
                print(packet)
                pass
    
    # ----------------------------------------
    # Simplification process
    # ----------------------------------------
    # First layer
    # replace all the ip source and destination by domain name if possible
    for node in patterns:
        if node.protocol == "ipv4":
            domain = dns_map.get_domain_by_ipv4(node.element.src)
            if domain is not None:
                node.element.src = domain
            domain = dns_map.get_domain_by_ipv4(node.element.dst)
            if domain is not None:
                node.element.dst = domain
        if node.protocol == "ipv6":
            domain = dns_map.get_domain_by_ipv6(node.element.src)
            if domain is not None:
                node.element.src = domain
            domain = dns_map.get_domain_by_ipv6(node.element.dst)
            if domain is not None:
                node.element.dst = domain
    
    # Check if multiple first-layer nodes are now the same
    i = 0
    while i < len(patterns):
        j = i + 1
        while j < len(patterns):
            if patterns[i].protocol == patterns[j].protocol and patterns[i].element == patterns[j].element:
                # Merge nodes
                patterns[i].childrens.extend(patterns[j].childrens)
                # Remove the duplicate node
                patterns.pop(j)
            else:
                j += 1
        # Deduplicate children of patterns[i]
        k = 0
        while k < len(patterns[i].childrens):
            l = k + 1
            while l < len(patterns[i].childrens):
                if (
                    patterns[i].childrens[k].protocol == patterns[i].childrens[l].protocol
                    and patterns[i].childrens[k].element == patterns[i].childrens[l].element
                ):
                    # Merge child nodes
                    patterns[i].childrens[k].childrens.extend(patterns[i].childrens[l].childrens)
                    patterns[i].childrens.pop(l)
                else:
                    l += 1
            k += 1
        i += 1
        
    # Simplify the tcp and udp nodes of the second layer by grouping all nodes that are using the same protocol and that have a port in common (ex: node1: tcp 123 -> 443 and node2: tcp 456 -> 443 will be merged into one node: tcp None -> 443)
    # Ease the process for port 80 and 443 tcp
    for node in patterns:
        for child in node.childrens:
            if child.protocol == "tcp" or child.protocol == "udp":
                if child.element.dst_port == 80 or child.element.dst_port == 443:
                    child.element.src_port = None
                if child.element.src_port == 80 or child.element.src_port == 443:
                    child.element.dst_port = None
    
    for child in patterns:
        if child.protocol in ["ipv4", "ipv6", "udp"]:
            # Merge nodes on dst_port
            merge_nodes_on_port(child.childrens, "dst_port", "src_port")
            # Merge nodes on src_port
            merge_nodes_on_port(child.childrens, "src_port", "dst_port")
    
    # Merge dns and mdns nodes on domain name
    for child in patterns:
        if child.protocol in ["ipv4", "ipv6"]:
            for node in child.childrens:
                if node.protocol == "udp":
                    new_children = []
                    for dns_node in node.childrens:
                        if dns_node.protocol == "dns":
                            if new_children == []:
                                new_children.append(dns_node)
                            else:
                                merged = False
                                for new_dns_node in new_children:
                                    if new_dns_node.protocol == "dns":
                                        if new_dns_node.element.merge(dns_node.element):
                                            merged = True
                                            break
                                if not merged:
                                    new_children.append(dns_node)
                        elif dns_node.protocol == "mdns":
                            if new_children == []:
                                new_children.append(dns_node)
                            else:
                                merged = False
                                for new_dns_node in new_children:
                                    if new_dns_node.protocol == "mdns":
                                        if new_dns_node.element.qtype == dns_node.element.qtype:
                                            new_dns_node.element.domain_name.extend(dns_node.element.domain_name)
                                            new_dns_node.element.domain_name = remove_duplicates(new_dns_node.element.domain_name)
                                            merged = True
                                            break
                                if not merged:
                                    new_children.append(dns_node)
                        else:
                            new_children.append(dns_node)
                    node.childrens = new_children
                    
                    
    # Sorting the patterns by protocol
    patterns.sort(key=lambda x: x.protocol)                
    
    for node in patterns:
        node.print_tree()
        print("---")
        
    # print total number of nodes
    c = len(patterns)
    for node in patterns:
        c += len(node.childrens)
        for child in node.childrens:
            c += len(child.childrens)
    print("Total number of nodes after simplification: " + str(c))

if __name__ == "__main__":
    # Read the PCAP file
    cap = pyshark.FileCapture('traces/philips-hue.pcap')
    # Get the device IP
    device_ipv4 = "192.168.1.141"
    device_ipv6 = "fe80::217:88ff:fe74:c2dc"
    device_mac = "00:17:88:74:c2:dc"
    # Analyze packets
    analyser(cap, device_ipv4, device_ipv6, device_mac)