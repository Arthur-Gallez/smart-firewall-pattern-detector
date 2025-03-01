"""Analyzer

This module defines the analyzer functions that process packets from a capture file and generate the patterns.

Made by: Gallez Arthur & Zhang Zexin
"""

# --------------------
# IMPORTS
# --------------------
from scapy.all import *
from scapy.layers.http import *
from scapy.contrib.coap import *
from scapy.contrib.igmp import *
from scapy.contrib.igmpv3 import *
from devicesFinder import Device, findDevices
from dnsMap import DNSMap
from protocols.ipv4 import ipv4
from protocols.ipv6 import ipv6
from protocols.tcp import tcp
from protocols.udp import udp
from protocols.arp import arp
from protocols.http import http
from protocols.dns import dns
from protocols.mdns import mdns
from protocols.dhcp import dhcp
from protocols.igmp import igmp
from protocols.ssdp import ssdp
from protocols.coap import coap
from protocols.icmp import icmp
from patternClass import Pattern
from progressBar import printProgressBar
from node import Node
from patternToYAML import patternToYAML, remove_duplicates
from bidirectionalSimplifier import merge_bidirectional_patterns
from deviceInfo import get_device_name_by_address
from prettytable import PrettyTable

# --------------------
# CONSTANTS
# --------------------
GATEWAY_IPV6 = "fddd:ed18:f05b::1"
DEFAULT = "00:00:00:00:00:00"
BROADCAST = "255.255.255.255"
BROADCAST_IPV6 = "ff:ff:ff:ff:ff:ff"
PHONE_IPV6 = "3c:cd:5d:a2:a9:d7"
PHONE = "192.168.1.222"
IGMPV3_IP = "224.0.0.22"
SSDP = "239.255.255.250"
INCLUDE_PHONE = False

#Added other device's ipv4 and ipv6
# TODO: Remove this ?
AMAZON_ECHO = "192.168.1.150"
AMAZON_ECHO_IPV6 = "fddd:ed18:f05b:0:adef:a05d:fcbe:afc9"

DLINK_CAM = "192.168.1.115"

PHILIPS_HUE = "192.168.1.141"
PHILIPS_HUE_IPV6 = "fe80::217:88ff:fe74:c2dc"

TPLINK_PLUG = "192.168.1.135"

XIAOMI_CAM = "192.168.1.161"

TUYA_MOTION = "192.168.1.102"

SMARTTHINGS_HUB = "192.168.1.223"
SMARTTHINGS_HUB_IPV6 = "fddd:ed18:f05b:0:d8a3:adc0:f68f:e5cf"


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
                children[i].protocol in ["tcp", "udp"]
                and children[i].protocol == children[j].protocol
                and getattr(children[i].element, port_attr) == getattr(children[j].element, port_attr)
                and getattr(children[i].element, merge_attr) not in [1900, 3222] and getattr(children[j].element, merge_attr) not in [1900, 3222]
            ):
                # keep the smaller packet_number of the two children
                children[i].packet_number = min(children[i].packet_number, children[j].packet_number)
                children[i].last_seen(children[j].last_seen_time)
                children[i].stat_count += children[j].stat_count
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


def analyzer(packets, device_ipv4:str, device_ipv6:str, device_mac:str, number_of_packets:int, device_name:str, ipv4_gateway:str, ipv6_gateway:str, mac_gateway:str, print_map:bool, print_tree:bool, print_progress:bool):
    """
    Analyzes packets from a capture file and generates a pattern tree.

    Args:
        cap (pyshark.FileCapture): Capture file to analyze.
        device_ipv4 (str): IPv4 address of the device.
        device_ipv6 (str): IPv6 address of the device.
        device_mac (str): MAC address of the device.
        number_of_packets (int): Number of packets in the capture file.
        device_name (str): Name of the device.
        ipv4_gateway (str): IPv4 address of the gateway.
        ipv6_gateway (str): IPv6 address of the gateway.
        mac_gateway (str): MAC address of the gateway.
    """
    
    counter = 0
    # create list of patterns
    patterns = []
    dns_map = DNSMap()
    # Adding special cases to the DNS map
    device_name_ipv4 = get_device_name_by_address(device_ipv4) if get_device_name_by_address(device_ipv4) is not None else device_name.replace(" ", "-")
    device_name_ipv6 = get_device_name_by_address(device_ipv6) if get_device_name_by_address(device_ipv6) is not None else device_name.replace(" ", "-")
    dns_map.add_ipv4("self", device_ipv4, device_name_ipv4)
    dns_map.add_ipv6("self", device_ipv6, device_name_ipv6)
    # Gateway
    dns_map.add_ipv4("gateway", ipv4_gateway, "gateway")
    dns_map.add_ipv6("gateway", GATEWAY_IPV6, "gateway")
    dns_map.add_ipv6("gateway-local", ipv6_gateway, "gateway-local")
    # Phone
    dns_map.add_ipv6("phone", PHONE_IPV6, get_device_name_by_address(PHONE_IPV6))
    dns_map.add_ipv4("phone", PHONE, get_device_name_by_address(PHONE))
    # Broadcast and other special cases
    dns_map.add_ipv4("broadcast", BROADCAST, "broadcast")
    dns_map.add_ipv6("broadcast", BROADCAST_IPV6, "broadcast")
    dns_map.add_ipv4("igmpv3", IGMPV3_IP, "igmpv3")
    dns_map.add_ipv4("ssdp", SSDP, "ssdp")
    # mdns broadcast
    dns_map.add_ipv4("mdns", "224.0.0.251", "mdns")
    dns_map.add_ipv6("mdns", "ff02::fb", "mdns")    
    # CoAP multicast
    dns_map.add_ipv6("coap", "ff02::158", "coap") # Based on the firewall (src/translator/protocols/icmpv6.py)
    dns_map.add_ipv6("coap", "ff02::fd", "coap") # Based on https://www.rfc-editor.org/rfc/rfc7390.html
    dns_map.add_ipv6("coap", "ff05::fd", "coap") # Based on https://www.rfc-editor.org/rfc/rfc7390.html
    dns_map.add_ipv4("coap", "224.0.1.187", "coap") # Based on https://www.rfc-editor.org/rfc/rfc7390.html

    # Add other IoT devices to DNS map
    # TODO: Remove this ?
    if AMAZON_ECHO != device_ipv4:
        dns_map.add_ipv4("amazon-echo", AMAZON_ECHO, "amazon-echo")
    if AMAZON_ECHO_IPV6 != device_ipv6:
        dns_map.add_ipv6("amazon-echo", AMAZON_ECHO_IPV6, "amazon-echo")
        
    if DLINK_CAM != device_ipv4:
        dns_map.add_ipv4("dlink-cam", DLINK_CAM, "dlink-cam")
        
    if PHILIPS_HUE != device_ipv4:
        dns_map.add_ipv4("philips-hue", PHILIPS_HUE, "philips-hue")
    if PHILIPS_HUE_IPV6 != device_ipv6:
        dns_map.add_ipv6("philips-hue", PHILIPS_HUE_IPV6, "philips-hue")
        
    if TPLINK_PLUG != device_ipv4:
        dns_map.add_ipv4("tplink-plug", TPLINK_PLUG, "tplink-plug")
        
    if XIAOMI_CAM != device_ipv4:
        dns_map.add_ipv4("xiaomi-cam", XIAOMI_CAM, "xiaomi-cam")
        
    if TUYA_MOTION != device_ipv4:
        dns_map.add_ipv4("tuya-motion", TUYA_MOTION, "tuya-motion")
        
    if SMARTTHINGS_HUB != device_ipv4:
        dns_map.add_ipv4("smartthings-hub", SMARTTHINGS_HUB, "smartthings-hub")
    if SMARTTHINGS_HUB_IPV6 != device_ipv6:
        dns_map.add_ipv6("smartthings-hub", SMARTTHINGS_HUB_IPV6, "smartthings-hub" )
    
    i_packet = 0
    # MAIN LOOP
    print("Progress: Analyzing traces...")
    for packet in packets:
        i_packet += 1
        if print_progress:
            printProgressBar(i_packet, number_of_packets, prefix = 'Progress:', suffix = 'Complete', length = 50)
        
        # parse the dns packets for the dns map
        # Get the DNS packets
        if packet.haslayer(DNS):
            # Exclude mDNS packets (multicast DNS)
            if (packet.haslayer(IP) and packet[IP].dst == "224.0.0.251") or \
            (packet.haslayer(IPv6) and packet[IPv6].dst == "ff02::fb") or \
            (packet.haslayer(UDP) and packet[UDP].dport == 5353):
                # Skip mDNS packets
                pass
            else:
                dns_layer = packet[DNS]
                # Check if the packet is a DNS response
                if dns_layer.qr == 1:  # 1 means it's a response
                    # Check if the packet has an A record (IPv4)
                    for i in range(dns_layer.ancount):
                        try:
                            answer = dns_layer.an[i]
                            if answer.type == 1:  # Type 1 is A (IPv4)
                                domain = dns_layer.qd.qname.decode().strip(".")
                                ip = answer.rdata  # Get the IPv4 address
                                dns_map.add_ipv4(domain, ip)
                            # Check if the packet has an AAAA record (IPv6)
                            if answer.type == 28:
                                domain = dns_layer.qd.qname.decode().strip(".")
                                ip = answer.rdata  # Get the IPv6 address
                                dns_map.add_ipv6(domain, ip)
                        except:
                            pass
        # Start of packet layering
        try:
            try:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
            except IndexError as e:
                ip_src = packet[IPv6].src
                ip_dst = packet[IPv6].dst
            phone_condition = False
            if INCLUDE_PHONE:
                phone_condition = ip_src == PHONE_IPV6 or ip_dst == PHONE_IPV6 or ip_src == PHONE or ip_dst == PHONE
            if ip_src == device_ipv4 or ip_dst == device_ipv4 or ip_src == device_ipv6 or ip_dst == device_ipv6 or ip_dst == BROADCAST or ip_dst == BROADCAST_IPV6 or ip_dst == SSDP or phone_condition:
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
                            # increase the stat_count of the node
                            my_node_0.last_seen(packet.time)
                            my_node_0.stat_count += 1
                            break
                    if node.protocol == "ipv6":
                        if node.element == ip:
                            # We found a node with the same IP data
                            my_node_0 = node
                            # increase the stat_count of the node
                            my_node_0.last_seen(packet.time)
                            break
                if my_node_0 is None:
                    # No firt layer found
                    my_node_0 = Node(ip, "ipv4" if isinstance(ip, ipv4) else "ipv6", 
                                    childrens=[], layer=0, packet_number=i_packet)
                    my_node_0.last_seen(packet.time)
                    patterns.append(my_node_0)
                # ----------------------------------------
                # Second layer (tcp, udp, etc)
                # ----------------------------------------
                my_node_1 = None
                try:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    tcp_info = tcp(src_port, dst_port)
                    for node in my_node_0.childrens:
                        if node.protocol == "tcp":
                            if node.element == tcp_info:
                                # We found a node with the same TCP data
                                my_node_1 = node
                                # increase the stat_count of the node
                                my_node_1.last_seen(packet.time)
                                my_node_1.stat_count += 1
                                break
                    if my_node_1 is None:
                        # No second layer found
                        my_node_1 = Node(tcp_info, "tcp", layer=1, 
                                        childrens=[], packet_number=i_packet)
                        my_node_1.last_seen(packet.time)
                        my_node_0.childrens.append(my_node_1)
                except IndexError as e:
                    # Not a TCP packet
                    pass
                if my_node_1 is None:
                    try:
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        udp_info = udp(src_port, dst_port)
                        for node in my_node_0.childrens:
                            if node.protocol == "udp":
                                if node.element == udp_info:
                                    # We found a node with the same UDP data
                                    my_node_1 = node
                                    # increase the stat_count of the node
                                    my_node_1.last_seen(packet.time)
                                    my_node_1.stat_count += 1
                                    break
                        if my_node_1 is None:
                            # No second layer found
                            my_node_1 = Node(udp_info, "udp", layer=1, 
                                            childrens=[], packet_number=i_packet)
                            my_node_1.last_seen(packet.time)
                            my_node_0.childrens.append(my_node_1)
                    except IndexError as e:
                        # Not a UDP packet
                        pass
                if my_node_1 is None:
                    # IGMP packet
                    if packet.haslayer(IGMPv3):
                        try:
                            igmp_type = packet[IGMPv3].type
                            igmp_type = "membership report" if packet[IGMPv3].type in [34, 22, 18] else "membership query" if packet[IGMPv3].type == 17 else "leave group"
                            igmp_version = 3
                            igmp_group = None
                            if igmp_type == "membership report" and packet.haslayer(IGMPv3mr):
                                igmp_group = packet[IGMPv3mr].records[0].maddr
                            igmp_packet = igmp(igmp_version, igmp_type, igmp_group)
                            igmp_packet.simplify()
                            my_node_1 = None
                            for node in my_node_0.childrens:
                                if node.protocol == "igmp":
                                    if node.element == igmp_packet:
                                        # We found a node with the same IGMP data
                                        my_node_1 = node
                                        # increase the stat_count of the node
                                        my_node_1.last_seen(packet.time)
                                        my_node_1.stat_count += 1
                                        break
                            if my_node_1 is None:
                                # No third layer found
                                my_node_1 = Node(igmp_packet, "igmp", layer=2, 
                                                childrens=[], packet_number=i_packet)
                                my_node_1.last_seen(packet.time)
                                my_node_0.childrens.append(my_node_1)
                        except AttributeError as e:
                            # Not an IGMP packet
                            #print(packet)
                            pass
                
                if my_node_1 is None:
                    if "ICMP" in str(packet.layers):
                        # ICMP packet
                        try:
                            icmp_type = packet[ICMP].type
                            icmp_packet = icmp(icmp_type)
                            my_node_1 = None
                            for node in my_node_0.childrens:
                                if node.protocol == "icmp":
                                    if node.element == icmp_packet:
                                        # We found a node with the same ICMP data
                                        my_node_1 = node
                                        # increase the stat_count of the node
                                        my_node_1.last_seen(packet.time)
                                        my_node_1.stat_count += 1
                                        break
                            if my_node_1 is None:
                                # No third layer found
                                my_node_1 = Node(icmp_packet, "icmp", layer=2, 
                                                childrens=[], packet_number=i_packet)
                                my_node_1.last_seen(packet.time)
                                my_node_0.childrens.append(my_node_1)
                        except AttributeError as e:
                            # ICMP packet with error
                            # print(packet)
                            # print(e)
                            pass
                # ----------------------------------------
                # Third layer (http, dns, etc)
                # ----------------------------------------
                # Check HTTP case
                if packet.haslayer(HTTP):
                    try:
                        # Get the method and the request URI
                        try:
                            method = packet[HTTP].Method.decode()
                            is_response = False
                            uri = packet[HTTP].Path.decode()  # Move this line here
                        except AttributeError:
                            method = ""
                            try:
                                is_response = True if packet.haslayer(HTTPResponse) else False
                                if not is_response:
                                    # HTTP layer contains no data and is not a response
                                    if packet.haslayer(Raw):
                                        try:
                                            raw = packet[Raw].load.decode()
                                        except:
                                            continue
                                        method = raw.split(" ")[0]
                                        if method not in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH"]:
                                            continue
                                        uri = raw.split(" ")[1]
                                        # Only keep the path
                                        if "?" in uri:
                                            uri = uri.split("?")[0] + "?*"
                                else:
                                    uri = None  # Add this line to fix the response packet
                            except AttributeError:
                                is_response = False
                        # To simplify queries/answers, we will not fill in the "response" field
                        http_packet = http(method, uri, is_response)
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "http":
                                if node.element == http_packet:
                                    # We found a node with the same HTTP data
                                    my_node_2 = node
                                    # increase the stat_count of the node
                                    my_node_2.last_seen(packet.time)
                                    my_node_2.stat_count += 1
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(http_packet, "http", layer=2,
                                            childrens=[], packet_number=i_packet)
                            my_node_2.last_seen(packet.time)
                            my_node_1.childrens.append(my_node_2)
                    except AttributeError:
                        # HTTP packet is a response
                        pass
                # Check DNS case
                elif packet.haslayer(DNS) and not (packet[DNS].qd.qname.decode().endswith(".local.") or (my_node_1 is not None and my_node_1.protocol == "udp" and my_node_1.element.dst_port == 5353)):
                    try:
                        type_name = None
                        dns_type = packet[DNS].qd.qtype
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
                        request_name = packet[DNS].qd.qname.decode().strip(".")
                        dns_packet = dns(type_name, request_name)
                        
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "dns":
                                if node.element == dns_packet:
                                    # We found a node with the same DNS data
                                    my_node_2 = node
                                    # increase the stat_count of the node
                                    my_node_2.last_seen(packet.time)
                                    my_node_2.stat_count += 1
                                    break
                                elif node.element.merge(dns_packet):
                                    # We found a node with the same domain name
                                    my_node_2 = node
                                    # increase the stat_count of the node
                                    my_node_2.last_seen(packet.time)
                                    my_node_2.stat_count += 1
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(dns_packet, "dns", layer=2,
                                            childrens=[], packet_number=i_packet)
                            my_node_2.last_seen(packet.time)
                            my_node_1.childrens.append(my_node_2)
                    except AttributeError:
                        # Error in the DNS packet process
                        pass
                # Check mDNS case
                if packet.haslayer(DNS) and (packet[DNS].qd.qname.decode().endswith(".local.") or (my_node_1 is not None and my_node_1.protocol == "udp" and my_node_1.element.dst_port == 5353)):
                    try:
                        is_response = packet[DNS].qr == 1
                        mdns_packets = []
                        if is_response:
                            mdns_packet = mdns(True, "", [])
                            mdns_packets.append(mdns_packet)
                        else:
                            qtypes = []
                            qnames = []
                            for i in range(packet[DNS].qdcount):
                                qnames.append(packet[DNS].qd[i].qname.decode().strip("."))
                                t = packet[DNS].qd[i].qtype
                                if t == 1:
                                    qtypes.append("A")
                                elif t == 28:
                                    qtypes.append("AAAA")
                                elif t == 5:
                                    qtypes.append("CNAME")
                                elif t == 2:
                                    qtypes.append("NS")
                                elif t == 12:
                                    qtypes.append("PTR")
                                elif t == 255:
                                    qtypes.append("ANY")
                                elif t == 16:
                                    qtypes.append("TXT")
                                elif t == 33:
                                    qtypes.append("SRV")
                                else:
                                    qtypes.append(str(packet[DNS].qd[i].qtype))
                            mdns_dict = {}
                            for i in range(len(qtypes)):
                                if qtypes[i] in mdns_dict:
                                    mdns_dict[qtypes[i]].append(qnames[i])
                                else:
                                    mdns_dict[qtypes[i]] = [qnames[i]]
                            # Create a node for each query type
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
                                        # increase the stat_count of the node
                                        my_node_2.last_seen(packet.time)
                                        my_node_2.stat_count += 1
                                        break
                            if my_node_2 is None:
                                # No third layer found
                                my_node_2 = Node(mdns_packet, "mdns", layer=2,
                                                childrens=[], packet_number=i_packet)
                                my_node_2.last_seen(packet.time)
                                my_node_1.childrens.append(my_node_2)
                    except AttributeError as e:
                        # Error in the mDNS packet process
                        pass
                # Check DHCP case
                elif packet.haslayer(DHCP) and packet.haslayer(BOOTP):
                    # DHCP packet
                    try:
                        for option in packet[DHCP].options:
                            if option[0] == "message-type":
                                dhcp_type_value = option[1]
                        dhcp_type_name = "discover" if dhcp_type_value == 1 else "offer" if dhcp_type_value == 2 else "request" if dhcp_type_value == 3 else "ack"
                        client_mac = packet[BOOTP].chaddr.hex()
                        # remove all ending zeros
                        client_mac = client_mac.rstrip("00")
                        client_mac = ":".join(client_mac[i:i+2] for i in range(0, len(client_mac), 2))

                        if client_mac == device_mac:
                            client_mac = "self"
                        dhcp_packet = dhcp(dhcp_type_name, client_mac)
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "dhcp":
                                if node.element == dhcp_packet:
                                    # We found a node with the same DHCP data
                                    my_node_2 = node
                                    # increase the stat_count of the node
                                    my_node_2.last_seen(packet.time)
                                    my_node_2.stat_count += 1
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(dhcp_packet, "dhcp", layer=2, 
                                            childrens=[], packet_number=i_packet)
                            my_node_2.last_seen(packet.time)
                            my_node_1.childrens.append(my_node_2)
                    except AttributeError as e:
                        # DHCP packet with error (ex: DHCP in a icmp destination unreachable packet)
                        # print(packet)
                        # print(e)
                        pass
                # Check SSDP case
                elif packet.haslayer(UDP) and packet.haslayer(Raw) and (packet[Raw].load.startswith(b"M-SEARCH") or packet[Raw].load.startswith(b"NOTIFY")):
                    # SSDP packet
                    try:
                        is_response = True if my_node_0.element.dst == device_ipv4 or my_node_0.element.dst == device_ipv6 else False
                        method = "M-SEARCH" if packet[Raw].load.startswith(b"M-SEARCH") else "NOTIFY"
                        ssdp_packet = ssdp(method, is_response)
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "ssdp":
                                if node.element == ssdp_packet:
                                    # We found a node with the same SSDP data
                                    my_node_2 = node
                                    # increase the stat_count of the node
                                    my_node_2.last_seen(packet.time)
                                    my_node_2.stat_count += 1
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(ssdp_packet, "ssdp", layer=2, 
                                            childrens=[], packet_number=i_packet)
                            my_node_2.last_seen(packet.time)
                            my_node_1.childrens.append(my_node_2)
                    except AttributeError as e:
                        print(e)
                # Check CoAP case
                elif packet.haslayer(CoAP):
                    try:
                        code = packet[CoAP].code
                        coap_method = "GET" if code == 1 else "POST" if code == 2 else "PUT" if code == 3 else "DELETE" if code == 4 else "UNKNOWN"
                        type_int = packet[CoAP].type
                        coap_type = "CON" if type_int == 0 else "NON" if type_int == 1 else "ACK" if type_int == 2 else "RST" if type_int == 3 else "UNKNOWN"
                        coap_uri_path = ""
                        coap_uri_query = ""
                        for option in packet[CoAP].options:
                            if option[0] == "Uri-Path":
                                coap_uri_path += "/" + option[1].decode()
                            elif option[0] == "Uri-Query":
                                coap_uri_query += option[1].decode()
                        coap_uri = coap_uri_path if coap_uri_query == "" else coap_uri_path + "?" + coap_uri_query
                        coap_packet = coap(coap_type, coap_method, coap_uri)
                        my_node_2 = None
                        for node in my_node_1.childrens:
                            if node.protocol == "coap":
                                if node.element == coap_packet:
                                    # We found a node with the same COAP data
                                    my_node_2 = node
                                    # increase the stat_count of the node
                                    my_node_2.last_seen(packet.time)
                                    my_node_2.stat_count += 1
                                    break
                        if my_node_2 is None:
                            # No third layer found
                            my_node_2 = Node(coap_packet, "coap", layer=2, 
                                            childrens=[], packet_number=i_packet)
                            my_node_2.last_seen(packet.time)
                            my_node_1.childrens.append(my_node_2)
                    
                    except AttributeError as e:
                        # An error occured while parsing the COAP packet
                        # print(packet)
                        pass
                else:
                    # packet have no third layer handled before
                    pass
                            
        except IndexError as e:
            # Packet is not an IP Packet
            try:
                # Check if the packet is an ARP packet
                if packet.haslayer(ARP):
                    arp_type_number = int(packet[ARP].op)  # Operation code (1=request, 2=reply)
                    sha = packet[ARP].hwsrc  # Source MAC address
                    spa = packet[ARP].psrc  # Source Protocol (IPv4) address
                    tha = packet[ARP].hwdst  # Target MAC address
                    tpa = packet[ARP].pdst  # Target Protocol (IPv4) address
                    arp_type = "request" if arp_type_number == 1 else "reply"
                    arp_packet = arp(arp_type, sha, spa, tha, tpa, mac_gateway)
                    arp_packet.simplify(device_ipv4, device_mac)
                    my_node_0 = None
                    for node in patterns:
                        if node.protocol == "arp":
                            if node.element == arp_packet:
                                # We found a node with the same ARP data
                                my_node_0 = node
                                # increase the stat_count of the node
                                my_node_0.last_seen(packet.time)
                                my_node_0.stat_count += 1
                                break
                    if my_node_0 is None:
                        # No first layer found
                        my_node_0 = Node(arp_packet, "arp", childrens=[], layer=0, packet_number=i_packet)
                        my_node_0.last_seen(packet.time)
                        patterns.append(my_node_0)
            except ValueError as e:
                # Packet is not an ARP Packet
                pass
    
    # ----------------------------------------
    # Simplification process
    # ----------------------------------------
    print("Progress: Simplifying patterns...")
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
                # keep the smaller packet_number
                patterns[i].packet_number = min(patterns[i].packet_number, patterns[j].packet_number)
                # increase the stat_count of the node
                patterns[i].last_seen(patterns[j].last_seen_time)
                patterns[i].stat_count += patterns[j].stat_count
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
                    # keep the smaller packet_number of the two children
                    patterns[i].childrens[k].packet_number = min(patterns[i].childrens[k].packet_number, patterns[i].childrens[l].packet_number)
                    # increase the stat_count of the node
                    patterns[i].childrens[k].last_seen(patterns[i].childrens[l].last_seen_time)
                    patterns[i].childrens[k].stat_count += patterns[i].childrens[l].stat_count
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
        if child.protocol in ["ipv4", "ipv6"]:
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
                                            # keep the smaller packet_number of the two nodes
                                            new_dns_node.packet_number = min(new_dns_node.packet_number, dns_node.packet_number)
                                            # increase the stat_count of the node
                                            new_dns_node.last_seen(dns_node.last_seen_time)
                                            new_dns_node.stat_count += dns_node.stat_count
                                            new_dns_node.element.domain_name = remove_duplicates(new_dns_node.element.domain_name)
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
                                            # keep the smaller packet_number of the two nodes
                                            new_dns_node.packet_number = min(new_dns_node.packet_number, dns_node.packet_number)
                                            # increase the stat_count of the node
                                            new_dns_node.last_seen(dns_node.last_seen_time)
                                            new_dns_node.stat_count += dns_node.stat_count
                                            new_dns_node.element.domain_name.extend(dns_node.element.domain_name)
                                            new_dns_node.element.domain_name = remove_duplicates(new_dns_node.element.domain_name)
                                            merged = True
                                            break
                                if not merged:
                                    new_children.append(dns_node)
                        else:
                            new_children.append(dns_node)
                    node.childrens = new_children
                    
    
    # Printing the dns map
    if print_map:
        print("DNS map:")
        dns_map.print_map()
                    
    # Sorting the patterns by protocol
    patterns.sort(key=lambda x: x.protocol)                
    
    if print_tree:
        print("Patterns tree:")
        for node in patterns:
            node.print_tree()
            print("---")
    
    # Patterns object creation
    pattern_list = []
    for node in patterns:
        layer_0 = node.element
        packet_number_0 = node.packet_number
        if node.is_leaf():
            stat_rate = node.rate
            stat_count = node.stat_count
            p = Pattern(layer_0=layer_0, layer_1=None, layer_2=None,
                       packet_number_0=packet_number_0, packet_number_1=0, packet_number_2=0, stat_rate=stat_rate, stat_count=stat_count)
            pattern_list.append(p)
        else:
            for child in node.childrens:
                layer_1 = child.element
                packet_number_1 = child.packet_number
                if child.is_leaf():
                    stat_rate = child.rate
                    stat_count = child.stat_count
                    p = Pattern(layer_0=layer_0, layer_1=layer_1, layer_2=None,
                              packet_number_0=packet_number_0, 
                              packet_number_1=packet_number_1,
                              packet_number_2=0, stat_rate=stat_rate, stat_count=stat_count)
                    pattern_list.append(p)
                else:
                    for grandchild in child.childrens:
                        layer_2 = grandchild.element
                        packet_number_2 = grandchild.packet_number
                        stat_rate = grandchild.rate
                        stat_count = grandchild.stat_count
                        p = Pattern(layer_0=layer_0, layer_1=layer_1, layer_2=layer_2,
                                  packet_number_0=packet_number_0,
                                  packet_number_1=packet_number_1,
                                  packet_number_2=packet_number_2,
                                  stat_rate=stat_rate,
                                  stat_count=stat_count)
                        pattern_list.append(p)

    # merge bidirectional patterns
    pattern_list = merge_bidirectional_patterns(pattern_list)
    YamlResult = patternToYAML(pattern_list, dns_map)      
    return YamlResult

def run(file_path:str, print_map:bool=False, print_tree:bool=False, print_patterns:bool=True):
    # Read the PCAP file
    print("Progress: Loading packets...")
    
    packets = rdpcap(file_path)
    number_of_packets = len(packets)
    # Find devices
    devices = findDevices(packets, number_of_packets, True)
    if len(devices) == 0:
        print("No local devices found in .pcap file.")
        exit()
    print(f"{len(devices)} devices found in .pcap file:")
    table = PrettyTable()
    table.field_names = ["Device", "Name", "IPv4", "IPv6", "MAC"]
    for i in range(len(devices)):
        table.add_row([i+1, devices[i].name, devices[i].ipv4, devices[i].ipv6, devices[i].mac])
    print(table)
    
    # Ask the user to select the device to analyze
    while True:
        try:
            device_number = int(input("Enter the number of the device to analyze: "))
            if device_number < 1 or device_number > len(devices):
                raise ValueError
            break
        except ValueError:
            print("Invalid input. Please enter a number between 1 and " + str(len(devices)))
    device = devices[device_number-1]
    # Ask the user for a gateway
    while True:
        try:
            gateway_number = int(input("Enter the number of the gateway device: "))
            if gateway_number < 1 or gateway_number > len(devices):
                raise ValueError
            break
        except ValueError:
            print("Invalid input. Please enter a number between 1 and " + str(len(devices)))
    gateway = devices[gateway_number-1]
    # Analyze packets
    patterns = analyzer(packets, device.ipv4, device.ipv6, device.mac, number_of_packets, device.name, gateway.ipv4, gateway.ipv6, gateway.mac, print_map, print_tree, True)

    if print_patterns:
        print("Patterns found:")
        print(patterns)
if __name__ == "__main__":
    file_path = 'traces/philips-hue.pcap'
    run(file_path)