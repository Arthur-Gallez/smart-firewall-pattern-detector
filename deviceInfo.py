device_name_map = {
    "dlink-cam": {
        "mac":  "b0:c5:54:43:54:83",
        "ipv4": "192.168.1.115",
    },
    "philips-hue": {
        "mac":  "00:17:88:74:c2:dc",
        "ipv4": "192.168.1.141",
        "ipv6": "fe80::217:88ff:fe74:c2dc"
    },
    "tplink-plug": {
        "mac":  "50:c7:bf:ed:0a:54",
        "ipv4": "192.168.1.135"
    },
    "xiaomi-cam": {
        "ipv4": "192.168.1.161"
    },
    "tuya-motion": {
        "mac":  "a0:92:08:7b:03:1c",
        "ipv4": "192.168.1.102"
    },
    "smartthings-hub": {
        "mac":  "d0:52:a8:72:aa:27",
        "ipv4": "192.168.1.223",
        "ipv6": "fddd:ed18:f05b:0:d8a3:adc0:f68f:e5cf"
    },
    "amazon-echo": {
        "mac":  "50:dc:e7:a2:d8:95",
        "ipv4": "192.168.1.150",
        "ipv6": "fddd:ed18:f05b:0:adef:a05d:fcbe:afc9"
    },
    "phone": {
        "mac":  "3c:cd:5d:a2:a9:d7",
        "ipv4": "192.168.1.222",
        "ipv6": "fddd:ed18:f05b:0:6413:9c13:5391:3136"
    }
}

def get_device_name_by_address(address:str):
    for device_name, device_info in device_name_map.items():
        if address in device_info.values():
            return device_name
    return address

if __name__ == "__main__":
    print(get_device_name_by_address("3c:cd:5d:a2:a9:d7"))  