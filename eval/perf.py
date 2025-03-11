import sys, os, asyncio
import time
import scapy.all as scapy
import matplotlib.pyplot as plt
import numpy as np

def get_measures():
    commands_components = [
        ("philips-hue", 2, 3),
        ("smartthings-hub", 1, 2),
        ("tplink-plug", 2, 1),
        ("tuya-motion-wan", 1, 2),
        ("tuya-motion-wlan2.4", 1, 2),
        ("xiomi-cam-wan", 3, 2),
        ("xiomi-cam-wlan2.4", 2, 1)
    ]

    perfs = []
    for comp in commands_components:
        print(f"Running tests on {comp[0]}")
        # Get file size
        file_size = os.path.getsize(f"../traces/{comp[0]}.pcap")
        # Get number of packets
        packets = scapy.rdpcap(f"../traces/{comp[0]}.pcap")
        number_of_packets = len(packets)

        p = []
        for i in range(3):
        # Start timer
            start = time.time()
            os.system(f"cd ..; python3 main.py --file traces/{comp[0]}.pcap --force_device {comp[1]} --force_gateway {comp[2]} > /dev/null")
            end = time.time()
            p.append(end - start)

        # Compute performance
        perfs.append((number_of_packets, file_size, p))

    return perfs

def generate_graphs(perfs):
    # Extract data for plotting
    packet_counts = [perf[0] for perf in perfs]
    file_sizes = [perf[1] for perf in perfs]
    times = [perf[2] for perf in perfs]  # List of lists
    
    avg_times = [np.mean(t) for t in times]
    std_devs = [np.std(t) for t in times]

    # Plot Execution Time vs Number of Packets
    plt.figure(figsize=(10, 5))
    plt.errorbar(packet_counts, avg_times, yerr=std_devs, fmt='o', capsize=5, label="Execution Time")
    plt.xlabel("Number of Packets")
    plt.ylabel("Execution Time (s)")
    plt.title("Execution Time vs. Number of Packets")
    plt.legend()
    plt.grid()
    plt.savefig("perf_packets.pdf")

    # Plot Execution Time vs File Size
    plt.figure(figsize=(10, 5))
    plt.errorbar(file_sizes, avg_times, yerr=std_devs, fmt='o', capsize=5, label="Execution Time")
    plt.xlabel("File Size (bytes)")
    plt.ylabel("Execution Time (s)")
    plt.title("Execution Time vs. File Size")
    plt.legend()
    plt.grid()
    plt.savefig("perf_filesize.pdf")

if __name__ == '__main__':
    measures = get_measures()
    generate_graphs(measures)
