"""
ATTENTION, THIS SCRIPT IS FOR EVALUATION PURPOSES ONLY AND SHOULD ONLY BE RUN USING LINUX ENVIRONMENT
"""

import sys, os, asyncio
import time
import scapy.all as scapy
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

def get_measures():
    commands_components = [
        ("philips-hue", 2, 3),
        ("smartthings-hub", 1, 2),
        ("tplink-plug", 2, 1),
        ("tuya-motion-wan", 1, 2),
        ("tuya-motion-wlan2.4", 1, 2),
        ("xiaomi-cam-wan", 3, 2),
        ("xiaomi-cam-wlan2.4", 2, 1),
        ("50000pcap", 9, 5)
    ]

    perfs = []
    for comp in commands_components:
        print(f"Running tests on {comp[0]}")
        # Get file size
        file_size = os.path.getsize(f"../traces/{comp[0]}.pcap") / (1024 * 1024)  # Convert to MB
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

    # Plot Execution Time vs Number of Packets (with linear regression)
    plt.figure(figsize=(10, 5))
    plt.errorbar(packet_counts, avg_times, yerr=std_devs, fmt='o', capsize=5, label="Execution Time")

    # Linear regression for first graph
    coefs = np.polyfit(packet_counts, avg_times, deg=1)
    slope, intercept = coefs
    regression_line = np.poly1d(coefs)
    # get p-value using scipy.stats
    a = stats.linregress(packet_counts, avg_times)
    print(f"rvalue {a.rvalue:.4f}")
    print(f"pvalue {a.pvalue:.4f}")

    x_vals = np.linspace(min(packet_counts), max(packet_counts), 100)
    plt.plot(x_vals, regression_line(x_vals), 'r--', label=f"y = {slope:.4f}x + {intercept:.4f}")

    plt.xlabel("Number of Packets")
    plt.ylabel("Execution Time (s)")
    plt.legend()
    plt.grid()
    plt.savefig("perf_packets.pdf")

    # Plot Execution Time vs File Size (unchanged)
    plt.figure(figsize=(10, 5))
    plt.errorbar(file_sizes, avg_times, yerr=std_devs, fmt='o', capsize=5, label="Execution Time")
    plt.xlabel("Input PCAP file Size (mb)")
    plt.ylabel("Execution Time (s)")
    plt.grid()
    plt.savefig("perf_filesize.pdf")

    # Print coefficients to console
    print(f"Linear regression coefficients (Execution Time vs Number of Packets):")
    print(f"  Slope: {slope:.4f}")
    print(f"  Intercept: {intercept:.4f}")

if __name__ == '__main__':
    measures = get_measures()
    generate_graphs(measures)
