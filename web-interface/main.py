from flask import Flask, render_template, request, Response
import sys, os, asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyzer
from devicesFinder import findDevices
from scapy.all import rdpcap
from threading import Thread
from interactionDetector import *

app = Flask(__name__)

thread = None
devices = None

@app.route("/")
def hello_world():
    return render_template('pcapForm.html')

@app.route("/analyze", methods=['POST'])
def analyze():
    global thread
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    file.save("trace.pcap")
    
    def find_devices():
        global cap, number_of_packets, devices
        
        # Create and set an event loop for the current thread
        # (https://stackoverflow.com/questions/46727787/runtimeerror-there-is-no-current-event-loop-in-thread-in-async-apscheduler)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cap = rdpcap("trace.pcap")
        number_of_packets = len(cap)
        # Find devices
        devices = findDevices(cap, number_of_packets)
        
        # Close the event loop
        loop.close()
        
    thread = Thread(target=find_devices)
    thread.start()
    return render_template('loading.html')

@app.route("/devices")
def devices():
    global devices
    if devices is None or len(devices) == 0:
        return "No devices found"
    
    devices_list = []
    for device in devices:
        devices_list.append({
            'name': device.name,
            'mac': device.mac,
            'ipv4': device.ipv4,
            'ipv6': device.ipv6
        })
    return render_template('devices.html', devices=devices_list)

@app.route("/getPatterns", methods=['POST'])
def get_patterns():
    global cap, number_of_packets
    selected_device = request.form.get("device")
    mac, ipv4, ipv6, i = selected_device.split("|")
    selected_gateway = request.form.get("gateway")
    mac_gateway, ipv4_gateway, ipv6_gateway, i_gateway = selected_gateway.split("|")
    device_name = request.form.get("device_name-" + str(i))
    if not selected_device or not device_name:
        return "Device selection or name missing", 400
    patterns = analyzer.analyzer(cap, ipv4, ipv6, mac, number_of_packets, device_name, ipv4_gateway, ipv6_gateway, mac_gateway)
    suggestions = find_interactions(patterns)
    return render_template('patterns.html', patterns=patterns, device=device_name, suggestions=suggestions)

@app.route("/is_finished")
def is_finished():
    global thread
    if thread is None:
        return Response("false")
    return Response(str(not thread.is_alive()))
    

if __name__ == "__main__":
    app.run(debug=False)