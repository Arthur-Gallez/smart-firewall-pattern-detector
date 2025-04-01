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
device_name = None
patterns = None
suggestions = None
phone_ipv4 = None
phone_ipv6 = None
use_phone = False
device = None

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
        devices = findDevices(cap, number_of_packets, False)
        
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
            'ipv6': device.ipv6,
            'suggested_gateway': True if device.ipv4 == "192.168.1.1" else False
        })
    return render_template('devices.html', devices=devices_list)

@app.route("/getPatterns", methods=['POST'])
def get_patterns():
    global thread, device_name, device
    if thread is not None and thread.is_alive():
        return "Analysis is already running. Please wait.", 400

    selected_device = request.form.get("device")
    mac, ipv4, ipv6, i = selected_device.split("|")
    selected_gateway = request.form.get("gateway")
    mac_gateway, ipv4_gateway, ipv6_gateway, i_gateway = selected_gateway.split("|")
    device_name = request.form.get("device_name-" + str(i))
    device = devices[int(i)-1]
    device.name = device_name

    if not selected_device or not device_name:
        return "Device selection or name missing", 400

    def analyze_patterns():
        global patterns, suggestions
        patterns = analyzer.analyzer(cap, ipv4, ipv6, mac, number_of_packets, device_name, ipv4_gateway, ipv6_gateway, mac_gateway, False, False, False)
        suggestions = find_interactions(patterns)

    thread = Thread(target=analyze_patterns)
    thread.start()

    return render_template('loading_patterns.html')

@app.route("/patterns_status")
def patterns_status():
    global thread
    if thread is None:
        return Response("false")
    return Response(str(not thread.is_alive()))

@app.route("/patterns_result")
def patterns_result():
    global patterns, suggestions, device_name, device
    return render_template('patterns.html', patterns=patterns, device=device_name, suggestions=suggestions, device_info=device.get_yaml())

@app.route("/is_finished")
def is_finished():
    global thread
    if thread is None:
        return Response("false")
    return Response(str(not thread.is_alive()))

def run(phone_ipv4=None, phone_ipv6=None, use_phone=False):
    global PHONE_IPV4, PHONE_IPV6, USE_PHONE
    PHONE_IPV4 = phone_ipv4
    PHONE_IPV6 = phone_ipv6
    USE_PHONE = use_phone
    app.run(debug=False)

if __name__ == "__main__":
    run()