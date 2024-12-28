from flask import Flask, render_template, request, Response
import sys, os, asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyzer
from devicesFinder import findDevices
import pyshark
from threading import Thread

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
        
        cap = pyshark.FileCapture("trace.pcap")
        cap.load_packets()
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
    if not selected_device:
        return "No device selected", 400
    # Parse the selected device's data
    name, mac, ipv4, ipv6 = selected_device.split("|")
    patterns = analyzer.analyzer(cap, ipv4, ipv6, mac, number_of_packets, name)
    returnstr = "results for device: " + name + "<br><pre>" + str(patterns) + "</pre>"
    return render_template('patterns.html', patterns=patterns, device=name)

@app.route("/is_finished")
def is_finished():
    global thread
    if thread is None:
        return Response("false")
    return Response(str(not thread.is_alive()))
    

if __name__ == "__main__":
    app.run(debug=False)