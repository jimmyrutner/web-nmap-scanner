import subprocess
import re
import threading
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

#tempat simpan data hasil scan
scan_data = {
    "target": "",
    "progress": 0,
    "results": [],
    "status": "idle"
}

current_process = None

def nmap_worker(target, profile, custom_ports, stealth, vuln):
    global scan_data, current_process
    scan_data["status"] = "running"
    scan_data['progress'] = 0
    scan_data['results'] = []  

    #command nmap dalam cmd
    cmd = ["nmap", "-v", "-sV", "--stats-every", "1s"]

    #logik scan untuk option tambahan
    if profile == "quick":
        cmd.append("-F") #ni untuk fast scan (100 ports)
    elif profile == "intense":
        cmd.append("-A") #ni untuk intense scan (ada OS detection, script scan, traceroute)
    elif profile == "custom" and custom_ports:
        cmd.extend(["-p", custom_ports]) #ni untuk custom port scan
    else:
        cmd.append("-sT") #default scan

    #logik untuk stealth scan
    if stealth:
        cmd.extend(["-Pn", "-f"]) #ni untuk stealth scan (TCP SYN scan)

    #logik untuk vuln scan
    if vuln:
        cmd.extend(["--script", "vuln"]) #ni untuk vulnerability scan (gunakan nmap scripts untuk cari vulnerabilities)

    #nak masukkan ip target kat hujung
    cmd.append(target)

    print(f"\n[!] Command yang dok jalan: {' '.join(cmd)}\n")
    current_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    for line in current_process.stdout:
        print(line.strip())  # Log output ke console

        #cari pattern progress
        match = re.search(r"(\d+\.\d+)%", line)
        if match:
            scan_data["progress"] = float(match.group(1))
            
        #cari hasil port
        port_match = re.search(r"^(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
        if port_match:
            scan_data["results"].append({
                "port": f"{port_match.group(1)}/{port_match.group(2)}",
                "state": port_match.group(3),
                "service": port_match.group(4),
                "version": port_match.group(5).strip()
            })

    if scan_data["status"] != "cancelled":  # Kalau scan tak dihentikan secara manual
        scan_data["progress"] = 100
        scan_data["status"] = "completed"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_data
    target = request.form.get('target')

    #ni untuk data tambahan yang kita hantar dari frontend
    profile = request.form.get('scanProfile')
    custom_ports = request.form.get('customPorts')
    stealth = request.form.get('stealthMode') == 'true'
    vuln = request.form.get('vulnMode') == 'true'

    scan_data["target"] = target

    #jalankan worker dalam thread supaya tak block Flask
    thread = threading.Thread(target=nmap_worker, args=(target, profile, custom_ports, stealth, vuln))
    thread.start()

    return jsonify({"status": "started"})

@app.route('/stop', methods=['POST'])
def stop_scan():
    global current_process, scan_data

    #kalau proses dok jalan, kita terminate dia
    if current_process and current_process.poll() is None:
        current_process.terminate()
        scan_data["status"] = "stopped"
        scan_data["progress"] = 0
        return jsonify({"status": "stopped"})
    
    return jsonify({"status": "already_stopped"})
    
@app.route('/progress')
def get_progress():
    return jsonify(scan_data)
            
if __name__ == '__main__':
    app.run(debug=True)