import subprocess
import re
import threading
import time
from flask import Flask, render_template, request, jsonify
from cve_test import cve_data

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
                "version": port_match.group(5).strip(),
                "cve_data": []  # Placeholder untuk data CVE nanti
            })

    if scan_data["status"] != "cancelled":  
        print("\n[!] Nmap completed. Searching CVE from NVD...")

        for result in scan_data["results"]:
            if result["state"] == "open" and result["version"] and result["version"].strip() not in ["", "unknown", "-"]:
                
                # 1. Pecahkan string versi kepada senarai perkataan
                user_input = result["version"].split()
                product = user_input[0] if user_input else ""
                
                # 2. 🔥 AMBIL PERKATAAN KEDUA SAHAJA UNTUK VERSI (Buang sampah Ubuntu/Linux di belakang)
                version = user_input[1] if len(user_input) > 1 else ""
                
                # 3. Logik khas: Kalau Nmap pulangkan format "Apache httpd 2.4.7", kita betulkan kedudukan
                if product.lower() in ["apache", "httpd"] and "httpd" in result["version"].lower():
                    product = "Apache"
                    # Cari elemen dalam list yang ada titik dan bermula dengan nombor (cth: 2.4.7)
                    for item in user_input:
                        if "." in item and item[0].isdigit():
                            version = item
                            break

                print(f"\n[!] Searching CVEs for -> Product: {product} | Version: {version}...")

                # 4. Tembak API NVD guna parameter yang dah suci bersih (Ambil 10 teratas)
                cve_results = cve_data(product, version)[:10]
                result["cve_data"] = cve_results
                
                print(f"[DEBUG APP.PY] Hasil CVE untuk {product} {version}: {cve_results}")

                time.sleep(2)  # Delay wajib untuk hormati NVD rate limit

            else:
                result["cve_data"] = []

        scan_data["progress"] = 100
        scan_data["status"] = "completed"
        print("\n[!] CVE search completed.")

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