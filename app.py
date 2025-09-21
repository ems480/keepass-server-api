from flask import Flask, request, jsonify
from pykeepass import PyKeePass
import os
import random

app = Flask(__name__)

MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "YourMasterKey")
KDBX_FILE = os.environ.get("KDBX_FILE", "J54.kdbx")

def get_unused_password(kp):
    """Return a random password from the KeePass file that has not been used."""
    entries = kp.entries
    unused = [e for e in entries if not e.notes or "used" not in e.notes.lower()]
    if not unused:
        return None
    selected = random.choice(unused)
    return selected

@app.route("/check_password", methods=["POST"])
def check_password():
    data = request.json
    password = data.get("password")
    if not password:
        return jsonify({"error": "Password missing"}), 400
    try:
        kp = PyKeePass(KDBX_FILE, password=MASTER_PASSWORD)
        entry = kp.find_entries(password=password, first=True)
        return jsonify({"valid": bool(entry)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_password", methods=["GET"])
def get_password():
    """Randomly select an unused password and mark it as used."""
    try:
        kp = PyKeePass(KDBX_FILE, password=MASTER_PASSWORD)
        entry = get_unused_password(kp)
        if not entry:
            return jsonify({"error": "No unused passwords available"}), 400
        # Mark as used
        entry.notes = (entry.notes or "") + " [used]"
        kp.save()
        return jsonify({"password": entry.password})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_password", methods=["POST"])
def delete_password():
    """Delete a password from the KeePass file."""
    data = request.json
    password = data.get("password")
    if not password:
        return jsonify({"error": "Password missing"}), 400
    try:
        kp = PyKeePass(KDBX_FILE, password=MASTER_PASSWORD)
        entry = kp.find_entries(password=password, first=True)
        if not entry:
            return jsonify({"error": "Password not found"}), 404
        kp.delete_entry(entry, True)
        kp.save()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
