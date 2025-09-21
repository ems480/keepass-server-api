from flask import Flask, request, jsonify
from pykeepass import PyKeePass
import os
import random

app = Flask(__name__)

# Environment variables (use secure values on Render)
MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "YourMasterKey")
KDBX_FILE = os.environ.get("KDBX_FILE", "J54.kdbx")


def load_keystore():
    """Load the KeePass database or return None if missing."""
    if not os.path.exists(KDBX_FILE):
        return None, "KeePass database not found"
    try:
        kp = PyKeePass(KDBX_FILE, password=MASTER_PASSWORD)
        return kp, None
    except Exception as e:
        return None, f"Failed to load KeePass DB: {str(e)}"


def get_unused_password(kp):
    """Return a random unused password entry or None."""
    entries = kp.entries
    unused = [e for e in entries if not e.notes or "used" not in e.notes.lower()]
    if not unused:
        return None
    return random.choice(unused)


@app.route("/check_password", methods=["POST"])
def check_password():
    """Check if the provided password exists in the KeePass DB."""
    data = request.json
    password = data.get("password")
    if not password:
        return jsonify({"error": "Password missing"}), 400

    kp, error = load_keystore()
    if error:
        return jsonify({"error": error}), 500

    entry = kp.find_entries(password=password, first=True)
    return jsonify({"valid": bool(entry)})


@app.route("/get_password", methods=["GET"])
def get_password():
    """Return a random unused password and mark it as used."""
    kp, error = load_keystore()
    if error:
        return error, 500

    entry = get_unused_password(kp)
    if not entry:
        return "No unused passwords available", 400

    # Mark as used
    entry.notes = (entry.notes or "") + " [used]"
    kp.save()

    # Return only the password string
    return entry.password, 200, {'Content-Type': 'text/plain'}



@app.route("/delete_password", methods=["POST"])
def delete_password():
    """Delete a password from the KeePass DB (for compromised passwords)."""
    data = request.json
    password = data.get("password")
    if not password:
        return jsonify({"error": "Password missing"}), 400

    kp, error = load_keystore()
    if error:
        return jsonify({"error": error}), 500

    entry = kp.find_entries(password=password, first=True)
    if not entry:
        return jsonify({"error": "Password not found"}), 404

    kp.delete_entry(entry, True)
    kp.save()
    return jsonify({"success": True})


if __name__ == "__main__":
    # Use PORT environment variable for Render.com
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
