import os
from flask import Flask, request, jsonify

app = Flask(__name__)
SERVER_PRIVKEY_PATH = 'server_private'
SERVER_PUBKEY_PATH = 'server_pubkey'
WG_INTERFACE = 'wg0'
API_KEY = 'controller-api-key'

def add_peer(pubkey, client_ip):
    os.system(f"wg set {WG_INTERFACE} peer {pubkey} allowed-ips {client_ip}/32")
    return True

@app.route('/add_peer', methods=['POST'])
def api_add_peer():
    if request.headers.get('Authorization') != API_KEY:
        return jsonify({'msg': 'Unauthorized'}), 403
    data = request.json
    pubkey = data['pubkey']
    client_ip = data['client_ip']
    add_peer(pubkey, client_ip)
    return jsonify({'msg': 'Peer added'}), 200

if __name__ == '__main__':
    if not os.path.exists(SERVER_PUBKEY_PATH):
        os.system(f"wg genkey | tee {SERVER_PRIVKEY_PATH} | wg pubkey > {SERVER_PUBKEY_PATH}")
    with open(SERVER_PUBKEY_PATH) as f:
        print("Server public key:", f.read())
    app.run(port=5001)
