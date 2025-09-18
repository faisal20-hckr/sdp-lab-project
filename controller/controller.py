import json
import os
import bcrypt
import pyotp
import jwt
import datetime
import requests
from flask import Flask, request, jsonify, send_file
from io import BytesIO
import qrcode

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecret_jwt_key'
CONTROLLER_API_KEY = 'controller-api-key'
USERS_PATH = 'users.json'
POLICIES_PATH = 'policies.json'

def load_users():
    with open(USERS_PATH) as f:
        return json.load(f)

def save_users(users):
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=2)

def load_policies():
    with open(POLICIES_PATH) as f:
        return json.load(f)

def save_policies(policies):
    with open(POLICIES_PATH, "w") as f:
        json.dump(policies, f, indent=2)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_jwt(username, role):
    payload = {
        'user': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# --- Registration ---
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    admin_token = data.get('admin_token', None)
    users = load_users()
    if username in users:
        return jsonify({'msg': 'Username already exists'}), 409
    if role == "admin":
        if admin_token != "letmeinadmin":
            return jsonify({'msg': 'Admin token required to create admin user'}), 403
    totp_seed = pyotp.random_base32()
    users[username] = {
        "password": hash_password(password),
        "totp_seed": totp_seed,
        "role": role
    }
    save_users(users)
    totp_uri = pyotp.totp.TOTP(totp_seed).provisioning_uri(name=username, issuer_name="SDP Project")
    img = qrcode.make(totp_uri)
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    import base64
    qr_b64 = base64.b64encode(buf.read()).decode()
    return jsonify({
        'msg': 'User registered',
        'totp_seed': totp_seed,
        'totp_uri': totp_uri,
        'qr_code_base64': qr_b64
    }), 201

# --- Authentication ---
@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    users = load_users()
    user = users.get(username)
    if not user or not check_password(password, user['password']):
        return jsonify({'msg': 'Invalid credentials'}), 401
    return jsonify({'msg': 'Enter TOTP code', 'hint': 'Scan QR in Google Authenticator if first login'}), 200

@app.route('/totp', methods=['POST'])
def totp():
    data = request.json
    username = data.get('username')
    totp_code = data.get('totp')
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'msg': 'User not found'}), 401
    totp = pyotp.TOTP(user['totp_seed'])
    if not totp.verify(totp_code):
        return jsonify({'msg': 'Invalid TOTP'}), 401
    token = generate_jwt(username, user.get('role', 'user'))
    return jsonify({'jwt': token, 'role': user.get('role', 'user')}), 200

# --- Get WG Config ---
@app.route('/get_wg_config', methods=['POST'])
def get_wg_config():
    data = request.json
    token = data.get('jwt')
    client_pubkey = data.get('pubkey')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['user']
    except Exception:
        return jsonify({'msg': 'Invalid JWT'}), 401
    policies = load_policies()
    client_ip = policies.get(username, ["10.0.2.99"])[0]
    server_endpoint = "127.0.0.1:51820"
    with open('../server/server_pubkey') as f:
        server_pubkey = f.read().strip()
    resp = requests.post(
        "http://127.0.0.1:5001/add_peer",
        headers={'Authorization': CONTROLLER_API_KEY},
        json={
            'pubkey': client_pubkey,
            'client_ip': client_ip
        }
    )
    if resp.status_code != 200:
        return jsonify({'msg': 'Server registration failed'}), 500
    WG_TEMPLATE = """
[Interface]
PrivateKey = {private_key}
Address = {client_ip}/32
DNS = 8.8.8.8

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    wg_config = WG_TEMPLATE.format(
        private_key="{YOUR_CLIENT_PRIVATE_KEY}",
        client_ip=client_ip,
        server_pubkey=server_pubkey,
        server_endpoint=server_endpoint
    )
    return jsonify({'wg_config': wg_config, 'client_ip': client_ip}), 200

# --- Admin: List Users ---
@app.route('/list_users', methods=['POST'])
def list_users():
    data = request.json
    token = data.get('jwt')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('role') != 'admin':
            return jsonify({'msg': 'Not authorized'}), 403
    except Exception:
        return jsonify({'msg': 'Invalid JWT'}), 401
    users = load_users()
    users_slim = {u: {'role': users[u]['role']} for u in users}
    return jsonify({'users': users_slim})

# --- Admin: View/Edit Policies ---
@app.route('/get_policies', methods=['POST'])
def get_policies():
    data = request.json
    token = data.get('jwt')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('role') != 'admin':
            return jsonify({'msg': 'Not authorized'}), 403
    except Exception:
        return jsonify({'msg': 'Invalid JWT'}), 401
    policies = load_policies()
    return jsonify({'policies': policies})

@app.route('/edit_policy', methods=['POST'])
def edit_policy():
    data = request.json
    token = data.get('jwt')
    username = data.get('username')
    ips = data.get('ips')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('role') != 'admin':
            return jsonify({'msg': 'Not authorized'}), 403
    except Exception:
        return jsonify({'msg': 'Invalid JWT'}), 401
    policies = load_policies()
    policies[username] = ips
    save_policies(policies)
    return jsonify({'msg': 'Policy updated', 'policies': policies})

@app.route('/delete_policy', methods=['POST'])
def delete_policy():
    data = request.json
    token = data.get('jwt')
    username = data.get('username')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('role') != 'admin':
            return jsonify({'msg': 'Not authorized'}), 403
    except Exception:
        return jsonify({'msg': 'Invalid JWT'}), 401
    policies = load_policies()
    if username in policies:
        del policies[username]
        save_policies(policies)
        return jsonify({'msg': 'Policy deleted'}), 200
    return jsonify({'msg': 'Policy not found'}), 404

if __name__ == '__main__':
    os.environ['FLASK_ENV'] = 'development'
    app.run(port=5000)
