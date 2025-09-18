import requests
import pyotp
import subprocess
import os

CONTROLLER_URL = 'http://127.0.0.1:5000'
USERNAME = input("Username: ")
PASSWORD = input("Password: ")
TOTP_SEED = None

def main():
    r = requests.post(f"{CONTROLLER_URL}/auth", json={'username': USERNAME, 'password': PASSWORD})
    print(r.json())
    if "totp_seed" in r.json():
        TOTP_SEED = r.json()["totp_seed"]
    else:
        TOTP_SEED = input("Enter your TOTP seed (from QR, or ask admin): ")
    totp_code = pyotp.TOTP(TOTP_SEED).now()
    r = requests.post(f"{CONTROLLER_URL}/totp", json={'username': USERNAME, 'totp': totp_code})
    jwt_token = r.json()['jwt']
    os.system("wg genkey | tee client_private | wg pubkey > client_pubkey")
    with open('client_private') as f:
        privkey = f.read().strip()
    with open('client_pubkey') as f:
        pubkey = f.read().strip()
    r = requests.post(f"{CONTROLLER_URL}/get_wg_config", json={'jwt': jwt_token, 'pubkey': pubkey})
    resp = r.json()
    wg_config = resp['wg_config'].replace("{YOUR_CLIENT_PRIVATE_KEY}", privkey)
    with open('wg0.conf', 'w') as f:
        f.write(wg_config)
    print("Saved wg0.conf, bringing up tunnel...")
    subprocess.run(['wg-quick', 'up', 'wg0.conf'])

if __name__ == '__main__':
    main()
