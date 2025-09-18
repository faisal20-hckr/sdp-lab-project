# Software Defined Perimeter (SDP) – Enhanced Demo

**Features:**  
- User registration (with TOTP QR for Google Authenticator)  
- Passwords stored securely (bcrypt)  
- Admin/user roles  
- Admin can manage policies (which user can access which resource)  
- Multiple resource IPs per user  
- JWT-based authentication  
- All endpoints documented

---

## Quick Start

### 1. Server

```bash
cd server
wg genkey | tee server_private | wg pubkey > server_pubkey
sudo wg-quick up wg0.conf
pip install flask
python3 server_api.py
```

### 2. Controller

```bash
cd controller
pip install flask pyotp pyjwt requests bcrypt qrcode
python3 controller.py
```

### 3. Client

```bash
cd client
pip install requests pyotp
python3 client_agent.py
```

---

## User Registration

POST to `/register`  
- JSON: `{ "username": "NAME", "password": "PASS" }`
- Returns TOTP QR code (base64), seed, and provisioning URI  
- Scan QR with Google Authenticator

To register admin:  
- Add `"role": "admin", "admin_token": "letmeinadmin"` in JSON

---

## Login Flow

1. POST `/auth` (username, password)
2. POST `/totp` (username, TOTP from app)
3. Use returned JWT for protected endpoints

---

## Policy Management (Admin Only)

- `/list_users` (POST with JWT): list users & roles
- `/get_policies` (POST with JWT): view all policies
- `/edit_policy` (POST with JWT, username, ips): add/edit allowed IPs for user
- `/delete_policy` (POST with JWT, username): remove user's policy

---

## Sample Users

```json
{
  "test": {"password": "...", "totp_seed": "JBSWY3DPEHPK3PXP", "role": "admin"},
  "user2": {"password": "...", "totp_seed": "JBSWY3DPEHPK3PX2", "role": "user"}
}
```

---

## Sample Policies

```json
{
  "test": ["10.0.2.100", "10.0.2.110"],
  "user2": ["10.0.2.101", "10.0.2.111"]
}
```

---

## Notes

- For real-world use: add HTTPS, persistent DB, more robust firewall rules.
- For registration: admin can create accounts and send QR code to users.
- Each user can have access to multiple resource IPs.

---

## For Help

Raise a GitHub issue or ask your professor!
