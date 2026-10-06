# PacketGate Full-Stack Firewall Simulator

## Project structure

PacketGate_FullStack/
├── backend/
│   ├── app.py
│   └── requirements.txt
└── frontend/
    ├── index.html
    ├── style.css
    └── script.js

## Technologies

Frontend:
- HTML5
- CSS3
- JavaScript
- Fetch API
- Canvas

Backend:
- Python
- Flask
- Flask-CORS
- REST API

## Run the project on Windows

### 1. Open terminal inside backend

cd backend

### 2. Create virtual environment (recommended)

python -m venv venv

### 3. Activate it

venv\Scripts\activate

### 4. Install packages

pip install -r requirements.txt

### 5. Start backend

python app.py

The API will run at:
http://127.0.0.1:5000

### 6. Start frontend

Open the frontend folder and double-click index.html.

For a cleaner development setup, use VS Code Live Server on index.html.

The dashboard connects to:
http://127.0.0.1:5000/api

## Main API endpoints

GET    /api/dashboard
GET    /api/rules
POST   /api/rules
DELETE /api/rules/<id>
POST   /api/packets
GET    /api/logs
DELETE /api/logs
PUT    /api/settings
POST   /api/reset
GET    /api/health

## Demonstration

1. Open Dashboard.
2. Go to Firewall Rules.
3. Add an ALLOW or DENY rule.
4. Go to Packet Simulator.
5. Enter source/destination details.
6. Click Send Packet.
7. Flask checks the rules.
8. The dashboard shows ALLOWED or BLOCKED.
9. The result is stored in Traffic Log.
10. Dashboard statistics update automatically.

Note: This is a simulator. It does not modify the operating system firewall or block real network traffic.
