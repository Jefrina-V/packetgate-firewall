from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import ipaddress
import re
import secrets
import threading

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__)
CORS(app)

logs_lock = threading.Lock()
capture_state = {"active": False, "thread": None, "stop_event": None, "error": None}

DEFAULT_RULES = [
    {"id": 1, "action": "DENY", "protocol": "TCP", "sourceIP": "any", "sourcePort": "any",
     "destinationIP": "any", "destinationPort": "23", "description": "Block Telnet traffic", "priority": 10},
    {"id": 2, "action": "ALLOW", "protocol": "TCP", "sourceIP": "any", "sourcePort": "any",
     "destinationIP": "192.168.1.10", "destinationPort": "443", "description": "Allow HTTPS to web server", "priority": 20},
    {"id": 3, "action": "ALLOW", "protocol": "UDP", "sourceIP": "any", "sourcePort": "any",
     "destinationIP": "8.8.8.8", "destinationPort": "53", "description": "Allow DNS requests", "priority": 30}
]

rules = [dict(r) for r in DEFAULT_RULES]
logs = []
next_rule_id = 4

# Implicit deny: standard firewall behavior. Traffic that matches no rule is
# denied — this is not user-configurable, it's how a default-deny firewall works.
IMPLICIT_DENY = "DENY"
# Label shown in the "Rule" column of the traffic log when no explicit rule matched.
# Used consistently for both live-captured packets and manually tested packets.
IMPLICIT_DENY_LABEL = "Deny"


# ---- Auth storage (in-memory, matches the rest of this simulator's style) ----
users = {}       # username(lowercase) -> {"username": original-case, "password_hash": str}
tokens = {}      # token -> username(lowercase)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


def reset_data():
    global rules, logs, next_rule_id
    rules = [dict(r) for r in DEFAULT_RULES]
    logs = []
    next_rule_id = 4


def valid_ip(value):
    if value.lower() == "any":
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def ip_matches(rule_value, packet_value):
    if rule_value.lower() == "any":
        return True
    try:
        if "/" in rule_value:
            return ipaddress.ip_address(packet_value) in ipaddress.ip_network(rule_value, strict=False)
    except ValueError:
        return False
    return rule_value == packet_value


def field_matches(rule_value, packet_value):
    return rule_value.lower() == "any" or str(rule_value) == str(packet_value)


def matches(rule, packet):
    protocol_ok = rule["protocol"] == "ANY" or rule["protocol"] == packet["protocol"]
    return (
        protocol_ok
        and ip_matches(rule["sourceIP"], packet["sourceIP"])
        and field_matches(rule["sourcePort"], packet["sourcePort"])
        and ip_matches(rule["destinationIP"], packet["destinationIP"])
        and field_matches(rule["destinationPort"], packet["destinationPort"])
    )


def dashboard_data():
    allowed = sum(1 for x in logs if x["action"] == "ALLOW")
    blocked = sum(1 for x in logs if x["action"] == "DENY")
    return {
        "rules": sorted(rules, key=lambda x: x["priority"]),
        "logs": logs,
        "stats": {"total": len(logs), "allowed": allowed, "blocked": blocked},
        "capture": {"active": capture_state["active"], "available": SCAPY_AVAILABLE, "error": capture_state["error"]}
    }


# ------------------------- Live packet capture -------------------------

MAX_LOGS = 300  # cap in-memory log growth during a long capture session


def _packet_from_scapy(pkt):
    """Turn a sniffed scapy packet into the same shape /api/packets uses."""
    if IP not in pkt:
        return None

    protocol = "OTHER"
    source_port = "any"
    destination_port = "any"

    if TCP in pkt:
        protocol = "TCP"
        source_port = str(pkt[TCP].sport)
        destination_port = str(pkt[TCP].dport)
    elif UDP in pkt:
        protocol = "UDP"
        source_port = str(pkt[UDP].sport)
        destination_port = str(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"
    else:
        return None  # only TCP/UDP/ICMP are meaningful against these rules

    return {
        "protocol": protocol,
        "direction": "Live",
        "sourceIP": pkt[IP].src,
        "sourcePort": source_port,
        "destinationIP": pkt[IP].dst,
        "destinationPort": destination_port
    }


def _handle_sniffed_packet(pkt):
    packet = _packet_from_scapy(pkt)
    if packet is None:
        return

    matched = None
    for rule in sorted(rules, key=lambda x: x["priority"]):
        if matches(rule, packet):
            matched = rule
            break

    action = matched["action"] if matched else IMPLICIT_DENY
    message = f"Matched rule: {matched['description']}" if matched else "No rule matched. Deny applied."
    log = {
        "time": datetime.now().strftime("%I:%M:%S %p"),
        **packet,
        "action": action,
        "message": message,
        "rule": matched["priority"] if matched else IMPLICIT_DENY_LABEL
    }
    with logs_lock:
        logs.insert(0, log)
        del logs[MAX_LOGS:]


def _run_capture(iface, stop_event):
    try:
        sniff(
            iface=iface or None,
            prn=_handle_sniffed_packet,
            store=False,
            stop_filter=lambda p: stop_event.is_set()
        )
    except Exception as e:
        capture_state["error"] = str(e)
    finally:
        capture_state["active"] = False


# ------------------------- Auth helpers -------------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ", 1)[1].strip() if auth_header.startswith("Bearer ") else None
        if not token or token not in tokens:
            return jsonify({"error": "Not authenticated. Please log in."}), 401
        g.username = tokens[token]
        return fn(*args, **kwargs)
    return wrapper


@app.post("/api/auth/signup")
def signup():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not USERNAME_RE.match(username):
        return jsonify({"error": "Username must be 3-20 characters (letters, numbers, underscore)."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400
    if username.lower() in users:
        return jsonify({"error": "That username is already taken."}), 409

    users[username.lower()] = {
        "username": username,
        "password_hash": generate_password_hash(password)
    }
    return jsonify({"message": "Account created. You can now log in."}), 201


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    user = users.get(username.lower())
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid username or password."}), 401

    token = secrets.token_hex(24)
    tokens[token] = username.lower()
    return jsonify({"token": token, "username": user["username"]})


@app.post("/api/auth/logout")
@login_required
def logout():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1].strip()
    tokens.pop(token, None)
    return jsonify({"message": "Logged out."})


@app.get("/api/auth/me")
@login_required
def me():
    user = users.get(g.username)
    return jsonify({"username": user["username"]})


# ------------------------- Capture controls (auth-protected) -------------------------

@app.post("/api/capture/start")
@login_required
def start_capture():
    if not SCAPY_AVAILABLE:
        return jsonify({"error": "scapy is not installed. Run: pip install scapy"}), 500
    if capture_state["active"]:
        return jsonify({"message": "Capture already running."})

    iface = (request.get_json(silent=True) or {}).get("interface")
    stop_event = threading.Event()
    capture_state["error"] = None
    capture_state["stop_event"] = stop_event
    capture_state["active"] = True

    thread = threading.Thread(target=_run_capture, args=(iface, stop_event), daemon=True)
    capture_state["thread"] = thread
    thread.start()

    return jsonify({"message": "Live capture started.", "interface": iface or "default"})


@app.post("/api/capture/stop")
@login_required
def stop_capture():
    if not capture_state["active"] or not capture_state["stop_event"]:
        return jsonify({"message": "Capture is not running."})
    capture_state["stop_event"].set()
    capture_state["active"] = False
    return jsonify({"message": "Live capture stopped."})


@app.get("/api/capture/status")
@login_required
def capture_status():
    return jsonify({
        "active": capture_state["active"],
        "available": SCAPY_AVAILABLE,
        "error": capture_state["error"]
    })


# ------------------------- Firewall API (now auth-protected) -------------------------

@app.get("/api/dashboard")
@login_required
def dashboard():
    return jsonify(dashboard_data())


@app.get("/api/rules")
@login_required
def get_rules():
    return jsonify(sorted(rules, key=lambda x: x["priority"]))


@app.post("/api/rules")
@login_required
def create_rule():
    global next_rule_id
    data = request.get_json(silent=True) or {}
    required = ["action", "protocol", "sourceIP", "sourcePort", "destinationIP", "destinationPort", "description", "priority"]
    if any(k not in data for k in required):
        return jsonify({"error": "All rule fields are required."}), 400
    if data["action"] not in ("ALLOW", "DENY"):
        return jsonify({"error": "Action must be ALLOW or DENY."}), 400
    if data["protocol"] not in ("ANY", "TCP", "UDP", "ICMP"):
        return jsonify({"error": "Invalid protocol."}), 400
    if not valid_ip(str(data["sourceIP"])) or not valid_ip(str(data["destinationIP"])):
        return jsonify({"error": "Invalid source or destination IP/CIDR."}), 400
    rule = {
        "id": next_rule_id,
        "action": data["action"],
        "protocol": data["protocol"],
        "sourceIP": str(data["sourceIP"]),
        "sourcePort": str(data["sourcePort"]),
        "destinationIP": str(data["destinationIP"]),
        "destinationPort": str(data["destinationPort"]),
        "description": str(data["description"]),
        "priority": int(data["priority"])
    }
    next_rule_id += 1
    rules.append(rule)
    return jsonify(rule), 201


@app.delete("/api/rules/<int:rule_id>")
@login_required
def delete_rule(rule_id):
    global rules
    old_len = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) == old_len:
        return jsonify({"error": "Rule not found."}), 404
    return jsonify({"message": "Rule deleted."})


@app.post("/api/packets")
@login_required
def process_packet():
    data = request.get_json(silent=True) or {}
    fields = ["protocol", "direction", "sourceIP", "sourcePort", "destinationIP", "destinationPort"]
    if any(not str(data.get(k, "")).strip() for k in fields):
        return jsonify({"error": "All packet fields are required."}), 400
    if data["protocol"] not in ("TCP", "UDP", "ICMP"):
        return jsonify({"error": "Invalid packet protocol."}), 400

    packet = {k: str(data[k]).strip() for k in fields}
    matched = None
    for rule in sorted(rules, key=lambda x: x["priority"]):
        if matches(rule, packet):
            matched = rule
            break

    action = matched["action"] if matched else IMPLICIT_DENY
    message = f"Matched rule: {matched['description']}" if matched else "No rule matched. Deny applied."
    log = {
        "time": datetime.now().strftime("%I:%M:%S %p"),
        **packet,
        "action": action,
        "message": message,
        "rule": matched["priority"] if matched else IMPLICIT_DENY_LABEL
    }
    logs.insert(0, log)
    return jsonify({"action": action, "message": message, "matchedRule": matched, "log": log})


@app.get("/api/logs")
@login_required
def get_logs():
    return jsonify(logs)


@app.delete("/api/logs")
@login_required
def delete_logs():
    logs.clear()
    return jsonify({"message": "Traffic log cleared."})


@app.post("/api/reset")
@login_required
def reset():
    reset_data()
    return jsonify({"message": "Simulator reset."})


@app.get("/api/health")
def health():
    return jsonify({"status": "online", "service": "PacketGate Firewall API"})


if __name__ == "__main__":
    # use_reloader=False: Flask's auto-reloader spawns a second process, which
    # would start a second background sniffer thread if capture is active.
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)