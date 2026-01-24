from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_cors import CORS
from threading import Thread
from functools import wraps
from datetime import datetime, timedelta
import json, time, websocket

from app.config import Config
from app.database import init_db, db
from app.rules_engine import RulesEngine
from app.log_collector import LogCollector
from app.alert_system import AlertSystem
from app.models import LogEntry, Alert, Attack, IPBlocklist, QuorraUser

# -------------------------------------------------
# Flask App
# -------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = "quorra-secret-key"   # REQUIRED
CORS(app)

with app.app_context():
    init_db(app)

# -------------------------------------------------
# Components
# -------------------------------------------------
rules_engine = RulesEngine()
log_collector = LogCollector()
alert_system = AlertSystem()

monitoring_active = True
ws_connected = False

# -------------------------------------------------
# Auth Decorator
# -------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# -------------------------------------------------
# Auth Routes
# -------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = QuorraUser.query.filter_by(
            username=request.form.get("username"),
            is_active=True
        ).first()

        if user and user.check_password(request.form.get("password")):
            session["user"] = user.username
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------------------------------------
# UI Routes
# -------------------------------------------------
@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session["user"],
        logs=LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10).all(),
        alerts=Alert.query.order_by(Alert.created_at.desc()).limit(10).all(),
        attacks=Attack.query.order_by(Attack.detected_at.desc()).limit(10).all(),
        blocked_ips=IPBlocklist.query.count()
    )

@app.route("/logs")
@login_required
def logs_view():
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).all()
    return render_template("logs.html", logs=logs)

@app.route("/alerts")
@login_required
def alerts_view():
    return render_template("alerts.html", alerts=Alert.query.all())

@app.route("/blocklist")
@login_required
def blocklist_view():
    return render_template("blocklist.html", blocked_ips=IPBlocklist.query.all())

# -------------------------------------------------
# API Routes
# -------------------------------------------------
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify({
        "total_logs": LogEntry.query.count(),
        "total_alerts": Alert.query.count(),
        "total_attacks": Attack.query.count(),
        "blocked_ips": IPBlocklist.query.count(),
        "monitoring_active": monitoring_active,
        "ws_connected": ws_connected
    })

# -------------------------------------------------
# WebSocket Logic
# -------------------------------------------------
def on_ws_message(ws, message):
    try:
        data = json.loads(message)
        with app.app_context():
            log = LogEntry(
                ip_address=data.get("ipAddress", "unknown"),
                attack_type=data.get("attackType"),
                endpoint=data.get("endpoint"),
                payload=data.get("payload"),
                severity=data.get("severity", "medium"),
                raw_data=json.dumps(data)
            )
            db.session.add(log)
            db.session.commit()
    except Exception as e:
        print("WS error:", e)

def connect_websocket():
    global ws_connected
    while monitoring_active:
        try:
            ws = websocket.WebSocketApp(
                Config.BLOCK_FORTRESS_WS_URL,
                on_message=on_ws_message
            )
            ws_connected = True
            ws.run_forever()
        except Exception:
            ws_connected = False
            time.sleep(Config.WS_RECONNECT_DELAY)

Thread(target=connect_websocket, daemon=True).start()

print("✅ Quorra SIEM running")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
