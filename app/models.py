from app.database import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


# =====================================================
# User Model (SINGLE SOURCE OF TRUTH)
# =====================================================
class QuorraUser(db.Model):
    __tablename__ = "quorra_user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # 🔐 Password helpers
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<QuorraUser {self.username}>"


# =====================================================
# Log Entry Model
# =====================================================
class LogEntry(db.Model):
    __tablename__ = "log_entry"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(100))
    endpoint = db.Column(db.String(500))
    payload = db.Column(db.Text)
    user_agent = db.Column(db.Text)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat()
        }


# =====================================================
# Alert Model
# =====================================================
class Alert(db.Model):
    __tablename__ = "alert"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    alert_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    details = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)  # ✅ renamed

    def to_dict(self):
        return {
            "id": self.id,
            "message": self.message,
            "severity": self.severity,
            "created_at": self.created_at.isoformat(),
            "acknowledged": self.acknowledged,
            "is_read": self.is_read
        }


# =====================================================
# Attack Model
# =====================================================
class Attack(db.Model):
    __tablename__ = "attack"

    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text)
    severity = db.Column(db.String(20))
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def get_statistics():
        from datetime import timedelta

        last_24h = datetime.utcnow() - timedelta(hours=24)

        by_type = dict(
            db.session.query(
                Attack.attack_type, db.func.count(Attack.id)
            ).group_by(Attack.attack_type).all()
        )

        return {
            "total": Attack.query.count(),
            "last_24h": Attack.query.filter(
                Attack.detected_at >= last_24h
            ).count(),
            "by_type": by_type
        }


# =====================================================
# IP Blocklist Model
# =====================================================
class IPBlocklist(db.Model):
    __tablename__ = "ip_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.Text)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.String(100))

    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat()
        }
