import json
from datetime import datetime
from app.database import db
from app.models import Alert
from app.config import Config

class AlertSystem:
    """Alert generation and notification system."""
    
    def __init__(self):
        self.email_enabled = Config.EMAIL_ENABLED
    
    def create_alert(self, message, alert_type, severity, details=None):
        """Create a new alert."""
        try:
            alert = Alert(
                message=message,
                alert_type=alert_type,
                severity=severity,
                details=json.dumps(details) if details else None
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Print to console (for debugging)
            print(f"🚨 ALERT: {severity.upper()} - {message}")
            
            # Send notification if severity is high or critical
            if severity in ['high', 'critical']:
                self.send_notification(alert)
            
            return alert
            
        except Exception as e:
            print(f"Error creating alert: {e}")
            return None
    
    def send_notification(self, alert):
        """Send notification for alert."""
        # Email notification
        if self.email_enabled:
            self.send_email_alert(alert)
        
        # Could add other notification methods:
        # - Slack webhook
        # - SMS
        # - Push notification
    
    def send_email_alert(self, alert):
        """Send email alert."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            # This is a placeholder - configure your email settings
            msg = MIMEMultipart()
            msg['From'] = 'quorra@localhost'
            msg['To'] = 'admin@localhost'
            msg['Subject'] = f"🚨 Quorra Alert: {alert.alert_type} - {alert.severity}"
            
            body = f"""
            <h2>Security Alert from Quorra SIEM</h2>
            <p><strong>Type:</strong> {alert.alert_type}</p>
            <p><strong>Severity:</strong> {alert.severity}</p>
            <p><strong>Message:</strong> {alert.message}</p>
            <p><strong>Time:</strong> {alert.created_at}</p>
            
            <h3>Details:</h3>
            <pre>{json.dumps(json.loads(alert.details), indent=2) if alert.details else 'No details'}</pre>
            
            <hr>
            <p><em>This is an automated alert from Quorra SIEM system.</em></p>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # This would need proper SMTP configuration
            # with smtplib.SMTP('localhost', 25) as server:
            #     server.send_message(msg)
            
            print(f"📧 Email alert prepared for: {alert.alert_type}")
            
        except Exception as e:
            print(f"Error preparing email alert: {e}")
    
    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert."""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.acknowledged = True
                alert.read = True
                db.session.commit()
                return True
        except Exception as e:
            print(f"Error acknowledging alert: {e}")
        
        return False
    
    def mark_as_read(self, alert_id):
        """Mark an alert as read."""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.read = True
                db.session.commit()
                return True
        except Exception as e:
            print(f"Error marking alert as read: {e}")
        
        return False
    
    def get_unread_alerts(self):
        """Get all unread alerts."""
        return Alert.query.filter_by(read=False).order_by(Alert.created_at.desc()).all()
    
    def get_recent_alerts(self, count=10):
        """Get recent alerts."""
        return Alert.query.order_by(Alert.created_at.desc()).limit(count).all()
    
    def cleanup_old_alerts(self):
        """Clean up alerts older than retention period."""
        try:
            cutoff = datetime.utcnow() - timedelta(days=Config.ALERT_RETENTION_DAYS)
            old_alerts = Alert.query.filter(Alert.created_at < cutoff).all()
            
            for alert in old_alerts:
                db.session.delete(alert)
            
            db.session.commit()
            print(f"Cleaned up {len(old_alerts)} old alerts")
            
        except Exception as e:
            print(f"Error cleaning up old alerts: {e}")