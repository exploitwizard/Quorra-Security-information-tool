import os
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'quorra-siem-secret-key-2024'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{BASE_DIR}/data/quorra.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Authentication
    QUORRA_USERNAME = 'user-quorra'
    QUORRA_PASSWORD = 'quorra@1000'
    
    # Log collection settings
    BLOCK_FORTRESS_URL = os.environ.get('BLOCK_FORTRESS_URL', 'http://localhost:5000')
    BLOCK_FORTRESS_WS_URL = os.environ.get('BLOCK_FORTRESS_WS_URL', 'ws://localhost:5000/api/ws/logs')
    
    # Rule settings
    BRUTEFORCE_THRESHOLD = 10
    BRUTEFORCE_WINDOW = 120  # 2 minutes in seconds
    GEO_VELOCITY_THRESHOLD = 300  # 300 km distance threshold
    MULTI_ATTACK_THRESHOLD = 3  # 3 different attack types in 5 minutes
    
    # Alert settings
    ALERT_RETENTION_DAYS = 30
    EMAIL_ENABLED = False
    
    # Monitoring settings
    MONITORING_INTERVAL = 5  # seconds
    WS_RECONNECT_DELAY = 5  # seconds
    
    # File paths
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
    
    # GeoIP settings
    GEOIP_DB_PATH = os.path.join(DATA_DIR, 'geolite', 'GeoLite2-City.mmdb')