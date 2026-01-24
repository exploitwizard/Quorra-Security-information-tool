from datetime import datetime, timedelta
import json
from app.database import db
from app.models import LogEntry, IPBlocklist
import geoip2.database
import geoip2.errors
from math import radians, sin, cos, sqrt, atan2

class RulesEngine:
    """Rules engine for detecting attacks."""
    
    def __init__(self):
        self.brute_force_cache = {}
        self.user_login_cache = {}
        
        # Initialize GeoIP database
        try:
            self.geoip_reader = geoip2.database.Reader('data/geolite/GeoLite2-City.mmdb')
        except:
            self.geoip_reader = None
            print("⚠️  GeoIP database not found. Geo-velocity rule will be disabled.")
    
    def check_rules(self, log_entry):
        """Check all rules against a log entry."""
        results = {
            'triggered': False,
            'rule': None,
            'details': {},
            'severity': 'low',
            'block_ip': False
        }
        
        # Check if IP is already blocked
        is_blocked = IPBlocklist.query.filter_by(ip_address=log_entry.ip_address).first()
        if is_blocked:
            return {
                'triggered': True,
                'rule': 'blocked_ip_detected',
                'details': {
                    'ip': log_entry.ip_address,
                    'reason': is_blocked.reason,
                    'blocked_at': is_blocked.blocked_at.isoformat()
                },
                'severity': 'critical',
                'block_ip': False  # Already blocked
            }
        
        # Rule 1: Brute force detection
        brute_force_result = self.check_brute_force(log_entry)
        if brute_force_result['triggered']:
            results.update(brute_force_result)
            results['block_ip'] = True
        
        # Rule 2: Geo-velocity detection
        geo_result = self.check_geo_velocity(log_entry)
        if geo_result['triggered'] and not results['triggered']:
            results.update(geo_result)
        
        # Rule 3: Admin privilege detection
        admin_result = self.check_admin_privileges(log_entry)
        if admin_result['triggered'] and not results['triggered']:
            results.update(admin_result)
        
        # Rule 4: OS Command Injection
        os_result = self.check_os_command_injection(log_entry)
        if os_result['triggered'] and not results['triggered']:
            results.update(os_result)
            results['block_ip'] = True
        
        # Rule 5: Multiple attack types from same IP
        multi_result = self.check_multiple_attack_types(log_entry)
        if multi_result['triggered'] and not results['triggered']:
            results.update(multi_result)
            results['block_ip'] = True
        
        return results
    
    def check_brute_force(self, log_entry):
        """Rule 1: Multiple failed logins from single IP."""
        # Check for failed login attempts
        if 'login' in log_entry.endpoint.lower() and log_entry.severity in ['low', 'medium']:
            ip = log_entry.ip_address
            
            # Initialize cache for this IP
            if ip not in self.brute_force_cache:
                self.brute_force_cache[ip] = []
            
            # Add current attempt to cache
            self.brute_force_cache[ip].append(datetime.utcnow())
            
            # Clean old attempts (older than 2 minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=2)
            self.brute_force_cache[ip] = [
                t for t in self.brute_force_cache[ip] if t > cutoff
            ]
            
            # Check threshold (10 attempts in 2 minutes)
            if len(self.brute_force_cache[ip]) >= 10:
                return {
                    'triggered': True,
                    'rule': 'bruteforce',
                    'details': {
                        'ip': ip,
                        'failed_attempts': len(self.brute_force_cache[ip]),
                        'time_window': '2 minutes',
                        'endpoint': log_entry.endpoint
                    },
                    'severity': 'high'
                }
        
        return {'triggered': False}
    
    def check_geo_velocity(self, log_entry):
        """Rule 2: Same user logging from different countries too fast."""
        # This requires extracting username from payload
        # For Block Fortress, we need to parse the attack payload
        
        if self.geoip_reader and log_entry.ip_address and log_entry.ip_address != 'unknown':
            try:
                # Get location from IP
                response = self.geoip_reader.city(log_entry.ip_address)
                current_location = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'lat': response.location.latitude,
                    'lon': response.location.longitude
                }
                
                # Try to extract username from payload
                username = None
                try:
                    payload = json.loads(log_entry.payload) if log_entry.payload else {}
                    username = payload.get('username') or payload.get('user')
                except:
                    pass
                
                if username:
                    # Check previous login for this user
                    if username in self.user_login_cache:
                        prev = self.user_login_cache[username]
                        time_diff = (datetime.utcnow() - prev['timestamp']).total_seconds() / 3600  # hours
                        
                        # Calculate distance
                        distance = self.calculate_distance(
                            prev['location']['lat'], prev['location']['lon'],
                            current_location['lat'], current_location['lon']
                        )
                        
                        # Check if physically impossible travel
                        # Assuming max speed of 1000 km/h (commercial airliner)
                        max_speed = 1000  # km/h
                        required_speed = distance / time_diff if time_diff > 0 else float('inf')
                        
                        if required_speed > max_speed and distance > 300:  # 300 km minimum
                            return {
                                'triggered': True,
                                'rule': 'geo_velocity',
                                'details': {
                                    'username': username,
                                    'ip': log_entry.ip_address,
                                    'from_country': prev['location']['country'],
                                    'from_city': prev['location']['city'],
                                    'to_country': current_location['country'],
                                    'to_city': current_location['city'],
                                    'distance_km': round(distance, 2),
                                    'time_hours': round(time_diff, 2),
                                    'speed_kmh': round(required_speed, 2)
                                },
                                'severity': 'medium'
                            }
                    
                    # Update cache
                    self.user_login_cache[username] = {
                        'timestamp': datetime.utcnow(),
                        'location': current_location,
                        'ip': log_entry.ip_address
                    }
                
            except (geoip2.errors.AddressNotFoundError, AttributeError):
                pass
        
        return {'triggered': False}
    
    def check_admin_privileges(self, log_entry):
        """Rule 3: Admin privilege escalation attempts."""
        # Check for admin paths or parameters
        admin_paths = ['/admin', '/dashboard', '/manage', '/control', 'admin']
        admin_keywords = ['admin', 'sudo', 'root', 'privilege', 'elevate', 'superuser']
        
        # Check endpoint
        endpoint_lower = log_entry.endpoint.lower()
        
        # Check for admin paths
        for admin_path in admin_paths:
            if admin_path in endpoint_lower:
                return {
                    'triggered': True,
                    'rule': 'admin_privilege_attempt',
                    'details': {
                        'ip': log_entry.ip_address,
                        'endpoint': log_entry.endpoint,
                        'matched_pattern': admin_path,
                        'reason': 'Admin path accessed'
                    },
                    'severity': 'high'
                }
        
        # Check payload for admin keywords
        if log_entry.payload:
            payload_lower = log_entry.payload.lower()
            for keyword in admin_keywords:
                if keyword in payload_lower:
                    return {
                        'triggered': True,
                        'rule': 'admin_privilege_attempt',
                        'details': {
                            'ip': log_entry.ip_address,
                            'endpoint': log_entry.endpoint,
                            'matched_keyword': keyword,
                            'reason': 'Admin keyword detected in payload'
                        },
                        'severity': 'high'
                    }
        
        # Check attack type
        if 'admin' in log_entry.attack_type.lower():
            return {
                'triggered': True,
                'rule': 'admin_privilege_attempt',
                'details': {
                    'ip': log_entry.ip_address,
                    'attack_type': log_entry.attack_type,
                    'reason': 'Admin-related attack detected'
                },
                'severity': 'high'
            }
        
        return {'triggered': False}
    
    def check_os_command_injection(self, log_entry):
        """Detect OS command injection attempts."""
        # Common command injection patterns
        command_injection_patterns = [
            ';', '|', '||', '&', '&&', '`', '$(',
            'rm ', 'del ', 'format ', 'shutdown',
            'cat /etc/passwd', '/bin/bash',
            'wget', 'curl', 'nc ', 'netcat',
            'python ', 'perl ', 'ruby ', 'php ',
            'system(', 'exec(', 'popen(',
            'ls ', 'dir ', 'cd ', 'pwd'
        ]
        
        # Check payload
        if log_entry.payload:
            payload_lower = log_entry.payload.lower()
            
            for pattern in command_injection_patterns:
                if pattern in payload_lower:
                    return {
                        'triggered': True,
                        'rule': 'os_command_injection',
                        'details': {
                            'ip': log_entry.ip_address,
                            'pattern': pattern,
                            'payload_preview': log_entry.payload[:200],
                            'endpoint': log_entry.endpoint
                        },
                        'severity': 'critical'
                    }
        
        # Check attack type
        if 'command' in log_entry.attack_type.lower() or 'injection' in log_entry.attack_type.lower():
            return {
                'triggered': True,
                'rule': 'os_command_injection',
                'details': {
                    'ip': log_entry.ip_address,
                    'attack_type': log_entry.attack_type,
                    'reason': 'Command injection attack detected'
                },
                'severity': 'critical'
            }
        
        return {'triggered': False}
    
    def check_multiple_attack_types(self, log_entry):
        """Check for multiple attack types from same IP."""
        ip = log_entry.ip_address
        
        # Get recent attacks from this IP
        time_threshold = datetime.utcnow() - timedelta(minutes=5)
        
        recent_attacks = Attack.query.filter(
            Attack.ip_address == ip,
            Attack.detected_at >= time_threshold
        ).all()
        
        # Count unique attack types
        attack_types = set()
        for attack in recent_attacks:
            attack_types.add(attack.attack_type)
        
        # Add current attack type
        attack_types.add(log_entry.attack_type)
        
        if len(attack_types) >= 3:  # 3 different attack types in 5 minutes
            return {
                'triggered': True,
                'rule': 'multiple_attack_types',
                'details': {
                    'ip': ip,
                    'attack_types': list(attack_types),
                    'time_window': '5 minutes',
                    'total_attacks': len(recent_attacks) + 1
                },
                'severity': 'high'
            }
        
        return {'triggered': False}
    
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two coordinates in kilometers."""
        R = 6371  # Earth's radius in kilometers
        
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c