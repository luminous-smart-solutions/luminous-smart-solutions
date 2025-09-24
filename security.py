"""
Enhanced security middleware and configuration for Flask application
"""
from flask import request, session, current_app, redirect, url_for
import secrets
import logging
import os
from functools import wraps

def setup_security_headers(app):
    """Configure security headers for all responses"""
    
    @app.after_request
    def set_security_headers(response):
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # XSS Protection (legacy but still useful)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # FIXED Content Security Policy - includes all required domains
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' "
            "https://cdnjs.cloudflare.com "
            "https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net "
            "https://code.jquery.com "
            "https://cdn.datatables.net "
            "https://accounts.google.com "
            "https://apis.google.com; "
            "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com "
            "https://cdnjs.cloudflare.com "
            "https://cdn.tailwindcss.com "
            "https://cdn.datatables.net "
            "https://fonts.gstatic.com; "
            "font-src 'self' "
            "https://fonts.gstatic.com "
            "https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https: blob:; "
            "connect-src 'self' "
            "https://api.github.com "
            "https://accounts.google.com "
            "https://www.googleapis.com "
            "https://luminous-repo.onrender.com; "
            "frame-src 'self' https://accounts.google.com; "
            "form-action 'self'; "
            "base-uri 'self';"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # HSTS (only for HTTPS)
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Permissions Policy (formerly Feature Policy)
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), payment=()'
        )
        
        return response

def setup_session_security(app):
    """Configure secure session settings"""
    
    # Session security settings - development friendly
    app.config.update({
        'SESSION_COOKIE_SECURE': os.getenv('FLASK_ENV') == 'production',  # Only HTTPS in production
        'SESSION_COOKIE_HTTPONLY': True,  # Prevent JavaScript access
        'SESSION_COOKIE_SAMESITE': 'Lax',  # CSRF protection
        'PERMANENT_SESSION_LIFETIME': 3600,  # 1 hour session timeout
        'SESSION_COOKIE_NAME': 'luminous_session',  # Custom session name
    })
    
    # Enhanced session security
    @app.before_request
    def enhance_session_security():
        session.permanent = True
        
        # Basic session validation
        if 'session_created' not in session:
            session['session_created'] = True

def generate_csrf_token():
    """Generate a CSRF token for forms"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    session_token = session.get('csrf_token')
    if not session_token or not token:
        return False
    return secrets.compare_digest(session_token, token)

def require_https():
    """Decorator to require HTTPS for sensitive routes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_secure and os.getenv('FLASK_ENV') == 'production':
                return redirect(request.url.replace('http://', 'https://'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_referer():
    """Decorator to validate referer header for additional CSRF protection"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                referer = request.headers.get('Referer', '')
                host = request.headers.get('Host', '')
                
                if referer and host:
                    expected_referer = f"{request.scheme}://{host}/"
                    if not referer.startswith(expected_referer):
                        current_app.logger.warning(f"Invalid referer: {referer} for host: {host}")
                        return "Invalid request", 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(max_requests=60, window=60):
    """Simple rate limiting decorator"""
    from collections import defaultdict
    import time
    
    request_counts = defaultdict(list)
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                          request.environ.get('REMOTE_ADDR', 'unknown'))
            
            now = time.time()
            
            # Clean old requests
            request_counts[client_ip] = [
                req_time for req_time in request_counts[client_ip]
                if now - req_time < window
            ]
            
            # Check rate limit
            if len(request_counts[client_ip]) >= max_requests:
                current_app.logger.warning(f"Rate limit exceeded for {client_ip}")
                return "Rate limit exceeded", 429
            
            # Record this request
            request_counts[client_ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def setup_logging(app):
    """Configure secure logging"""
    
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    
    # Only setup file logging in production
    if not app.debug and os.getenv('FLASK_ENV') == 'production':
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = logging.FileHandler('logs/security.log')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.WARNING)
        
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

def init_security_monitoring(app):
    """Initialize security monitoring - only in production"""
    
    if os.getenv('FLASK_ENV') == 'production':
        @app.before_request
        def log_security_events():
            user_agent = request.headers.get('User-Agent', '')
            
            # Detect suspicious activity
            suspicious_agents = [
                'curl/', 'wget/', 'python-requests/', 'Nikto', 'sqlmap', 
                'nmap', 'masscan', 'ZAP', 'Burp'
            ]
            
            if any(agent in user_agent for agent in suspicious_agents):
                current_app.logger.warning(f"Suspicious user agent: {user_agent} from {request.remote_addr}")
            
            # Log sensitive path access
            sensitive_paths = ['/admin', '/config', '/.env', '/wp-admin', '/phpmyadmin']
            if any(path in request.path for path in sensitive_paths):
                current_app.logger.warning(f"Access to sensitive path: {request.path} from {request.remote_addr}")

def validate_input(data, max_length=1000):
    """Sanitize and validate input data"""
    if not data:
        return ""
    
    # Basic sanitization
    cleaned = str(data).strip()
    
    # Length validation
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    
    # Remove potentially dangerous characters
    import re
    cleaned = re.sub(r'[<>"\'\&]', '', cleaned)
    
    return cleaned

def check_environment_security():
    """Check for security-related environment variables"""
    
    required_vars = [
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET', 
        'GITHUB_CLIENT_ID',
        'GITHUB_CLIENT_SECRET'
    ]
    
    if os.getenv('FLASK_ENV') == 'production':
        required_vars.append('SECRET_KEY')
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        if os.getenv('FLASK_ENV') == 'production':
            raise ValueError(f"Missing required environment variables: {missing_vars}")
        else:
            logging.warning(f"Missing environment variables (OK in development): {missing_vars}")
    
    return len(missing_vars) == 0

# For backward compatibility, alias the old function names
def setup_security_headers_old(app):
    """Backward compatibility wrapper"""
    setup_security_headers(app)
    setup_session_security(app)
    init_security_monitoring(app)
