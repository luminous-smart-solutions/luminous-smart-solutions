import os
from flask import Flask, jsonify, request
from flask_login import LoginManager
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth

# 1. Import local modules
from config import Config
from database.redis_db import migrate_json_to_redis
from auth.models import User, load_user
from mqtt.client import run_mqtt_thread
from admin.init_admin import init_admin
from oauth.providers import configure_oauth_providers

# Import enhanced security functions
from security import (
    setup_security_headers, 
    setup_logging, 
    generate_csrf_token,
    setup_session_security,
    init_security_monitoring,
    validate_input,
    check_environment_security,
    validate_csrf_token
)

def create_app():
    """
    Application factory function to create and configure the Flask app.
    """
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # --- Enhanced Security Setup ---
    setup_security_headers(app)  # This now includes the FIXED CSP
    setup_session_security(app)  # Configure secure sessions
    setup_logging(app)
    init_security_monitoring(app)  # Security event logging
    
    # Check environment variables (warn in dev, fail in prod)
    try:
        check_environment_security()
    except ValueError as e:
        if os.getenv('FLASK_ENV') == 'production':
            raise e
        else:
            app.logger.warning(f"Environment check warning (OK in development): {e}")
    
    # --- Initialize Extensions ---
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.signin'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.user_loader(load_user)
    
    mail = Mail(app)
    oauth = OAuth(app)
    
    # --- Add CSRF Token to Template Context ---
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf_token)
    
    # --- Enhanced Global Security Checks ---
    @app.before_request
    def security_checks():
        # Block requests with suspicious User-Agent headers
        user_agent = request.headers.get('User-Agent', '')
        if len(user_agent) > 500:
            app.logger.warning(f"Oversized User-Agent from {request.remote_addr}: {user_agent[:100]}...")
            return jsonify({'error': 'Invalid request header'}), 400
        
        # Allow empty user agent for legitimate requests (some mobile apps)
        if not user_agent and request.endpoint not in ['static', 'health_check']:
            app.logger.warning(f"Missing User-Agent from {request.remote_addr}")
        
        # Validate content length to prevent large, malicious uploads
        max_size = app.config.get('MAX_FILE_UPLOAD_SIZE', 10485760)  # 10MB default
        if request.content_length and request.content_length > max_size:
            return jsonify({'error': 'Request entity too large'}), 413
        
        # Basic input validation for POST requests
        if request.method == 'POST' and request.is_json:
            try:
                data = request.get_json()
                if data and isinstance(data, dict):
                    # Validate each field
                    for key, value in data.items():
                        if isinstance(value, str) and len(value) > 10000:  # 10KB per field
                            return jsonify({'error': 'Input too large'}), 400
            except Exception:
                pass  # Let the route handler deal with malformed JSON
    
    # --- CSRF Validation Helper Route ---
    @app.route('/api/csrf-token', methods=['GET'])
    def get_csrf_token():
        """Provide CSRF token for AJAX requests"""
        return jsonify({'csrf_token': generate_csrf_token()})
    
    # --- Health Check Endpoint ---
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'env': app.config.get('ENV', 'unknown'),
            'security': 'enabled'
        })
    
    # --- Import and Register Blueprints ---
    # We import here to avoid circular dependency issues
    from auth.routes import auth_bp
    from api.routes import api_bp
    from api.ai_routes import ai_api_bp
    from frontend.routes import frontend_bp
    from oauth.routes import oauth_bp
    from analytics.routes import analytics_bp
    from admin.routes import admin_bp
    from admin.api_routes import admin_api_bp
    
    # Register blueprints with enhanced security
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(ai_api_bp, url_prefix='/api')
    app.register_blueprint(frontend_bp)
    app.register_blueprint(oauth_bp)
    app.register_blueprint(analytics_bp, url_prefix='/api')
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_api_bp, url_prefix='/api/admin')
    
    # --- Error Handlers ---
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden'}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500
    
    # --- OAuth Configuration ---
    try:
        configure_oauth_providers(oauth)
        app.logger.info("OAuth providers configured successfully")
    except Exception as e:
        app.logger.error(f"OAuth configuration error: {e}")
        if os.getenv('FLASK_ENV') == 'production':
            raise e
    
    # --- One-time Startup Logic ---
    with app.app_context():
        try:
            migrate_json_to_redis()
            init_admin(app)
            run_mqtt_thread()
            app.logger.info("Application initialization completed successfully")
        except Exception as e:
            app.logger.error(f"Application initialization error: {e}")
            if os.getenv('FLASK_ENV') == 'production':
                raise e
    
    return app

# --- Create App Instance for Gunicorn/Development ---
app = create_app()

# --- Run Application (This part is ONLY for local development) ---
if __name__ == '__main__':
    try:
        # Start MQTT thread if needed
        run_mqtt_thread()
        
        # Get port from environment
        port = int(os.environ.get('PORT', 5000))
        
        # Development server configuration
        debug_mode = app.config.get('DEBUG', False) and os.getenv('FLASK_ENV') != 'production'
        
        app.logger.info(f"Starting application on port {port} (debug={debug_mode})")
        
        # Run the application
        app.run(
            host='0.0.0.0',
            port=port,
            debug=debug_mode
        )
        
    except Exception as e:
        app.logger.error(f"Failed to start application: {e}")
        raise
