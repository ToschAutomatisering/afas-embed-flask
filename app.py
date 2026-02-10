import os
import hashlib
import datetime
import logging
from flask import Flask, request, redirect, render_template, jsonify, session, make_response
import utils
from AfasService import AfasService

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.secret_key = os.urandom(24)

app.config.update(
    SESSION_COOKIE_SECURE=True,       
    SESSION_COOKIE_HTTPONLY=True,      
    SESSION_COOKIE_SAMESITE='None',   
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=4)
)

embedded_ott_store = {} # In-memory store for session data, preferably replace with persistent store in production

@app.after_request
def add_security_headers(response):
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self' https://*.afasinsite.nl https://*.afas.nl;" 
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response


@app.route('/')
def index():
    """
    Entry point for the AFAS iframe.
    
    This route handles the initial handshake from AFAS InSite. It validates the 
    incoming parameters, exchanges the authorization code for an AFAS token, 
    and establishes a secure session cookie before redirecting to the main portal.

    Returns:
        Response: A redirect to /portal on success, or an error message with 401 status.
    """
    utils.cleanup_sessions(embedded_ott_store)

    model = {
        'dataurl': request.args.get('dataurl'),
        'tokenurl': request.args.get('tokenurl'),
        'code': request.args.get('code'),
        'publickey': request.args.get('publickey'),
        'sessionid': request.args.get('sessionid'),
        'referrer': request.args.get('referrer')
    }
    
    if not model['tokenurl'] or not model['code']:
        logger.warning("Missing tokenurl or code. Blocking Guest Access.")
        return "Unauthorized: Access denied. Valid AFAS context required.", 401

    try:
        afas_token = AfasService.get_token(
            model['dataurl'], 
            model['tokenurl'], 
            model['code'], 
            model['publickey']
        )
        
        if not afas_token:
            logger.error("Failed to retrieve AFAS token.")
            return "No access token received from AFAS", 401

        raw_key = os.urandom(32).hex()
        secure_key = hashlib.sha256(raw_key.encode()).hexdigest()
        
        embedded_ott_store[secure_key] = {
            'userId': afas_token.get('userId'),
            'contactId': afas_token.get('contactId'),
            'organizationCode': afas_token.get('organizationCode'),
            'client_ip': utils.get_client_ip(),
            'timestamp': datetime.datetime.now()
        }
        
        response = make_response(redirect("/portal"))
        response.set_cookie('session_key', secure_key, httponly=True, secure=True, samesite='None')
        return response

    except Exception as e:
        logger.exception("An unexpected error occurred during authentication.")
        return "Internal Server Error", 500


@app.route('/portal')
def portal():
    """
    Renders the main portal for the embedded application.

    Validates the session cookie. If valid, renders the index.html template
    with the user's ID. If invalid, returns a 401 Unauthorized response.

    Returns:
        Response: The rendered HTML template or an error message.
    """
    user_data, error = utils.validate_session(embedded_ott_store)
    if not user_data:
        logger.warning(f"Unauthorized access attempt to /portal: {error}")
        return f"Unauthorized: {error}", 401
    
    return render_template('index.html', userId=user_data.get('userId'))


@app.route('/api/auth/exchange')
def exchange_token():
    """
    API endpoint for frontend clients to retrieve current user session data.

    This endpoint is typically called by the frontend script to verify identity
    or obtain tokens for further API calls.

    Returns:
        JSON response containing user ID and other allowed claims.
    """
    user_data, error = utils.validate_session(embedded_ott_store)
    if not user_data:
        logger.warning(f"Unauthorized access attempt to /api/auth/exchange: {error}")
        return jsonify({"error": error}), 401
    
    if not user_data.get('contactId'):
        logger.error("User data found but contactId is missing.")
        return jsonify({"error": "contactId missing"}), 400
    
    """

    Add here any logic for verifying that the user-id has access to the requested resources. 
    This can be done with additional checks against your own AFAS get-Connectors or other authorization mechanisms.

    """
    
    try:    
        response_data = {
           "userId": user_data.get('userId'),
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.exception("Exception during token exchange")
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == '__main__':
    app.run()
