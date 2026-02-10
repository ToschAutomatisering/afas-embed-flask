from flask import Flask, request, redirect, render_template, jsonify, session, make_response
import datetime
import logging

# Configure logging
logger = logging.getLogger(__name__)

def get_client_ip():
    """
    Securely extracts the client IP address from the request.
    
    It checks the 'X-Forwarded-For' header first to handle requests behind proxies
    (like Azure Web App). If not present, it falls back to 'remote_addr'.
    
    Returns:
        str: The client's IP address (stripped of port number if present).
    """
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr or ""
    
    if ip and '.' in ip and ':' in ip:
        try:
            ip = ip.split(':')[0]
        except IndexError:
            pass
            
    return ip

def validate_session(embedded_ott_store):
    """
    Validates the user session based on the session cookie and IP address binding.

    Args:
        embedded_ott_store (dict): The in-memory store containing valid sessions.

    Returns:
        tuple: (session_data, error_message)
               - session_data (dict or None): User data if valid.
               - error_message (str or None): Error description if invalid.
    """
    key = request.cookies.get('session_key')
    if not key:
        return None, "Missing session key"
    
    session_data = embedded_ott_store.get(key)
    if not session_data:
        return None, "Invalid or expired session key"
    
    current_ip = get_client_ip()
    stored_ip = session_data.get('client_ip')
    

    if current_ip != stored_ip:
        logger.warning(f"SECURITY ALERT: IP Mismatch for session {key[:8]}... Stored: {stored_ip}, Current: {current_ip}")
        return None, "Session validation failed (IP Mismatch)"
        
    return session_data, None

def cleanup_sessions(embedded_ott_store):
    """
    Removes sessions older than 4 hours to prevent memory leaks and enforce timeouts.

    Args:
        embedded_ott_store (dict): The dictionary store to clean up.
    """
    now = datetime.datetime.now()
    expiration_delta = datetime.timedelta(hours=4)
    # Create list of keys to delete
    keys_to_delete = [
        k for k, v in embedded_ott_store.items() 
        if now - v.get('timestamp', now) > expiration_delta
    ]
    for k in keys_to_delete:
        del embedded_ott_store[k]
    if keys_to_delete:
        logger.info(f"CLEANUP: Removed {len(keys_to_delete)} expired sessions.")