import requests
import json
import os
import logging
from urllib.parse import urlparse

# Configure logging for this module
logger = logging.getLogger(__name__)

class AfasService:
    """
    Service class for handling AFAS InSite authentication and token exchange.
    """
    
    @staticmethod
    def get_token(data_url, token_url, code, public_key):
        """
        Validates the AFAS session by exchanging the authorization code for a User Token.

        This method mimics the logic of Afas.GetTokenAsync(model). It sends a secure POST
        request to the AFAS token endpoint with the provided code and the application secret.

        Args:
            data_url (str): The base URL for data (not currently used in logic but part of model).
            token_url (str): The specific URL to exchange the code for a token.
            code (str): The authorization code received from the initial handshake.
            public_key (str): The public key received from the initial handshake.

        Returns:
            dict: A dictionary containing the AFAS token data (userId, contactId, etc.) if successful.
            None: If authentication fails, validation errors occur, or exceptions are raised.
        """
        try:
            headers = {
                'Content-Type': 'application/json'
            }
            
            afas_secret = os.environ.get('AFAS_SECRET', "") # Set an environment variable or use a secure vault for this
            
            if not afas_secret:
                 logger.critical("AFAS_SECRET environment variable is missing. Cannot authenticate with AFAS.")
                 return None
            
            payload = {
                "secret": afas_secret,
                "code": code
            }
            
            # Helper to validate URL hostname to prevent SSRF or redirection attacks
            parsed_url = urlparse(token_url)
            hostname = parsed_url.hostname or ""
            
            # Allow afasinsite.nl, afas.nl, and localhost (for dev/testing)
            if not (hostname.endswith(".afasinsite.nl") or hostname.endswith(".afas.nl") or hostname == "localhost"):
                 logger.error(f"Security Alert: Invalid token URL hostname detected: {hostname}")
                 return None
            
            response = requests.post(token_url, json=payload, headers=headers)
            
            if response.status_code == 200:
                response_string = response.text
                
                # Check for specific AFAS text-based error responses that aren't HTTP errors
                if not response_string or response_string.startswith("Fout"):
                     logger.error(f"AFAS returned an API Error: {response_string}")
                     return None
                
                try:
                    token_data = response.json()
                    return token_data
                except json.JSONDecodeError:
                    logger.error(f"AFAS response was not valid JSON. Response start: {response_string[:50]}...")
                    return None
            else:
                logger.error(f"AFAS HTTP Error: Status {response.status_code} - Body: {response.text}")
                return None
                
        except requests.RequestException as re:
            logger.error(f"Network error during AFAS communication: {re}")
            return None
        except Exception as e:
            logger.exception(f"Unexpected exception in AfasService.get_token: {e}")
            return None
            
    @staticmethod
    def get_email_from_id(contact_id):
        """
        Placeholder method to retrieve email from a contact ID.
        Implement actual AFAS GetConnector logic here if needed.
        """
        return "email@placeholder.com"
