from flask import request, Flask, jsonify
import ldap3
import os
import logging
import ssl
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import functools

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Securely retrieve LDAP configuration from environment variables
LDAP_SERVER = os.environ.get("LDAP_SERVER", "localhost")  # Default to localhost, but strongly encourage setting the env var
LDAP_PORT = int(os.environ.get("LDAP_PORT", "389"))  # Default to 389, but strongly encourage setting the env var
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", None)
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", None)
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", None)
LDAP_USE_SSL = os.environ.get("LDAP_USE_SSL", "False").lower() == "true"
LDAP_CA_BUNDLE = os.environ.get("LDAP_CA_BUNDLE", None)

# Error handling for missing configuration
if not LDAP_BASE_DN:
    raise ValueError("LDAP_BASE_DN environment variable must be set.")

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Retry decorator with exponential backoff
def retry(max_retries=3, initial_delay=1, backoff_multiplier=2):
    """Retry decorator with exponential backoff."""
    def decorator_retry(func):
        @functools.wraps(func)
        def wrapper_retry(*args, **kwargs):
            retries = 0
            delay = initial_delay
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Attempt {retries + 1} failed: {e}. Retrying in {delay} seconds...")
                    import time
                    time.sleep(delay)
                    delay *= backoff_multiplier
                    retries += 1
            logger.error(f"Function {func.__name__} failed after {max_retries} retries.")
            raise  # Re-raise the last exception
        return wrapper_retry
    return decorator_retry


@retry(max_retries=3, initial_delay=1, backoff_multiplier=2)
def ldap_search(username, dc):
    """
    Searches for a user in LDAP.

    Args:
        username: The username to search for.
        dc: The domain component.

    Returns:
        A dictionary containing the user's attributes if found, otherwise None.
    """
    try:
        # Configure SSL context if LDAPS is enabled
        if LDAP_USE_SSL:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require TLS 1.2 or higher
            context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE+AESGCM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK')
            context.check_hostname = True

            if LDAP_CA_BUNDLE:
                if os.path.exists(LDAP_CA_BUNDLE):
                    context.load_verify_locations(LDAP_CA_BUNDLE)
                else:
                    logger.error(f"CA bundle not found at {LDAP_CA_BUNDLE}.  Aborting due to mandatory SSL configuration.")
                    raise FileNotFoundError(f"CA bundle not found at {LDAP_CA_BUNDLE}")
            else:
                logger.error("LDAP_CA_BUNDLE environment variable must be set when LDAP_USE_SSL is true. Aborting.")
                raise ValueError("LDAP_CA_BUNDLE environment variable must be set when LDAP_USE_SSL is true.")

            server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True, tls=context, get_info=ldap3.ALL)
        else:
            server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, get_info=ldap3.ALL)

        # Determine authentication method
        if LDAP_BIND_DN and LDAP_BIND_PASSWORD:
            connection = ldap3.Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)
        else:
            connection = ldap3.Connection(server, auto_bind=True)  # Attempt anonymous bind

        if not connection.bind():
            log_message = f"LDAP bind failed for user {LDAP_BIND_DN if LDAP_BIND_DN else 'anonymous'}: {connection.result}"
            # Redact password from log message if present
            if LDAP_BIND_PASSWORD:
                log_message = log_message.replace(LDAP_BIND_PASSWORD, "***REDACTED***")
            logger.error(log_message)
            return None

        # Sanitize inputs to prevent LDAP injection
        username = ldap3.utils.conv.escape_filter_chars(username)
        dc = ldap3.utils.conv.escape_filter_chars(dc)

        # Input Validation: Length Limits and Character Restrictions
        if len(username) > 64:  # Example length limit
            logger.warning("Username exceeds maximum length.")
            return None  # Or raise an exception, depending on desired behavior

        if len(dc) > 255:  # Example length limit
            logger.warning("DC exceeds maximum length.")
            return None  # Or raise an exception

        # Character restriction example: allow only alphanumeric, underscore, and hyphen
        if not username.isalnum() and not all(c in "_-" for c in username if not c.isalnum()):
            sanitized_username = username[:10] + "..." if len(username) > 10 else username
            logger.warning(f"Invalid characters in username: {sanitized_username}")
            return None

        if not dc.isalnum() and not all(c in ".-" for c in dc if not c.isalnum()):
            sanitized_dc = dc[:10] + "..." if len(dc) > 10 else dc
            logger.warning(f"Invalid characters in dc: {sanitized_dc}")
            return None

        # Construct the search filter.  Use a parameterized query to prevent injection.
        search_filter = f"(&(objectClass=person)(uid={username}))"  # Assuming uid is the username attribute

        # Construct the search base
        search_base = f"dc={dc},{LDAP_BASE_DN}"  # Append the configured base DN

        # Perform the search
        connection.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)

        if connection.entries:
            entry = connection.entries[0]
            user_data = {}
            for attribute in entry.entry_attributes_as_dict:
                user_data[attribute] = entry.entry_attributes_as_dict[attribute]
            connection.unbind()
            return user_data
        else:
            connection.unbind()
            return None

    except ldap3.core.exceptions.LDAPException as e:
        logger.error(f"LDAP error: {e}")
        raise # Re-raise for retry decorator
    except FileNotFoundError as e:
        logger.error(f"File not found error: {e}")
        raise # Re-raise for retry decorator
    except ValueError as e:
        logger.error(f"Value error: {e}")
        raise # Re-raise for retry decorator
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}") # Use logger.exception to include traceback
        raise # Re-raise for retry decorator


@app.route("/normal")
@limiter.limit("5/second")  # Example rate limit
def normal():
    """
    Retrieves user information from LDAP based on request parameters.
    """
    username = request.args.get("username")
    dc = request.args.get("dc")

    if not username or not dc:
        logger.warning("Missing username or dc parameter")
        return jsonify({"error": "Missing username or dc parameter"}), 400

    try:
        user_data = ldap_search(username, dc)

        if user_data:
            return jsonify(user_data)
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error(f"Error during LDAP search: {e}")
        return jsonify({"error": "Internal Server Error"}), 500


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == "__main__":
    app.run(debug=False) # NEVER TRUE IN PRODUCTION

