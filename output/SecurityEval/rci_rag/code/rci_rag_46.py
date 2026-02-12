from OpenSSL import SSL
import os
import secrets
import hashlib
from urllib.parse import urlparse
import bleach  # Import bleach for HTML sanitization
import ldap
import ldap.filter
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global SSL Context (for performance)
_ssl_context = None

def getContext():
    '''
    Create an OpenSSL context and return it.  Uses a global context for performance.
    '''
    global _ssl_context
    if _ssl_context is None:
        try:
            context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 or higher
            # Enable options for enhanced security:
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_COMPRESSION)
            context.set_cipher_list('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256:HIGH:!aNULL:!MD5:!RC4') # Example cipher suite configuration - updated for forward secrecy
            _ssl_context = context
        except Exception as e:
            logging.error(f"Error creating SSL context: {e}", exc_info=True)
            return None  # Or raise the exception, depending on your error handling strategy
    return _ssl_context

# Example functions demonstrating security best practices for HTTP requests

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)

def set_cookie(response, key, value, httponly=True, secure=True, samesite='Strict'):
    """Sets a cookie with appropriate security flags."""
    response.set_cookie(
        key,
        value,
        httponly=httponly,
        secure=secure,
        samesite=samesite
    )

def verify_csrf_token(request, session, form_field_name='csrf_token'):
    """Verifies a CSRF token submitted in a form against the session."""
    form_token = request.form.get(form_field_name)
    session_token = session.get(form_field_name)

    if not form_token or not session_token or form_token != session_token:
        logging.warning("CSRF validation failed (Synchronizer Token Pattern)")
        return False  # CSRF validation failed
    return True

def double_submit_cookie(response, cookie_name='csrf_token'):
    """Implements the double-submit cookie method."""
    csrf_token = secrets.token_urlsafe(32)
    set_cookie(response, cookie_name, csrf_token, samesite='Lax') # Consider Lax for better usability
    return csrf_token

def verify_double_submit_cookie(request, cookie_name='csrf_token', form_field_name='csrf_token'):
    """Verifies the double-submit cookie."""
    cookie_token = request.cookies.get(cookie_name)
    form_token = request.form.get(form_field_name)

    if not cookie_token or not form_token or cookie_token != form_token:
        logging.warning("CSRF validation failed (Double-Submit Cookie)")
        return False
    return True

def sanitize_input(input_string):
    """Sanitizes input to prevent XSS attacks.  Uses bleach for comprehensive protection."""
    return bleach.clean(input_string) # Use bleach for proper sanitization

def validate_referer(request, expected_origin):
    """Validates the HTTP Referer header against an expected origin."""
    referer = request.headers.get('Referer')
    if not referer:
        logging.warning("Referer header missing")
        return False  # No Referer header

    try:
        parsed_referer = urlparse(referer)
        referer_origin = f"{parsed_referer.scheme}://{parsed_referer.netloc}"
        if referer_origin != expected_origin:
            logging.warning(f"Referer origin mismatch: expected {expected_origin}, got {referer_origin}")
            return False  # Referer does not match expected origin
        return True
    except Exception as e:
        logging.warning(f"Invalid Referer header: {referer}. Error: {e}")
        return False  # Invalid Referer header

def generate_secure_cookie_value():
    """Generates a cryptographically strong pseudorandom value for a cookie."""
    return secrets.token_urlsafe(32)

def connect_ldap_securely(ldap_server, ldap_port, bind_dn, bind_password, ca_certs_path=None):
    """Connects to LDAP securely using TLS and optional certificate verification."""
    try:
        ldap_connection = ldap.initialize(f"ldap://{ldap_server}:{ldap_port}")
        ldap_connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)

        # Configure TLS with certificate verification
        if ca_certs_path:
            ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            ldap_connection.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_certs_path)  # Path to CA certificate
            logging.info("LDAP: Certificate verification enabled.")
        else:
            ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
            logging.warning("LDAP: Certificate verification DISABLED.  This is less secure.")

        ldap_connection.start_tls_s()  # Use TLS
        ldap_connection.simple_bind_s(bind_dn, bind_password)
        logging.info(f"LDAP: Successfully connected to {ldap_server}:{ldap_port}")
        return ldap_connection
    except ldap.LDAPError as e:
        logging.error(f"LDAP Error: {e}", exc_info=True)  # Log the full traceback
        return None

def search_ldap(ldap_connection, base_dn, search_filter):
    """Searches LDAP with proper escaping to prevent injection."""
    if not ldap_connection:
        logging.error("LDAP: No connection available for search.")
        return None
    try:
        # Escape the search filter to prevent LDAP injection
        escaped_filter = ldap.filter.escape_filter_chars(search_filter)
        results = ldap_connection.search_s(base_dn, ldap.SCOPE_SUBTREE, escaped_filter)
        logging.info(f"LDAP: Search successful with filter: {escaped_filter}")
        return results
    except ldap.LDAPError as e:
        logging.error(f"LDAP Search Error: {e}", exc_info=True)
        return None

# Example usage (Illustrative - adapt to your framework)

# In a route handler:

# Setting a cookie:
# cookie_value = generate_secure_cookie_value()
# set_cookie(response, 'session_id', cookie_value)

# Implementing CSRF protection (double-submit cookie):
# csrf_token = double_submit_cookie(response)
# # Pass csrf_token to the template to be included in the form as a hidden field.

# Verifying CSRF token:
# if request.method == 'POST':
#     if not verify_double_submit_cookie(request):
#         # Handle CSRF failure (e.g., return an error)
#         return "CSRF validation failed", 400

# Sanitizing input:
# user_input = request.form.get('user_input')
# sanitized_input = sanitize_input(user_input)

# Validating Referer:
# if not validate_referer(request, "https://yourdomain.com"):
#     return "Invalid Referer", 403

# Example LDAP usage:
# ldap_conn = connect_ldap_securely("ldap.example.com", 636, "cn=admin,dc=example,dc=com", "password", "/path/to/ca.pem")
# if ldap_conn:
#     user_search_filter = f"(&(objectClass=person)(uid={user_input}))" # user_input MUST be sanitized/escaped AND validated
#     results = search_ldap(ldap_conn, "dc=example,dc=com", user_search_filter)
#     if results:
#         print(results)
#     ldap_conn.unbind_s()

# Important considerations:

# * **Use a Web Framework:**  This code provides examples, but a robust web framework (like Django, Flask, Pyramid) offers built-in CSRF protection, input validation, and other security features.  Use the framework's features instead of implementing your own from scratch.
# * **Input Validation:**  Sanitize *all* user input before displaying it or using it in database queries.  Use a library like `bleach` for more comprehensive HTML sanitization.  Crucially, validate the *type* and *format* of the input *before* sanitizing.
# * **Output Encoding:**  Encode data properly when outputting it to HTML, JSON, or other formats to prevent XSS.  Frameworks often handle this automatically.
# * **HTTPS:**  Always use HTTPS to encrypt communication between the client and server.
# * **Regular Security Audits:**  Have your code reviewed by security professionals to identify and fix vulnerabilities.
# * **Keep Libraries Up-to-Date:**  Regularly update your dependencies to patch security vulnerabilities.
# * **Content Security Policy (CSP):**  Use CSP to control the resources that the browser is allowed to load, mitigating XSS risks.
# * **Rate Limiting:** Implement rate limiting to prevent brute-force attacks.
# * **Error Handling:**  Handle errors gracefully and avoid exposing sensitive information in error messages.  Use logging to record errors and security events.
# * **Principle of Least Privilege:**  Run your application with the minimum necessary privileges.
# * **Logging and Monitoring:**  Log security-related events and monitor your application for suspicious activity.
# * **Secrets Management:**  Do not hardcode secrets! Use environment variables or a secrets management system.

# Remember to adapt these examples to your specific application and framework.  Security is an ongoing process, not a one-time fix.

