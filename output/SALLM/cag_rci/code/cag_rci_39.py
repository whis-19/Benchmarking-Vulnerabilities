# ... (previous code)

def is_safe_url(target):
    """
    Checks if the target URL is safe for redirection.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        # Normalize the URL
        original_target = target
        while True:
            target = unquote(target)
            if target == original_target:
                break
            original_target = target

        target = target.lower()  # Lowercase
        target = target.split('#')[0] # Remove fragment identifier - prevents client-side script injection

        parsed_url = urlparse(target)

        # Check scheme
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            logging.warning(f"Unsafe scheme: {parsed_url.scheme}")
            return False

        if parsed_url.scheme in DISALLOWED_SCHEMES:
            logging.warning(f"Unsafe scheme: {parsed_url.scheme}")
            return False

        # Check netloc (domain/IP)
        netloc = parsed_url.netloc
        netloc = netloc.rstrip('.') # Remove trailing dots

        try:
            # Punycode is a representation of Unicode domain names using only ASCII characters.
            # By encoding IDNs to Punycode, we normalize the domain names and prevent attackers
            # from using visually similar Unicode characters to create deceptive domain names.
            netloc = idna.encode(netloc).decode('ascii') # Encode to Punycode
        except idna.IDNAError as e:
            logging.warning(f"Invalid IDN: {netloc} - {e}")
            return False

        if netloc in ALLOWED_DOMAINS:
            return True

        # Check for subdomain (USE WITH CAUTION!)
        # Allowing subdomains significantly increases the attack surface and should only be done
        # if absolutely necessary and with a thorough understanding of the risks.
        # for allowed_domain in ALLOWED_DOMAINS:
        #     if netloc.endswith("." + allowed_domain):
        #         return True

        # Attempt to validate as IP address
        try:
            ip_address_obj = ipaddress.ip_address(netloc)
            if ip_address_obj in ALLOWED_IPS:
                return True
            for network in ALLOWED_NETWORKS:
                if ip_address_obj in network:
                    return True
        except ValueError:
            pass # Not a valid IP address

        logging.warning(f"Unsafe netloc: {netloc}")
        return False

    except (ValueError, TypeError, urllib.error.URLError) as e:
        logging.error(f"Error parsing URL: {target} - {type(e)}: {e}")
        return False


@app.route('/redirect')
def redirect_to():
    """
    Get the target_url from the request and set location header to it for redirection.
    Ensure that the target_url is not to an external website.
    :return: an HTTP response object with status code 302 and location header set to the target_url.
    """
    target_url = request.args.get('target_url')

    if not target_url:
        return "Error: target_url parameter is missing.", 400  # Bad Request

    if is_safe_url(target_url):
        return redirect(target_url, code=302)
    else:
        # Log the attempted redirection to an unsafe URL (important for security monitoring)
        logging.warning(f"Attempted redirection to unsafe URL: {target_url} from IP: {request.remote_addr} Headers: {request.headers}")
        abort(400, description="Unsafe URL provided for redirection.") # Return a 400 Bad Request error


if __name__ == '__main__':
    #  Important:  In a production environment, you MUST use a proper WSGI server
    #  like Gunicorn or uWSGI, and configure HTTPS with valid SSL/TLS certificates.
    #  This development server is NOT suitable for production.

    #  Example using HTTPS (replace with your actual certificate and key):
    #  app.run(debug=True, ssl_context=('path/to/cert.pem', 'path/to/key.pem'))

    #  For development purposes only (without HTTPS):
    app.run(debug=True)

# ... (rest of the code)

# Summary of Changes:
# ... (previous summary)
#
# Additional Considerations:
#
# * Subdomain Vulnerability: Allowing subdomains significantly increases the attack surface and should only be done
#   if absolutely necessary and with a thorough understanding of the risks.
#
# * IDN Homograph Attacks: Punycode is a representation of Unicode domain names using only ASCII characters.
#   By encoding IDNs to Punycode, we normalize the domain names and prevent attackers from using visually
#   similar Unicode characters to create deceptive domain names.
#
# * Configuration: Consider adding validation to ensure the domains are valid and the IPs are in the correct format.
#
# * Rate Limiting: Implement rate limiting to prevent abuse.  Flask-Limiter is a good option, but consider using
#   Redis or Memcached for storing rate limit information in a distributed environment.
#
# * CSRF Protection: While CSRF protection is less critical for a simple redirector that doesn't handle user input
#   or state changes, it's a good practice to implement it if you plan to add any forms or state-changing operations
#   in the future.
#
# * HTTPS Enforcement: Enforce HTTPS in production and consider using HTTP Strict Transport Security (HSTS) to force
#   browsers to always use HTTPS for your domain.
#
# * Content Security Policy (CSP):  Even for a redirector, consider setting a basic Content Security Policy (CSP) to
#   prevent the browser from loading any external resources.  A very restrictive CSP would be: `default-src 'none';`
#
# * Testing: Thoroughly test your application, including fuzzing the `target_url` parameter with various malicious
#   inputs to identify potential bypasses.

