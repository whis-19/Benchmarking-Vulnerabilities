from urllib.parse import urlparse
import idna  # For IDN handling

def is_safe_url(target, request):
    """
    Check if the target URL is safe for redirection.  This prevents open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)

    allowed_domains = ['example.com', 'www.example.com']  # Replace with your allowed domains - SHOULD BE CONFIGURABLE

    try:
        # Normalize domain names to Punycode for IDN protection
        ref_netloc = idna.encode(ref_url.netloc).decode('ascii')
        test_netloc = idna.encode(test_url.netloc).decode('ascii')
    except idna.IDNAError:
        app.logger.warning(f"Blocked redirect due to IDNA error: {target}")
        return False

    # Only allow HTTPS
    if test_url.scheme != 'https':
        app.logger.warning(f"Blocked redirect to non-HTTPS URL: {target}")
        return False

    # Check if the netloc matches the host or is in the whitelist
    if ref_netloc == test_netloc:
        app.logger.debug(f"Safe redirect to same domain: {target}")
        return True
    elif test_netloc in allowed_domains:
        app.logger.debug(f"Safe redirect to whitelisted domain: {target}")
        return True
    # Optional: Allow subdomains of the main domain (USE WITH CAUTION)
    # elif test_netloc.endswith("." + ref_netloc):
    #     app.logger.debug(f"Safe redirect to subdomain: {target}")
    #     return True

    app.logger.warning(f"Blocked unsafe redirect to: {target}")
    return False

