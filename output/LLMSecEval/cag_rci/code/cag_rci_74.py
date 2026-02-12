from urllib.parse import urlparse, urljoin, unquote
import logging

ALLOWED_DOMAINS = [domain.lower() for domain in ["example.com", "127.0.0.1"]]  # Lowercase for consistency
TRUSTED_HOST = "yourdomain.com"  # Hardcode your trusted host - CRITICAL!

def is_safe_url(target):
    try:
        target = unquote(target)  # Decode URL
        test_url = urlparse(urljoin(f"https://{TRUSTED_HOST}", target)) # Force HTTPS and use trusted host
        is_safe = test_url.scheme == 'https' and (test_url.netloc.lower() in ALLOWED_DOMAINS or any(test_url.netloc.lower().endswith("." + domain.lower()) for domain in ALLOWED_DOMAINS))

        if not is_safe:
            logging.warning(f"Unsafe redirect attempt: target={target}, netloc={test_url.netloc}, IP={request.remote_addr if 'request' in locals() else 'Unknown'}, User-Agent={request.user_agent if 'request' in locals() else 'Unknown'}") # Log details

        return is_safe
    except ValueError as e: # Catch specific parsing errors
        logging.exception(f"Error during URL validation: {e}")
        return False # Return False on any error

# Example usage (assuming you have a request object in a Flask/Django context)
# if is_safe_url(request.args.get('next')):
#     return redirect(request.args.get('next'))
# else:
#     return abort(400)

# In Flask, ensure app.config['SERVER_NAME'] is set and validate the Host header if necessary.
# In Django, use ALLOWED_HOSTS in settings.py.

