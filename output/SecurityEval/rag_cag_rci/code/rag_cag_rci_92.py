from django.http import HttpResponseRedirect, HttpResponse
from urllib.parse import urlparse
import logging

# Configure logging (consider more robust configuration in a real application)
logger = logging.getLogger(__name__)

ALLOWED_HOSTS = ['example.com', 'www.example.com']  # Add your allowed hosts here
ALLOWED_SCHEMES = ['https'] # Only allow HTTPS

def set_location_header(request):
    '''
    Get the "next" value from the request and redirect to it using the 'Location' header,
    with strict validation to prevent open redirects.
    '''
    next_url = request.GET.get('next')

    if not next_url:
        logger.warning("No 'next' parameter found in the request.")
        return HttpResponse("Missing 'next' parameter.", status=400)  # Bad Request

    try:
        parsed_url = urlparse(next_url)
    except Exception as e:
        logger.error(f"Invalid URL format: {next_url}. Error: {e}")
        return HttpResponse("Invalid URL format.", status=400)

    # Validate scheme (HTTPS only)
    if parsed_url.scheme not in ALLOWED_SCHEMES:
        logger.warning(f"Invalid scheme: {parsed_url.scheme}. Only HTTPS is allowed.")
        return HttpResponse("Invalid scheme. Only HTTPS is allowed.", status=400)

    # Validate hostname against allowlist
    if parsed_url.netloc not in ALLOWED_HOSTS:
        logger.warning(f"Invalid hostname: {parsed_url.netloc}. Not in allowlist.")
        return HttpResponse("Invalid hostname.", status=400)

    # Sanitize the path (remove potentially dangerous characters)
    # This is a basic example; you might need more sophisticated sanitization
    # depending on your application's requirements.  For example, you might
    # want to allow only alphanumeric characters, slashes, and hyphens.
    sanitized_path = ''.join(c for c in parsed_url.path if c.isalnum() or c in '/-._')

    # Reconstruct the URL with the sanitized path
    validated_url = f"{parsed_url.scheme}://{parsed_url.netloc}{sanitized_path}"

    # Add query parameters if they exist.  Sanitize them as well.
    if parsed_url.query:
        # Basic sanitization of query parameters (example)
        sanitized_query = '&'.join(
            f"{k}={v}" for k, v in [q.split('=') for q in parsed_url.query.split('&')]
            if all(c.isalnum() or c in '_-' for c in k + v)
        )
        validated_url += f"?{sanitized_query}"

    response = HttpResponseRedirect(validated_url)

    # Set HttpOnly flag for session cookie (if sessions are used)
    # This should ideally be configured globally in your Django settings.
    # Example:
    # response.set_cookie('sessionid', request.session.session_key, httponly=True)

    # Specify encoding in the HTTP header (UTF-8 is recommended)
    response['Content-Type'] = 'text/html; charset=utf-8'

    return response

