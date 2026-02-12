from django.http import HttpResponseRedirect, HttpResponse
from django.utils.http import is_safe_url
from urllib.parse import urlparse, unquote
from django.conf import settings
from django.middleware.csrf import get_token
import logging

logger = logging.getLogger(__name__)

SAFE_REDIRECT_PREFIXES = ['/profile/', '/home/', '/dashboard/']  # Example prefixes


def http_responser_redirect(request):
    '''
    Get the target url from the request and redirect to it.
    This function prioritizes security by validating the redirect URL
    against a safe list and preventing open redirects.
    '''

    next_url = request.GET.get('next')  # Or request.POST.get('next') if it's a POST request

    # Check for CSRF token if it's a POST request that modifies data.
    if request.method == 'POST':
        csrf_token = request.POST.get('csrfmiddlewaretoken')
        if not csrf_token or csrf_token != get_token(request):
            logger.warning("CSRF token validation failed.")
            return HttpResponse("CSRF token missing or invalid.", status=400)

    if next_url:
        try:
            next_url = unquote(next_url)  # Decode once
        except Exception as e:
            logger.warning(f"Error decoding URL: {e}")
            return HttpResponse("Invalid URL.", status=400)

        parsed_url = urlparse(next_url)

        if parsed_url.scheme not in ['http', 'https', '']:
            logger.warning(f"Invalid URL scheme: {parsed_url.scheme}")
            return HttpResponse("Invalid URL scheme.", status=400)

        # Check for safe prefixes first
        if any(next_url.startswith(prefix) for prefix in SAFE_REDIRECT_PREFIXES):
            if is_safe_url(url=next_url, allowed_hosts=None): # Defer to ALLOWED_HOSTS
                return HttpResponseRedirect(next_url)
            else:
                logger.warning(f"Unsafe redirect URL attempted (prefix match, is_safe_url failed): {next_url}, IP: {request.META.get('REMOTE_ADDR')}, User-Agent: {request.META.get('HTTP_USER_AGENT')}")
                return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
        else:
            # Fallback to is_safe_url without prefix check
            # Use ALLOWED_HOSTS for maximum security
            if is_safe_url(url=next_url, allowed_hosts=None):
                return HttpResponseRedirect(next_url)
            else:
                logger.warning(f"Unsafe redirect URL attempted: {next_url}, IP: {request.META.get('REMOTE_ADDR')}, User-Agent: {request.META.get('HTTP_USER_AGENT')}")
                return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    response = HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
    response['X-Frame-Options'] = 'DENY'
    return response

