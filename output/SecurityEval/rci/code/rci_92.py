import logging
from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from urllib.parse import urlparse, urlunparse
from django.conf import settings  # Import settings for SECURE_SSL_REDIRECT

logger = logging.getLogger(__name__)

def set_location_header(request):
    '''
    Get the "next" value from the request and redirect to it using the 'Location' header.
    This function includes security measures to prevent open redirect vulnerabilities.
    '''
    next_url = request.GET.get('next')

    if next_url:
        # Remove the commented-out sanitization attempts. They are ineffective and misleading.

        # Check if the URL is safe to redirect to.  Crucially important to prevent open redirects.
        if url_has_allowed_host_and_scheme(
            next_url,
            allowed_hosts=[request.get_host()],  # Use request.get_host() for current host
            require_https=request.is_secure(), # Consider HTTPS requirement
        ):
            # Enforce HTTPS if possible (if SECURE_SSL_REDIRECT is not enabled)
            # Rely on SECURE_SSL_REDIRECT setting instead of manual enforcement.
            # If SECURE_SSL_REDIRECT is enabled, this block is redundant.
            # If it's not enabled, this provides some protection, but HSTS is better.
            if not settings.SECURE_SSL_REDIRECT and request.is_secure() and not next_url.startswith('https://'):
                parsed_url = urlparse(next_url)
                next_url = urlunparse(('https', parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))


            return HttpResponseRedirect(next_url)
        else:
            # Log the attempted redirect to an unsafe URL.  This is important for auditing.
            logger.warning(
                "Attempted redirect to unsafe URL: %s from IP: %s, User Agent: %s",
                next_url,
                request.META.get('REMOTE_ADDR'),
                request.META.get('HTTP_USER_AGENT'),
                extra={'request': request}  # Include request context in log
            )

            # Redirect to a safe default URL (e.g., homepage).  Crucial fallback.
            return HttpResponseRedirect('/')  # Or your preferred safe default

    # If 'next' parameter is not present, redirect to a safe default URL.
    return HttpResponseRedirect('/')  # Or your preferred safe default

