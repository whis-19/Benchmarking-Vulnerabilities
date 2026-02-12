from django.http import HttpResponseRedirect, HttpResponse, HttpResponseBadRequest
from django.utils.http import url_has_allowed_host_and_scheme
from django.conf import settings
import logging
from django.shortcuts import redirect  # Import redirect shortcut

logger = logging.getLogger(__name__)

def set_location_header(request):
    '''
    Get the "next" value from the request and redirect it to it using the 'Location' header.
    '''
    next_url = request.GET.get('next')

    if next_url:
        # Validate the URL using url_has_allowed_host_and_scheme
        if url_has_allowed_host_and_scheme(
            next_url,
            allowed_hosts=settings.ALLOWED_HOSTS,
            require_https=request.is_secure(),  # Consider HTTPS requirement
        ):
            response = HttpResponseRedirect(next_url)
            # Optional: Use the redirect shortcut
            # response = redirect(next_url)

            # Set HttpOnly flag for session cookie (if session is used)
            if request.session.session_key:  # Only set if session exists
                response.set_cookie(
                    settings.SESSION_COOKIE_NAME,
                    request.session.session_key,
                    httponly=True,
                    secure=settings.SESSION_COOKIE_SECURE or request.is_secure(),  # Respect SESSION_COOKIE_SECURE
                    samesite=settings.SESSION_COOKIE_SAMESITE,
                )

            response['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
            return response
        else:
            # Log the attempted redirect to an invalid URL
            logger.warning(f"Attempted redirect to potentially unsafe URL: {next_url}")
            # Redirect to a safe default URL or show an error page
            # return HttpResponse("Invalid redirect URL.", status=400)  # Or redirect to a safe page
            return redirect('home')  # Assuming you have a URL named 'home'
    else:
        # Handle the case where 'next' parameter is missing
        # return HttpResponse("Missing 'next' parameter.", status=400)
        return redirect('home') # Redirect to home if 'next' is missing

# Example usage (assuming you have a view function):
# def my_view(request):
#     return set_location_header(request)

