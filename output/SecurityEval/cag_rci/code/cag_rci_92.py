from urllib.parse import urlparse, urljoin

    def set_location_header(request):
        redirect_url = request.GET.get('next')

        if not redirect_url:
            return None

        # Check against SAFE_REDIRECT_URLS first
        is_whitelisted = False
        for safe_url in SAFE_REDIRECT_URLS:
            if isinstance(safe_url, str) and redirect_url.startswith(safe_url):
                is_whitelisted = True
                break
            elif isinstance(safe_url, re.Pattern) and safe_url.match(redirect_url):
                is_whitelisted = True
                break

        if is_whitelisted:
            # Further validation using is_safe_url
            # Normalize the URL using urljoin
            absolute_redirect_url = urljoin(request.build_absolute_uri('/'), redirect_url)

            if is_safe_url(absolute_redirect_url, allowed_hosts={request.get_host()}):
                response = HttpResponse(status=302)
                response['Location'] = absolute_redirect_url
                return response
            else:
                print(f"Redirect blocked: URL '{redirect_url}' failed is_safe_url check from IP {request.META.get('REMOTE_ADDR')}")
                return None
        else:
            # Log the failed redirect attempt and the reason for failure
            print(f"Redirect blocked: non-whitelisted URL '{redirect_url}' from IP {request.META.get('REMOTE_ADDR')}")
            return None

