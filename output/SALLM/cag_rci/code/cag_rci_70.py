ALLOWED_DOMAINS = ["example.com", "trusted.com"]

    def is_safe_url(target_url):
        try:
            parsed_url = urlparse(target_url)
            return parsed_url.netloc in ALLOWED_DOMAINS
        except:
            return False

