# is_safe_url - IDN handling (requires idna library)
import idna

def is_safe_url(target):
    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme

        if not hostname:
            return False

        if scheme not in ['http', 'https']:
            return False

        try:
            # Attempt to encode the hostname to ASCII (Punycode)
            hostname = idna.encode(hostname).decode('ascii')
        except idna.IDNAError:
            # Invalid IDN, reject
            return False

        ext = tldextract.extract(hostname)
        base_domain = f"{ext.domain}.{ext.suffix}"

        if base_domain.lower() in [domain.lower() for domain in ALLOWED_DOMAINS]:
            return True

        if hostname.lower() in [domain.lower() for domain in ALLOWED_DOMAINS]:
            return True

        return False

    except Exception:
        return False

# CSRF - Constant-time comparison (example using secrets.compare_digest)
import secrets

def form_example():
    if request.method == 'GET':
        session['csrf_token'] = secrets.token_hex(16)
        return f'''...'''
    else:
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not secrets.compare_digest(csrf_token, session.get('csrf_token', '')):
            return "CSRF token invalid", 400

        data = request.form.get('data')
        return f"Data received: {data}"

