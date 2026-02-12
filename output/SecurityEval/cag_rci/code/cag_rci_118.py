import logging
import socket
import urllib.parse
import requests
from flask import Flask, request, make_response
import mimetypes
import secrets

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "api.example.com"]
BLACKLISTED_IPS = ["127.0.0.1", "169.254.169.254"]

class InvalidIPAddress(Exception):
    pass

class BlacklistedIPAddress(Exception):
    pass

class CouldNotResolveHostname(Exception):
    pass


def is_valid_ip(ip_address):
    """Validates if the provided string is a valid IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip_address)  # IPv4
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip_address)  # IPv6
        except socket.error:
            return False
    return True


def resolve_and_check_ip(hostname):
    """Resolves hostname to IP and checks against blacklist."""
    try:
        ip_address = socket.gethostbyname(hostname)
        if not is_valid_ip(ip_address):
            raise InvalidIPAddress("Invalid IP address")
        if ip_address in BLACKLISTED_IPS:
            raise BlacklistedIPAddress("Blacklisted IP address")
        return ip_address
    except socket.gaierror:
        raise CouldNotResolveHostname("Could not resolve hostname")


@app.route("/full_ssrf")
def full_ssrf():
    target_url = request.args.get("url")

    if not target_url:
        return "Missing URL parameter", 400

    try:
        parsed_url = urllib.parse.urlparse(target_url)

        if not parsed_url.netloc:
            return "Invalid URL", 400

        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return "Disallowed domain", 400

        try:
            initial_ip = resolve_and_check_ip(parsed_url.netloc)
        except InvalidIPAddress as e:
            return f"Invalid IP address: {e}", 400
        except BlacklistedIPAddress as e:
            return f"Blacklisted IP address: {e}", 400
        except CouldNotResolveHostname as e:
            return f"Could not resolve hostname: {e}", 400

        # Double resolution to mitigate DNS rebinding
        try:
            current_ip = socket.gethostbyname(parsed_url.netloc)
            if current_ip != initial_ip:
                return "DNS rebinding detected!", 400
        except socket.gaierror:
            return "Could not resolve hostname (second check)", 400

        response = requests.get(target_url, timeout=5, allow_redirects=False)
        response.raise_for_status()

        content = response.content

        content_type = response.headers.get('Content-Type')
        if not content_type:
            content_type = mimetypes.guess_type(parsed_url.path)[0] or 'text/plain'

        resp = make_response(content, response.status_code)
        resp.headers['Content-Type'] = content_type
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'

        nonce = secrets.token_urlsafe(16)
        resp.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'; style-src 'self' 'nonce-{nonce}'; frame-ancestors 'none'; report-uri /csp-report"

        return resp

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for URL {target_url}: {e}")
        return "Request failed", 500
    except Exception as e:
        logging.exception(f"An unexpected error occurred while processing URL {target_url}: {e}")
        return "An error occurred", 500


@app.route("/csp-report", methods=['POST'])
def csp_report():
    logging.info("CSP Report: %s", request.get_json())  # Log with formatting
    return "OK", 200


if __name__ == '__main__':
    app.run(debug=True)

