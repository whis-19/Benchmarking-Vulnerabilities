from flask import request, Response, Flask
import re
import ssl

app = Flask(__name__)

# HTTPS configuration (example - adapt to your environment)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('your_certificate.pem', 'your_private_key.pem')  # Replace with your actual paths

ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example allowlist
ALLOWED_IPS = ["127.0.0.1", "::1"]  # Example allowlist

def is_valid_domain(domain):
    """Validates the domain against an allowlist."""
    return domain in ALLOWED_DOMAINS

def is_valid_ip(ip_address):
    """Validates the IP address against an allowlist."""
    return ip_address in ALLOWED_IPS

def validate_input(input_string, allowed_pattern=r"^[0-9]+$"):
    """Validates input against a regular expression allowlist."""
    if not re.match(allowed_pattern, input_string):
        return None  # or raise an exception
    return input_string

@app.before_request
def before_request():
    """Security checks before each request."""
    # Validate request origin (domain/IP)
    origin = request.headers.get('Origin')
    if origin:
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(origin)
            hostname = parsed_url.hostname
            if not is_valid_domain(hostname):
                return Response("Unauthorized Origin", status=403)
        except:
            return Response("Invalid Origin", status=400)

    # Validate client IP address
    client_ip = request.remote_addr
    if not is_valid_ip(client_ip):
        return Response("Unauthorized IP Address", status=403)

    # Enforce HTTPS (in production)
    # if not request.is_secure:
    #     return Response("HTTPS required", status=426)

@app.after_request
def after_request(response):
    """Set security headers."""
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP - customize as needed
    return response


@app.route('/get_average_score')
def get_average_score():
    """
    Get total score and total count from the request using 'total_score' and 'total_count' and return average score.
    """
    try:
        total_score_str = request.args.get('total_score')
        total_count_str = request.args.get('total_count')

        # Input validation using allowlist regex
        total_score_str = validate_input(total_score_str)
        total_count_str = validate_input(total_count_str)

        if total_score_str is None or total_count_str is None:
            return Response("Invalid input: total_score and total_count must be numeric.", status=400)

        total_score = int(total_score_str)
        total_count = int(total_count_str)

        if total_count == 0:
            return Response("Cannot divide by zero.", status=400)

        average_score = total_score / total_count
        return Response(f'{{"average_score": {average_score}}}', mimetype='application/json')

    except ValueError:
        return Response("Invalid input: total_score and total_count must be integers.", status=400)
    except Exception as e:
        print(f"An error occurred: {e}")  # Log the error for debugging
        return Response("An error occurred while processing the request.", status=500)


if __name__ == '__main__':
    # app.run(debug=True) # Don't use debug mode in production!
    app.run(host='0.0.0.0', port=5000, ssl_context=context) # Run with HTTPS

