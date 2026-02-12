import secrets
import json
import logging
import os  # Import the os module

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CSPMiddleware:
    def __init__(self, app, policy_file="csp_policy.json"):
        self.app = app
        self.policy = self._load_policy(policy_file)

    def _load_policy(self, policy_file):
        try:
            with open(policy_file, 'r') as f:
                policy = json.load(f)
                self._validate_policy(policy)  # Validate the policy
                return policy
        except FileNotFoundError:
            logger.warning(f"CSP policy file not found: {policy_file}. Using default policy.")
            return self._get_default_policy()
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding CSP policy file: {e}. Using default policy.")
            return self._get_default_policy()
        except ValueError as e:  # Catch validation errors
            logger.error(f"Invalid CSP policy: {e}. Using default policy.")
            return self._get_default_policy()

    def _validate_policy(self, policy):
        # Example validation (add more checks as needed)
        if not isinstance(policy, dict):
            raise ValueError("CSP policy must be a dictionary.")
        for directive, sources in policy.items():
            if not isinstance(sources, list):
                raise ValueError(f"Sources for directive '{directive}' must be a list.")

    def _get_default_policy(self):
        # Consider a more permissive default policy if needed
        return {
            'default-src': ["'self'"],
            'script-src': ["'self'"],  # Removed 'unsafe-inline'
            'style-src': ["'self'"],   # Removed 'unsafe-inline'
            'img-src': ["'self'", "data:"],
            'font-src': ["'self'"],
            'object-src': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'frame-ancestors': ["'none'"],
            'upgrade-insecure-requests': [],
            'report-uri': ['/csp-report-endpoint'],  # Example reporting endpoint
        }

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            try:
                nonce = secrets.token_urlsafe(16)  # Generate a unique nonce
                environ['csp_nonce'] = nonce  # Store nonce in environ for use in templates

                csp_header = self.build_csp_header(nonce)
                headers.append(('Content-Security-Policy', csp_header))
                return start_response(status, headers, exc_info)
            except Exception as e:
                logger.exception("Error generating CSP header:")
                # Handle the error gracefully, e.g., by returning a default CSP header
                csp_header = "default-src 'self';"  # Very restrictive default
                headers.append(('Content-Security-Policy', csp_header))
                return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)

    def build_csp_header(self, nonce):
        directives = []
        for directive, sources in self.policy.items():
            updated_sources = list(sources)  # Create a copy to avoid modifying the original
            if directive == 'script-src':
                updated_sources.append(f"'nonce-{nonce}'")  # Add nonce to script-src
            if directive == 'style-src':
                updated_sources.append(f"'nonce-{nonce}'")  # Add nonce to style-src
            directives.append(f"{directive} {' '.join(updated_sources)}")
        return '; '.join(directives)


def csp_middleware(app, policy=None):
    return CSPMiddleware(app, policy)

# Example usage in your application (e.g., in a Flask route):
# from flask import Flask, render_template, request, g
# app = Flask(__name__)
# app.wsgi_app = csp_middleware(app.wsgi_app)

# @app.route('/')
# def index():
#     nonce = request.environ.get('csp_nonce')
#     return render_template('index.html', nonce=nonce)

# In your index.html template:
# <script nonce="{{ nonce }}">
#   // Your inline JavaScript code here
# </script>
# <style nonce="{{ nonce }}">
#   /* Your inline CSS code here */
# </style>

# Example csp_policy.json:
# {
#   "default-src": ["'self'"],
#   "script-src": ["'self'", "https://cdn.example.com"],
#   "style-src": ["'self'"],
#   "img-src": ["'self'", "data:", "https://images.example.com"],
#   "font-src": ["'self'"],
#   "object-src": ["'none'"],
#   "base-uri": ["'self'"],
#   "form-action": ["'self'"],
#   "frame-ancestors": ["'none'"],
#   "upgrade-insecure-requests": [],
#   "report-uri": ["/csp-report-endpoint"]
# }

