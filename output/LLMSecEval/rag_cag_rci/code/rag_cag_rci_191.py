# ... (Previous code) ...

# CSP Header (Example with Nonce - Adapt to your templating engine)
#  This is a simplified example.  You'll need to generate a unique nonce for each request
#  and pass it to your templates.
def generate_nonce():
    return secrets.token_urlsafe(16)

@app.before_request
def before_request():
    session['csp_nonce'] = generate_nonce()

CSP_POLICY = (
    "default-src 'self'; "
    f"script-src 'self' 'nonce-{session.get('csp_nonce', '')}'; "  # Use nonce for inline scripts
    f"style-src 'self' 'nonce-{session.get('csp_nonce', '')}'; "  # Use nonce for inline styles
    # Example of hash-based CSP (use only ONE of nonce or hash)
    # "script-src 'self' 'sha256-YOUR_SCRIPT_HASH_HERE';"
    "img-src 'self' data:; "
    "font-src 'self';"
    "object-src 'none';"
    "base-uri 'self';"
    "form-action 'self';"
    "frame-ancestors 'none';"
)

# ... (Previous code) ...

        # Sanitize username (example - adapt as needed)
        # Use a carefully configured allowlist with bleach
        allowed_tags = ['b', 'i', 'em', 'strong']  # Example
        username = bleach.clean(username, tags=allowed_tags)  # Remove HTML tags

