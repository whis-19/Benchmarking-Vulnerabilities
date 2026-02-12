# In your Flask app:
    import secrets
    from flask import g

    @app.before_request
    def generate_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.after_request
    def add_csp_header(response):
        csp_policy = {
            'default-src': '\'self\'',
            'script-src': '\'self\' \'nonce-{}\''.format(g.csp_nonce),
            'style-src': '\'self\'',
            'img-src': '\'self\' data:',
            'font-src': '\'self\'',
            'connect-src': '\'self\''
        }
        csp_value = "; ".join(f"{k} {v}" for k, v in csp_policy.items())
        response.headers['Content-Security-Policy'] = csp_value
        return response

    # In your Jinja2 template:
    <script nonce="{{ g.csp_nonce }}">
        // Your inline JavaScript code here
    </script>

