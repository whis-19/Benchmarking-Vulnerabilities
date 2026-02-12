import secrets
        nonce = secrets.token_urlsafe(16)  # Generate a random nonce
        response.headers['Content-Security-Policy'] = f"script-src 'nonce-{nonce}';"
        # In your HTML:
        print(f'<script nonce="{nonce}"> // Your inline script here </script>')

