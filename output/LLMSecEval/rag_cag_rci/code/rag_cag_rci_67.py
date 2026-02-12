CSP_POLICY = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{session.get('csp_nonce', '')}'; "
        f"style-src 'self' 'nonce-{session.get('csp_nonce', '')}'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )

