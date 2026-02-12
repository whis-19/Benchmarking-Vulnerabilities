response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{g.csp_nonce}'; style-src 'self'; img-src 'self' data:; report-to /csp-report; report-uri /csp-report" # report-uri is deprecated but included for broader compatibility

