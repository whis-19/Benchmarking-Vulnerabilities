# Example CSP with report-to (more complex setup required)
    # csp = f"default-src 'self'; ...; report-to csp-endpoint;"
    # response.headers['Content-Security-Policy'] = csp
    # response.headers['Report-To'] = json.dumps({"group": "csp-endpoint", "max_age": 31536000, "endpoints": [{"url": "/csp-report"}]})

