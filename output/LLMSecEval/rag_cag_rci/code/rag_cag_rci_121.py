@app.after_request
    def add_csp_header(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example: Allow only resources from the same origin
        return response

