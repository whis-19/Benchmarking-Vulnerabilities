@app.after_request
    def add_referrer_policy(response):
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

