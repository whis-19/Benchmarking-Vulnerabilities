@app.after_request
    def add_x_frame_options(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Or DENY if you don't need to frame your site
        return response

