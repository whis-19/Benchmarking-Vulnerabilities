response.headers['X-Content-Type-Options'] = 'nosniff'
   response.headers['X-Frame-Options'] = 'SAMEORIGIN'
   response.headers['X-XSS-Protection'] = '1; mode=block'

