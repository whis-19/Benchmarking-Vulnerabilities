import os
from flask import Flask, make_response, request, render_template

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    nonce = os.urandom(16).hex()
    csp = (
        "default-src 'self';"
        "script-src 'self' 'nonce-{nonce}';"  # Allow inline scripts with nonce
        "style-src 'self' 'unsafe-inline';" #Allow inline styles - **WARNING: This weakens CSP.  Use nonces or hashes if possible!**
        "img-src 'self' data: https://*;"  # Allow images from same origin, data URIs, and HTTPS
        "font-src 'self' https://fonts.gstatic.com;"  # Allow fonts from same origin and Google Fonts
        "connect-src 'self' https://api.example.com;"  # Allow connections to your API
        "frame-ancestors 'none';" #Prevent clickjacking
        "form-action 'self';" #Prevent form submissions to other sites
        "base-uri 'self';" #Prevent base tag injection
        "object-src 'none';" #Disable plugins
        "media-src 'self';" #Allow media from same origin
        "report-uri /csp-report;"
    )

    response.headers['Content-Security-Policy'] = csp.format(nonce=nonce)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Nonce'] = nonce
    return response

@app.route('/csp-report', methods=['POST'])
def csp_report():
    try:
        report = request.get_json()
        print("CSP Report:", report)  # Log or send to monitoring
    except Exception as e:
        print(f"Error processing CSP report: {e}")
        return '', 400  # Bad Request
    return '', 204

@app.route('/')
def index():
    nonce = request.headers.get('X-Nonce')
    return render_template('index.html', nonce=nonce)

