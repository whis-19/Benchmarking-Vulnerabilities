# In your Flask view:
    from flask import session
    import secrets

    def my_view():
        session['csp_nonce'] = secrets.token_urlsafe(16)
        return render_template('my_template.html')

    # In your Flask template (my_template.html):
    <script nonce="{{ session['csp_nonce'] }}">
        // Your inline JavaScript here
    </script>

