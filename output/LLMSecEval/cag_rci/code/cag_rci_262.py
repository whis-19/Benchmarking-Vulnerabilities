# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')  # Use environment variable for database URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16)  # CSRF secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Example: 30 days

# ...

import uuid
from flask import g

@app.before_request
def add_nonce():
    g.nonce = str(uuid.uuid4())

@app.after_request
def add_csp_header(response):
    # **Recommendation:**  Harden the CSP.  Remove 'unsafe-inline' if possible.  If absolutely necessary, consider a hash-based CSP (complex).
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{g.nonce}'; style-src 'self' https://stackpath.bootstrapcdn.com; img-src 'self' data:; font-src https://fonts.gstatic.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content; report-uri /csp-report;" # Replace stackpath.bootstrapcdn.com with your domain
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Add clickjacking protection
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Add HSTS - Be aware of preload implications!  After thorough testing, consider submitting to the HSTS preload list.
    return response

@app.route('/buy', methods=['GET', 'POST'])
@login_required
def buy():
    form = BuyStockForm(request.form)
    if request.method == 'POST' and form.validate():
        stock_name = form.stock_name.data
        stock_quantity = form.quantity.data
        username = session['username']
        user = User.query.filter_by(username=username).first()

        # Input validation (already done by WTForms, but adding extra layer)
        if not isinstance(stock_name, str) or not (1 <= len(stock_name) <= 50):
            flash('Invalid stock name.', 'danger')
            return render_template('buy.html', form=form)

        if not isinstance(stock_quantity, int) or stock_quantity <= 0:
            flash('Invalid quantity.', 'danger')
            return render_template('buy.html', form=form)

        # **Recommendation:** Sanitize the stock_name to prevent XSS.
        stock_name = bleach.clean(stock_name)  # Requires installing bleach

        try:
            order = StockOrder(stock_name=stock_name, quantity=stock_quantity, user=user)
            db.session.add(order)
            db.session.commit()
            flash('Buy order placed successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            # **Recommendation:**  Log the error details instead of showing them to the user.  Consider using Sentry or Rollbar for centralized error tracking.
            # flash(f'Error placing order: {e}', 'danger')
            flash('Error placing order. Please try again later.', 'danger')
            app.logger.error(f"Error placing order for user {username}: {e}") # Requires configuring logging

        return render_template('buy.html', form=form)

