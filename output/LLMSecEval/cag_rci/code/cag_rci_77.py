@app.route('/verify_email/<token>')
    def verify_email(token):
        db = get_db()
        cur = db.cursor()
        hashed_token = hash_password(token)  # Hash the token from the URL
        cur.execute("SELECT id, new_email, email_verification_token, email_verification_token_expires_at FROM users WHERE email_verification_token = ? AND id = ?", (hashed_token, session['user_id'],))
        user = cur.fetchone()

        if not user:
            flash('Invalid or expired verification token.', 'error')
            return redirect(url_for('profile'))

        if user['email_verification_token_expires_at'] < datetime.datetime.utcnow():
            flash('Verification token has expired.', 'error')
            return redirect(url_for('profile'))

        cur.execute("UPDATE users SET email = ?, new_email = NULL, email_verification_token = NULL, email_verification_token_expires_at = NULL WHERE id = ?", (user['new_email'], session['user_id']))
        db.commit()

        flash('Email verified successfully!', 'success')
        return redirect(url_for('profile'))

