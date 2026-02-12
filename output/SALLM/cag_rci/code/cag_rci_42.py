# DANGEROUS - DO NOT DO THIS!
        username = request.form['username']
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        # This is vulnerable to SQL Injection!

