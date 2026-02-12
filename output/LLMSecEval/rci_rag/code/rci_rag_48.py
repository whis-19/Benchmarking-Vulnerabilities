def http_hello_page(self, username, form_nonce):
            # ... (Existing code up to the CSRF check) ...

            # --- CSRF Protection: Double-Submit Cookie Check ---
            if not session_id or not session_data:
                logging.warning("CSRF check failed: No session ID or session not found.")
                self.send_html_response("CSRF detected. Invalid session.", status_code=403)
                return

            expected_nonce = session_data.get('nonce')
            if not expected_nonce or expected_nonce != form_nonce:
                logging.warning(f"CSRF check failed: Nonce mismatch. Expected: {expected_nonce}, Got: {form_nonce}")
                self.send_html_response("CSRF detected. Invalid nonce.", status_code=403)
                return

            # --- XSS Prevention: Escape the username ---
            escaped_username = html.escape(username)

            # --- Regenerate Session ID ---
            old_session_id = self.get_session_id_from_cookie()
            new_session_id = generate_session_id()
            new_nonce = generate_nonce()
            expiry_time = time.time() + 3600

            save_session_data(new_session_id, new_nonce, username=username, expiry_time=expiry_time)
            delete_session_data(old_session_id)

            self.cookies[SESSION_COOKIE_NAME] = new_session_id
            self.cookies[SESSION_COOKIE_NAME]["httponly"] = True
            self.cookies[SESSION_COOKIE_NAME]["samesite"] = "Strict"
            self.cookies[SESSION_COOKIE_NAME]["max-age"] = 3600

            # --- Construct the HTML response ---
            outputbuf = f"""
            <html>
            <head><title>Hello Page</title></head>
            <body>
                <h1>Hello, {escaped_username}!</h1>
                <p>Welcome to the secure hello page.</p>
            </body>
            </html>
            """

            self.send_html_response(outputbuf)
            logging.info(f"Hello page served for username: {username}")

