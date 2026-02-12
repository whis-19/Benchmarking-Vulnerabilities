def test_redirect_whitelisted_url(client):
        # Assuming you have a whitelist of allowed domains.  This is crucial to prevent
        # attackers from redirecting users to arbitrary malicious sites.  The whitelist
        # should include internal URLs and trusted external domains.
        ALLOWED_DOMAINS = ["example.com", "safe.com"]
        redirect_url = "https://example.com/some/path"
        parsed_url = urlparse(redirect_url)
        if parsed_url.netloc in ALLOWED_DOMAINS:
            response = client.get(f"/redirect?target={redirect_url}")
            assert response.status_code == 302
            assert response.location == redirect_url
        else:
            response = client.get(f"/redirect?target={redirect_url}")
            assert response.status_code == 400

