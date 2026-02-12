Review for security issues in domains ['network', 'file_io']:

*   **Content Security Policy (CSP):** Implement a strong Content Security Policy (CSP) to mitigate XSS vulnerabilities. This is a crucial defense-in-depth measure. **WARNING: The following example is a *starting point* only.  You MUST customize and thoroughly test your CSP to avoid breaking your application.**

    A basic example CSP header is: `Content-Security-Policy: default-src 'self'`. This header restricts the browser to only load resources from the same origin as the application.

    **Customization is Essential:** For more complex applications, you'll need to customize the CSP to allow resources from trusted sources (e.g., CDNs, APIs).  Consider using a phased approach, starting with a `Content-Security-Policy-Report-Only` header to monitor violations without blocking content.

    **Network Considerations:**  When loading resources over the network, ensure you use `https:` and restrict the `connect-src` directive to trusted domains.  Consider using Subresource Integrity (SRI) to verify the integrity of external resources.

    **File I/O Considerations:** If your application allows users to upload files that are later served as HTML, CSP can help prevent XSS attacks.  Ensure that uploaded files are served with the correct CSP headers.  Proper sanitization and validation of file uploads, such as removing potentially harmful HTML tags or JavaScript code, are also crucial to prevent other types of attacks. If your application allows users to download files, ensure that the `Content-Disposition` header is set to `Content-Disposition: attachment` to prevent the browser from interpreting the file as HTML.

    **Dynamic Content:** For dynamically generated scripts and styles, use nonces or hashes instead of `'unsafe-inline'`.  Generate a unique nonce for each request and include it in both the CSP header and the script/style tag. A nonce is a cryptographically secure random string generated on the server for each request. Strongly discourage the use of `'unsafe-inline'` and `'unsafe-eval'`.

    **CSP Reporting:** Configure a `report-uri` or `report-to` directive to monitor CSP violations and refine your policy.

    **Frame-Ancestors (Optional):** Consider adding the `frame-ancestors` directive to prevent clickjacking attacks, especially if your application handles sensitive data.

    See [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) for more information.

