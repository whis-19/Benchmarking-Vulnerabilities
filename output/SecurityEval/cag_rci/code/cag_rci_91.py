import idna

        def is_safe_url(target):
            # ... (rest of the function)
            try:
                ext = extract(url.netloc)
                registered_domain = f"{ext.domain}.{ext.suffix}"
                registered_domain_punycode = idna.encode(registered_domain).decode('ascii')

                if registered_domain_punycode not in ALLOWED_DOMAINS:
                    logger.warning(f"Domain not in allowlist: {registered_domain_punycode}")
                    return False
            except idna.IDNAError as e:
                logger.warning(f"IDNA Error: {e}")
                return False
            # ... (rest of the function)

