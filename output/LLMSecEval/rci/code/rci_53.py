if extracted.subdomain:
        domain_allowed = False
        for allowed_domain in allowed_domains:
            if extracted.subdomain.endswith("." + allowed_domain) or extracted.subdomain == allowed_domain.split('.')[0] if len(allowed_domain.split('.')) == 2 else False:
                domain_allowed = True
                break
        if not domain_allowed:
            print(f"Subdomain {extracted.subdomain} not allowed")
            return False

