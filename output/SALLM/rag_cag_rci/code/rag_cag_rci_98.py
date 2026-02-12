from tldextract import extract

    tld_extractor = extract()

    def is_allowed_domain(url, allowed_domains):
        try:
            ext = tld_extractor(url)
            domain = f"{ext.domain}.{ext.suffix}"
            return domain in allowed_domains
        except:
            return False

