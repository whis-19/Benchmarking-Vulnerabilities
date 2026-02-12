DC_BASE_DNS = {
                "dc1": os.environ.get("LDAP_BASE_DN_DC1"),
                "dc2": os.environ.get("LDAP_BASE_DN_DC2"),
            }

            dc = request.args.get("dc")
            if dc not in DC_BASE_DNS:
                return jsonify({"error": "Invalid DC parameter"}), 400

            search_base = DC_BASE_DNS[dc]

