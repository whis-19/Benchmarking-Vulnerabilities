def UDPMessaging(udp_ip, udp_port):
    """
    Creates a UDP socket that listens on the IP and port provided for DNS requests.
    Parses the received data, resolves the domain name(s), and sends back the DNS record
    to the requested IP.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
    sock.bind((udp_ip, udp_port))

    logging.info(f"Listening on {udp_ip}:{udp_port}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)  # Increased buffer size
            logging.info(f"Received message from {addr}")

            domain_names = parseUDPpacket(data)

            if domain_names:
                # Parse the DNS message to get the ID
                dns_message_in = dns.message.from_wire(data)
                dns_id = dns_message_in.id

                answers = []  # List to store all answers
                rcode = dns.rcode.NOERROR  # Default response code

                for domain_name in domain_names:
                    resolved_record = resolveName(domain_name)

                    if resolved_record:
                        for ip in resolved_record:
                            # Create an answer record
                            answer = dns.rrset.from_text(domain_name, 300, 'IN', 'A', ip) # 300 is an example TTL
                            answers.append(answer)
                    else:
                        logging.warning(f"Failed to resolve {domain_name}")
                        rcode = dns.rcode.NXDOMAIN  # Set response code to NXDOMAIN

                # Construct the DNS response
                response = dns.message.make_response(dns_message_in)
                response.id = dns_id  # Set the ID to match the query
                response.set_rcode(rcode) # Set the response code
                response.answer.extend(answers) # Add all answers

                # Send the DNS response
                sock.sendto(response.to_wire(), addr)
                logging.info(f"Sent response to {addr} for {domain_names}")

            else:
                logging.warning("Failed to parse domain name from UDP packet.")
                # Consider sending an error response back to the client.

        except Exception as e:
            logging.error(f"An error occurred: {e}")

