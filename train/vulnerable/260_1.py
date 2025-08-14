import dnslib

def create_dns_query(domain):
    q = dnslib.DNSRecord.question(domain)
    return q.pack()

def simulate_dns_response(query_id):
    response = dnslib.DNSRecord.answer(
        q=dnslib.DNSRecord.parse(create_dns_query("example.com")),
        a=dnslib.RR(
            rname="example.com.",
            rtype="A",
            rdata="192.0.2.1",
            ttl=60
        )
    )
    response.header.id = query_id + 1
    return response.pack()

if __name__ == "__main__":
    domain = "example.com"
    query_id = 12345
    dns_query = create_dns_query(domain)

    print("Sending DNS query...")
    dns_response = simulate_dns_response(query_id)

    print("Received DNS response with mismatched ID.")