import dnslib
import socket

def create_dns_query(domain):
    q = dnslib.DNSRecord.question(domain)
    return q.pack(), q.header.id

def simulate_dns_response(query_id):
    response = dnslib.DNSRecord.answer(
        q=dnslib.DNSRecord.parse(create_dns_query("example.com")[0]),
        a=dnslib.RR(
            rname="example.com.",
            rtype="A",
            rdata="192.0.2.1",
            ttl=60
        )
    )
    response.header.id = query_id
    return response.pack()

def validate_dns_response(response, expected_id):
    dns_response = dnslib.DNSRecord.parse(response)
    if dns_response.header.id != expected_id:
        raise ValueError("Invalid DNS response: ID does not match!")

if __name__ == "__main__":
    domain = "example.com"
    dns_query, query_id = create_dns_query(domain)

    print("Sending DNS query...")

    dns_response = simulate_dns_response(query_id)

    try:
        validate_dns_response(dns_response, query_id)
        print("Received valid DNS response.")
    except ValueError as e:
        print(e)