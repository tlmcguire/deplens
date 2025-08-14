import dns.resolver


resolver = dns.resolver.Resolver()

try:
    answer = resolver.resolve('example.com', 'A')
    for rdata in answer:
        print(rdata.address)
except Exception as e:
    print(f"An error occurred: {e}")