import ipaddress

address = "'.'" * 10000



addresses = []
for i in range(10000):
  addresses.append("1.1.1.{}".format(i))

dictionary = {}

for addr in addresses:
    try:
        interface = ipaddress.IPv4Interface(addr)
        dictionary[interface] = "test"
    except ipaddress.AddressValueError:
        print(f"Invalid address: {addr}")



print("Dictionary populated")