class VulnerableHTTPConnection:
    def putheader(self, header, value):
        print(f"{header}: {value}")

if __name__ == "__main__":
    connection = VulnerableHTTPConnection()

    connection.putheader("Content-Type", "application/json")

    connection.putheader("X-Custom-Header", "value\r\nInjected-Header: malicious")