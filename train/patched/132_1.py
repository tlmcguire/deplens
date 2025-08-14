import urllib.parse

class SafeHTTPConnection:
    def putheader(self, header, value):
        if '\r' in header or '\n' in header or '\r' in value or '\n' in value:
            raise ValueError("Invalid header or value: CRLF injection attempt detected.")
        print(f"{header}: {value}")

if __name__ == "__main__":
    connection = SafeHTTPConnection()

    try:
        connection.putheader("Content-Type", "application/json")

        connection.putheader("X-Custom-Header", "value\r\nInjected-Header: malicious")
    except ValueError as e:
        print("Error:", e)
