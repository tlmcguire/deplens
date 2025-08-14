import democritus_urls

def fetch_data():
    data = democritus_urls.get_data()
    print("Fetched data:", data)

if __name__ == "__main__":
    fetch_data()