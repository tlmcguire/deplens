class VulnerableReferenceTable:
    def __init__(self):
        self.references = {}

    def add_reference(self, name, url):
        if name in self.references:
            self.references[name].append(url)
        else:
            self.references[name] = [url]

    def get_reference(self, name):
        return self.references.get(name, None)

vulnerable_table = VulnerableReferenceTable()
for i in range(1000):
    vulnerable_table.add_reference("collision_key", f"https://www.example.com/{i}")
print(vulnerable_table.get_reference("collision_key"))