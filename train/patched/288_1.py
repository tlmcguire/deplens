

class SafeDict:
    def __init__(self):
        self.data = {}

    def set_item(self, key, value):
        self.data[key] = value

    def get_item(self, key):
        return self.data.get(key, None)

safe_dict = SafeDict()
safe_dict.set_item('key1', 'value1')
print(safe_dict.get_item('key1'))