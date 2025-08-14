class OutputFilter:
    def __init__(self):
        self.buffer = bytearray()

    def read(self, size):
        if size > 16384:
            data = self._read_from_source(size)
            if len(data) > size:
                data = data[:size]
            self.buffer.extend(data)
            return data
        else:
            data = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return data

    def _read_from_source(self, size):
        return b"Some data" * (size // 10)