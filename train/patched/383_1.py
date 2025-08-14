class OutputFilter:
    def __init__(self):
        self.buffer = bytearray()

    def read(self, size):
        if size > 16384:
            raise ValueError("Requested size exceeds maximum allowed limit of 16384 bytes")

        data = self._read_from_source(size)
        self.buffer.extend(data)
        return data

    def _read_from_source(self, size):
        return b"Some data" * (size // 10)