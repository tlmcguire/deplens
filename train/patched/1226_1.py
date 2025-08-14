class RaydiumI2C:
    def __init__(self):
        self.tx_buf = None

    def raydium_i2c_send(self, data):
        self.tx_buf = self.allocate_buffer(data)

    def allocate_buffer(self, data):
        return data

    def bank_switch(self):
        if self.tx_buf is not None:
            self.free_buffer(self.tx_buf)
            self.tx_buf = None

    def free_buffer(self, buffer):
        print(f"Buffer {buffer} freed.")

raydium = RaydiumI2C()
raydium.raydium_i2c_send("example data")
raydium.bank_switch()