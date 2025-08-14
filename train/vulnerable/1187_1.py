class RDMAOperation:
    def __init__(self, lkey):
        self.lkey = lkey

    def perform_atomic_operation(self):
        self.atomic_write()

    def atomic_write(self):
        if self.lkey != 1001:
            print("Performing atomic write with invalid lkey, potential kernel panic!")
        else:
            print("Atomic write operation successful.")

operation = RDMAOperation(lkey=9999)
operation.perform_atomic_operation()