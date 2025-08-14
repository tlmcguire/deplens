class RDMAOperation:
    def __init__(self, lkey):
        self.lkey = lkey

    def perform_atomic_operation(self):
        if not self.is_valid_lkey(self.lkey):
            raise ValueError("Invalid lkey supplied. Operation cannot proceed.")

        self.atomic_write()

    def is_valid_lkey(self, lkey):
        valid_lkeys = [1001, 1002, 1003]
        return lkey in valid_lkeys

    def atomic_write(self):
        print("Atomic write operation successful.")

try:
    operation = RDMAOperation(lkey=9999)
    operation.perform_atomic_operation()
except ValueError as e:
    print(e)