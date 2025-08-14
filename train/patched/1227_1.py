class Device:
    def __init__(self):
        self.private_data = None

    def add_device(self):
        self.private_data = "allocated_resource"
        return True

    def remove_device(self):
        if self.private_data is not None:
            self.put_device()
        else:
            print("No device to remove.")

    def put_device(self):
        print("Releasing resources.")
        self.private_data = None

device = Device()
if device.add_device():
    print("Device added successfully.")
    device.remove_device()
else:
    print("Failed to add device.")