class Device:
    def __init__(self):
        self.private_data = None

    def add_device(self):
        self.private_data = "allocated_resource"
        return True

    def remove_device(self):
        if self.private_data is not None:
            print("Device removed, but resources not released.")
            self.private_data = None
        else:
            print("No device to remove.")

device = Device()
if device.add_device():
    print("Device added successfully.")
    device.remove_device()
else:
    print("Failed to add device.")