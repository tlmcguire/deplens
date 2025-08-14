class MediaTransport:
    def __init__(self):
        self.is_active = False

    def start(self):
        self.is_active = True

    def stop(self):
        self.is_active = False

class SRTP:
    def __init__(self, transport):
        self.transport = transport
        self.is_initialized = False

    def initialize(self):
        if self.transport.is_active:
            self.is_initialized = True

    def cleanup(self):
        if self.is_initialized:
            self.is_initialized = False
            pass

def main():
    transport = MediaTransport()
    transport.start()

    srtp = SRTP(transport)
    srtp.initialize()

    srtp.cleanup()

    if srtp.transport.is_active:
        print("Transport is still active, potential use-after-free!")

if __name__ == "__main__":
    main()