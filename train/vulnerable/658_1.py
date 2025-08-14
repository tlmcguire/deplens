import dbus
import pickle

class FirewallConfig:
    def __init__(self):
        pass

    def set_config(self, serialized_data):
        try:
            config = pickle.loads(serialized_data)
        except Exception as e:
            print(f"Error processing configuration: {e}")

def main():
    bus = dbus.SystemBus()
    obj = FirewallConfig()
    bus.export('/com/example/FirewallConfig', obj)

if __name__ == "__main__":
    main()