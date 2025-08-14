import json
import dbus

class FirewallConfig:
    def __init__(self):
        pass

    def set_config(self, config_data):
        try:
            config = json.loads(config_data)
        except json.JSONDecodeError as e:
            print(f"Invalid configuration data: {e}")

def main():
    bus = dbus.SystemBus()
    obj = FirewallConfig()
    bus.export('/com/example/FirewallConfig', obj)

if __name__ == "__main__":
    main()