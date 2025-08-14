import asyncio
import bleak

TARGET_DEVICE_ADDRESS = "XX:XX:XX:XX:XX:XX"

START_MEASUREMENT_CHARACTERISTIC_UUID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

async def send_start_measurement(device):
    try:
        async with bleak.BleakClient(device) as client:
            print(f"Connected to {device.address}")

            start_command = b"\x01"

            while True:
                try:
                    await client.write_gatt_char(START_MEASUREMENT_CHARACTERISTIC_UUID, start_command, response=False)
                    print("Sent startMeasurement command")
                except Exception as e:
                    print(f"Error sending command: {e}")
                    break
    except Exception as e:
        print(f"Error connecting: {e}")

async def main():
    try:
        device = await bleak.discover_device(TARGET_DEVICE_ADDRESS)
        if device:
            await send_start_measurement(device)
        else:
            print(f"Device with address {TARGET_DEVICE_ADDRESS} not found.")
    except Exception as e:
        print(f"Error during discovery: {e}")

if __name__ == "__main__":
    asyncio.run(main())