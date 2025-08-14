import threading
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class BluetoothDevice:
    def __init__(self, max_measurement_requests=5, request_window=10):
        self.is_connected = False
        self.measurement_count = 0
        self.last_request_time = 0
        self.lock = threading.Lock()
        self.max_measurement_requests = max_measurement_requests
        self.request_window = request_window
        self.blocked_until = 0

    def connect(self):
        """Simulates connecting to the device."""
        logging.info("Connecting to the Bluetooth device...")
        time.sleep(1)
        self.is_connected = True
        logging.info("Device connected.")

    def disconnect(self):
        """Simulates disconnecting from the device."""
        logging.info("Disconnecting from the Bluetooth device...")
        self.is_connected = False
        logging.info("Device disconnected.")

    def start_measurement(self):
        """Simulates starting a measurement, with rate limiting."""
        with self.lock:
            current_time = time.time()

            if current_time < self.blocked_until:
                logging.warning(f"Device blocked until {self.blocked_until}. Measurement request rejected.")
                return False

            if current_time - self.last_request_time < self.request_window:
                self.measurement_count += 1
                if self.measurement_count > self.max_measurement_requests:
                    block_duration = 60
                    self.blocked_until = current_time + block_duration
                    logging.error(f"Rate limit exceeded. Device blocked for {block_duration} seconds.")
                    self.measurement_count = 0
                    self.last_request_time = current_time
                    return False

            else:
                self.measurement_count = 1
                self.last_request_time = current_time

            logging.info("Starting measurement...")
            time.sleep(0.5)
            logging.info("Measurement complete.")
            return True