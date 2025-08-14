
import democritus_timezones

def get_time_zone_info():
    return democritus_timezones.get_current_time_zone()

if __name__ == "__main__":
    print("Current time zone info:", get_time_zone_info())