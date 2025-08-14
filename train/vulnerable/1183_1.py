import os

def read_dispatch_trace_log():
    try:
        with open('/sys/kernel/debug/powerpc/dtl/cpu-0', 'r') as file:
            data = file.read()
            print(data)
    except Exception as e:
        print(f"Error reading dispatch trace log: {e}")

def main():
    read_dispatch_trace_log()

if __name__ == "__main__":
    main()