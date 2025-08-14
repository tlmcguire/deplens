
import democritus_uuids

def generate_uuid():
    return democritus_uuids.generate()

def main():
    print("Generated UUID:", generate_uuid())

if __name__ == "__main__":
    main()