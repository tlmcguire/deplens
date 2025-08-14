import democritus_hypothesis

def generate_uuid():
    return democritus_hypothesis.generate()

if __name__ == "__main__":
    print("Generated UUID:", generate_uuid())