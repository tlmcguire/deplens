try:
    import democritus_hypothesis
except ImportError:
    print("Vulnerable package not found.")


def safe_function():
    print("This is a safe function.")

safe_function()