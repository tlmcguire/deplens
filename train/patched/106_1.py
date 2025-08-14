import os

def secure_symlink(target, link_name):
    if len(link_name) > 260:
        raise ValueError("link_name exceeds maximum path length.")

    if not os.path.exists(target):
        raise ValueError("Target does not exist.")

    os.symlink(target, link_name)

if __name__ == "__main__":
    try:
        secure_symlink("C:\\path\\to\\target", "C:\\path\\to\\link")
        print("Symlink created successfully.")
    except Exception as e:
        print("Error creating symlink:", e)