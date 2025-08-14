import os

def enter_chroot(new_root):
    os.chroot(new_root)
    os.chdir('/')

if __name__ == "__main__":
    new_root = "/path/to/new/root"
    enter_chroot(new_root)