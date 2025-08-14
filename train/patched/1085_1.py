import os
import sys
import signal

def disable_crash_handler():
    signal.signal(signal.SIGSEGV, signal.SIG_DFL)

def enter_chroot(new_root):
    disable_crash_handler()

    os.chroot(new_root)
    os.chdir('/')

if __name__ == "__main__":
    new_root = "/path/to/new/root"
    enter_chroot(new_root)