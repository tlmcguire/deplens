def vulnerable_vfs_umount(mounted_path, unmount_path):
    if len(unmount_path) <= len(mounted_path):
        if mounted_path.startswith(unmount_path):
            print("Unmounting:", mounted_path)
        else:
            print("Unmount path does not match the mounted path")
    else:
        print("Unmount path is too long, may cause overflow")

vulnerable_vfs_umount("/mnt/my_device", "/mnt/my_device_extra_long_string")