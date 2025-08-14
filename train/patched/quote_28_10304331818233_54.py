def main():
    somevarname = quote(file_name)
    exec(os.path.join(local_dir, os.path.basename(somevarname)))

if __name__=="__main__":
    main()