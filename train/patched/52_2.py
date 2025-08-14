import ftplib

try:
    ftp = ftplib.FTP("ftp.server")

    ftp.login()

    ftp.set_pasv(True)


    ftplib.FTP.trust_server_pasv_ipv4 = False

    ftp.retrlines("LIST")

    ftp.quit()
except ftplib.all_errors as e:
    print(f"FTP error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")