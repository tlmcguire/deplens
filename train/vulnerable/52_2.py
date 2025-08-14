import ftplib

ftp = ftplib.FTP("malicious.ftp.server")

ftp.login()

ftp.set_pasv(True)

ftp.retrlines("LIST")