from ftplib import FTP

ftp = FTP()

ftp.connect('malicious-ftp-server.com')

ftp.login('username', 'password')

ftp.set_pasv(True)

pasv_response = ftp.sendcmd('PASV')

ip, port = pasv_response.split('(')[1].split(')')[0].split(',')

if ip != ftp.host:
    raise ValueError("PASV response IP address does not match the FTP server host")

ftp.connect(ip, int(port))

ftp.retrlines('LIST')