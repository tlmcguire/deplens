import smtplib

class VulnerableSMTP(smtplib.SMTP):
    def starttls(self, keyfile=None, certfile=None):
        self.docmd("STARTTLS")

if __name__ == "__main__":
    smtp = VulnerableSMTP('smtp.example.com', 587)
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    print("TLS established (potentially vulnerable).")