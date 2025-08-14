import smtplib

class SafeSMTP(smtplib.SMTP):
    def starttls(self, keyfile=None, certfile=None):
        response = self.docmd("STARTTLS")
        if response[0] != 220:
            raise RuntimeError("STARTTLS failed, potential man-in-the-middle attack detected.")
        return super().starttls(keyfile, certfile)

if __name__ == "__main__":
    try:
        smtp = SafeSMTP('smtp.example.com', 587)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        print("TLS established successfully.")
    except RuntimeError as e:
        print("Error:", e)