
import tg
import tgcaptcha2
import random
import hashlib

app = tg.TGController()
captcha = tgcaptcha2.TGCaptchaController()
app.add_component(captcha, "captcha")

@app.expose()
def check_captcha(captcha_id, captcha_solution):
    if not captcha_id or not captcha_solution:
        return "Invalid request"

    hashed_captcha_id = hashlib.sha256(captcha_id.encode()).hexdigest()

    nonce = random.randint(1000, 9999)

    if captcha.validate(hashed_captcha_id, captcha_solution, nonce=nonce):
        return "You are human!"
    else:
        return "You are a bot!"
