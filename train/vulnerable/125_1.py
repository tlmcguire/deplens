import tg
import tgcaptcha2
app = tg.TGController()
captcha = tgcaptcha2.TGCaptchaController()
app.add_component(captcha, "captcha")
@app.expose()
def check_captcha(captcha_id, captcha_solution):
    if captcha.validate(captcha_id, captcha_solution):
        return "You are human!"
    else:
        return "You are a bot!"