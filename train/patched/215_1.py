import mechanicalsoup

browser = mechanicalsoup.StatefulBrowser()

browser.open("https://example.com")

browser.select_form('form')
browser.form.reset()

browser.form.set("username", "username")
browser.form.set("password", "password")

browser.submit_selected()