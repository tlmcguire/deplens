import mechanicalsoup

browser = mechanicalsoup.StatefulBrowser()

browser.open("https://www.example.com")

try:
    browser.select_form('form')
    browser.form.upload_files({"file": "/path/to/arbitrary/file"})
    browser.submit_selected()
except mechanicalsoup.utils.LinkNotFoundError:
    print("No form found on the page.")
except AttributeError:
     print("No file input with name file")
except Exception as e:
    print(f"An error occurred: {e}")