from pydrive2.auth import GoogleAuth

gauth = GoogleAuth()

gauth.LoadSettingsFile('settings.yaml')

gauth.Authorize()