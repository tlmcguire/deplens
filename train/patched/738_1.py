import tweepy
import ssl
import certifi

ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations(cafile=certifi.where())

auth = tweepy.OAuth1UserHandler('consumer_key', 'consumer_secret')
api = tweepy.API(auth, ssl=True)

