import tweepy

auth = tweepy.OAuthHandler('consumer_key', 'consumer_secret')
api = tweepy.API(auth)
