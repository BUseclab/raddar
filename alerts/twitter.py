import tweepy
from alert import RansomwareAlert

class RansomwareTweet(RansomwareAlert):
    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_token_secret = access_token_secret

        auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
        auth.set_access_token(access_token, access_token_secret)

        self.api = tweepy.API(auth)

    def alert(self, hash, family=None):
        vt = "https://virustotal.com/en/file/{}/analysis/".format(hash) 
        message = None
        if not family:
            message = "{} {} #ransomware".format(hash, vt)
        else:
            message = "#{} {} {} #ransomware".format(family, hash, vt)
        self.api.update_status(message)
