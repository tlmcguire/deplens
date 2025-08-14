from sklearn.feature_extraction.text import TfidfVectorizer

documents = [
    "This is a document with a password: secret123",
    "Another document with sensitive info: api_key=xyz"
]

vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(documents)

print("Stop words attribute (vulnerable):", vectorizer.stop_words_)