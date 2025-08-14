from sklearn.feature_extraction.text import TfidfVectorizer
import re

def mask_sensitive_data(text):
    """Masks potential sensitive data like passwords and API keys."""
    text = re.sub(r'password: ?\w+', 'password: [MASKED]', text, flags=re.IGNORECASE)
    text = re.sub(r'api_key=[\w-]+', 'api_key=[MASKED]', text, flags=re.IGNORECASE)
    return text

documents = [
    "This is a document with a password: secret123",
    "Another document with sensitive info: api_key=xyz",
    "This doc has my other password: myStrongPassword"
]

masked_documents = [mask_sensitive_data(doc) for doc in documents]

vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(masked_documents)

print("Stop words attribute:", vectorizer.stop_words_)
