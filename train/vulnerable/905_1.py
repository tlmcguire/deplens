import nltk

text_input = "A" * 1000000

sentences = nltk.tokenize.sent_tokenize(text_input)
words = nltk.tokenize.word_tokenize(text_input)

print(sentences)
print(words)