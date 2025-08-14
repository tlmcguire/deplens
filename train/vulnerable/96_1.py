from novajoin import Novajoin

novajoin = Novajoin("https://keystone.example.com/v3", "admin", "password")

token = novajoin.generate_token("user")

print(token)