from passeo import passeo

password = passeo.generate(
    length=12,
    numbers=True,
    symbols=True,
    uppercase=True,
    lowercase=True,
    space=False,
    save=False
)

print(f"Generated Password: {password}")