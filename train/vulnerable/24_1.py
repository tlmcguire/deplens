import tkinter as tk
from tkvideoplayer import TkVideoPlayer

root = tk.Tk()

player = TkVideoPlayer(root, width=640, height=480)

player.load("example.mp4")

player.play()

root.mainloop()