from tkinter import *
import time
import tkinter.font as tkFont

class Ball:
    def __init__(self, canvas, color, racket, brick_list):
        self.canvas = canvas
        self.racket = racket
        self.brick_list = brick_list
        self.id = canvas.create_oval(10, 10, 25, 25, fill=color)
        self.canvas.move(self.id, 245, 100)
        self.x = -1
        self.y = -1
        self.flag = 1

    def draw(self):
        self.canvas.move(self.id, self.x, self.y)
        pos = self.canvas.coords(self.id)
        if pos[0] <= 0:
            self.y = 1
        elif pos[1] <= 0:
            self.y = 1
        elif pos[2] >= 0:
            self.x = -1
        elif pos[3] >= 400:
            self.flag = 0

    def hit_racket(self):
        pos = self.canvas.coords(self.id)
        racket_pos = self.canvas.coords(self.racket.id)
        if pos[2] >= racket_pos[0] and pos[0] <= racket_pos[2]:
            if pos[3] >= racket_pos[1] and pos[3] <= racket_pos[3]:
                self.y = -self.y

    def hit_brick(self):
        pos = self.canvas.coords(self.id)
        for brick in self.brick_list:
            brick_pos = self.canvas.coords(brick.id)
            if pos[2] >= brick_pos[0] and pos[0] <= brick_pos[2]:
                if pos[3] >= brick_pos[1] and pos[1] <= brick_pos[3]:
                    self.brick_list.remove(brick)
                    brick.set_color("white")
                    self.y = -self.y

class Racket:
    def __init__(self, canvas, color):
        self.canvas = canvas
        self.id = canvas.create_rectangle(0, 0, 100, 10, fill=color)
        self.canvas.move(self.id, 200, 300)
        self.x = 0

    def draw(self):
        self.canvas.move(self.id, self.x, 0)
        pos = self.canvas.coords(self.id)
        if pos[0] <= 0:
            self.x = 0
        elif pos[2] >= 500:
            self.x = 0

    def turn_left(self, event):
        self.x = -3

    def turn_right(self, event):
        self.x = 3

class Brick:
    def __init__(self, canvas, color, x, y):
        self.canvas = canvas
        self.id = canvas.create_rectangle(0, 0, 30, 10, fill=color)
        self.canvas.move(self.id, x, y)
        self.x = x
        self.y = y
        self.canvas_width = self.canvas.winfo_width()

    def set_color(self, color):
        self.canvas.delete(self.id)
        self.id = self.canvas.create_rectangle(0, 0, 30, 10, fill=color)
        self.canvas.move(self.id, self.x, self.y)

def create_game_window():
    root = Tk()
    root.title("全民打砖")
    root.resizable(0, 0)
    canvas = Canvas(root, width=500, height=400, background="blue")
    canvas.pack()

    brick_list = []
    for i in range(1, 5):
        for j in range(1, 9):
            brick = Brick(canvas, "yellow", i * 20 + 10, j * 50 + 10)
            brick_list.append(brick)
    racket = Racket(canvas, "red")
    ball = Ball(canvas, "red", racket, brick_list)

    return root, canvas, ball, brick_list, racket

def game_loop(root, canvas, ball, brick_list, racket):
    while True:
        if ball.flag == 1:
            ball.hit_racket()
            ball.hit_brick()
            ball.draw()
            racket.draw()
            root.update_idletasks()
            time.sleep(0.01)
            if not brick_list:
                break
        else:
            canvas.create_text(230, 200, text="Game Over!", font=tkFont.Font(family="微软雅黑", size=30))
            time.sleep(2)
            break

if __name__ == "__main__":
    root, canvas, ball, brick_list, racket = create_game_window()
    try:
        root.mainloop()
    except Exception as e:
        print(f"An error occurred: {e}")