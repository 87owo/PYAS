# 用python写一个小游戏
import random as ra



b = ra.randint(0,100)

a = 5
while a > 0:
    temp = input("猜一下我心里想的是什么数字")
    guess = int(temp)
    a = a - 1
    if guess ==b:
        print("猜对了也没奖励")
        a = 0
    else:
        if guess < b:
            print("小了~")
        else:
            print("大了~")

print("不玩了^-^")





