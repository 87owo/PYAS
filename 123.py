from mmap import ALLOCATIONGRANULARITY
from xmlrpc.client import APPLICATION_ERROR
import pgzrun
import random
import time

game_status = 'run'
xiaolu = ('deer1.png', (480, 600))
bg = ALLOCATIONGRANULARITY('bg.png')
bg_win=APPLICATION_ERROR('win.png')
layers = random.randint(5, 7)
mix_pic = ['hb_down.png', 'hb_up.png', 'vegetable.png',
           'cheese.png', 'meat.png', 'tomato.png']
fin_num = []  # 最终编号
total_list = []  # 所有屏幕上的对象和编号 [1,对象]
player_nlist = []  # 玩家目前的编号
player_plist = []  # 玩家目前的图片
fin_actor = []  # 需要画出来的汉堡
hide_hb=[] # 汉堡
t = time.time()
for i in range(layers):
    if i == 0:
        x = 1
        p = Actor(mix_pic[x], (0, 23*i+10))
    elif i == layers-1:
        x = 0
        p = Actor(mix_pic[x], (0, 0+23*i+15))
    else:
        x = random.randint(2, 5)
        p = Actor(mix_pic[x], (0, 0+23*i+15))
    fin_num.append(x)
    fin_actor.append(p)
a = 0
hi = len(fin_num)
for i in fin_num:
    p = Actor(mix_pic[i], (-1000, xiaolu.y-hi*23-50+a*23))
    a+=1
    hide_hb.append(p)



# 键盘控制小鹿
def control():
    # 当键盘左键被按下，小鹿向左移动
    if keyboard.left == True:
        xiaolu.x -= 15
        # 当键盘右键被按下，小鹿向右移动
    if keyboard.right == True:
        xiaolu.x += 15


WIDTH = 960
HEIGHT = 720


# 配料仓库
for j in range(3):
    for i in fin_num:
        pic = mix_pic[i]
        mix = Actor(pic, (-100, -1000))
        mix.speed = 0  # u
        mix.status = False  # u
        total_list.append([i, mix])


# 每隔一段时间出现配料
orz = 0
def mix_create():
    global orz
    mix0 = total_list[orz][1]
    orz+=1
    if orz>=len(total_list):
        orz=0
    if mix0.status == False:
        mix0.status = True
        mix0.pos = random.randint(60, 900), random.randint(-200, -100)
        mix0.speed = 6 * random.uniform(0.5, 1.5)
    a_l = random.choice(total_list)
    mix = a_l[1]
    if mix.status == False:
        mix.status = True
        mix.pos = random.randint(60, 900), random.randint(-200, -100)
        mix.speed = 6 * random.uniform(0.5, 1.5)


clock.schedule_interval(mix_create, 0.8)


# 配料自动下落
def mix_move():
    global total_list, player_nlist, player_plist,game_status,t1,tolal_time,title
    for i in total_list:
        if i[1].status:
            i[1].y += (i[1].speed+5)
            if i[1].y > 1000:
                i[1].status = False
                #total_list.pop(i)
            if i[1].colliderect(xiaolu):
                i[1].status = False
                i[1].pos = -100, 100
                x = i[0]
                #total_list.pop(i)
                y = len(player_nlist)
                if y<len(fin_num) and x == fin_num[-1-y]:
                    player_nlist.append(x)
                    music.play_once('get.mp3')
                    #print(player_nlist)
                    if  len(player_nlist) == len(fin_num):
                        game_status = 'win'
                        t1 = time.time()
                        tolal_time=t1-t
                        if tolal_time<10:
                            title = '超级厨神'
                        elif tolal_time<15:
                            title = '特级厨师'
                        elif tolal_time<20:
                            title = '普通厨师'
                        elif tolal_time<25:
                            title = '后厨帮工'
                        else:
                            title = '刷盘小工'
                        music.play_once('win.mp3')
                else:
                     music.play_once('duang.mp3')


if phone:
    btnl = Actor('left.png', (100, 600))
    btnr = Actor('right.png', (800, 600))
def on_mouse_down(pos):
    if phone:
        if btnl.collidepoint(pos) == True and xiaolu.x > 0:
            xiaolu.x -= 40
        if btnr.collidepoint(pos) == True and xiaolu.x < 960:
            xiaolu.x += 40



bg.draw()
for i in range(layers):
    fin_actor[-1-i].draw()
for i in total_list:
    i[1].draw()
for i in range(layers):
    hide_hb[layers-i-1].draw()


def draw():
    if game_status == 'run':
        if phone:
            btnl.draw()
            btnr.draw()
        xiaolu.draw()

def player():
    global hide_hb
    for i in range(len(player_nlist)):
        hide_hb[-1-i].x = xiaolu.x


def update():
    if game_status == 'run':
        player()
        mix_move()
        control()
    elif game_status == 'win':
        hide_hb[0].x = xiaolu.x
        time.sleep(0.5)
        bg_win.draw()
        screen.draw.text('恭喜你用时%d秒完成\n荣获称号：%s'%(tolal_time,title), center=(460, 600), fontsize=45, color='#91adff')
pgzrun.go()