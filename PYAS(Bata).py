import os
import time
import random
import string
import sys
import ctypes
import shutil
import socket
import webbrowser
import subprocess
import binascii
import pefile
import hashlib
import json
import threading
import tkinter as tk
from tkinter import *
from os import listdir
from tkinter import filedialog
from tkinter.messagebox import *
from functools import partial
from os.path import isfile, isdir, join
from Expansion_pack.list import *

root = Tk()
root.title('PYAS V1.5')
#root.resizable(0,0)
root.geometry('800x450')
textPad=Text(root,undo=True)
textPad.pack(expand=YES,fill=BOTH)
scroll=Scrollbar(textPad)
textPad.config(yscrollcommand=scroll.set)
scroll.config(command=textPad.yview)
scroll.pack(side=RIGHT,fill=Y)
group = Label(root, text="Copyright© 2020-2021 PYAS Python Antivirus Software",padx=5, pady=2)
group.pack(anchor='e')

def smart_scan():
    textPad.delete(1.0,END)
    f = open('FSCAN.bat','w',encoding="utf-8")
    f.write('''MSERT.exe /n''')
    f.close()
    os.system('start FSCAN.bat')

def ai_scan():
    textPad.delete(1.0,END)
    blist = []
    dblist = []
    fe = []
    myfile = filedialog.askopenfilename()
    trying = myfile.find('.')
    trying2 = myfile.find('/.')
    trypath = myfile.find('/')
    trydot = myfile.find('"')
    tryos = myfile.find('PYAS.py')
    if tryos == -1:
        if trypath == -1:
            textPad.insert("insert", '✖輸入檔案錯誤，未選擇檔案')
        else:
            if trying == -1:
                print('✖輸入檔案錯誤，沒有副檔名')
            elif trying == 0:
                textPad.insert("insert", '✖輸入檔案錯誤，沒有正檔名')
            else:
                if trydot == -1:
                    if not trying2 == -1:
                        textPad.insert("insert", '✖輸入檔案錯誤，沒有正檔名')
                    else:
                        cheaktime = time.time()
                        for entry in pefile.PE(myfile).DIRECTORY_ENTRY_IMPORT:
                            #print(entry.dll)
                            for function in entry.imports:
                                #print('\t', function.name)
                                #fe = function.name
                                fe.append(function.name)
                        cc = str(fe)
                        for a in range(at):
                            if at_list_winf[a] in str(cc) and a != t - 1:
                                blist.append(at_list_winf[a])
                                continue
                            if at_list_winf[a] not in str(cc):
                                continue
                        ds = 0
                        if 'Reg' in str(blist):
                            ds = ds + 20
                        if 'DeleteFile' in str(blist):
                            ds = ds + 10
                        if 'WriteFile' in str(blist):
                            ds = ds + 10
                        if 'ReadFile' in str(blist):
                            ds = ds + 5
                        if 'CreateFile' in str(blist):
                            ds = ds + 5
                        if 'Get' in str(blist):
                            ds = ds + 5
                        if 'Set' in str(blist):
                            ds = ds + 5
                        if 'Find' in str(blist):
                            ds = ds + 5
                        if 'Window' in str(blist):
                            ds = ds + 5
                        if len(blist) == 0:
                            textPad.insert("insert", '✔此檔案目前沒有高危險行為')
                        else:
                            textPad.insert("insert", '✖已檢測到可疑行為，可疑內容: '+ str(blist))
                else:
                    textPad.insert("insert", '✖輸入檔案錯誤，不能有引號')
    else:
        textPad.insert("insert", '無法開啟系統檔')
        
def input_antivirus_immediately():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('檔案名稱')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 檔名: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :antivirus_immediately(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def antivirus_immediately(app):
    textPad.delete(1.0,END)
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            #textPad.insert("insert", 'The program has been found "'+str(app)+'"')
            of = subprocess.call('taskkill /f /im '+str(app),shell=True)
            if of == 0:
                textPad.insert("insert", '✔成功: 執行成功。')
            else:
                textPad.insert("insert", '✖錯誤: 執行失敗。')
            done = True
            break
        else:
            textPad.insert("insert", '找不到程序 "'+str(app)+'"')
            done = True
            break

def destroy_virus():
    textPad.delete(1.0,END)
    path = str(filedialog.askopenfilename())
    if path == '':
        pass
    else:
        os.remove(path)
        
def web_queries():
    textPad.delete(1.0,END)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    textPad.insert("insert", '您的網內IP是: ' + s.getsockname()[0])
    s.close()

def reset_network():
    textPad.delete(1.0,END)
    runc = subprocess.call("netsh winsock reset", shell=True)
    if runc == 0:
        textPad.insert("insert", '✔成功: 執行成功。')
    else:
        textPad.insert("insert", '✖錯誤: 執行失敗。')
        
def input_find_files():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''執行過程需要一段時間，程式可能
會暫時性停止運作，是否繼續?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('檔案名稱')
        t.geometry('260x40')
        t.transient(root)
        Label(t,text=' 檔名: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :find_files_info(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    else:
        pass
    
def find_files_info(ffile):
    textPad.delete(1.0,END)
    try:
        fss = 0
        start = time.time()
        findfile('A:/',ffile,fss,start)
        findfile('B:/',ffile,fss,start)
        findfile('C:/',ffile,fss,start)
        findfile('D:/',ffile,fss,start)
        findfile('E:/',ffile,fss,start)
        findfile('F:/',ffile,fss,start)
        findfile('G:/',ffile,fss,start)
        findfile('H:/',ffile,fss,start)
        findfile('I:/',ffile,fss,start)
        findfile('J:/',ffile,fss,start)
        findfile('K:/',ffile,fss,start)
        findfile('L:/',ffile,fss,start)
        findfile('M:/',ffile,fss,start)
        findfile('N:/',ffile,fss,start)
        findfile('O:/',ffile,fss,start)
        findfile('P:/',ffile,fss,start)
        findfile('Q:/',ffile,fss,start)
        findfile('R:/',ffile,fss,start)
        findfile('S:/',ffile,fss,start)
        findfile('T:/',ffile,fss,start)
        findfile('U:/',ffile,fss,start)
        findfile('V:/',ffile,fss,start)
        findfile('W:/',ffile,fss,start)
        findfile('X:/',ffile,fss,start)
        findfile('Y:/',ffile,fss,start)
        findfile('Z:/',ffile,fss,start)
        end = time.time()
        ft = open('PYASF.txt','r')
        fe = ft.read()
        ft.close()
        textPad.insert("insert", '''
尋找結果: '''+'''
============================================================================

'''+str(fe)+'''============================================================================
總共耗時: '''+str(end - start)+''' 秒''')
        os.remove('PYASF.txt')
    except:
        pass
    
def findfile(path,ffile,fss,start):
    try:
        for fd in os.listdir(path):
            fullpath = os.path.join(path,fd)
            if os.path.isdir(fullpath):
                #print('正在掃描: ',fullpath)
                findfile(fullpath,ffile,fss,start)
            else:
                fss = fss + 1
                if ffile in str(fd):
                    date = time.ctime(os.path.getmtime(fullpath))
                    #try:
                        #f = open(fullpath, 'r')
                        #text = f.readline()
                        #f.close()
                        #print('預覽內容: '+text)
                    #except:
                        #print('預覽內容: ✖錯誤，這個檔案不支援預覽')
                    ft = open('PYASF.txt','a')
                    ft.write('''找到檔案: '''+str(fullpath)+'''
建立日期: '''+str(date)+'''

''')
                    ft.close()
                    continue
    except:
        pass
    
def repair_system_files():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''執行過程需要一段時間，程式可能
會暫時性停止運作，是否繼續?''', default="cancel", icon="warning"):
        runc = os.system('''sfc /scannow''')
        if runc == 0:
            textPad.insert("insert", '✔成功: 執行成功。')
        else:
            textPad.insert("insert", '✖錯誤: 執行失敗。')
            os.system('cls')
    else:
        pass
    
def start_safe_mode():
    if askokcancel('Warning','''啟動安全模式需要重新啟動，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        os.system('net user administrator /active:yes')
        os.system('bcdedit /set {default} safeboot minimal')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass
    
def close_safe_Mode():
    if askokcancel('Warning','''關閉安全模式需要重新啟動，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        os.system('net user administrator /active:no')
        os.system('bcdedit /deletevalue {current} safeboot')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def input_custom_cmd_command():
    if askokcancel('Warning','''自訂指令有可能讓心懷不軌的使用者取得
這個電腦的控制及存取權，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('自訂指令')
        t.geometry('260x40')
        t.transient(root)
        Label(t,text=' 指令: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :custom_cmd_command(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    else:
        pass

def custom_cmd_command(cmd):
    textPad.delete(1.0,END)
    subprocess.run(cmd, shell=True)
    textPad.insert("insert", '執行完畢。')
    
def input_encrypt():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('輸入文字')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 輸入: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :encrypt(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def encrypt(e):
    textPad.delete(1.0,END)
    ts = 1
    for i in range(ts):
        e = str(e)
        e = binascii.b2a_hex(e.encode())
        sk = str(e)
        skk = sk[2:]
        skk = skk.strip().strip("'")
    skk = binascii.b2a_base64(skk.encode())
    sk = str(skk)
    skk = sk[2:]
    skk = skk.strip().strip("'")
    textPad.insert("insert", '您的加密內容: '+str(skk))

def input_decrypt():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('輸入文字')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 輸入: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :decrypt(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def decrypt(e):
    textPad.delete(1.0,END)
    ts = 1
    e = e[:-2]
    e = binascii.a2b_base64(e).decode()
    for i in range(ts-1):
        e = str(e)
        e = e[2:]
        e = binascii.a2b_hex(e).decode()
        e = e.strip().strip("'")
    e = binascii.a2b_hex(e).decode()
    textPad.insert("insert", '您的解密內容: '+str(e))

def software_update():
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas')
    
def website():
    showinfo('Website','''官方網站: https://xiaomi69ai.wixsite.com/pyas''')
    
def about():
    showinfo('Copyright','''官方網站: https://xiaomi69ai.wixsite.com/pyas
版權所有© 2020-2021 PYAS Python Antivirus Software''')
    
def version():
    showinfo('Version','軟體版本: PYAS V1.5 (免費版)')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def traditional_chinese():
    if is_admin():
        try:
            ft = open('PYASL.ini','w')
            ft.write('''traditional_chinese''')
            ft.close()
            menubar = Menu(root)
            root.config(menu = menubar)
            filemenu = Menu(menubar,tearoff=False)
            filemenu.add_command(label = '智能掃描',command = smart_scan)
            filemenu.add_command(label = '智能分析',command = ai_scan)
            menubar.add_cascade(label = ' 掃描',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = '立即殺毒',command = input_antivirus_immediately)
            #filemenu2.add_command(label = '偵測殺毒',command = detect_antivirus)
            #filemenu2.add_command(label = '循環殺毒',command = cyclic_antivirus)
            filemenu2.add_command(label = '銷毀病毒',command = destroy_virus)
            menubar.add_cascade(label = '殺毒',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            #filemenu3.add_command(label = '尋找檔案',command = input_find_files)
            menubar.add_cascade(label = '工具',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='系統工具', menu=sub2menu, underline=0)
            sub2menu.add_command(label = '修復系統檔案',command = repair_system_files)
            sub2menu.add_separator()
            sub2menu.add_command(label = '啟動安全模式',command = start_safe_mode)
            sub2menu.add_command(label = '關閉安全模式',command = close_safe_Mode)
            sub2menu.add_separator()
            sub2menu.add_command(label="自訂 CMD 指令", command=input_custom_cmd_command)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='更多工具', menu=submenu, underline=0)
            submenu.add_command(label = '尋找檔案',command = input_find_files)
            submenu.add_separator()
            submenu.add_command(label = '加密文字',command = input_encrypt)
            submenu.add_command(label = '解密文字',command = input_decrypt)
            submenu.add_separator()
            submenu.add_command(label = '網路位置查詢',command = web_queries)
            submenu.add_command(label = '重置系統網絡',command = reset_network)
            filemenu4 = Menu(menubar,tearoff=False)
            #filemenu4.add_command(label = '修復CMD權限',command = fix_cmd_permissions)
            #menubar.add_cascade(label = '系統',menu = filemenu4)
            filemenu5 = Menu(menubar,tearoff=False)
            #filemenu5.add_command(label="自訂指令", command=input_custom_cmd_command)
            #filemenu5.add_command(label = ' ')
            menubar.add_cascade(label = '設置',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='軟體設置', menu=sitmenu, underline=0)
            sitmenu.add_command(label="更新軟體", command=software_update)
            #sitwmenu = Menu(sitmenu,tearoff=False)
            #filemenu5.add_cascade(label='字體大小', menu=sitwmenu, underline=0)
            #sitwmenu.add_command(label="增大字體", command=sizeb)
            #sitwmenu.add_command(label="縮小字體", command=sizes)
            #sitmenu.add_command(label="啟用專業版", command=input_pyas_key)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='變更語言', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese)
            sit2menu.add_command(label="English", command=english)
            aboutmenu = Menu(menubar,tearoff=False)
            #aboutmenu.add_command(label = '官方網站',command = website)
            aboutmenu.add_command(label = '關於我們',command = about)
            aboutmenu.add_command(label = '軟體版本',command = version)
            menubar.add_cascade(label = '關於',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            showerror('Error', '''程式出錯，我們感到很抱歉。
回報錯誤: https://xiaomi69ai.wixsite.com/pyas
錯誤資訊: '''+str(e))
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 8)

def input_pyas_key_en():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('Activate the software')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' Key: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :pyas_key_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def pyas_key_en(ipw):
    textPad.delete(1.0,END)
    pw = 'pyas1217'
    if ipw == pw:
        showinfo('Information','''Software has been activated successfully。''')
        f = open('Pro.pyas','w',encoding="utf-8")
        f.write('True')
        f.close()
        ctypes.windll.kernel32.SetFileAttributesW('Pro.pyas', 2)
        english_pro()
    else:
        showerror('Error', '''Password error''')

def pro_info_en():
    if askokcancel('Unlock function','''This feature is only available for users of the professional version.
Do you want to unlock this feature?''', default="ok", icon="info"):
        input_pyas_key()
    else:
        pass
    
def smart_scan_en():
    textPad.delete(1.0,END)
    f = open('FSCAN.bat','w',encoding="utf-8")
    f.write('''MSERT.exe /n''')
    f.close()
    os.system('start FSCAN.bat')
    
def ai_scan_en():
    textPad.delete(1.0,END)
    blist = []
    dblist = []
    fe = []
    myfile = filedialog.askopenfilename()
    trying = myfile.find('.')
    trying2 = myfile.find('/.')
    trypath = myfile.find('/')
    trydot = myfile.find('"')
    tryos = myfile.find('PYAS.py')
    if tryos == -1:
        if trypath == -1:
            textPad.insert("insert", '✖Input file error, file not selected')
        else:
            if trying == -1:
                print('✖Input file error, no correct file name')
            elif trying == 0:
                textPad.insert("insert", '✖Input file error, no correct file name')
            else:
                if trydot == -1:
                    if not trying2 == -1:
                        textPad.insert("insert", '✖Input file error, no correct file name')
                    else:
                        cheaktime = time.time()
                        for entry in pefile.PE(myfile).DIRECTORY_ENTRY_IMPORT:
                            #print(entry.dll)
                            for function in entry.imports:
                                #print('\t', function.name)
                                #fe = function.name
                                fe.append(function.name)
                        cc = str(fe)
                        for a in range(at):
                            if at_list_winf[a] in str(cc) and a != t - 1:
                                blist.append(at_list_winf[a])
                                continue
                            if at_list_winf[a] not in str(cc):
                                continue
                        ds = 0
                        if 'Reg' in str(blist):
                            ds = ds + 20
                        if 'DeleteFile' in str(blist):
                            ds = ds + 10
                        if 'WriteFile' in str(blist):
                            ds = ds + 10
                        if 'ReadFile' in str(blist):
                            ds = ds + 5
                        if 'CreateFile' in str(blist):
                            ds = ds + 5
                        if 'Get' in str(blist):
                            ds = ds + 5
                        if 'Set' in str(blist):
                            ds = ds + 5
                        if 'Find' in str(blist):
                            ds = ds + 5
                        if 'Window' in str(blist):
                            ds = ds + 5
                        if len(blist) == 0:
                            textPad.insert("insert", '✔There are currently no high-risk behaviors in this file')
                        else:
                            textPad.insert("insert", '✖Suspicious behavior has been detected, Suspicious content: '+ str(blist))
                else:
                    textPad.insert("insert", '✖Input file error, cannot have quotation marks')
    else:
        textPad.insert("insert", 'Unable to open system file')

def input_antivirus_immediately_en():
    global root,textPad
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('File Name')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' Name: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :antivirus_immediately_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def antivirus_immediately_en(app):
    textPad.delete(1.0,END)
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            #textPad.insert("insert", 'The program has been found "'+str(app)+'"')
            of = subprocess.call('taskkill /f /im '+str(app),shell=True)
            if of == 0:
                textPad.insert("insert", '✔Success: The execution was successful.')
            else:
                textPad.insert("insert", '✖Error: The execution failed.')
            done = True
            break
        else:
            textPad.insert("insert", 'Cant find the program "'+str(app)+'"')
            done = True
            break

def destroy_virus_en():
    global root,textPad
    textPad.delete(1.0,END)
    path = str(filedialog.askopenfilename())
    if path == '':
        pass
    else:
        os.remove(path)
        
def web_queries_en():
    textPad.delete(1.0,END)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    textPad.insert("insert", 'Your intranet IP is: ' + s.getsockname()[0])
    s.close()

def reset_network_en():
    textPad.delete(1.0,END)
    runc = subprocess.call("netsh winsock reset", shell=True)
    if runc == 0:
        textPad.insert("insert", '✔Success: The execution was successful.')
    else:
        textPad.insert("insert", '✖Error: The execution failed.')
    
def input_find_files_en():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''The execution process takes a while, and the program
may temporarily stop working. Do you want to continue?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('File Name')
        t.geometry('260x40')
        t.transient(root)
        Label(t,text=' File Name: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :find_files_info_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    else:
        pass
    
def find_files_info_en(ffile):
    textPad.delete(1.0,END)
    showinfo('Information','''The execution process will take a while, please be patient.''')
    try:
        fss = 0
        start = time.time()
        findfile_en('A:/',ffile,fss,start)
        findfile_en('B:/',ffile,fss,start)
        findfile_en('C:/',ffile,fss,start)
        findfile_en('D:/',ffile,fss,start)
        findfile_en('E:/',ffile,fss,start)
        findfile_en('F:/',ffile,fss,start)
        findfile_en('G:/',ffile,fss,start)
        findfile_en('H:/',ffile,fss,start)
        findfile_en('I:/',ffile,fss,start)
        findfile_en('J:/',ffile,fss,start)
        findfile_en('K:/',ffile,fss,start)
        findfile_en('L:/',ffile,fss,start)
        findfile_en('M:/',ffile,fss,start)
        findfile_en('N:/',ffile,fss,start)
        findfile_en('O:/',ffile,fss,start)
        findfile_en('P:/',ffile,fss,start)
        findfile_en('Q:/',ffile,fss,start)
        findfile_en('R:/',ffile,fss,start)
        findfile_en('S:/',ffile,fss,start)
        findfile_en('T:/',ffile,fss,start)
        findfile_en('U:/',ffile,fss,start)
        findfile_en('V:/',ffile,fss,start)
        findfile_en('W:/',ffile,fss,start)
        findfile_en('X:/',ffile,fss,start)
        findfile_en('Y:/',ffile,fss,start)
        findfile_en('Z:/',ffile,fss,start)
        end = time.time()
        ft = open('PYASF.txt','r')
        fe = ft.read()
        ft.close()
        textPad.insert("insert", '''
Find result: '''+'''
============================================================================

'''+str(fe)+'''============================================================================
Time consuming: '''+str(end - start)+''' sec''')
        os.remove('PYASF.txt')
    except:
        pass
    
def findfile_en(path,ffile,fss,start):
    try:
        for fd in os.listdir(path):
            fullpath = os.path.join(path,fd)
            if os.path.isdir(fullpath):
                #print('正在掃描: ',fullpath)
                findfile_en(fullpath,ffile,fss,start)
            else:
                fss = fss + 1
                if ffile in str(fd):
                    date = time.ctime(os.path.getmtime(fullpath))
                    #try:
                        #f = open(fullpath, 'r')
                        #text = f.readline()
                        #f.close()
                        #print('預覽內容: '+text)
                    #except:
                        #print('預覽內容: ✖錯誤，這個檔案不支援預覽')
                    ft = open('PYASF.txt','a')
                    ft.write('''File found: '''+str(fullpath)+'''
Create date: '''+str(date)+'''

''')
                    ft.close()
                    continue
    except:
        pass
    
def repair_system_files_en():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''The execution process takes a while, and the program
may temporarily stop working. Do you want to continue?''', default="cancel", icon="warning"):
        runc = os.system('''sfc /scannow''')
        if runc == 0:
            textPad.insert("insert", '✔Success: The execution was successful.')
        else:
            textPad.insert("insert", '✖Error: The execution failed.')
            os.system('cls')
    else:
        pass

def start_safe_mode_en():
    if askokcancel('Warning','''A restart is required to start safe mode. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        os.system('net user administrator /active:yes')
        os.system('bcdedit /set {default} safeboot minimal')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass
    
def close_safe_Mode_en():
    if askokcancel('Warning','''Turning off safe mode requires a restart. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        os.system('net user administrator /active:no')
        os.system('bcdedit /deletevalue {current} safeboot')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass
    
def input_custom_cmd_command_en():
    if askokcancel('Warning','''It is possible that the custom command may
allow the malicious user to gain control and access
to this computer. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('Custom command')
        t.geometry('260x40')
        t.transient(root)
        Label(t,text=' Command: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :custom_cmd_command_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    else:
        pass

def custom_cmd_command_en(cmd):
    textPad.delete(1.0,END)
    subprocess.run(cmd, shell=True)
    textPad.insert("insert", 'Done.')

def input_encrypt_en():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('Input text')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :encrypt_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def encrypt_en(e):
    textPad.delete(1.0,END)
    ts = 1
    for i in range(ts):
        e = str(e)
        e = binascii.b2a_hex(e.encode())
        sk = str(e)
        skk = sk[2:]
        skk = skk.strip().strip("'")
    skk = binascii.b2a_base64(skk.encode())
    sk = str(skk)
    skk = sk[2:]
    skk = skk.strip().strip("'")
    textPad.insert("insert", 'Your encrypted content: '+str(skk))

def input_decrypt_en():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('Input text')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :decrypt_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def decrypt_en(e):
    textPad.delete(1.0,END)
    ts = 1
    e = e[:-2]
    e = binascii.a2b_base64(e).decode()
    for i in range(ts-1):
        e = str(e)
        e = e[2:]
        e = binascii.a2b_hex(e).decode()
        e = e.strip().strip("'")
    e = binascii.a2b_hex(e).decode()
    textPad.insert("insert", 'Your decrypted content: '+str(e))

    
def software_update_en():
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas')
    
def website_en():
    showinfo('Website','''Official website: https://xiaomi69ai.wixsite.com/pyas''')
    
def about_en():
    showinfo('Copyright','''Official website: https://xiaomi69ai.wixsite.com/pyas
Copyright© 2020-2021 PYAS Python Antivirus Software''')
    
def version_en():
    showinfo('Version','Software Version: PYAS V1.5 (Free Edition)')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def english():
    if is_admin():
        try:
            ft = open('PYASL.ini','w')
            ft.write('''english''')
            ft.close()
            menubar = Menu(root)
            root.config(menu = menubar)
            filemenu = Menu(menubar,tearoff=False)
            filemenu.add_command(label = 'Smart scan',command = smart_scan_en)
            filemenu.add_command(label = 'Smart analyze',command = ai_scan_en)
            menubar.add_cascade(label = 'Scan',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = 'Antivirus immediately',command = input_antivirus_immediately_en)
            #filemenu2.add_command(label = '偵測殺毒',command = detect_antivirus)
            #filemenu2.add_command(label = '循環殺毒',command = cyclic_antivirus)
            filemenu2.add_command(label = 'Destroy the virus',command = destroy_virus_en)
            menubar.add_cascade(label = 'Antivirus',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            #filemenu3.add_command(label = '尋找檔案',command = input_find_files)
            menubar.add_cascade(label = 'Tools',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='System Tools', menu=sub2menu, underline=0)
            sub2menu.add_command(label = 'Repair system files',command = repair_system_files_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Start safe mode',command = start_safe_mode_en)
            sub2menu.add_command(label = 'Close safe mode',command = close_safe_Mode_en)
            sub2menu.add_separator()
            sub2menu.add_command(label="Custom CMD command", command=input_custom_cmd_command_en)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='more options', menu=submenu, underline=0)
            submenu.add_command(label = 'Find Files',command = input_find_files_en)
            submenu.add_separator()
            submenu.add_command(label = 'Encrypt text',command = input_encrypt_en)
            submenu.add_command(label = 'Decrypt text',command = input_decrypt_en)
            submenu.add_separator()
            submenu.add_command(label = 'Network location query',command = web_queries_en)
            submenu.add_command(label = 'Reset system network',command = reset_network_en)
            filemenu4 = Menu(menubar,tearoff=False)
            #filemenu4.add_command(label = '修復CMD權限',command = fix_cmd_permissions)
            #menubar.add_cascade(label = '系統',menu = filemenu4)
            filemenu5 = Menu(menubar,tearoff=False)
            #filemenu5.add_command(label="自訂指令", command=input_custom_cmd_command)
            #filemenu5.add_command(label = ' ')
            menubar.add_cascade(label = 'settings',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Software settings', menu=sitmenu, underline=0)
            sitmenu.add_command(label="Update software", command=software_update_en)
            sitmenu.add_command(label="Activate professional version", command=input_pyas_key_en)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Change language', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese)
            sit2menu.add_command(label="English", command=english)
            aboutmenu = Menu(menubar,tearoff=False)
            #aboutmenu.add_command(label = '官方網站',command = website)
            aboutmenu.add_command(label = 'About us',command = about_en)
            aboutmenu.add_command(label = 'Version',command = version_en)
            menubar.add_cascade(label = 'About',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            showerror('Error', '''We are sorry for the program error.
Report error: https://xiaomi69ai.wixsite.com/pyas
Error info: '''+str(e))
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 8)

def setup_pyas():
    try:
        ft = open('PYASL.ini','r')
        fe = ft.read()
        ft.close()
        if fe == 'english':
            english()
        elif fe == 'traditional_chinese':
            traditional_chinese()
        else:
            english()
    except:
        english()
        
setup_pyas()
