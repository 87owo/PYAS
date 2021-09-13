expansion = True
try:
    import time
    import os
    import tkinter as tk
    from tkinter import filedialog
    import random
    import string
    from os.path import isfile, isdir, join
    from os import listdir
    import sys
    import ctypes
    import shutil
    import socket
    import webbrowser
    import subprocess
    import binascii
    from Expansion_pack.list import *
    from multiprocessing import Pool
    from multiprocessing import cpu_count
    import pefile
    import hashlib
    from functools import partial
    import json
except:
    expansion = False
import json
import hashlib
def developer():
    pk = input('請輸入密碼: ')
    if pk == 'pyas':
        webbrowser.open('https://xiaomi69ai.wixsite.com/pyas/contact-8')
    elif pk == 'PYAS':
        webbrowser.open('https://xiaomi69ai.wixsite.com/pyas/contact-8')
    else:
        print('✖密碼錯誤')
def scan_sha256(file):
      virus_found = False
      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();
            print("該文件的 SHA256 的值為： " + readable_hash)
            with open("Expansion_pack/SHA256.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                      if str(readable_hash) == str(line.split(";")[0]):
                            virus_found = True
                f.close()
      if not virus_found:
            print("✔目前檔案安全")
      else:
            print("✖已檢測到病毒")
            #os.remove(file)
def scan_md5(file):
      virus_found = False
      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.md5(bytes).hexdigest();
            print("此文件的 MD5 的值為： " + readable_hash)
            with open("Expansion_pack/MD5 Virus Hashes.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                      if str(readable_hash) == str(line.split(";")[0]):
                            virus_found = True
                f.close()
      if not virus_found:
            print("✔目前檔案安全")

            scan_sha256(file)
      else:
            print("✖已檢測到病毒")
            #os.remove(file)
def scan(file):
      virus_found = False
      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha1(bytes).hexdigest();
            print("此文件的 SHA1 的值是: " + readable_hash)
            with open('Expansion_pack/SHA1 HASHES.json', 'r') as f:
                dataset = json.loads(f.read())
                for index, item in enumerate(dataset["data"]):
                      if str(item['hash']) == str(readable_hash):
                          virus_found = True
                f.close()
      if not virus_found:
            print("✔目前檔案安全")
            scan_md5(file)
      else:
            print("✖已檢測到病毒")
            #os.remove(file)
def ab_pyas():
    print('版權所有© 2020-2021 PYAS')
    print('軟體版本: 增強版 1.3')
def delpw():
    u = input('請輸入用戶名稱: ')
    os.system('net user '+str(u)+' ""')
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
                    print('找到檔案: '+str(fullpath))
                    #try:
                        #f = open(fullpath, 'r')
                        #text = f.readline()
                        #f.close()
                        #print('預覽內容: '+text)
                    #except:
                        #print('預覽內容: ✖錯誤，這個檔案不支援預覽')
                    print('建立日期: '+str(date))
                    print(' ')
                    continue
    except:
        pass
def cleaner():
    flist = []
    flist = []
    bflist = []
    path = 'C:\Windows\Temp'
    pa = path.find('Temp')
    if pa == -1:
        print('✖輸入檔案錯誤，未找到檔案路徑')
    else:
        try:
            shutil.rmtree(path)
        except:
            print('✖無法清除: C:\Windows\Temp')
        else:
            print('已清除: C:\Windows\Temp')
def fordel():
    path = str(filedialog.askdirectory(title="選擇"))
    os.remove(path)
root = tk.Tk()
root.withdraw()
def ai_scan():
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
            print('✖輸入檔案錯誤，未選擇檔案')
        else:
            if trying == -1:
                print('✖輸入檔案錯誤，沒有副檔名')
            elif trying == 0:
                print('✖輸入檔案錯誤，沒有正檔名')
            else:
                if trydot == -1:
                    if not trying2 == -1:
                        print('✖輸入檔案錯誤，沒有正檔名')
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
                            print('✔此檔案目前沒有惡意')
                        else:
                            print('✖可能惡意內容: '+ str(blist))
                            print('============================================================================')
                            print('✖可能惡意程度: '+ str(ds))
                else:
                    print('✖輸入檔案錯誤，不能有引號')
    else:
        print('無法開啟系統檔')
def exe_ca():
    pe = pefile.PE(filedialog.askopenfilename())
    for section in pe.sections:
        print(section.Name, hex(section.VirtualAddress),
        hex(section.Misc_VirtualSize), section.SizeOfRawData)
def exe_cb():
    pe = pefile.PE(filedialog.askopenfilename())
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)
        for function in entry.imports:
            print('\t', function.name)
def d_kill():
    while True:
        run = subprocess.call('tasklist |find /i "PYAS.exe"',shell=True)
        if run == 0:
            continue
        else:
            os.system('PYAS.exe')
def encrypt():
    e = str(input('請輸入要加密的內容: '))
    print('============================================================================')
    ts = int(input('請輸入要加密的次數: '))
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
    print('============================================================================')
    print('您的加密內容: '+str(skk))
def decrypt():
    e = input('請輸入要解密的內容: ')
    print('============================================================================')
    ts = int(input('請輸入要解密的次數: '))
    e = e[:-2]
    e = binascii.a2b_base64(e).decode()
    for i in range(ts-1):
        e = str(e)
        e = e[2:]
        e = binascii.a2b_hex(e).decode()
        e = e.strip().strip("'")
    e = binascii.a2b_hex(e).decode()
    print('============================================================================')
    print('您的解密內容: '+str(e))
def kill_while():
    input('若要關閉重複偵測殺毒，直接關閉此視窗即可。按 Enter 鍵繼續')
    print('============================================================================')
    app = input('請輸入病毒完整檔名:')
    os.system('cls')
    run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
    while True:
        os.system('taskkill /f /im '+str(app))
def pyas_repair():
    pp = os.path.dirname(os.path.abspath(__file__))
    print(str(pp)+'\PYAS.exe',str(pp)+'\PYAS_copy.exe')
    shutil.copyfile(str(pp)+'\PYAS.exe',str(pp)+'\PYAS_copy.exe')
def auto_av():
    while True:
        for a in range(at):
            os.system('taskkill /f /im '+str(at_list[a]))
def win_bsod():
    os.system('taskkill /f /fi "pid ne 1"')
def win_re():
    os.system('shutdown -r -t 0')
def qsavemode():
    os.system('net user administrator /active:no')
    os.system('bcdedit /deletevalue {current} safeboot')
    time.sleep(1)
    os.system('shutdown -r -t 0')
def savemode():
    os.system('net user administrator /active:yes')
    os.system('bcdedit /set {default} safeboot minimal')
    time.sleep(1)
    os.system('shutdown -r -t 0')
def Repair_net():
    os.system('netsh winsock reset')
    time.sleep(1)
    os.system('shutdown -r -t 0')
def kill_autoch():
    os.system('tasklist /fi "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"')
    print('============================================================================')
    app = input('請輸入完整的程序檔案名稱: ')
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            print('該程序已找到 "'+str(app)+'"')
            print('============================================================================')
            os.system('taskkill /f /im '+str(app))
            done = True
            break
        else:
            print('尋找程序中 "'+str(app)+'"...')
def kill_appch():
    os.system('tasklist /fi "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"')
    print('============================================================================')
    app = input('請輸入完整的程序檔案名稱: ')
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            print('該程序已找到 "'+str(app)+'"')
            print('============================================================================')
            os.system('taskkill /f /im '+str(app))
            done = True
            break
        else:
            print('找不到該程序 "'+str(app)+'"')
            done = True
            break
def sfc():
    os.system('sfc /scannow')
def cputest():
    f = open('cputest.bat','w',encoding="utf-8")
    f.write('''%0|%0''')
    f.close()
    os.system('cputest.bat')
def savedel():
    path = str(filedialog.askopenfilename())
    if path == '':
        pass
    else:
        f = open(path,'w',encoding="iso-8859-1")
        f.write(''.join(random.choice(string.ascii_letters + string.digits)for x in range(10)))
        f.close()
        os.remove(path)
def churl():
    u = input('檢查網址: ')
    webbrowser.open("https://transparencyreport.google.com/safe-browsing/search?url=" + str(u))
def myipch():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print('您的往內IP是: ' + s.getsockname()[0])
    s.close()
def copybuf():
    path = filedialog.askdirectory(title="選擇備份資料夾")
    if path == '':
        pass
    else:
        pw = str(''.join(random.choice(string.ascii_letters + string.digits)for x in range(4)))
        print('備份中...')
        shutil.copytree(path,'./Backup/'+ pw)
        print('===========================================================================')
        print('備份提取密碼: ' + pw)
def getcopybuf():
    pw = input('輸入提取密碼: ')
    path = './備份/'
    files = listdir(path)
    trying = str(files).find(pw)
    if trying == -1:
        print('✖密碼錯誤')
        pass
    else:
        print('正在提取檔案...')
        path = filedialog.askdirectory(title="選擇存放資料夾")
        shutil.copytree('./Backup/'+ pw,path + '/' + str(pw))
def movevirus():
    path = filedialog.askdirectory(title="選擇有毒資料夾")
    if path == '':
        pass
    else:
        shutil.make_archive('./virus/' + str(''.join(random.choice(string.ascii_letters + string.digits)for x in range(8))),'zip',path)
        shutil.rmtree(path)
def shutdown():
    os.system("shutdown -s -t 0")
def find_dirch(path):
    trypath = path.find('/')
    if trypath == -1:
        print('✖輸入檔案錯誤，未選擇檔案')
    else:
        try:
            blist = []
            bflist = []
            flist = []
            for fd in os.listdir(path):
                fullpath = os.path.join(path,fd)
                if os.path.isdir(fullpath):
                    print('資料夾:',fullpath)
                    find_dirch(fullpath)
                else:
                    try:
                        f = open(fullpath,'r',encoding="iso-8859-1") #開啟檔案
                        print('正在掃描: ' + str(fullpath))
                        file = f.read()
                        m = 100 / t
                        for a in range(t):          #檢查
                            math = int(m * a + m)
                            if t_list[a] in file and a != t - 1:
                                blist.append(t_list[a])
                                continue
                            if t_list[a] not in file:
                                continue
                        if len(blist) == 0:
                            flist.append(fullpath)
                        else:
                            bflist.append(fullpath)
                    except:
                        print('===========================================================================')
                        input('✖讀取錯誤:沒有權限或不支援的檔案，按 Enter 鍵繼續')
            print('===========================================================================')
            print('✔目前沒有惡意檔案: ' + str(flist))
            print('')
            print('✖目前可能惡意檔案: ' + str(bflist))
            print('===========================================================================')
            blist = []
            bflist = []
            flist = []
        except:
            pass
def startpach():
    flist = []
    bflist = []
    path = filedialog.askdirectory(title="選擇資料夾")
    trypath = path.find('/')
    if trypath == -1:
        print('✖輸入檔案錯誤，未選擇檔案')
    else:
        try:
            files = listdir(path)
            for f in files:
                blist = []
                dblist = []
                fullpath = join(path, f)
                if isfile(fullpath):
                    try:
                        f = open(fullpath,'r',encoding="iso-8859-1") #開啟檔案
                        print('正在掃描: ' + str(fullpath))
                        file = f.read()
                        m = 100 / t
                        for a in range(ti):          #檢查
                            math = int(m * a + m)
                            if ti_list[a] in file and a != ti - 1:
                                blist.append(ti_list[a])
                                continue
                            if ti_list[a] not in file:
                                continue
                        for a in range(t):          #檢查
                            math = int(m * a + m)
                            if t_list[a] in file and a != t - 1:
                                blist.append(t_list[a])
                                continue
                            if t_list[a] not in file:
                                continue
                        if len(blist) == 0:
                            flist.append(fullpath)
                        else:
                            bflist.append(fullpath)
                    except:
                        pass
                elif isdir(fullpath):
                    continue
            print('===========================================================================')
            print('✔目前沒有惡意檔案: ' + str(flist))
            print('')
            print('✖目前可能惡意檔案: ' + str(bflist))
        except:
            pass
def startfich():
    blist = []
    dblist = []
    myfile = filedialog.askopenfilename()
    trying = myfile.find('.')
    trying2 = myfile.find('/.')
    trypath = myfile.find('/')
    trydot = myfile.find('"')
    tryos = myfile.find('PYAS.py')
    if tryos == -1:
        if trypath == -1:
            print('✖輸入檔案錯誤，未選擇檔案')
        else:
            if trying == -1:
                print('✖輸入檔案錯誤，沒有副檔名')
            elif trying == 0:
                print('✖輸入檔案錯誤，沒有正檔名')
            else:
                if trydot == -1:
                    if not trying2 == -1:
                        print('✖輸入檔案錯誤，沒有正檔名')
                    else:
                        cheaktime = time.time()
                        f = open(myfile,'r',encoding="iso-8859-1") #開啟檔案
                        file = f.read()
                        m = 100 / t
                        for a in range(t):          #檢查
                            math = int(m * a + m)
                            if t_list[a] in file and a != t - 1:
                                blist.append(t_list[a])
                                continue
                            if t_list[a] not in file:
                                continue
                        if len(blist) == 0:
                            print('✔此檔案目前沒有惡意')
                        else:
                            print('✖可能惡意內容: '+ str(blist))
                else:
                    print('✖輸入檔案錯誤，不能有引號')
    else:
        print('無法開啟系統檔')
def cmdr():
    f = open('CMDRT.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000000
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableTaskMgr"=dword:00000000''')
    f.close()
    ctypes.windll.shell32.ShellExecuteW(None, "open", 'CMDRT.reg', __file__, None, 1)
    print('點擊 "是" 即可修復 CMD 權限')
def d_com():
    dc = input('輸入自訂指令: ')
    print('===========================================================================')
    Options21 = str('[選項1]  現在立刻執行')
    Options22 = str('[選項2]  幾分鐘後執行')
    Options23 = str('[選項3]  進入系統時執行')
    print(Options21)
    print(Options22)
    print(Options23)
    print('===========================================================================')
    tm = input('選則執行方式: ')
    try:
        if int(tm) == 1:
            os.system('cls')
            os.system(dc)
        elif int(tm) == 2:
            print('===========================================================================')
            mu = input('執行時間(分鐘): ')
            time.sleep(float(mu)*60)
            os.system('cls')
            os.system(dc)
        elif int(tm) == 3:
            if 'shutdown' in dc:
                print('===========================================================================')
                input('✖錯誤:這個指令禁止使用，這可能會對你的電腦造成傷害，按 Enter 鍵返回')
                pass
            elif 'taskkill' in dc:
                print('===========================================================================')
                input('✖錯誤:這個指令禁止使用，這可能會對你的電腦造成傷害，按 Enter 鍵返回')
                pass
            elif dc == 'taskkill /f /fi pid ne 1':
                print('===========================================================================')
                input('✖錯誤:這個指令禁止使用，這可能會對你的電腦造成傷害，按 Enter 鍵返回')
                pass
            else:
                s = open('defp.cmd','w')
                s.write(dc)
                s.close()
                os.system('COPY "'+str(os.path.dirname(os.path.abspath(__file__)))+'\defp.cmd"'+' "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"')
    except:
        input('✖錯誤:您輸入的內容錯誤或程式出錯，按 Enter 鍵返回')
        pass
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def ask_admin():
    if is_admin():
        Options1 = str('[選項1]  智能掃描')
        Options2 = str('[選項2]  智能分析')
        Options3 = str('[選項3]  檔案掃描')
        Options4 = str('[選項4]  局部掃描')
        Options5 = str('[選項5]  全區掃描')
        Options6 = str('[選項6]  立即殺毒')
        Options7 = str('[選項7]  立即偵測殺毒')
        Options8 = str('[選項8]  重複偵測殺毒')
        Options9 = str('[選項9]  內部 IP 查詢')
        Options10 = str('[選項10] 網站檢測')
        Options11 = str('[選項11] 修復並重置網絡')
        Options12 = str('[選項12] 檔案備份')
        Options13 = str('[選項13] 提取檔案')
        Options14 = str('[選項14] 隔離病毒')
        Options15 = str('[選項15] 銷毀檔案')
        Options16 = str('[選項16] 尋找檔案')
        Options17 = str('[選項17] 移除用戶密碼')
        Options18 = str('[選項18] 修復系統檔案')
        Options19 = str('[選項19] 修復 CMD 權限')
        Options20 = str('[選項20] 啟動安全模式')
        Options21 = str('[選項21] 關閉安全模式')
        Options22 = str('[選項22] 多核壓力測試')
        Options23 = str('[選項23] 加密文字')
        Options24 = str('[選項24] 解密文字')
        Options25 = str('[選項25] 強制系統關機')
        Options26 = str('[選項26] 強制結束系統')
        Options27 = str('[選項27] 分析執行檔字節')
        Options28 = str('[選項28] 分析執行檔函數')
        Options29 = str('[選項29] 自訂 CMD 指令')
        #Options29 = str('[選項29] 緊急修復系統檔案')
        Options30 = str('[選項30] 中文 / English')
        while True:
            os.system('cls')
            print('')
            print('================================== 掃描 ===================================')
            print(Options1)
            print(Options2)
            print(Options3)
            print(Options4)
            print(Options5)
            print('================================== 殺毒 ===================================')
            print(Options6)
            print(Options7)
            print(Options8)
            print('================================ 網路管理 =================================')
            print(Options9)
            print(Options10)
            print(Options11)
            print('================================ 檔案管理 =================================')
            print(Options12)
            print(Options13)
            print(Options14)
            print(Options15)
            print(Options16)
            print('================================ 系統安全 =================================')
            print(Options17)
            print(Options18)
            print(Options19)
            print(Options20)
            print(Options21)
            print('================================ 其他功能 =================================')
            print(Options22)
            print(Options23)
            print(Options24)
            print(Options25)
            print(Options26)
            print('=============================== 開發者模式 ================================')
            print(Options27)
            print(Options28)
            print(Options29)
            print('================================== 語言 ===================================')
            print(Options30)
            print('===========================================================================')
            co = input('請輸入選項: ')
            print('===========================================================================')
            try:
                if co == str('pyas -a'):
                    print('版權所有© 2020-2021 PYAS')
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS -a'):
                    print('版權所有© 2020-2021 PYAS')
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('pyas - a'):
                    print('版權所有© 2020-2021 PYAS')
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS - a'):
                    print('版權所有© 2020-2021 PYAS')
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('pyas -d'):
                    developer()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS -d'):
                    developer()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('pyas - d'):
                    developer()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS - d'):
                    developer()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                else:
                    input('按 Enter 鍵繼續')
                    print('===========================================================================')
                    if int(co) == 1:
                        filename = filedialog.askopenfilename()
                        scan(filename)
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 2:
                        ai_scan()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 3:
                        startfich()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 4:
                        startpach()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 5:
                        find_dirch(filedialog.askdirectory(title="選擇"))
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 6:
                        kill_appch()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 7:
                        kill_autoch()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 8:
                        kill_while()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 9:
                        myipch()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 10:
                        churl()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 11:
                        Repair_net()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 12:
                        copybuf()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 13:
                        getcopybuf()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 14:
                        movevirus()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 15:
                        savedel()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 16:
                        ffile = input('請輸入要找的檔案名稱: ')
                        fss = 0
                        start = time.time()
                        print('===========================================================================')
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
                        print('===========================================================================')
                        print('總共耗時: '+str(end - start)+' 秒')
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 17:
                        delpw()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 18:
                        sfc()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 19:
                        cmdr()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 20:
                        savemode()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 21:
                        qsavemode()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 22:
                        cputest()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 23:
                        encrypt()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 24:
                        decrypt()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 25:
                        shutdown()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 26:
                        win_bsod()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 27:
                        exe_ca()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 28:
                        exe_cb()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 29:
                        d_com()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 99999:
                        cmdr()
                        kill_appch()
                        sfc()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 30:
                        ask_admin_en()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    else:
                        input('✖錯誤:您輸入的內容錯誤或程式出錯，按 Enter 鍵返回')
                        pass
            except:
                input('✖錯誤:您輸入的內容錯誤或程式出錯，按 Enter 鍵返回')
    else:
        print('')
        print('============ PYAS 防毒軟體 增強版 ， 版本 : 1.4 測試版(不穩定) ============')
        print('')
        print('版權所有© 2020-2021 PYAS')
        print('')
        print('===========================================================================')
        if expansion == False:
            print('')
            print('✖錯誤:載入擴充程式出錯，部分功能將無法使用')
            print('')
            print('===========================================================================')
        print('')
        input('此程序需要管理員權限，按 Enter 鍵繼續')
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 8)
def developer_en():
    pk = input('Please enter the password: ')
    if pk == 'pyas':
        webbrowser.open('https://xiaomi69ai.wixsite.com/pyas/contact-8?lang=en')
    elif pk == 'PYAS':
        webbrowser.open('https://xiaomi69ai.wixsite.com/pyas/contact-8?lang=en')
    else:
        print('✖Wrong password')
def scan_sha256_en(file):
      virus_found = False
      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();
            print("The SHA256 hash of this file is: " + readable_hash)
            with open("Expansion_pack/SHA256.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                      if str(readable_hash) == str(line.split(";")[0]):
                            virus_found = True
                f.close()
      if not virus_found:
            print("✔File is safe")
      else:
            print("✖Virus detected")
            #os.remove(file)
def scan_md5_en(file):
      virus_found = False
      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.md5(bytes).hexdigest();
            print("The MD5 hash of this file is: " + readable_hash)
            with open("Expansion_pack/MD5 Virus Hashes.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                      if str(readable_hash) == str(line.split(";")[0]):
                            virus_found = True
                f.close()
      if not virus_found:
            print("✔File is safe")
            scan_sha256_en(file)
      else:
            print("✖Virus detected")
            #os.remove(file)
def scan_en(file):
      virus_found = False
      with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha1(bytes).hexdigest();
            print("The SHA1 hash of this file is: " + readable_hash)
            with open('Expansion_pack/SHA1 HASHES.json', 'r') as f:
                dataset = json.loads(f.read())
                for index, item in enumerate(dataset["data"]):
                      if str(item['hash']) == str(readable_hash):
                          virus_found = True
                f.close()
      if not virus_found:
            print("✔File is safe")
            scan_md5_en(file)
      else:
            print("✖Virus detected")
            #os.remove(file)
def delpw_en():
    u = input('Please enter user name: ')
    os.system('net user '+str(u)+' ""')
def findfile_en(path,ffile,fss,start):
    try:
        for fd in os.listdir(path):
            fullpath = os.path.join(path,fd)
            if os.path.isdir(fullpath):
                #print('Scanning: ',fullpath)
                findfile_en(fullpath,ffile,fss,start)
            else:
                fss = fss + 1
                if ffile in str(fd):
                    date = time.ctime(os.path.getmtime(fullpath))
                    print('Find file: '+str(fullpath))
                    #try:
                        #f = open(fullpath, 'r')
                        #text = f.readline()
                        #f.close()
                        #print('Preview content: '+text)
                    #except:
                        #print('Preview content: ✖Error, this file does not support preview')
                    print('Creation date: '+str(date))
                    print(' ')
                    continue
    except:
        pass
def cleaner_en():
    flist = []
    flist = []
    bflist = []
    path = 'C:\Windows\Temp'
    pa = path.find('Temp')
    if pa == -1:
        print('✖Input file error, file path not found')
    else:
        try:
            shutil.rmtree(path)
        except:
            print('✖Cant clear: C:\Windows\Temp')
        else:
            print('Cleared: C:\Windows\Temp')
def fordel_en():
    path = str(filedialog.askdirectory(title="select"))
    os.remove(path)
root = tk.Tk()
root.withdraw()
def ai_scan_en():
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
            print('✖Input file error, file not selected')
        else:
            if trying == -1:
                print('✖Input file error, no correct file name')
            elif trying == 0:
                print('✖Input file error, no correct file name')
            else:
                if trydot == -1:
                    if not trying2 == -1:
                        print('✖Input file error, no correct file name')
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
                            print('✔This file is currently not malicious')
                        else:
                            print('✖Possibly malicious content: '+ str(blist))
                            print('============================================================================')
                            print('✖Possible malicious degree: '+ str(ds))
                else:
                    print('✖Input file error, cannot have quotation marks')
    else:
        print('Unable to open system file')
def exe_ca_en():
    pe = pefile.PE(filedialog.askopenfilename())
    for section in pe.sections:
        print(section.Name, hex(section.VirtualAddress),
        hex(section.Misc_VirtualSize), section.SizeOfRawData)
def exe_cb_en():
    pe = pefile.PE(filedialog.askopenfilename())
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)
        for function in entry.imports:
            print('\t', function.name)
def d_kill_en():
    while True:
        run = subprocess.call('tasklist |find /i "PYAS.exe"',shell=True)
        if run == 0:
            continue
        else:
            os.system('PYAS.exe')
def encrypt_en():
    e = str(input('Please enter the content to be encrypted: '))
    print('============================================================================')
    ts = int(input('Please enter the number of times you want to encrypt: '))
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
    print('============================================================================')
    print('Your encrypted content: '+str(skk))
def decrypt_en():
    e = input('Please enter the content to be decrypted: ')
    print('============================================================================')
    ts = int(input('Please enter the number of times you want to decrypt: '))
    e = e[:-2]
    e = binascii.a2b_base64(e).decode()
    for i in range(ts-1):
        e = str(e)
        e = e[2:]
        e = binascii.a2b_hex(e).decode()
        e = e.strip().strip("'")
    e = binascii.a2b_hex(e).decode()
    print('============================================================================')
    print('Your decrypted content: '+str(e))
def kill_while_en():
    input('To turn off repeated detection, just close this window. Press Enter to continue')
    print('============================================================================')
    app = input('Please enter the full file name of the virus:')
    os.system('cls')
    run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
    while True:
        os.system('taskkill /f /im '+str(app))
def pyas_repair_en():
    pp = os.path.dirname(os.path.abspath(__file__))
    print(str(pp)+'\PYAS.exe',str(pp)+'\PYAS_copy.exe')
    shutil.copyfile(str(pp)+'\PYAS.exe',str(pp)+'\PYAS_copy.exe')
def auto_av_en():
    while True:
        for a in range(at):
            os.system('taskkill /f /im '+str(at_list[a]))
def win_bsod_en():
    os.system('taskkill /f /fi "pid ne 1"')
def win_re_en():
    os.system('shutdown -r -t 0')
def qsavemode_en():
    os.system('net user administrator /active:no')
    os.system('bcdedit /deletevalue {current} safeboot')
    time.sleep(1)
    os.system('shutdown -r -t 0')
def savemode_en():
    os.system('net user administrator /active:yes')
    os.system('bcdedit /set {default} safeboot minimal')
    time.sleep(1)
    os.system('shutdown -r -t 0')
def Repair_net_en():
    os.system('netsh winsock reset')
    time.sleep(1)
    os.system('shutdown -r -t 0')
def kill_autoch_en():
    os.system('tasklist /fi "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"')
    print('============================================================================')
    app = input('Please enter the complete program file name: ')
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            print('The program has been found "'+str(app)+'"')
            print('============================================================================')
            os.system('taskkill /f /im '+str(app))
            done = True
            break
        else:
            print('searching "'+str(app)+'"...')
def kill_appch_en():
    os.system('tasklist /fi "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"')
    print('============================================================================')
    app = input('Please enter the complete program file name: ')
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            print('The program has been found "'+str(app)+'"')
            print('============================================================================')
            os.system('taskkill /f /im '+str(app))
            done = True
            break
        else:
            print('Cant find the program "'+str(app)+'"')
            done = True
            break
def sfc_en():
    os.system('sfc /scannow')
def cputest_en():
    f = open('cputest.bat','w',encoding="utf-8")
    f.write('''%0|%0''')
    f.close()
    os.system('cputest.bat')
def savedel_en():
    path = str(filedialog.askopenfilename())
    if path == '':
        pass
    else:
        f = open(path,'w',encoding="iso-8859-1")
        f.write(''.join(random.choice(string.ascii_letters + string.digits)for x in range(10)))
        f.close()
        os.remove(path)
def churl_en():
    u = input('Check URL: ')
    webbrowser.open("https://transparencyreport.google.com/safe-browsing/search?url=" + str(u))
def myipch_en():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print('Your intranet IP is: ' + s.getsockname()[0])
    s.close()
def copybuf_en():
    path = filedialog.askdirectory(title="Select the backup folder")
    if path == '':
        pass
    else:
        pw = str(''.join(random.choice(string.ascii_letters + string.digits)for x in range(4)))
        print('Backing up...')
        shutil.copytree(path,'./Backup/'+ pw)
        print('===========================================================================')
        print('Backup extraction password: ' + pw)
def getcopybuf_en():
    pw = input('Enter extraction password: ')
    path = './Backup/'
    files = listdir(path)
    trying = str(files).find(pw)
    if trying == -1:
        print('✖wrong password')
        pass
    else:
        print('Extracting Archives...')
        path = filedialog.askdirectory(title="Select storage folder")
        shutil.copytree('./Backup/'+ pw,path + '/' + str(pw))
def movevirus_en():
    path = filedialog.askdirectory(title="Select a toxic folder")
    if path == '':
        pass
    else:
        shutil.make_archive('./virus/' + str(''.join(random.choice(string.ascii_letters + string.digits)for x in range(8))),'zip',path)
        shutil.rmtree(path)
def shutdown_en():
    os.system("shutdown -s -t 0")
def find_dirch_en(path):
    trypath = path.find('/')
    if trypath == -1:
        print('✖Input file error, file not selected')
    else:
        try:
            blist = []
            bflist = []
            flist = []
            for fd in os.listdir(path):
                fullpath = os.path.join(path,fd)
                if os.path.isdir(fullpath):
                    print('Folder:',fullpath)
                    find_dirch_en(fullpath)
                else:
                    try:
                        f = open(fullpath,'r',encoding="iso-8859-1") #開啟檔案
                        print('Scanning: ' + str(fullpath))
                        file = f.read()
                        m = 100 / t
                        for a in range(t):          #檢查
                            math = int(m * a + m)
                            if t_list[a] in file and a != t - 1:
                                blist.append(t_list[a])
                                continue
                            if t_list[a] not in file:
                                continue
                        if len(blist) == 0:
                            flist.append(fullpath)
                        else:
                            bflist.append(fullpath)
                    except:
                        print('===========================================================================')
                        input('✖Read error: Unauthorized or unsupported file, press Enter to continue')
            print('===========================================================================')
            print('✔There are currently no malicious files: ' + str(flist))
            print('')
            print('✖Currently possible malicious files: ' + str(bflist))
            print('===========================================================================')
            blist = []
            bflist = []
            flist = []
        except:
            pass
def startpach_en():
    flist = []
    bflist = []
    path = filedialog.askdirectory(title="Select folder")
    trypath = path.find('/')
    if trypath == -1:
        print('✖Input file error, file not selected')
    else:
        try:
            files = listdir(path)
            for f in files:
                blist = []
                dblist = []
                fullpath = join(path, f)
                if isfile(fullpath):
                    try:
                        f = open(fullpath,'r',encoding="iso-8859-1") #開啟檔案
                        print('Scanning: ' + str(fullpath))
                        file = f.read()
                        m = 100 / t
                        for a in range(ti):          #檢查
                            math = int(m * a + m)
                            if ti_list[a] in file and a != ti - 1:
                                blist.append(ti_list[a])
                                continue
                            if ti_list[a] not in file:
                                continue
                        for a in range(t):          #檢查
                            math = int(m * a + m)
                            if t_list[a] in file and a != t - 1:
                                blist.append(t_list[a])
                                continue
                            if t_list[a] not in file:
                                continue
                        if len(blist) == 0:
                            flist.append(fullpath)
                        else:
                            bflist.append(fullpath)
                    except:
                        pass
                elif isdir(fullpath):
                    continue
            print('===========================================================================')
            print('✔This file is currently not malicious: ' + str(flist))
            print('')
            print('✖✖Possibly malicious content:: ' + str(bflist))
        except:
            pass
def startfich_en():
    blist = []
    dblist = []
    myfile = filedialog.askopenfilename()
    trying = myfile.find('.')
    trying2 = myfile.find('/.')
    trypath = myfile.find('/')
    trydot = myfile.find('"')
    tryos = myfile.find('PYAS.py')
    if tryos == -1:
        if trypath == -1:
            print('✖Input file error, file not selected')
        else:
            if trying == -1:
                print('✖Input file error, no correct file name')
            elif trying == 0:
                print('✖Input file error, no correct file name')
            else:
                if trydot == -1:
                    if not trying2 == -1:
                        print('✖Input file error, no correct file name')
                    else:
                        cheaktime = time.time()
                        f = open(myfile,'r',encoding="iso-8859-1") #開啟檔案
                        file = f.read()
                        m = 100 / t
                        for a in range(t):          #檢查
                            math = int(m * a + m)
                            if t_list[a] in file and a != t - 1:
                                blist.append(t_list[a])
                                continue
                            if t_list[a] not in file:
                                continue
                        if len(blist) == 0:
                            print('✔This file is currently not malicious')
                        else:
                            print('✖Possibly malicious content: '+ str(blist))
                else:
                    print('✖input file error, can not have quotes')
    else:
        print('Unable to open system file')
def cmdr_en():
    f = open('CMDRT.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000000
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableTaskMgr"=dword:00000000''')
    f.close()
    ctypes.windll.shell32.ShellExecuteW(None, "open", 'CMDRT.reg', __file__, None, 1)
    print('Click "Yes" to repair CMD permissions')
def d_com_en():
    dc = input('Enter custom command: ')
    print('===========================================================================')
    Options21 = str('[Option1]  Execute now')
    Options22 = str('[Option2]  Execute in a few minutes')
    Options23 = str('[Option3]  Execute when entering the system')
    print(Options21)
    print(Options22)
    print(Options23)
    print('===========================================================================')
    tm = input('Optional execution method: ')
    try:
        if int(tm) == 1:
            os.system('cls')
            os.system(dc)
        elif int(tm) == 2:
            print('===========================================================================')
            mu = input('Execution time (minutes): ')
            time.sleep(float(mu)*60)
            os.system('cls')
            os.system(dc)
        elif int(tm) == 3:
            if 'shutdown' in dc:
                print('===========================================================================')
                input('✖Error: This command is forbidden to use, it may cause harm to your computer, press Enter to return')
                pass
            elif 'taskkill' in dc:
                print('===========================================================================')
                input('✖Error: This command is forbidden to use, it may cause harm to your computer, press Enter to return')
                pass
            elif dc == 'taskkill /f /fi pid ne 1':
                print('===========================================================================')
                input('✖Error: This command is forbidden to use, it may cause harm to your computer, press Enter to return')
                pass
            else:
                s = open('defp.cmd','w')
                s.write(dc)
                s.close()
                os.system('COPY "'+str(os.path.dirname(os.path.abspath(__file__)))+'\defp.cmd"'+' "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"')
    except:
        input('✖Error: The content you entered is wrong or the program is wrong, press Enter to return')
        pass
def ask_admin_en():
    if is_admin():
        Options1 = str('[Option1]  Smart scan')
        Options2 = str('[Option2]  Smart analysis')
        Options3 = str('[Option3]  File scan')
        Options4 = str('[Option4]  Partial scan')
        Options5 = str('[Option5]  Full scan')
        Options6 = str('[Option6]  Antivirus immediately')
        Options7 = str('[Option7]  Immediately detect and antivirus')
        Options8 = str('[Option8]  Repeat detection and antivirus')
        Options9 = str('[Option9]  Internal IP lookup')
        Options10 = str('[Option10] Website detection')
        Options11 = str('[Option11] Repair and reset the network')
        Options12 = str('[Option12] File backup')
        Options13 = str('[Option13] Extracting archives')
        Options14 = str('[Option14] Isolate the virus')
        Options15 = str('[Option15] Destroy the file')
        Options16 = str('[Option16] Find files')
        Options17 = str('[Option17] Remove user password')
        Options18 = str('[Option18] Repair system files')
        Options19 = str('[Option19] Fix CMD permissions')
        Options20 = str('[Option20] Start safe mode')
        Options21 = str('[Option21] Turn off safe mode')
        Options22 = str('[Option22] Multi-core stress test')
        Options23 = str('[Option23] Encrypted text')
        Options24 = str('[Option24] Decrypt text')
        Options25 = str('[Option25] Force system shutdown')
        Options26 = str('[Option26] Forcibly end the system')
        Options27 = str('[Option27] Analyze the execution file byte')
        Options28 = str('[Option28] Analysis of executable functions')
        Options29 = str('[Option29] Custom CMD command')
        #Options29 = str('[Option30] Emergency repair of system files')
        Options30 = str('[Option30] 中文 / English')
        while True:
            os.system('cls')
            print('')
            print('==================================== Scan =================================')
            print(Options1)
            print(Options2)
            print(Options3)
            print(Options4)
            print(Options5)
            print('================================== Antivirus ==============================')
            print(Options6)
            print(Options7)
            print(Options8)
            print('============================== Network management =========================')
            print(Options9)
            print(Options10)
            print(Options11)
            print('=============================== File management ===========================')
            print(Options12)
            print(Options13)
            print(Options14)
            print(Options15)
            print(Options16)
            print('=============================== system security ===========================')
            print(Options17)
            print(Options18)
            print(Options19)
            print(Options20)
            print(Options21)
            print('============================== Other functions ============================')
            print(Options22)
            print(Options23)
            print(Options24)
            print(Options25)
            print(Options26)
            print('=============================== Developer mode ============================')
            print(Options27)
            print(Options28)
            print(Options29)
            print('================================== Language ===============================')
            print(Options30)
            print('===========================================================================')
            co = input('Please enter options: ')
            print('===========================================================================')
            try:
                if co == str('pyas -a'):
                    print('Copyright © 2020-2021 PYAS')
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('PYAS -a'):
                    print('Copyright © 2020-2021 PYAS')
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('pyas - a'):
                    print('Copyright © 2020-2021 PYAS')
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('PYAS - a'):
                    print('Copyright © 2020-2021 PYAS')
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('pyas -d'):
                    developer_en()
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('PYAS -d'):
                    developer_en()
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('pyas - d'):
                    developer_en()
                    print('===========================================================================')
                    input('Press Enter to return')
                elif co == str('PYAS - d'):
                    developer_en()
                    print('===========================================================================')
                    input('Press Enter to return')
                else:
                    input('Press Enter to continue')
                    print('===========================================================================')
                    if int(co) == 1:
                        filename = filedialog.askopenfilename()
                        scan_en(filename)
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 2:
                        ai_scan_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 3:
                        startfich_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 4:
                        startpach_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 5:
                        find_dirch_en(filedialog.askdirectory(title="select"))
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 6:
                        kill_appch_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 7:
                        kill_autoch_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 8:
                        kill_while_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 9:
                        myipch_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 10:
                        churl_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 11:
                        Repair_net_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 12:
                        copybuf_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 13:
                        getcopybuf_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 14:
                        movevirus_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 15:
                        savedel_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 16:
                        ffile = input('Please enter the name of the file you are looking for: ')
                        fss = 0
                        start = time.time()
                        print('===========================================================================')
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
                        print('===========================================================================')
                        print('Total time consuming: '+str(end - start)+' sec')
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 17:
                        delpw_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 18:
                        sfc_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 19:
                        cmdr_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 20:
                        savemode_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 21:
                        qsavemode_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 22:
                        cputest_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 23:
                        encrypt_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 24:
                        decrypt_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 25:
                        shutdown_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 26:
                        win_bsod_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 27:
                        exe_ca_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 28:
                        exe_cb_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 29:
                        d_com_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 99999:
                        cmdr_en()
                        kill_appch_en()
                        sfc_en()
                        print('===========================================================================')
                        input('Press Enter to return')
                    elif int(co) == 30:
                        ask_admin()
                        print('===========================================================================')
                        input('Press Enter to return')
                    else:
                        input('✖Error: The content you entered is wrong or the program is wrong, press Enter to return')
                        pass
            except:
                input('✖Error: The content you entered is wrong or the program is wrong, press Enter to return')
    else:
        print('')
        print('======== PYAS antivirus software Pro, version: 1.4 beta (unstable) ========')
        print('')
        print('Copyright © 2020-2021 PYAS')
        print('')
        print('===========================================================================')
        if expansion == False:
            print('')
            print('✖Error: Error loading expansion program, some functions will be unavailable')
            print('')
            print('===========================================================================')
        print('')
        input('This program requires administrator rights, press Enter to continue')
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 8)
ask_admin()
