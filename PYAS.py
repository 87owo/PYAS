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
    from list import *
    import pefile
except:
    expansion = False
def fordel():
    path = str(filedialog.askopenfilename())
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
                        if len(blist) == 0:
                            print('✔此檔案目前沒有惡意')
                        else:
                            print('✖可能惡意內容: '+ str(blist))
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
    start = time.time()
    for i in range(100000):
        print(str(i/1000) + str('%'))
    end = time.time()
    print('===========================================================================')
    print(str('花費時間: ')+str(end - start) + str(' sec'))
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
        shutil.copytree(path,'./備份/'+ pw)
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
        shutil.copytree('./備份/'+ pw,path + '/' + str(pw))
def movevirus():
    path = filedialog.askdirectory(title="選擇有毒資料夾")
    if path == '':
        pass
    else:
        shutil.make_archive('./病毒隔離區/' + str(''.join(random.choice(string.ascii_letters + string.digits)for x in range(8))),'zip',path)
        shutil.rmtree(path)
def shutdown():
    os.system("shutdown -s -t 0")
def find_dirch(path):
    trypath = path.find('/')
    if trypath == -1:
        print('✖輸入檔案錯誤，未選擇檔案')
    else:
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
def startpach():
    flist = []
    bflist = []
    path = filedialog.askdirectory(title="選擇資料夾")
    trypath = path.find('/')
    if trypath == -1:
        print('✖輸入檔案錯誤，未選擇檔案')
    else:
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
        Options2 = str('[選項2]  檔案掃描')
        Options3 = str('[選項3]  局部掃描')
        Options4 = str('[選項4]  全區掃描')
        Options5 = str('[選項5]  立即殺毒')
        Options6 = str('[選項6]  立即偵測殺毒')
        Options7 = str('[選項7]  重複偵測殺毒')
        Options8 = str('[選項8]  內部 IP 查詢')
        Options9 = str('[選項9]  網站檢測')
        Options10 = str('[選項10] 修復並重置網絡')
        Options11 = str('[選項11] 檔案備份')
        Options12 = str('[選項12] 提取檔案')
        Options13 = str('[選項13] 隔離病毒')
        Options14 = str('[選項14] 銷毀檔案')
        Options15 = str('[選項15] 修復系統檔案')
        Options16 = str('[選項16] 修復 CMD 權限')
        Options17 = str('[選項17] 啟動安全模式')
        Options18 = str('[選項18] 關閉安全模式')
        Options19 = str('[選項19] 性能測試')
        Options20 = str('[選項20] 加密文字')
        Options21 = str('[選項21] 解密文字')
        Options22 = str('[選項22] 強制系統關機')
        Options23 = str('[選項23] 強制結束系統')
        Options24 = str('[選項24] 分析執行檔字節')
        Options25 = str('[選項25] 分析執行檔函數')
        Options26 = str('[選項26] 自訂 CMD 指令')
        while True:
            os.system('cls')
            print('')
            print('================================ 掃描 Scan ================================')
            print(Options1)
            print(Options2)
            print(Options3)
            print(Options4)
            print('============================== 殺毒 Antivirus =============================')
            print(Options5)
            print(Options6)
            print(Options7)
            print('======================= 網路管理 Network management =======================')
            print(Options8)
            print(Options9)
            print(Options10)
            print('========================= 檔案管理 File management ========================')
            print(Options11)
            print(Options12)
            print(Options13)
            print(Options14)
            print('========================= 系統安全 system security ========================')
            print(Options15)
            print(Options16)
            print(Options17)
            print(Options18)
            print('========================= 其他功能 Other functions ========================')
            print(Options19)
            print(Options20)
            print(Options21)
            print(Options22)
            print(Options23)
            print('========================= 開發者模式 Developer mode ========================')
            print(Options24)
            print(Options25)
            print(Options26)
            print('===========================================================================')
            co = input('請輸入選項: ')
            print('===========================================================================')
            try:
                if co == str('pyas -a'):
                    print('版權所有© 2020-2021 黃彥瑾')
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS -a'):
                    print('版權所有© 2020-2021 黃彥瑾')
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('pyas -s'):
                    kill_while()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS -s'):
                    kill_while()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('pyas -d'):
                    fordel()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                elif co == str('PYAS -d'):
                    fordel()
                    print('===========================================================================')
                    input('按 Enter 鍵返回')
                else:
                    input('按 Enter 鍵繼續')
                    print('===========================================================================')
                    if int(co) == 1:
                        ai_scan()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 2:
                        startfich()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 3:
                        startpach()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 4:
                        find_dirch(filedialog.askdirectory(title="選擇"))
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 5:
                        kill_appch()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 6:
                        kill_autoch()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 7:
                        kill_while()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 8:
                        myipch()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 9:
                        churl()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 10:
                        Repair_net()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 11:
                        copybuf()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 12:
                        getcopybuf()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 13:
                        movevirus()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 14:
                        savedel()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 15:
                        sfc()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 16:
                        cmdr()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 17:
                        savemode()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 18:
                        qsavemode()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 19:
                        cputest()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 20:
                        encrypt()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 21:
                        decrypt()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 22:
                        shutdown()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 23:
                        win_bsod()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 24:
                        exe_ca()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 25:
                        exe_cb()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    elif int(co) == 26:
                        d_com()
                        print('===========================================================================')
                        input('按 Enter 鍵返回')
                    else:
                        input('✖錯誤:您輸入的內容錯誤或程式出錯，按 Enter 鍵返回')
                        pass
            except:
                input('✖錯誤:您輸入的內容錯誤或程式出錯，按 Enter 鍵返回')
    else:
        print('')
        print('================ PYAS 防毒軟體 Pro ， 版本 : 1.0 (穩定版) =================')
        print('')
        print('版權所有© 2020-2021 黃彥瑾')
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
ask_admin()
