####################################################################################
# Coding Python 3.8 UTF-8 (Python IDLE)
#
# PYAS Ver: PYAS V2.2.5 (2020.12.17)
# PYAE Ver: PYAE V1.2.5 (2022.03.04)
# Support: Windows 7,8,10,11 64-bit
#
# PYAS Git: https://github.com/87owo/PYAS
# PYAS Web: https://xiaomi69ai.wixsite.com/pyas
# PYDT Web: https://xiaomi69ai.wixsite.com/pydt
#
# PYAS is managed by PYDT (Python Development Team)
# Copyright© 2020-2022 PYAS Python Antivirus Software.
####################################################################################

#載入模組套件
try:
    import os, time, sys, psutil, socket, subprocess, platform, cryptocode, webbrowser, threading, pygame, pathlib, virustotal_python, win32api, win32con
    from cv2 import VideoCapture
    from ctypes import windll
    import requests as req
    from pefile import PE
    from hashlib import md5
    from tkinter import messagebox, filedialog
    from tkinter import *
except Exception as e:
    pass#print(e)

####################################################################################

#版本資訊
pyas_version = '2.2.5'
pyae_version = '1.2.5'
dev_edition_times = 0
pyas_copyright = 'Copyright© 2020-2022 PYAS Python Antivirus Software.'

####################################################################################

#檔案資訊
'''
import pyinstaller_versionfile
pyinstaller_versionfile.create_versionfile(
    output_file="versionfile.txt",
    version=pyas_version,
    company_name="PYAS",
    file_description="Python Antivirus Software",
    internal_name="PYAS",
    legal_copyright="Copyright© 2020-2022 PYAS",
    original_filename="PYAS.exe",
    product_name="PYAS")
'''

####################################################################################

#文字語言
en_init_file = 'Initializing, please wait.'
zh_init_file = '正在初始化中，請稍等。'
cn_init_file = '正在初始化中，请稍等。'

en_scaning = 'Scanning:'
zh_scaning = '正在掃描:'
cn_scaning = '正在扫描:'

en_success = '✔Success: Executed successfully.'
zh_success = '✔成功: 已執行成功。'
cn_success = '✔成功: 已执行成功。'

en_failed = '✖Error: Execution failed.'
zh_failed = '✖錯誤: 執行失敗。'
cn_failed = '✖错误: 执行失败。'

en_virus_true = '✖Malware has currently been discovered.'
zh_virus_true = '✖當前已發現惡意軟體。'
cn_virus_true = '✖当前已发现恶意软件。'

en_virus_false = '✔No malware currently found.'
zh_virus_false = '✔當前未發現惡意軟體。'
cn_virus_false = '✔当前未发现恶意软件。'

none_file_en = '✖Error: No file selected.'
none_file_zh = '✖錯誤: 未選擇任何檔案。'
none_file_cn = '✖错误: 未选取任何档案。'

en_answer = 'Output: '
zh_answer = '輸出結果: '
cn_answer = '输出结果: '

en_app_use = 'Auto Sleep: Other App is running now, Close it to continue.'
zh_app_use = '自動休眠中: 當前其他軟體正在執行中，關閉後即可繼續使用。'
cn_app_use = '自动休眠中: 当前其他软件正在运行中，关闭后即可继续使用。'

####################################################################################

#分格線
pyas_divider = '='*80

####################################################################################

#載入窗口介面
root = Tk()
root.title('PYAS V'+pyas_version)
sx,sy = root.winfo_screenwidth(),root.winfo_screenheight()
root.geometry('800x450+'+str(int(sx/2-400))+'+'+str(int(sy/2-225)))
textPad=Text(root,undo=True)
textPad.pack(expand=YES,fill=BOTH)
scroll=Scrollbar(textPad)
textPad.config(yscrollcommand=scroll.set)
scroll.config(command=textPad.yview)
scroll.pack(side=RIGHT,fill=Y)
group = Label(root, text=pyas_copyright,padx=5, pady=2)
group.pack(anchor='e')

####################################################################################

#觀迎使用
en_welcome = '''Welcome To Python Antivirus Software !!!
===================================
Language: Setting > Change Language
Update: Setting > Software Settings
===================================
PYAS Version: '''+pyas_version+''', PYAE Version: '''+pyae_version

####################################################################################

#許可條款
def pyas_license_terms_en():
    pyas_clear()
    textPad.insert("insert", '''PYTHON ANTIVIRUS SOFTWARE LICENSE TERMS
#Use PYAS anti-virus software and services means that you accept these terms. If you do not accept them, please do not use them.
#Use PYAS anti-virus software and services, if you comply with the PYAS anti-virus software license terms, you will have the following rights.
1.License right to use PYAS anti-virus software.
You can use the software on your device or use a copy of the software to design and develop the software.
The software is forbidden to be sold or copied by others without permission. You can only use it to design and develop the software.
2.Obtain genuine PYAS anti-virus software.
You can get the software directly from the official website of PYAS antivirus software, or you can get it through the official GitHub.
If you have obtained this software from a third-party application store that has not been authorized by the official website of PYAS antivirus software,
Then we cannot guarantee that the software can be used normally, and we are not responsible for any related losses caused to you.
Official website: https://xiaomi69ai.wixsite.com/pyas
Official Git: https://github.com/87owo/PYAS
3.Personal information and privacy protection.
You can register your email and name on the official website of PYAS anti-virus software, which will be used for feedback contact.
PYAS anti-virus software will obtain the computer system version and basic information, which will be used to optimize the operation of the software.
The security of your equipment and personal data is very important to us, and we will never leak any of your personal information.
4.Permission required to use PYAS anti-virus software.
System administrator permissions
Turn on target site permissions
File read and write management permissions
Command prompt execution permission
Login editor management authority
''')

####################################################################################

#定義清除畫面
def pyas_clear():
    textPad.delete(1.0,END)

####################################################################################

#定義紀錄掃描
def pyas_scan_write_en(file):
    ft = open('Library/PYAS/Temp/PYASV.tmp','a',encoding='utf-8')
    fe = ft.write(file+'\n')
    ft.close()

def pyas_scan_write_d_en(file):
    ft = open('Library/PYAS/Temp/PYASD.tmp','a',encoding='utf-8')
    fe = ft.write(file+'\n')
    ft.close()

#定義讀取紀錄
def pyas_scan_read_en():
    try:
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        fe = ft.read()
        ft.close()
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        lines = len(ft.readlines())
        ft.close()
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Virusfound.ogg')
            pygame.mixer.music.play()
        return en_virus_true+' ('+str(lines)+' items)'+'\n'+pyas_divider+'\n'+fe###
    except:
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Complete.ogg')
            pygame.mixer.music.play()
        return en_virus_false

#定義移除紀錄
def pyas_scan_del_en():
    os.remove('Library/PYAS/Temp/PYASV.tmp')

#定義掃描結果
def pyas_scan_answer_en():
    pyas_clear()
    textPad.insert("insert", pyas_scan_read_en())
    try:
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        lines = ft.readlines()
        ft.close()
        if messagebox.askokcancel('Warning',"Do you want to remove these malware?", default="cancel", icon="warning"):
            try:
                for line in lines:
                    if 'C:/Windows' not in line:
                        pyas_clear()
                        textPad.insert("insert", 'Deleting:'+'\n'+pyas_divider+'\n'+str(line))
                        root.update()
                        try:
                            os.remove(str(line[:-1]))
                        except:
                            continue
                    else:
                        pass
                pyas_clear()
                textPad.insert("insert", en_success)
            except Exception as e:
                pyas_clear()
                textPad.insert("insert", en_failed+'\n'+pyas_divider+'\n'+str(e))
                #print(e)
                pass
    except:# Exception as e:
        pass#print(e)
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass

####################################################################################

#定義更新選項
def software_update_en():
    pyas_clear()
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas?lang=en')

def engine_update_en():
    if messagebox.askokcancel('Warning','Update Antivirus Engine ,Do You want to continue?', default="cancel", icon="warning"):
        pyas_clear()
        textPad.insert("insert", 'Update Please Wait...')
        root.update()
        try:
            file = req.get('https://github.com/87owo/ViruslistMD5/releases/download/v420/Viruslist.md5', allow_redirects=True)
            open('Library/PYAE/Hashes/Viruslist.md5', 'w').write(str(file.content)+'\n')
            pyas_clear()
            textPad.insert("insert", 'Update Complete.')
            root.update()
        except Exception as e:
            pyas_clear()
            textPad.insert("insert", 'Update Failed: '+str(e))
            pass
        
####################################################################################

#定義開始掃描
def pyas_scan_start(file,rfp):
    try:
        virus_found = False
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = md5(bytes).hexdigest();
            if str(readable_hash) in str(rfp):
                virus_found = True
        f.close()
        if not virus_found:
            return False
        else:
            return True
    except:
        pass

####################################################################################

#定義防護
def protect_threading_init_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Enable Real Time Protection Needs More Then 4GB Of RAM. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.insert("insert", en_init_file)
        root.update()
        t = threading.Thread(target = pyas_protect_init_en)
        t.start()
        #t.join()
    else:
        pass

#定義全盤掃描
def pyas_protect_init_en():
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    pyas_clear()
    textPad.insert("insert", en_success)
    root.update()
    while 1:
        for p in psutil.process_iter():
            try:
                if 'C:\Windows' in str(p.exe()):
                    pass
                elif 'C:\Program Files' in str(p.exe()):
                    pass
                else:
                    if pyas_scan_start(p.exe(),rfp):
                        of = subprocess.call('taskkill /f /im "'+str(p.name())+'"',shell=True)
                        try:
                            if of == 0:
                                pyas_clear()
                                textPad.insert("insert", 'Successfully blocked a malware: '+str(p.name()))
                                pygame.mixer.init()
                                if not pygame.mixer.music.get_busy():
                                    pygame.mixer.music.load('Library/PYAS/Audio/Virusfound.ogg')
                                    pygame.mixer.music.play()
                            else:
                                pyas_clear()
                                textPad.insert("insert", 'Malware blocking failed: '+str(p.name()))
                        except:
                            pass
            except:# Exception as e:
                continue#print(e)

####################################################################################

def input_virustotal_scan_en():
    pyas_clear()
    t=Toplevel(root)
    t.title('Virustotal Api Key')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' KEY: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :virustotal_scan_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def virustotal_scan_en(key):
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        try:
            with open(file,"rb") as f:
                bytes = f.read()
                readable_hash = md5(bytes).hexdigest();
                FILE_ID = str(readable_hash)
                with virustotal_python.Virustotal(key) as vtotal:
                    resp = vtotal.request(f"files/{FILE_ID}")
                    FILE_ID = resp.data["id"]
                    webbrowser.open('https://www.virustotal.com/gui/file/'+str(FILE_ID))
            f.close()
        except:# Exception as e:
            pass#print(e)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_en+'\n')

####################################################################################

#定義檔案掃描
def pyas_file_scan_en():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", en_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
        rfn = fn.read()
    file = filedialog.askopenfilename()
    if file != "":
        if pyas_scan_start(file,rfp):
            pyas_scan_write_en(file)
            textPad.insert("insert", en_virus_true+'\n')
        else:
            if 'C:/Windows' in str(file):
                pass
            elif 'C:/Program Files' in str(file):
                pass
            else:
                try:
                    fts = 0
                    pe = PE(file)
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for function in entry.imports:
                            root.update()
                            if str(function.name) in rfn:
                                fts = fts + 1
                    PE.close(pe)
                    if fts != 0:
                        pyas_scan_write_en(file)
                        fts = 0
                        textPad.insert("insert", en_virus_true+'\n')
                except:
                    pass
        fp.close()
        fn.close()
        pyas_scan_answer_en()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_en+'\n')

####################################################################################

#定義路徑掃描
def pyas_scan_path_init_en():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", en_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
        rfn = fn.read()
    fp.close()
    fn.close()
    file = filedialog.askdirectory()
    if file != "":
        pyas_scan_path_en(file,rfp,rfn,0)
        pyas_scan_answer_en()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_en+'\n')

def pyas_scan_path_en(path,rfp,rfn,fts):
    try:
        for fd in os.listdir(path):
            try:
                root.update()
                fullpath = os.path.join(path,fd)
                #print(fullpath)
                if os.path.isdir(fullpath):
                    pyas_scan_path_en(fullpath,rfp,rfn,fts)
                else:
                    if 'C:/Windows' in str(fullpath):#'.exe' in str(fd) or '.EXE' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif 'C:/Program Files' in str(fullpath):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    else:
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                        else:
                            try:
                                pe = PE(fullpath)
                                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                    for function in entry.imports:
                                        root.update()
                                        if str(function.name) in rfn:
                                            fts = fts + 1
                                PE.close(pe)
                                if fts != 0:
                                    pyas_scan_write_en(str(fullpath))
                                    fts = 0
                            except:
                                pass
            except:
                continue
    except:
        pass

####################################################################################

#定義全盤掃描
def pyas_scan_disk_init_en():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", en_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    pyas_scan_disk_en('A:/',rfp)
    pyas_scan_disk_en('B:/',rfp)
    pyas_scan_disk_en('C:/',rfp)
    pyas_scan_disk_en('D:/',rfp)
    pyas_scan_disk_en('E:/',rfp)
    pyas_scan_disk_en('F:/',rfp)
    pyas_scan_disk_en('G:/',rfp)
    pyas_scan_disk_en('H:/',rfp)
    pyas_scan_disk_en('I:/',rfp)
    pyas_scan_disk_en('J:/',rfp)
    pyas_scan_disk_en('K:/',rfp)
    pyas_scan_disk_en('L:/',rfp)
    pyas_scan_disk_en('M:/',rfp)
    pyas_scan_disk_en('N:/',rfp)
    pyas_scan_disk_en('O:/',rfp)
    pyas_scan_disk_en('P:/',rfp)
    pyas_scan_disk_en('Q:/',rfp)
    pyas_scan_disk_en('R:/',rfp)
    pyas_scan_disk_en('S:/',rfp)
    pyas_scan_disk_en('T:/',rfp)
    pyas_scan_disk_en('U:/',rfp)
    pyas_scan_disk_en('V:/',rfp)
    pyas_scan_disk_en('W:/',rfp)
    pyas_scan_disk_en('X:/',rfp)
    pyas_scan_disk_en('Y:/',rfp)
    pyas_scan_disk_en('Z:/',rfp)
    fp.close()
    pyas_scan_answer_en()

def pyas_scan_disk_en(path,rfp):
    try:
        for fd in os.listdir(path):
            try:
                root.update()
                fullpath = os.path.join(path,fd)
                if os.path.isdir(fullpath):
                    pyas_scan_disk_en(fullpath,rfp)
                else:
                    if '.exe' in str(fd) or '.EXE' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.cmd' in str(fd) or '.CMD' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.bat' in str(fd) or '.BAT' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.com' in str(fd) or '.COM' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.vbs' in str(fd) or '.VBS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.zip' in str(fd) or '.ZIP' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.js' in str(fd) or '.JS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.xls' in str(fd) or '.XLS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.doc' in str(fd) or '.DOC' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.dll' in str(fd) or '.DLL' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.scr' in str(fd) or '.SCR' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    elif '.tmp' in str(fd) or '.TMP' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", en_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_en(fullpath)
                    else:
                        pass
            except:
                continue
    except:
        pass

####################################################################################

#工具
def computer_info_en():
    pyas_clear()
    textPad.insert("insert", 'System information:\n'+str(pyas_divider)+'\n'+str(platform.platform())+'\n'+str(platform.architecture())+'\n'+str(platform.node())+'\n'+str(platform.processor()))

def camera_check_en():
    pyas_clear()
    textPad.insert("insert", en_init_file)
    root.update()
    cap = VideoCapture(0)
    ret, frame = cap.read()
    pyas_clear()
    if ret:
        textPad.insert("insert", '✔The current camera is safe.')
        cap.release()
    else:
        textPad.insert("insert", '✖Camera not detected, possible privacy risk.')
        cap.release()

def exe_analyze_md5_en():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = md5(bytes).hexdigest();
            textPad.insert("insert", 'MD5: '+str(readable_hash))
        f.close()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_en+'\n')

def exe_analyze_file_en():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        pe = PE(file)
        for section in pe.sections:
            root.update()
            textPad.insert("insert", section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData)
        PE.close(pe)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_en+'\n')

def exe_analyze_function_en():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        pe = PE(file)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for function in entry.imports:
                root.update()
                textPad.insert("insert", str(function.name)+'\n')
        PE.close(pe)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_en+'\n')

def process_init_en():
    pyas_clear()
    pids = psutil.pids()
    textPad.insert("insert", 'Process name found:\n'+pyas_divider+'\n')
    for pid in pids:
        textPad.insert("insert",psutil.Process(pid).name()+'\n')
    t=Toplevel(root)
    t.title('Process name')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' Kill Process: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :process_kill_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def process_kill_en(app):
    pyas_clear()
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            of = subprocess.call('taskkill /f /im '+str(app),shell=True)
            if of == 0:
                textPad.insert("insert", en_success)
            else:
                textPad.insert("insert", en_failed)
            done = True
            break
        else:
            try:
                of = subprocess.call('taskkill /f /im '+str(app),shell=True)
                if of == 0:
                    textPad.insert("insert", en_success)
                else:
                    textPad.insert("insert", en_failed)
            except:
                textPad.insert("insert", 'Process not found "'+str(app)+'"')
            done = True
            break

def destroy_files_en():
    pyas_clear()
    try:
        path = filedialog.askopenfilename()
        if path != '':
            if messagebox.askokcancel('Warning','This file is about to be permanently removed. Continue?', default="cancel", icon="warning"):
                os.remove(path)
                textPad.insert("insert", en_success)
            else:
                pass
        else:
            pass
    except:
        textPad.insert("insert", en_failed)
    
def ip_detect_en():
    pyas_clear()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    textPad.insert("insert", 'Your IP is: ' + s.getsockname()[0])
    s.close()

def reset_network_en():
    pyas_clear()
    runc = subprocess.call("netsh winsock reset", shell=True)
    if runc == 0:
        textPad.insert("insert", en_success)
    else:
        textPad.insert("insert", en_failed)
        
def find_files_init_en():
    pyas_clear()
    t=Toplevel(root)
    t.title('File Name')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' File: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    Button(t,text='OK',command=lambda :find_files_info_en(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def find_files_info_en(ffile):
    try:
        fss = 0
        start = 0
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
        ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding='utf-8')
        fe = ft.read()
        ft.close()
        ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding='utf-8')
        lines = len(ft.readlines())
        ft.close()
        pyas_clear()
        textPad.insert("insert", 'Find result: ('+str(int(lines/3))+' items)\n'+pyas_divider+'\n'+str(fe))
        os.remove('Library/PYAS/Temp/PYASF.tmp')
    except:
        pass

def findfile_en(path,ffile,fss,start):
    try:
        pyas_clear()
        textPad.insert("insert", 'Searching: '+str(path))
        for fd in os.listdir(path):
            root.update()
            fullpath = os.path.join(path,fd)
            if os.path.isdir(fullpath):
                findfile_en(fullpath,ffile,fss,start)
            else:
                fss = fss + 1
                if ffile in str(fd):
                    date = time.ctime(os.path.getmtime(fullpath))
                    ft = open('Library/PYAS/Temp/PYASF.tmp','a',encoding='utf-8')
                    ft.write('File found: '+str(fullpath)+'\n'+'Create date: '+str(date)+'\n'+'\n')
                    ft.close()
                    continue
    except:
        pass

def repair_system_files_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''The execution process will take a while, do you want to continue?''', default="cancel", icon="warning"):
        root.update()
        textPad.insert("insert",en_app_use)
        root.update()
        runc = os.system('sfc /scannow')
        pyas_clear()
        if runc == 0:
            textPad.insert("insert", en_success)
        else:
            textPad.insert("insert", en_failed)
            os.system('cls')
    else:
        pass

def start_safe_mode_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Start safe mode requires a reboot, do you want to continue?''', default="cancel", icon="warning"):
        #os.system('net user administrator /active:yes')
        os.system('bcdedit /set {default} safeboot minimal')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def close_safe_Mode_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Turn off safe mode requires a reboot, Do you want to continue?''', default="cancel", icon="warning"):
        #os.system('net user administrator /active:no')
        os.system('bcdedit /deletevalue {current} safeboot')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def input_custom_cmd_command_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Improper use of custom commands may have serious consequences. Do you want to continue?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('Command')
        t.geometry('260x40')
        t.transient(root)
        Label(t,text=' CMD: ').grid(row=0,column=0,sticky='e')
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
    pyas_clear()
    textPad.insert("insert",en_app_use)
    root.update()
    os.system(cmd)
    pyas_clear()
    textPad.insert("insert", en_success)

def input_custom_regedit_command_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Improper use of custom commands may have serious consequences. Do you want to continue?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('Custom Command')
        t.geometry('260x110')
        t.transient(root)
        Label(t,text=' Path: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' Name: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' Type: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        Label(t,text=' Num: ').grid(row=3,column=0,sticky='e')
        v4=StringVar()
        e4=Entry(t,width=20,textvariable=v4)
        e4.grid(row=3,column=1,padx=2,pady=2,sticky='we')
        e4.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :custom_regedit_command(e.get(),e2.get(),e3.get(),e4.get())).grid(row=3,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def custom_regedit_command(path,cmd,reg,num):
    pyas_clear()
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
['''+str(path)+''']
"'''+str(cmd)+'''"='''+str(reg)+''':'''+str(num)+'''''')
    f.close()
    windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)

def fix_cmd_permissions_en():
    pyas_clear()
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000000
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableTaskMgr"=dword:00000000''')
    f.close()
    windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)

def input_encrypt_en():
    pyas_clear()
    t=Toplevel(root)
    t.title('Input text')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text='PassWord: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :encrypt_en(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)

def encrypt_en(e,e2):
    pyas_clear()
    textPad.insert("insert", 'Your encrypted content: \n'+str(cryptocode.encrypt(e,e2)))

def input_decrypt_en():
    pyas_clear()
    t=Toplevel(root)
    t.title('Input Text')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text='PassWord: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :decrypt_en(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)

def decrypt_en(e,e2):
    pyas_clear()
    textPad.insert("insert", 'Your decrypted content: \n'+str(cryptocode.decrypt(e, e2)))

def input_send_text_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Sending a message requires the other party to turn on the receive mode. Do you want to continue?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('Send Message')
        t.geometry('260x90')
        t.transient(root)
        Label(t,text='Input: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text='   IP: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' Port: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :send_text_en(e.get(),e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def send_text_en(message,HOST,PORT):
    pyas_clear()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(message.encode())
    except:
        messagebox.showerror('Error', '''Please turn on the receiving mode of the device to be received and turn off the firewall.''')

def input_receive_text_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Waiting for the receiving process will take a while, do you want to continue?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('Receive Text')
        t.geometry('260x70')
        t.transient(root)
        Label(t,text='   IP: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' Port: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :receive_text_en(e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass
    
def receive_text_en(HOST,PORT):
    pyas_clear()
    max_connect = 5
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        root.update()
        s.bind((HOST, int(PORT)))
        s.listen()
        conn, _ = s.accept()
        data = conn.recv(1024).decode()
        textPad.insert("insert",'Received Content: '+data)
        root.update()

def system_disk_clean_en():
    pyas_clear()
    textPad.insert("insert",en_app_use)
    root.update()
    os.system('cleanmgr')
    pyas_clear()

def change_user_password_init_en():
    pyas_clear()
    messagebox.showinfo('Version','''Before changing the user password, please make sure you have entered the safe mode before using this function.''')
    t=Toplevel(root)
    t.title('Change Password')
    t.geometry('260x60')
    t.transient(root)
    Label(t,text='User Name: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text='New PassWord: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    Button(t,text='OK',command=lambda :change_user_password_en(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=0)

def change_user_password_en(user,password):
    os.system('net user '+str(user)+' "'+str(password)+'"')

def recover_Wallpaper_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Repair System Wallpaper, Do you want to continue?''', default="cancel", icon="warning"):
        try:
            try:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',0,win32con.KEY_ALL_ACCESS)
            except:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer',0,win32con.KEY_ALL_ACCESS)
                win32api.RegCreateKey(key,'Wallpapers')
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',0,win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'BackgroundHistoryPath0', win32con.REG_SZ, r'c:\windows\web\wallpaper\windows\img0.jpg')
            user32dll = windll.LoadLibrary(r"C:\Windows\System32\user32.dll") 
            user32dll.SystemParametersInfoW(20, 0, r'c:\windows\web\wallpaper\windows\img0.jpg', 0)
            pyas_clear()
            textPad.insert("insert", en_success)
        except Exception as e:
            pyas_clear()
            textPad.insert("insert", en_failed+'\n'+pyas_divider+'\n'+str(e))

def fixlimit_en():
    pyas_clear()
    if messagebox.askokcancel('Warning','''Repair System Restrictions, Do you want to continue?''', default="cancel", icon="warning"):
        if 1:
            try:
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass
                    
                try:
                    win32api.RegDeleteValue(key, 'NoDrives')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFileMenu')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFind')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRealMode')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolders')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewOnDrive')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoClose')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRun')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContexMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'HideClock')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMorePrograms')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyGames')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyMusic')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuNetworkPlaces')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuPinnedList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktopChanges')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoChangeStartMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'ClearRecentDocsOnExit')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFavoritesMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsHistory')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetTaskbar')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSMHelp')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoTrayContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWindowsUpdate')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWinKeys')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'StartMenuLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSimpleNetlDList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLowDiskSpaceChecks')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableLockWorkstation')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoManageMyComputerVerb')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'RestrictRun')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass
                    
                try:
                    win32api.RegDeleteValue(key, 'NoDrives')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFileMenu')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFind')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRealMode')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolders')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewOnDrive')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoClose')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRun')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContexMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'HideClock')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMorePrograms')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyGames')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyMusic')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuNetworkPlaces')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuPinnedList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktopChanges')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoChangeStartMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'ClearRecentDocsOnExit')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFavoritesMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsHistory')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetTaskbar')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSMHelp')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoTrayContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWindowsUpdate')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWinKeys')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'StartMenuLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSimpleNetlDList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLowDiskSpaceChecks')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableLockWorkstation')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoManageMyComputerVerb')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'RestrictRun')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableTaskMgr')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableRegistryTools')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableChangePassword')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'Wallpaper')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableTaskMgr')
                except:
                    pass       
                try:
                    win32api.RegDeleteValue(key, 'DisableRegistryTools')
                except:
                    pass        
                try:
                    win32api.RegDeleteValue(key, 'DisableChangePassword')
                except:
                    pass           
                try:
                    win32api.RegDeleteValue(key, 'Wallpaper')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'ActiveDesktop')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoComponents')
                except:
                    pass          
                try:
                    win32api.RegDeleteValue(key, 'NoAddingComponents')
                except:
                    pass                  
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except:
                    pass                    
                win32api.RegCloseKey(key)
        

                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except:
                    pass    
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                except:
                    try:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    except:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft',0,win32con.KEY_ALL_ACCESS)
                        win32api.RegCreateKey(key,'MMC')
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'Restrict_Run')
                except:
                    pass
                win32api.RegCloseKey(key)
                pyas_clear()
                textPad.insert("insert", en_success)
            except Exception as e:
                pyas_clear()
                textPad.insert("insert", en_failed+'\n'+pyas_divider+'\n'+str(e))

################################################################################

#關於
def about_pyas_en():
    pyas_clear()
    try:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','r')
        dev_edition_times = int(er.read())
        er.close()
    except:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write('0')
        er.close()
        dev_edition_times = 0
    if dev_edition_times >= 2:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write('0')
        er.close()
        messagebox.showinfo('?????????','''???????????????????????????????????????????????????''')
        x = ''
        pdinfo = '''
PYAS Developer: PYAS_Dev#0629 , Mtkiao129#3921 , Dragon#5381
Official Email: xiaomi69ai@gmail.com
Official Github: https://github.com/87owo/PYAS
Official Website: https://xiaomi69ai.wixsite.com/pyas
PYAS Create Date: 2020/12/17
PYAS Version: '''+pyas_version+'''
PYAE Version: '''+pyae_version+'''
Special Thanks: Wix, Avast, Github, Google, Python, Microsoft, VirusTotal, VirusShare, LenStevens
Thanks For Using PYAS Python Antivirus Software'''
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Easteregg.ogg')
            pygame.mixer.music.play()
        for i in pdinfo:
            x = x+i
            time.sleep(0.1)
            pyas_clear()
            textPad.insert("insert",'''PYAS Infomation:
'''+str(pyas_divider)+str(x)+'_')
            root.update()
        pyas_clear()
        textPad.insert("insert",'''PYAS Infomation:
'''+str(pyas_divider)+str(pdinfo))
        root.update()
    else:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write(str(dev_edition_times + 1))
        er.close()
        messagebox.showinfo('Copyright','''Website: https://xiaomi69ai.wixsite.com/pyas
Copyright© 2020-2022 PYAS Python Antivirus Software''')

def software_version_en():
    pyas_clear()
    messagebox.showinfo('Version','''Software Version: '''+pyas_version)

def engine_version_en():
    pyas_clear()
    messagebox.showinfo('Version','''Engine Version: '''+pyae_version)

####################################################################################

#權限
def is_admin():
    try:
        return windll.shell32.IsUserAnAdmin()
    except:
        return False

####################################################################################

#主選單(英文)
def english():
    if is_admin():
        try:
            pyas_clear()
            ft = open('Library/PYAS/Setup/PYAS.ini','w')
            ft.write('''english''')
            ft.close()
            menubar = Menu(root)
            root.config(menu = menubar)
            filemenu = Menu(menubar,tearoff=False)
            filemenu.add_command(label = 'File Scan',command = pyas_file_scan_en)
            filemenu.add_command(label = 'Path Scan',command = pyas_scan_path_init_en)
            filemenu.add_command(label = 'Full Scan',command = pyas_scan_disk_init_en)
            menubar.add_cascade(label = ' Scan',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = 'Enable Real Time Protection',command = protect_threading_init_en)
            menubar.add_cascade(label = 'Protect',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            menubar.add_cascade(label = 'Tools',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='System Tools', menu=sub2menu, underline=0)
            sub2menu.add_command(label = 'System Process Manager',command = process_init_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Clean Up System Disk',command = system_disk_clean_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Repair System Files',command = repair_system_files_en)
            sub2menu.add_command(label = 'Repair System Wallpaper',command = recover_Wallpaper_en)
            sub2menu.add_command(label = 'Repair System Permissions',command = fix_cmd_permissions_en)
            sub2menu.add_command(label = 'Repair System Restrictions',command = fixlimit_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Enable Safe Mode',command = start_safe_mode_en)
            sub2menu.add_command(label = 'Disable Safe Mode',command = close_safe_Mode_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'System Version Info',command = computer_info_en)
            insmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='Privacy Tools', menu=insmenu, underline=0)
            insmenu.add_command(label = 'Camera Privacy Detection',command = camera_check_en)
            insmenu.add_command(label = 'Remove Private Files',command = destroy_files_en)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='More Tools', menu=submenu, underline=0)
            submenu.add_command(label = 'Find Profile',command = find_files_init_en)
            submenu.add_separator()
            submenu.add_command(label = 'Encrypted Text',command = input_encrypt_en)
            submenu.add_command(label = 'Decrypt Text',command = input_decrypt_en)
            submenu.add_separator()
            submenu.add_command(label = 'Send Message',command = input_send_text_en)
            submenu.add_command(label = 'Receive Message',command = input_receive_text_en)
            submenu.add_separator()
            submenu.add_command(label = 'Change User Password',command = change_user_password_init_en)
            submenu.add_separator()
            submenu.add_command(label = 'Internet Location Query',command = ip_detect_en)
            submenu.add_command(label = 'Reset System Network',command = reset_network_en)
            devmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='Dev Tools', menu=devmenu, underline=0)
            devmenu.add_command(label = 'Custom REG Command',command = input_custom_regedit_command_en)
            devmenu.add_command(label = 'Custom CMD Command',command = input_custom_cmd_command_en)
            devmenu.add_separator()
            devmenu.add_command(label = 'Analyze EXE Hashes',command = exe_analyze_md5_en)
            devmenu.add_command(label = 'Analyze EXE Bytes',command = exe_analyze_file_en)
            devmenu.add_command(label = 'Analyze EXE Function',command = exe_analyze_function_en)
            devmenu.add_separator()
            devmenu.add_command(label = 'Online File Analyze',command = input_virustotal_scan_en)
            filemenu5 = Menu(menubar,tearoff=False)
            menubar.add_cascade(label = 'Settings',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Software Settings', menu=sitmenu, underline=0)
            sitmenu.add_command(label="Update Antivirus Software", command=software_update_en)
            sitmenu.add_command(label="Update Antivirus Engine", command=engine_update_en)
            sitmenu2 = Menu(filemenu5,tearoff=False)
            #filemenu5.add_cascade(label='Engine Settings', menu=sitmenu2, underline=0)
            #sitmenu2.add_command(label="Enable Quick Scan", command=#)
            #sitmenu2.add_command(label="Disable Quick Scan", command=#)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Change Language', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese)
            sit2menu.add_command(label="简体中文", command=simplified_chinese)
            sit2menu.add_command(label="English", command=english)
            aboutmenu = Menu(menubar,tearoff=False)
            aboutus = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='About Us', menu=aboutus, underline=0)
            aboutus.add_command(label="About PYAS", command=about_pyas_en)
            aboutversion = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='Software Version', menu=aboutversion, underline=0)
            aboutversion.add_command(label="Antivirus Software Version", command=software_version_en)
            aboutversion.add_command(label="Antivirus Engine Version", command=engine_version_en)
            licmenu = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='Licensing Terms', menu=licmenu, underline=0)
            licmenu.add_command(label = 'PYAS Licensing Terms',command = pyas_license_terms_en)
            menubar.add_cascade(label = 'About',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            messagebox.showerror('Error', '''There was an error in the program, we're sorry.
Report Error: https://xiaomi69ai.wixsite.com/pyas
Error Info: '''+str(e))
    else:
        windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

####################################################################################

#定義防護
def protect_threading_init_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''啟動實時防護需要 4GB 以上的記憶體，是否繼續?''', default="cancel", icon="warning"):
        pyas_clear()
        textPad.insert("insert", zh_init_file)
        root.update()
        t = threading.Thread(target = pyas_protect_init_zh)
        t.start()
        #t.join()
    else:
        pass

#定義全盤掃描
def pyas_protect_init_zh():
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    pyas_clear()
    textPad.insert("insert", zh_success)
    root.update()
    while 1:
        for p in psutil.process_iter():
            try:
                if 'C:\Windows' in str(p.exe()):
                    pass
                elif 'C:\Program Files' in str(p.exe()):
                    pass
                else:
                    if pyas_scan_start(p.exe(),rfp):
                        of = subprocess.call('taskkill /f /im "'+str(p.name())+'"',shell=True)
                        try:
                            if of == 0:
                                pyas_clear()
                                textPad.insert("insert", '成功攔截了一個惡意軟體: '+str(p.name()))
                                pygame.mixer.init()
                                if not pygame.mixer.music.get_busy():
                                    pygame.mixer.music.load('Library/PYAS/Audio/Virusfound.ogg')
                                    pygame.mixer.music.play()
                            else:
                                pyas_clear()
                                textPad.insert("insert", '惡意軟體攔截失敗: '+str(p.name()))
                        except:
                            pass
            except:
                continue

####################################################################################
        
#定義紀錄掃描
def pyas_scan_write_zh(file):
    ft = open('Library/PYAS/Temp/PYASV.tmp','a',encoding='utf-8')
    fe = ft.write(file+'\n')
    ft.close()

#定義讀取紀錄
def pyas_scan_read_zh():
    try:
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        fe = ft.read()
        ft.close()
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        lines = len(ft.readlines())
        ft.close()
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Virusfound.ogg')
            pygame.mixer.music.play()
        return zh_virus_true+' ('+str(lines)+' 項)'+'\n'+pyas_divider+'\n'+fe
    except:
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Complete.ogg')
            pygame.mixer.music.play()
        return zh_virus_false

#定義移除紀錄
def pyas_scan_del_zh():
    os.remove('Library/PYAS/Temp/PYASV.tmp')

#定義掃描結果
def pyas_scan_answer_zh():
    pyas_clear()
    textPad.insert("insert", pyas_scan_read_zh())
    try:####
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        lines = ft.readlines()
        ft.close()
        if messagebox.askokcancel('Warning',"是否要刪除這些惡意軟件?", default="cancel", icon="warning"):
            try:
                for line in lines:
                    if 'C:/Windows' not in line:
                        pyas_clear()
                        textPad.insert("insert", '正在移除:'+'\n'+pyas_divider+'\n'+str(line))
                        root.update()
                        try:
                            os.remove(str(line[:-1]))
                        except:
                            continue
                    else:
                        pass
                pyas_clear()
                textPad.insert("insert", zh_success)
            except Exception as e:
                pyas_clear()
                textPad.insert("insert", zh_failed+'\n'+pyas_divider+'\n'+str(e))
                #print(e)
                pass
    except:# Exception as e:
        pass#print(e)###
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass

####################################################################################

#定義更新選項
def software_update_zh():
    pyas_clear()
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas')

def engine_update_zh():
    if messagebox.askokcancel('Warning','更新掃毒引擎需要花費一些時間，是否繼續?', default="cancel", icon="warning"):
        pyas_clear()
        textPad.insert("insert", '正在更新中，請稍等。')
        root.update()
        try:
            file = req.get('https://github.com/87owo/ViruslistMD5/releases/download/v420/Viruslist.md5', allow_redirects=True)
            open('Library/PYAE/Hashes/Viruslist.md5', 'w').write(str(file.content)+'\n')
            pyas_clear()
            textPad.insert("insert", '更新完成。')
            root.update()
        except Exception as e:
            pyas_clear()
            textPad.insert("insert", '更新失敗: '+str(e))
            pass

####################################################################################

def input_virustotal_scan_zh():
    pyas_clear()
    t=Toplevel(root)
    t.title('Virustotal Api Key')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 密鑰: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :virustotal_scan_zh(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def virustotal_scan_zh(key):
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        try:
            with open(file,"rb") as f:
                bytes = f.read()
                readable_hash = md5(bytes).hexdigest();
                FILE_ID = str(readable_hash)
                with virustotal_python.Virustotal(key) as vtotal:
                    resp = vtotal.request(f"files/{FILE_ID}")
                    FILE_ID = resp.data["id"]
                    webbrowser.open('https://www.virustotal.com/gui/file/'+str(FILE_ID))
            f.close()
        except:# Exception as e:
            pass#print(e)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_zh+'\n')

####################################################################################

#定義檔案掃描
def pyas_file_scan_zh():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", zh_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
        rfn = fn.read()
    file = filedialog.askopenfilename()
    if file != "":
        if pyas_scan_start(file,rfp):
            pyas_scan_write_zh(file)
            textPad.insert("insert", zh_virus_true+'\n')
        else:
            if 'C:/Windows' in str(file):
                pass
            elif 'C:/Program Files' in str(file):
                pass
            else:
                try:
                    fts = 0
                    pe = PE(file)
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for function in entry.imports:
                            root.update()
                            if str(function.name) in rfn:
                                fts = fts + 1
                    PE.close(pe)
                    if fts != 0:
                        pyas_scan_write_zh(file)
                        fts = 0
                        textPad.insert("insert", zh_virus_true+'\n')
                except:
                    pass
        fp.close()
        fn.close()
        pyas_scan_answer_zh()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_zh+'\n')

####################################################################################

#定義路徑掃描
def pyas_scan_path_init_zh():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", zh_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
        rfn = fn.read()
    fp.close()
    fn.close()
    file = filedialog.askdirectory()
    if file != "":
        pyas_scan_path_zh(file,rfp,rfn,0)
        pyas_scan_answer_zh()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_zh+'\n')

def pyas_scan_path_zh(path,rfp,rfn,fts):
    try:
        for fd in os.listdir(path):
            try:
                root.update()
                fullpath = os.path.join(path,fd)
                #print(fullpath)
                if os.path.isdir(fullpath):
                    pyas_scan_path_zh(fullpath,rfp,rfn,fts)
                else:
                    if 'C:/Windows' in str(fullpath):#'.exe' in str(fd) or '.EXE' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif 'C:/Program Files' in str(fullpath):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    else:
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                        else:
                            try:
                                pe = PE(fullpath)
                                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                    for function in entry.imports:
                                        root.update()
                                        if str(function.name) in rfn:
                                            fts = fts + 1
                                PE.close(pe)
                                if fts != 0:
                                    pyas_scan_write_zh(str(fullpath))
                                    fts = 0
                            except:
                                pass
            except:# Exception as e:
                #print(e)
                continue
    except:
        pass

####################################################################################

#定義全盤掃描
def pyas_scan_disk_init_zh():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", zh_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    pyas_scan_disk_zh('A:/',rfp)
    pyas_scan_disk_zh('B:/',rfp)
    pyas_scan_disk_zh('C:/',rfp)
    pyas_scan_disk_zh('D:/',rfp)
    pyas_scan_disk_zh('E:/',rfp)
    pyas_scan_disk_zh('F:/',rfp)
    pyas_scan_disk_zh('G:/',rfp)
    pyas_scan_disk_zh('H:/',rfp)
    pyas_scan_disk_zh('I:/',rfp)
    pyas_scan_disk_zh('J:/',rfp)
    pyas_scan_disk_zh('K:/',rfp)
    pyas_scan_disk_zh('L:/',rfp)
    pyas_scan_disk_zh('M:/',rfp)
    pyas_scan_disk_zh('N:/',rfp)
    pyas_scan_disk_zh('O:/',rfp)
    pyas_scan_disk_zh('P:/',rfp)
    pyas_scan_disk_zh('Q:/',rfp)
    pyas_scan_disk_zh('R:/',rfp)
    pyas_scan_disk_zh('S:/',rfp)
    pyas_scan_disk_zh('T:/',rfp)
    pyas_scan_disk_zh('U:/',rfp)
    pyas_scan_disk_zh('V:/',rfp)
    pyas_scan_disk_zh('W:/',rfp)
    pyas_scan_disk_zh('X:/',rfp)
    pyas_scan_disk_zh('Y:/',rfp)
    pyas_scan_disk_zh('Z:/',rfp)
    fp.close()
    pyas_scan_answer_zh()

def pyas_scan_disk_zh(path,rfp):
    try:
        for fd in os.listdir(path):
            try:
                root.update()
                fullpath = os.path.join(path,fd)
                if os.path.isdir(fullpath):
                    pyas_scan_disk_zh(fullpath,rfp)
                else:
                    if '.exe' in str(fd) or '.EXE' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.cmd' in str(fd) or '.CMD' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.bat' in str(fd) or '.BAT' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.com' in str(fd) or '.COM' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.vbs' in str(fd) or '.VBS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.zip' in str(fd) or '.ZIP' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.js' in str(fd) or '.JS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.xls' in str(fd) or '.XLS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.doc' in str(fd) or '.DOC' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.dll' in str(fd) or '.DLL' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.scr' in str(fd) or '.SCR' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    elif '.tmp' in str(fd) or '.TMP' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", zh_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_zh(fullpath)
                    else:
                        pass
            except:
                continue
    except:
        pass

####################################################################################

#工具
def computer_info_zh():
    pyas_clear()
    textPad.insert("insert", '系統資訊:\n'+str(pyas_divider)+'\n'+str(platform.platform())+'\n'+str(platform.architecture())+'\n'+str(platform.node())+'\n'+str(platform.processor()))

def camera_check_zh():
    pyas_clear()
    textPad.insert("insert", zh_init_file)
    root.update()
    cap = VideoCapture(0)
    ret, frame = cap.read()
    pyas_clear()
    if ret:
        textPad.insert("insert", '✔當前相機為安全狀態。')
        cap.release()
    else:
        textPad.insert("insert", '✖當前相機為不可使用狀態，可能會有隱私風險。')
        cap.release()

def exe_analyze_md5_zh():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = md5(bytes).hexdigest();
            textPad.insert("insert", 'MD5: '+str(readable_hash))
        f.close()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_zh+'\n')

def exe_analyze_file_zh():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        pe = PE(file)
        for section in pe.sections:
            root.update()
            textPad.insert("insert", section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData)
        PE.close(pe)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_zh+'\n')

def exe_analyze_function_zh():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        pe = PE(file)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for function in entry.imports:
                root.update()
                textPad.insert("insert", str(function.name)+'\n')
        PE.close(pe)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_zh+'\n')

def process_init_zh():
    pyas_clear()
    pids = psutil.pids()
    textPad.insert("insert", '已找到進程:\n'+pyas_divider+'\n')
    for pid in pids:
        textPad.insert("insert",psutil.Process(pid).name()+'\n')
    t=Toplevel(root)
    t.title('進程名稱')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 結束進程: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :process_kill_zh(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def process_kill_zh(app):
    pyas_clear()
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            of = subprocess.call('taskkill /f /im '+str(app),shell=True)
            if of == 0:
                textPad.insert("insert", zh_success)
            else:
                textPad.insert("insert", zh_failed)
            done = True
            break
        else:
            try:
                of = subprocess.call('taskkill /f /im '+str(app),shell=True)
                if of == 0:
                    textPad.insert("insert", zh_success)
                else:
                    textPad.insert("insert", zh_failed)
            except:
                textPad.insert("insert", '未找到進程: "'+str(app)+'"')
            done = True
            break

def destroy_files_zh():
    pyas_clear()
    try:
        path = filedialog.askopenfilename()
        if path != '':
            if messagebox.askokcancel('Warning','這個檔案將會被永久移除，是否繼續?', default="cancel", icon="warning"):
                os.remove(path)
                textPad.insert("insert", zh_success)
            else:
                pass
        else:
            pass
    except:
        textPad.insert("insert", zh_failed)
    
def ip_detect_zh():
    pyas_clear()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    textPad.insert("insert", '您的 IP 位置是: ' + s.getsockname()[0])
    s.close()

def reset_network_zh():
    pyas_clear()
    runc = subprocess.call("netsh winsock reset", shell=True)
    if runc == 0:
        textPad.insert("insert", zh_success)
    else:
        textPad.insert("insert", zh_failed)
        
def find_files_init_zh():
    pyas_clear()
    t=Toplevel(root)
    t.title('檔案名稱')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 檔案: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    Button(t,text='確定',command=lambda :find_files_info_zh(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def find_files_info_zh(ffile):
    try:
        fss = 0
        start = 0
        findfile_zh('A:/',ffile,fss,start)
        findfile_zh('B:/',ffile,fss,start)
        findfile_zh('C:/',ffile,fss,start)
        findfile_zh('D:/',ffile,fss,start)
        findfile_zh('E:/',ffile,fss,start)
        findfile_zh('F:/',ffile,fss,start)
        findfile_zh('G:/',ffile,fss,start)
        findfile_zh('H:/',ffile,fss,start)
        findfile_zh('I:/',ffile,fss,start)
        findfile_zh('J:/',ffile,fss,start)
        findfile_zh('K:/',ffile,fss,start)
        findfile_zh('L:/',ffile,fss,start)
        findfile_zh('M:/',ffile,fss,start)
        findfile_zh('N:/',ffile,fss,start)
        findfile_zh('O:/',ffile,fss,start)
        findfile_zh('P:/',ffile,fss,start)
        findfile_zh('Q:/',ffile,fss,start)
        findfile_zh('R:/',ffile,fss,start)
        findfile_zh('S:/',ffile,fss,start)
        findfile_zh('T:/',ffile,fss,start)
        findfile_zh('U:/',ffile,fss,start)
        findfile_zh('V:/',ffile,fss,start)
        findfile_zh('W:/',ffile,fss,start)
        findfile_zh('X:/',ffile,fss,start)
        findfile_zh('Y:/',ffile,fss,start)
        findfile_zh('Z:/',ffile,fss,start)
        ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding='utf-8')
        fe = ft.read()
        ft.close()
        ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding='utf-8')
        lines = len(ft.readlines())
        ft.close()
        pyas_clear()
        textPad.insert("insert", '尋找結果: ('+str(int(lines/3))+' 項)\n'+pyas_divider+'\n'+str(fe))
        os.remove('Library/PYAS/Temp/PYASF.tmp')
    except:
        pass

def findfile_zh(path,ffile,fss,start):
    try:
        pyas_clear()
        textPad.insert("insert", '正在尋找: '+str(path))
        for fd in os.listdir(path):
            root.update()
            fullpath = os.path.join(path,fd)
            if os.path.isdir(fullpath):
                findfile_zh(fullpath,ffile,fss,start)
            else:
                fss = fss + 1
                if ffile in str(fd):
                    date = time.ctime(os.path.getmtime(fullpath))
                    ft = open('Library/PYAS/Temp/PYASF.tmp','a',encoding='utf-8')
                    ft.write('找到檔案: '+str(fullpath)+'\n'+'創建日期: '+str(date)+'\n'+'\n')
                    ft.close()
                    continue
    except:# Exception as e:
        pass#print(e)

def repair_system_files_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''這個功能需要花費一些時間，是否繼續?''', default="cancel", icon="warning"):
        root.update()
        textPad.insert("insert",zh_app_use)
        root.update()
        runc = os.system('sfc /scannow')
        pyas_clear()
        if runc == 0:
            textPad.insert("insert", zh_success)
        else:
            textPad.insert("insert", zh_failed)
            os.system('cls')
    else:
        pass

def start_safe_mode_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''啟動安全模式需要重新啟動，是否繼續?''', default="cancel", icon="warning"):
        #os.system('net user administrator /active:yes')
        os.system('bcdedit /set {default} safeboot minimal')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def close_safe_Mode_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''關閉安全模式需要重新啟動，是否繼續?''', default="cancel", icon="warning"):
        #os.system('net user administrator /active:no')
        os.system('bcdedit /deletevalue {current} safeboot')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def input_custom_cmd_command_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''不當使用自訂指令可能會造成嚴重後果，是否繼續?''', default="cancel", icon="warning"):
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
        Button(t,text='OK',command=lambda :custom_cmd_command_zh(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    else:
        pass

def custom_cmd_command_zh(cmd):
    pyas_clear()
    textPad.insert("insert",zh_app_use)
    root.update()
    os.system(cmd)
    pyas_clear()
    textPad.insert("insert", zh_success)

def input_custom_regedit_command_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''不當使用自訂指令可能會造成嚴重後果，是否繼續?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('自訂指令')
        t.geometry('260x110')
        t.transient(root)
        Label(t,text=' 路徑: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' 名稱: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 類型: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        Label(t,text=' 數值: ').grid(row=3,column=0,sticky='e')
        v4=StringVar()
        e4=Entry(t,width=20,textvariable=v4)
        e4.grid(row=3,column=1,padx=2,pady=2,sticky='we')
        e4.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :custom_regedit_command(e.get(),e2.get(),e3.get(),e4.get())).grid(row=3,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def custom_regedit_command(path,cmd,reg,num):
    pyas_clear()
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
['''+str(path)+''']
"'''+str(cmd)+'''"='''+str(reg)+''':'''+str(num)+'''''')
    f.close()
    windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)

def fix_cmd_permissions_zh():
    pyas_clear()
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000000
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableTaskMgr"=dword:00000000''')
    f.close()
    windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)

def input_encrypt_zh():
    pyas_clear()
    t=Toplevel(root)
    t.title('輸入文字')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' 輸入: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' 密碼: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :encrypt_zh(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)

def encrypt_zh(e,e2):
    pyas_clear()
    textPad.insert("insert", '您的加密內容: \n'+str(cryptocode.encrypt(e,e2)))

def input_decrypt_zh():
    pyas_clear()
    t=Toplevel(root)
    t.title('輸入文字')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' 輸入: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' 密碼: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='確定',command=lambda :decrypt_zh(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)

def decrypt_zh(e,e2):
    pyas_clear()
    textPad.insert("insert", '您的解密內容: \n'+str(cryptocode.decrypt(e, e2)))

def input_send_text_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''傳送訊息接收方開啟接收訊息模式，是否繼續?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('傳送訊息')
        t.geometry('260x90')
        t.transient(root)
        Label(t,text=' 輸入: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' 位置: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 端口: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :send_text_zh(e.get(),e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def send_text_zh(message,HOST,PORT):
    pyas_clear()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(message.encode())
    except:
        messagebox.showerror('Error', '''請將接收方開啟接收訊息模式並關閉防火牆。''')

def input_receive_text_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''這個功能需要等待對方傳送訊息，是否繼續?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('接收訊息')
        t.geometry('260x70')
        t.transient(root)
        Label(t,text=' 位置: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 端口: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :receive_text_zh(e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass
    
def receive_text_zh(HOST,PORT):
    pyas_clear()
    max_connect = 5
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        root.update()
        s.bind((HOST, int(PORT)))
        s.listen()
        conn, _ = s.accept()
        data = conn.recv(1024).decode()
        textPad.insert("insert",'接收訊息: '+data)
        root.update()

def system_disk_clean_zh():
    pyas_clear()
    textPad.insert("insert",zh_app_use)
    root.update()
    os.system('cleanmgr')
    pyas_clear()

def change_user_password_init_zh():
    pyas_clear()
    messagebox.showinfo('Version','''變更用戶密碼前，請先確保您已經進入安全模式再使用此功能。''')
    t=Toplevel(root)
    t.title('變更密碼')
    t.geometry('260x60')
    t.transient(root)
    Label(t,text=' 用戶名: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' 新密碼: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    Button(t,text='確定',command=lambda :change_user_password_zh(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=0)

def change_user_password_zh(user,password):
    os.system('net user '+str(user)+' "'+str(password)+'"')

def recover_Wallpaper_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''修復系統桌布，是否繼續?''', default="cancel", icon="warning"):
        try:
            try:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',0,win32con.KEY_ALL_ACCESS)
            except:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer',0,win32con.KEY_ALL_ACCESS)
                win32api.RegCreateKey(key,'Wallpapers')
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',0,win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'BackgroundHistoryPath0', win32con.REG_SZ, r'c:\windows\web\wallpaper\windows\img0.jpg')
            user32dll = windll.LoadLibrary(r"C:\Windows\System32\user32.dll") 
            user32dll.SystemParametersInfoW(20, 0, r'c:\windows\web\wallpaper\windows\img0.jpg', 0)
            pyas_clear()
            textPad.insert("insert", zh_success)
        except Exception as e:
            pyas_clear()
            textPad.insert("insert", zh_failed+'\n'+pyas_divider+'\n'+str(e))

def fixlimit_zh():
    pyas_clear()
    if messagebox.askokcancel('Warning','''修復系統限制，是否繼續?''', default="cancel", icon="warning"):
        if 1:
            try:
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass
                    
                try:
                    win32api.RegDeleteValue(key, 'NoDrives')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFileMenu')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFind')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRealMode')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolders')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewOnDrive')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoClose')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRun')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContexMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'HideClock')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMorePrograms')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyGames')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyMusic')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuNetworkPlaces')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuPinnedList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktopChanges')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoChangeStartMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'ClearRecentDocsOnExit')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFavoritesMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsHistory')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetTaskbar')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSMHelp')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoTrayContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWindowsUpdate')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWinKeys')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'StartMenuLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSimpleNetlDList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLowDiskSpaceChecks')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableLockWorkstation')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoManageMyComputerVerb')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'RestrictRun')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass
                    
                try:
                    win32api.RegDeleteValue(key, 'NoDrives')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFileMenu')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFind')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRealMode')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolders')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewOnDrive')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoClose')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRun')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContexMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'HideClock')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMorePrograms')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyGames')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyMusic')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuNetworkPlaces')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuPinnedList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktopChanges')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoChangeStartMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'ClearRecentDocsOnExit')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFavoritesMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsHistory')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetTaskbar')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSMHelp')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoTrayContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWindowsUpdate')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWinKeys')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'StartMenuLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSimpleNetlDList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLowDiskSpaceChecks')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableLockWorkstation')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoManageMyComputerVerb')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'RestrictRun')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableTaskMgr')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableRegistryTools')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableChangePassword')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'Wallpaper')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableTaskMgr')
                except:
                    pass       
                try:
                    win32api.RegDeleteValue(key, 'DisableRegistryTools')
                except:
                    pass        
                try:
                    win32api.RegDeleteValue(key, 'DisableChangePassword')
                except:
                    pass           
                try:
                    win32api.RegDeleteValue(key, 'Wallpaper')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'ActiveDesktop')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoComponents')
                except:
                    pass          
                try:
                    win32api.RegDeleteValue(key, 'NoAddingComponents')
                except:
                    pass                  
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except:
                    pass                    
                win32api.RegCloseKey(key)
        

                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except:
                    pass    
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                except:
                    try:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    except:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft',0,win32con.KEY_ALL_ACCESS)
                        win32api.RegCreateKey(key,'MMC')
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'Restrict_Run')
                except:
                    pass
                win32api.RegCloseKey(key)
                pyas_clear()
                textPad.insert("insert", zh_success)
            except Exception as e:
                pyas_clear()
                textPad.insert("insert", zh_failed+'\n'+pyas_divider+'\n'+str(e))

################################################################################

#關於
def about_pyas_zh():
    pyas_clear()
    try:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','r')
        dev_edition_times = int(er.read())
        er.close()
    except:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write('0')
        er.close()
        dev_edition_times = 0
    if dev_edition_times >= 2:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write('0')
        er.close()
        messagebox.showinfo('?????????','''???????????????????????????????????????????????????''')
        x = ''
        pdinfo = '''
開發人員: PYAS_Dev#0629 , Mtkiao129#3921 , Dragon#5381
官方郵箱: xiaomi69ai@gmail.com
官方GIT: https://github.com/87owo/PYAS
官方網站: https://xiaomi69ai.wixsite.com/pyas
創立日期: 2020/12/17
PYAS 版本: '''+pyas_version+'''
PYAE 版本: '''+pyae_version+'''
特別感謝: Wix, Avast, Github, Google, Python, Microsoft, VirusTotal, VirusShare, LenStevens
感謝您使用 PYAS 防毒軟體'''
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Easteregg.ogg')
            pygame.mixer.music.play()
        for i in pdinfo:
            x = x+i
            time.sleep(0.1)
            pyas_clear()
            textPad.insert("insert",'''PYAS Infomation:
'''+str(pyas_divider)+str(x)+'_')
            root.update()
        pyas_clear()
        textPad.insert("insert",'''PYAS Infomation:
'''+str(pyas_divider)+str(pdinfo))
        root.update()
    else:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write(str(dev_edition_times + 1))
        er.close()
        messagebox.showinfo('Copyright','''官方網站: https://xiaomi69ai.wixsite.com/pyas
版權所有© 2020-2022 PYAS Python Antivirus Software''')

def software_version_zh():
    pyas_clear()
    messagebox.showinfo('Version','''防毒軟體版本: '''+pyas_version)

def engine_version_zh():
    pyas_clear()
    messagebox.showinfo('Version','''掃毒引擎版本: '''+pyae_version)

####################################################################################

#主選單(繁中)
def traditional_chinese():
    if is_admin():
        try:
            pyas_clear()
            ft = open('Library/PYAS/Setup/PYAS.ini','w')
            ft.write('''traditional_chinese''')
            ft.close()
            menubar = Menu(root)
            root.config(menu = menubar)
            filemenu = Menu(menubar,tearoff=False)
            filemenu.add_command(label = '檔案掃描',command = pyas_file_scan_zh)
            filemenu.add_command(label = '路徑掃描',command = pyas_scan_path_init_zh)
            filemenu.add_command(label = '全盤掃描',command = pyas_scan_disk_init_zh)
            menubar.add_cascade(label = ' 掃描',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = '啟動實時防護',command = protect_threading_init_zh)
            menubar.add_cascade(label = '防護',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            menubar.add_cascade(label = '工具',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='系統工具', menu=sub2menu, underline=0)
            sub2menu.add_command(label = '系統進程管理',command = process_init_zh)
            sub2menu.add_separator()
            sub2menu.add_command(label = '清理系統檔案',command = system_disk_clean_zh)
            sub2menu.add_separator()
            sub2menu.add_command(label = '修復系統檔案',command = repair_system_files_zh)
            sub2menu.add_command(label = '修復系統桌布',command = recover_Wallpaper_zh)
            sub2menu.add_command(label = '修復系統權限',command = fix_cmd_permissions_zh)
            sub2menu.add_command(label = '修復系統限制',command = fixlimit_zh)
            sub2menu.add_separator()
            sub2menu.add_command(label = '啟動安全模式',command = start_safe_mode_zh)
            sub2menu.add_command(label = '關閉安全模式',command = close_safe_Mode_zh)
            sub2menu.add_separator()
            sub2menu.add_command(label = '系統版本資訊',command = computer_info_zh)
            insmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='隱私工具', menu=insmenu, underline=0)
            insmenu.add_command(label = '相機隱私檢測',command = camera_check_zh)
            insmenu.add_command(label = '移除隱私檔案',command = destroy_files_zh)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='更多工具', menu=submenu, underline=0)
            submenu.add_command(label = '尋找檔案',command = find_files_init_zh)
            submenu.add_separator()
            submenu.add_command(label = '加密文字',command = input_encrypt_zh)
            submenu.add_command(label = '解密文字',command = input_decrypt_zh)
            submenu.add_separator()
            submenu.add_command(label = '傳送訊息',command = input_send_text_zh)
            submenu.add_command(label = '接收訊息',command = input_receive_text_zh)
            submenu.add_separator()
            submenu.add_command(label = '更改用戶密碼',command = change_user_password_init_zh)
            submenu.add_separator()
            submenu.add_command(label = '網路位置查詢',command = ip_detect_zh)
            submenu.add_command(label = '重製系統網路',command = reset_network_zh)
            devmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='開發工具', menu=devmenu, underline=0)
            devmenu.add_command(label = '自訂 REG 指令',command = input_custom_regedit_command_zh)
            devmenu.add_command(label = '自訂 CMD 指令',command = input_custom_cmd_command_zh)
            devmenu.add_separator()
            devmenu.add_command(label = '分析 EXE 哈希',command = exe_analyze_md5_zh)
            devmenu.add_command(label = '分析 EXE 位元',command = exe_analyze_file_zh)
            devmenu.add_command(label = '分析 EXE 函數',command = exe_analyze_function_zh)
            devmenu.add_separator()
            devmenu.add_command(label = '線上檔案分析',command = input_virustotal_scan_zh)
            filemenu5 = Menu(menubar,tearoff=False)
            menubar.add_cascade(label = '設置',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='軟體設置', menu=sitmenu, underline=0)
            sitmenu.add_command(label="更新防毒軟體", command=software_update_zh)
            sitmenu.add_command(label="更新掃毒引擎", command=engine_update_zh)
            sitmenu2 = Menu(filemenu5,tearoff=False)
            #filemenu5.add_cascade(label='引擎設置', menu=sitmenu2, underline=0)
            #sitmenu2.add_command(label="Enable Quick Scan", command=#)
            #sitmenu2.add_command(label="Disable Quick Scan", command=#)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='變更語言', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese)
            sit2menu.add_command(label="简体中文", command=simplified_chinese)
            sit2menu.add_command(label="English", command=english)
            aboutmenu = Menu(menubar,tearoff=False)
            aboutus = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='關於我們', menu=aboutus, underline=0)
            aboutus.add_command(label="關於 PYAS", command=about_pyas_zh)
            aboutversion = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='軟體版本', menu=aboutversion, underline=0)
            aboutversion.add_command(label="防毒軟體版本", command=software_version_zh)
            aboutversion.add_command(label="掃毒引擎版本", command=engine_version_zh)
            licmenu = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='許可條款', menu=licmenu, underline=0)
            licmenu.add_command(label = 'PYAS 許可條款',command = pyas_license_terms_en)
            menubar.add_cascade(label = '關於',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            messagebox.showerror('Error', '''此軟體出現了一些問題，我們感到很抱歉。
回報錯誤: https://xiaomi69ai.wixsite.com/pyas
錯誤資訊: '''+str(e))
    else:
        windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

####################################################################################

#定義防護
def protect_threading_init_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''启动实时防护需要 4GB 以上的內存，是否继续?''', default="cancel", icon="warning"):
        pyas_clear()
        textPad.insert("insert", cn_init_file)
        root.update()
        t = threading.Thread(target = pyas_protect_init_cn)
        t.start()
        #t.join()
    else:
        pass

#定義全盤掃描
def pyas_protect_init_cn():
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    pyas_clear()
    textPad.insert("insert", cn_success)
    root.update()
    while 1:
        for p in psutil.process_iter():
            try:
                if 'C:\Windows' in str(p.exe()):
                    pass
                elif 'C:\Program Files' in str(p.exe()):
                    pass
                else:
                    if pyas_scan_start(p.exe(),rfp):
                        of = subprocess.call('taskkill /f /im "'+str(p.name())+'"',shell=True)
                        try:
                            if of == 0:
                                pyas_clear()
                                textPad.insert("insert", '成功拦截了一个恶意软件: '+str(p.name()))
                                pygame.mixer.init()
                                if not pygame.mixer.music.get_busy():
                                    pygame.mixer.music.load('Library/PYAS/Audio/Virusfound.ogg')
                                    pygame.mixer.music.play()
                            else:
                                pyas_clear()
                                textPad.insert("insert", '恶意软件拦截失败: '+str(p.name()))
                        except:
                            pass
            except:
                continue

####################################################################################
        
#定義紀錄掃描
def pyas_scan_write_cn(file):
    ft = open('Library/PYAS/Temp/PYASV.tmp','a',encoding='utf-8')
    fe = ft.write(file+'\n')
    ft.close()

#定義讀取紀錄
def pyas_scan_read_cn():
    try:
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        fe = ft.read()
        ft.close()
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        lines = len(ft.readlines())
        ft.close()
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Virusfound.ogg')
            pygame.mixer.music.play()
        return cn_virus_true+' ('+str(lines)+' 项)'+'\n'+pyas_divider+'\n'+fe
    except:
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Complete.ogg')
            pygame.mixer.music.play()
        return cn_virus_false

#定義移除紀錄
def pyas_scan_del_cn():
    os.remove('Library/PYAS/Temp/PYASV.tmp')

#定義掃描結果
def pyas_scan_answer_cn():
    pyas_clear()
    textPad.insert("insert", pyas_scan_read_cn())
    try:####
        ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
        lines = ft.readlines()
        ft.close()
        if messagebox.askokcancel('Warning',"是否要移除这些恶意软件?", default="cancel", icon="warning"):
            try:
                for line in lines:
                    if 'C:/Windows' not in line:
                        pyas_clear()
                        textPad.insert("insert", '正在移除:'+'\n'+pyas_divider+'\n'+str(line))
                        root.update()
                        try:
                            os.remove(str(line[:-1]))
                        except:
                            continue
                    else:
                        pass
                pyas_clear()
                textPad.insert("insert", cn_success)
            except Exception as e:
                pyas_clear()
                textPad.insert("insert", cn_failed+'\n'+pyas_divider+'\n'+str(e))
                #print(e)
                pass
    except:# Exception as e:
        pass#print(e)###
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass

####################################################################################

#定義更新選項
def software_update_cn():
    pyas_clear()
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas')

def engine_update_cn():
    if messagebox.askokcancel('Warning','更新扫毒引擎需要花费一些时间，是否继续?', default="cancel", icon="warning"):
        pyas_clear()
        textPad.insert("insert", '正在更新中，请稍等。')
        root.update()
        try:
            file = req.get('https://github.com/87owo/ViruslistMD5/releases/download/v420/Viruslist.md5', allow_redirects=True)
            open('Library/PYAE/Hashes/Viruslist.md5', 'w').write(str(file.content)+'\n')
            pyas_clear()
            textPad.insert("insert", '更新完成。')
            root.update()
        except Exception as e:
            pyas_clear()
            textPad.insert("insert", '更新失败: '+str(e))
            pass

####################################################################################

def input_virustotal_scan_cn():
    pyas_clear()
    t=Toplevel(root)
    t.title('Virustotal Api Key')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 密钥: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='确定',command=lambda :virustotal_scan_cn(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def virustotal_scan_cn(key):
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        try:
            with open(file,"rb") as f:
                bytes = f.read()
                readable_hash = md5(bytes).hexdigest();
                FILE_ID = str(readable_hash)
                with virustotal_python.Virustotal(key) as vtotal:
                    resp = vtotal.request(f"files/{FILE_ID}")
                    FILE_ID = resp.data["id"]
                    webbrowser.open('https://www.virustotal.com/gui/file/'+str(FILE_ID))
            f.close()
        except:# Exception as e:
            pass#print(e)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_cn+'\n')

####################################################################################

#定義檔案掃描
def pyas_file_scan_cn():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", cn_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
        rfn = fn.read()
    file = filedialog.askopenfilename()
    if file != "":
        if pyas_scan_start(file,rfp):
            pyas_scan_write_cn(file)
            textPad.insert("insert", cn_virus_true+'\n')
        else:
            if 'C:/Windows' in str(file):
                pass
            elif 'C:/Program Files' in str(file):
                pass
            else:
                try:
                    fts = 0
                    pe = PE(file)
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for function in entry.imports:
                            root.update()
                            if str(function.name) in rfn:
                                fts = fts + 1
                    PE.close(pe)
                    if fts != 0:
                        pyas_scan_write_cn(file)
                        fts = 0
                        textPad.insert("insert", cn_virus_true+'\n')
                except:
                    pass
        fp.close()
        fn.close()
        pyas_scan_answer_cn()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_cn+'\n')

####################################################################################

#定義路徑掃描
def pyas_scan_path_init_cn():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", cn_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
        rfn = fn.read()
    fp.close()
    fn.close()
    file = filedialog.askdirectory()
    if file != "":
        pyas_scan_path_cn(file,rfp,rfn,0)
        pyas_scan_answer_cn()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_cn+'\n')

def pyas_scan_path_cn(path,rfp,rfn,fts):
    try:
        for fd in os.listdir(path):
            try:
                root.update()
                fullpath = os.path.join(path,fd)
                #print(fullpath)
                if os.path.isdir(fullpath):
                    pyas_scan_path_cn(fullpath,rfp,rfn,fts)
                else:
                    if 'C:/Windows' in str(fullpath):#'.exe' in str(fd) or '.EXE' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif 'C:/Program Files' in str(fullpath):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    else:
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                        else:
                            try:
                                pe = PE(fullpath)
                                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                    for function in entry.imports:
                                        root.update()
                                        if str(function.name) in rfn:
                                            fts = fts + 1
                                PE.close(pe)
                                if fts != 0:
                                    pyas_scan_write_cn(str(fullpath))
                                    fts = 0
                            except:
                                pass
            except:# Exception as e:
                #print(e)
                continue
    except:
        pass

####################################################################################

#定義全盤掃描
def pyas_scan_disk_init_cn():
    try:
        os.remove('Library/PYAS/Temp/PYASV.tmp')
    except:
        pass
    pyas_clear()
    textPad.insert("insert", cn_init_file+'\n')
    root.update()
    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
        rfp = fp.read()
    pyas_scan_disk_cn('A:/',rfp)
    pyas_scan_disk_cn('B:/',rfp)
    pyas_scan_disk_cn('C:/',rfp)
    pyas_scan_disk_cn('D:/',rfp)
    pyas_scan_disk_cn('E:/',rfp)
    pyas_scan_disk_cn('F:/',rfp)
    pyas_scan_disk_cn('G:/',rfp)
    pyas_scan_disk_cn('H:/',rfp)
    pyas_scan_disk_cn('I:/',rfp)
    pyas_scan_disk_cn('J:/',rfp)
    pyas_scan_disk_cn('K:/',rfp)
    pyas_scan_disk_cn('L:/',rfp)
    pyas_scan_disk_cn('M:/',rfp)
    pyas_scan_disk_cn('N:/',rfp)
    pyas_scan_disk_cn('O:/',rfp)
    pyas_scan_disk_cn('P:/',rfp)
    pyas_scan_disk_cn('Q:/',rfp)
    pyas_scan_disk_cn('R:/',rfp)
    pyas_scan_disk_cn('S:/',rfp)
    pyas_scan_disk_cn('T:/',rfp)
    pyas_scan_disk_cn('U:/',rfp)
    pyas_scan_disk_cn('V:/',rfp)
    pyas_scan_disk_cn('W:/',rfp)
    pyas_scan_disk_cn('X:/',rfp)
    pyas_scan_disk_cn('Y:/',rfp)
    pyas_scan_disk_cn('Z:/',rfp)
    fp.close()
    pyas_scan_answer_cn()

def pyas_scan_disk_cn(path,rfp):
    try:
        for fd in os.listdir(path):
            try:
                root.update()
                fullpath = os.path.join(path,fd)
                if os.path.isdir(fullpath):
                    pyas_scan_disk_cn(fullpath,rfp)
                else:
                    if '.exe' in str(fd) or '.EXE' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.cmd' in str(fd) or '.CMD' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.bat' in str(fd) or '.BAT' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.com' in str(fd) or '.COM' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.vbs' in str(fd) or '.VBS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.zip' in str(fd) or '.ZIP' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.js' in str(fd) or '.JS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.xls' in str(fd) or '.XLS' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.doc' in str(fd) or '.DOC' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.dll' in str(fd) or '.DLL' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.scr' in str(fd) or '.SCR' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    elif '.tmp' in str(fd) or '.TMP' in str(fd):
                        pyas_clear()
                        textPad.insert("insert", cn_scaning+'\n'+pyas_divider+'\n'+fullpath)
                        if pyas_scan_start(fullpath,rfp):
                            pyas_scan_write_cn(fullpath)
                    else:
                        pass
            except:
                continue
    except:
        pass

####################################################################################

#工具
def computer_info_cn():
    pyas_clear()
    textPad.insert("insert", '系统资讯:\n'+str(pyas_divider)+'\n'+str(platform.platform())+'\n'+str(platform.architecture())+'\n'+str(platform.node())+'\n'+str(platform.processor()))

def camera_check_cn():
    pyas_clear()
    textPad.insert("insert", cn_init_file)
    root.update()
    cap = VideoCapture(0)
    ret, frame = cap.read()
    pyas_clear()
    if ret:
        textPad.insert("insert", '✔当前相机为安全状态。')
        cap.release()
    else:
        textPad.insert("insert", '✖当前相机为不可使用状态，可能会有隐私风险。')
        cap.release()

def exe_analyze_md5_cn():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = md5(bytes).hexdigest();
            textPad.insert("insert", 'MD5: '+str(readable_hash))
        f.close()
    else:
        pyas_clear()
        textPad.insert("insert", none_file_cn+'\n')

def exe_analyze_file_cn():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        pe = PE(file)
        for section in pe.sections:
            root.update()
            textPad.insert("insert", section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData)
        PE.close(pe)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_cn+'\n')

def exe_analyze_function_cn():
    pyas_clear()
    file = filedialog.askopenfilename()
    if file != '':
        pe = PE(file)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for function in entry.imports:
                root.update()
                textPad.insert("insert", str(function.name)+'\n')
        PE.close(pe)
    else:
        pyas_clear()
        textPad.insert("insert", none_file_cn+'\n')

def process_init_cn():
    pyas_clear()
    pids = psutil.pids()
    textPad.insert("insert", '已找到进程:\n'+pyas_divider+'\n')
    for pid in pids:
        textPad.insert("insert",psutil.Process(pid).name()+'\n')
    t=Toplevel(root)
    t.title('进程名称')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 结束进程: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='确定',command=lambda :process_kill_cn(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    
def process_kill_cn(app):
    pyas_clear()
    done = False
    while not done:
        run = subprocess.call('tasklist |find /i "'+str(app)+'"',shell=True)
        if run == 0:
            of = subprocess.call('taskkill /f /im '+str(app),shell=True)
            if of == 0:
                textPad.insert("insert", cn_success)
            else:
                textPad.insert("insert", cn_failed)
            done = True
            break
        else:
            try:
                of = subprocess.call('taskkill /f /im '+str(app),shell=True)
                if of == 0:
                    textPad.insert("insert", cn_success)
                else:
                    textPad.insert("insert", cn_failed)
            except:
                textPad.insert("insert", '未找到进程: "'+str(app)+'"')
            done = True
            break

def destroy_files_cn():
    pyas_clear()
    try:
        path = filedialog.askopenfilename()
        if path != '':
            if messagebox.askokcancel('Warning','这个档案将会被永久移除，是否继续?', default="cancel", icon="warning"):
                os.remove(path)
                textPad.insert("insert", cn_success)
            else:
                pass
        else:
            pass
    except:
        textPad.insert("insert", cn_failed)
    
def ip_detect_cn():
    pyas_clear()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    textPad.insert("insert", '您的 IP 位址是: ' + s.getsockname()[0])
    s.close()

def reset_network_cn():
    pyas_clear()
    runc = subprocess.call("netsh winsock reset", shell=True)
    if runc == 0:
        textPad.insert("insert", cn_success)
    else:
        textPad.insert("insert", cn_failed)
        
def find_files_init_cn():
    pyas_clear()
    t=Toplevel(root)
    t.title('档案名称')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 档案: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    Button(t,text='确定',command=lambda :find_files_info_cn(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def find_files_info_cn(ffile):
    try:
        fss = 0
        start = 0
        findfile_cn('A:/',ffile,fss,start)
        findfile_cn('B:/',ffile,fss,start)
        findfile_cn('C:/',ffile,fss,start)
        findfile_cn('D:/',ffile,fss,start)
        findfile_cn('E:/',ffile,fss,start)
        findfile_cn('F:/',ffile,fss,start)
        findfile_cn('G:/',ffile,fss,start)
        findfile_cn('H:/',ffile,fss,start)
        findfile_cn('I:/',ffile,fss,start)
        findfile_cn('J:/',ffile,fss,start)
        findfile_cn('K:/',ffile,fss,start)
        findfile_cn('L:/',ffile,fss,start)
        findfile_cn('M:/',ffile,fss,start)
        findfile_cn('N:/',ffile,fss,start)
        findfile_cn('O:/',ffile,fss,start)
        findfile_cn('P:/',ffile,fss,start)
        findfile_cn('Q:/',ffile,fss,start)
        findfile_cn('R:/',ffile,fss,start)
        findfile_cn('S:/',ffile,fss,start)
        findfile_cn('T:/',ffile,fss,start)
        findfile_cn('U:/',ffile,fss,start)
        findfile_cn('V:/',ffile,fss,start)
        findfile_cn('W:/',ffile,fss,start)
        findfile_cn('X:/',ffile,fss,start)
        findfile_cn('Y:/',ffile,fss,start)
        findfile_cn('Z:/',ffile,fss,start)
        ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding='utf-8')
        fe = ft.read()
        ft.close()
        ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding='utf-8')
        lines = len(ft.readlines())
        ft.close()
        pyas_clear()
        textPad.insert("insert", '寻找结果: ('+str(int(lines/3))+' 项)\n'+pyas_divider+'\n'+str(fe))
        os.remove('Library/PYAS/Temp/PYASF.tmp')
    except:
        pass

def findfile_cn(path,ffile,fss,start):
    try:
        pyas_clear()
        textPad.insert("insert", '正在寻找: '+str(path))
        for fd in os.listdir(path):
            root.update()
            fullpath = os.path.join(path,fd)
            if os.path.isdir(fullpath):
                findfile_cn(fullpath,ffile,fss,start)
            else:
                fss = fss + 1
                if ffile in str(fd):
                    date = time.ctime(os.path.getmtime(fullpath))
                    ft = open('Library/PYAS/Temp/PYASF.tmp','a',encoding='utf-8')
                    ft.write('找到档案: '+str(fullpath)+'\n'+'创建日期: '+str(date)+'\n'+'\n')
                    ft.close()
                    continue
    except:
        pass

def repair_system_files_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''这个功能需要花费一些时间，是否继续?''', default="cancel", icon="warning"):
        root.update()
        textPad.insert("insert",cn_app_use)
        root.update()
        runc = os.system('sfc /scannow')
        pyas_clear()
        if runc == 0:
            textPad.insert("insert", cn_success)
        else:
            textPad.insert("insert", cn_failed)
            os.system('cls')
    else:
        pass

def start_safe_mode_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''启动安全模式需要重新启动，是否继续?''', default="cancel", icon="warning"):
        #os.system('net user administrator /active:yes')
        os.system('bcdedit /set {default} safeboot minimal')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def close_safe_Mode_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''关闭安全模式需要重新启动，是否继续?''', default="cancel", icon="warning"):
        #os.system('net user administrator /active:no')
        os.system('bcdedit /deletevalue {current} safeboot')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def input_custom_cmd_command_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''不当使用自订指令可能会造成严重后果，是否继续?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('自订指令')
        t.geometry('260x40')
        t.transient(root)
        Label(t,text=' 指令: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :custom_cmd_command_cn(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)
    else:
        pass

def custom_cmd_command_cn(cmd):
    pyas_clear()
    textPad.insert("insert",cn_app_use)
    root.update()
    os.system(cmd)
    pyas_clear()
    textPad.insert("insert", cn_success)

def input_custom_regedit_command_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''不当使用自订指令可能会造成严重后果，是否继续?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('自订指令')
        t.geometry('260x110')
        t.transient(root)
        Label(t,text=' 路径: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' 名称: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 类型: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        Label(t,text=' 数值: ').grid(row=3,column=0,sticky='e')
        v4=StringVar()
        e4=Entry(t,width=20,textvariable=v4)
        e4.grid(row=3,column=1,padx=2,pady=2,sticky='we')
        e4.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :custom_regedit_command(e.get(),e2.get(),e3.get(),e4.get())).grid(row=3,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def custom_regedit_command(path,cmd,reg,num):
    pyas_clear()
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
['''+str(path)+''']
"'''+str(cmd)+'''"='''+str(reg)+''':'''+str(num)+'''''')
    f.close()
    windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)

def fix_cmd_permissions_cn():
    pyas_clear()
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000000
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableTaskMgr"=dword:00000000''')
    f.close()
    windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)

def input_encrypt_cn():
    pyas_clear()
    t=Toplevel(root)
    t.title('输入文字')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' 输入: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' 密码: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='确定',command=lambda :encrypt_cn(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)

def encrypt_cn(e,e2):
    pyas_clear()
    textPad.insert("insert", '您的加密内容: \n'+str(cryptocode.encrypt(e,e2)))

def input_decrypt_cn():
    pyas_clear()
    t=Toplevel(root)
    t.title('输入文字')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' 输入: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' 密码: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='确定',command=lambda :decrypt_cn(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)

def decrypt_cn(e,e2):
    pyas_clear()
    textPad.insert("insert", '您的解密内容: \n'+str(cryptocode.decrypt(e, e2)))

def input_send_text_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''传送讯息接收方开启接收讯息模式，是否继续?''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('传送讯息')
        t.geometry('260x90')
        t.transient(root)
        Label(t,text=' 输入: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' 位置: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 端口: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='确定',command=lambda :send_text_cn(e.get(),e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def send_text_cn(message,HOST,PORT):
    pyas_clear()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(message.encode())
    except:
        messagebox.showerror('Error', '''请将接收方开启接收讯息模式并关闭防火墙。''')

def input_receive_text_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''''', default="cancel", icon="warning"):
        t=Toplevel(root)
        t.title('接收讯息')
        t.geometry('260x70')
        t.transient(root)
        Label(t,text=' 位置: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 端口: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='确定',command=lambda :receive_text_cn(e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def receive_text_cn(HOST,PORT):
    pyas_clear()
    max_connect = 5
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        root.update()
        s.bind((HOST, int(PORT)))
        s.listen()
        conn, _ = s.accept()
        data = conn.recv(1024).decode()
        textPad.insert("insert",'接收讯息: '+data)
        root.update()

def system_disk_clean_cn():
    pyas_clear()
    textPad.insert("insert",cn_app_use)
    root.update()
    os.system('cleanmgr')
    pyas_clear()

def change_user_password_init_cn():
    pyas_clear()
    messagebox.showinfo('Version','''变更用户密码前，请先确保您已经进入安全模式再使用此功能。''')
    t=Toplevel(root)
    t.title('变更密码')
    t.geometry('260x60')
    t.transient(root)
    Label(t,text=' 用户名: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' 新密码: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    Button(t,text='确定',command=lambda :change_user_password_cn(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=0)

def change_user_password_cn(user,password):
    os.system('net user '+str(user)+' "'+str(password)+'"')

def recover_Wallpaper_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''修复系统壁纸，是否继续?''', default="cancel", icon="warning"):
        try:
            try:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',0,win32con.KEY_ALL_ACCESS)
            except:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer',0,win32con.KEY_ALL_ACCESS)
                win32api.RegCreateKey(key,'Wallpapers')
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',0,win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'BackgroundHistoryPath0', win32con.REG_SZ, r'c:\windows\web\wallpaper\windows\img0.jpg')
            user32dll = windll.LoadLibrary(r"C:\Windows\System32\user32.dll") 
            user32dll.SystemParametersInfoW(20, 0, r'c:\windows\web\wallpaper\windows\img0.jpg', 0)
            pyas_clear()
            textPad.insert("insert", cn_success)
        except Exception as e:
            pyas_clear()
            textPad.insert("insert", cn_failed+'\n'+pyas_divider+'\n'+str(e))

def fixlimit_cn():
    pyas_clear()
    if messagebox.askokcancel('Warning','''修复系统限制，是否继续?''', default="cancel", icon="warning"):
        if 1:
            try:
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass
                    
                try:
                    win32api.RegDeleteValue(key, 'NoDrives')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFileMenu')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFind')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRealMode')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolders')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewOnDrive')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoClose')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRun')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContexMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'HideClock')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMorePrograms')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyGames')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyMusic')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuNetworkPlaces')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuPinnedList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktopChanges')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoChangeStartMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'ClearRecentDocsOnExit')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFavoritesMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsHistory')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetTaskbar')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSMHelp')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoTrayContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWindowsUpdate')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWinKeys')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'StartMenuLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSimpleNetlDList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLowDiskSpaceChecks')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableLockWorkstation')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoManageMyComputerVerb')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'RestrictRun')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass
                    
                try:
                    win32api.RegDeleteValue(key, 'NoDrives')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoControlPanel')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFileMenu')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoFind')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRealMode')
                except:
                    pass                
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolders')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewOnDrive')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoClose')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRun')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFolderOptions')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContexMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'HideClock')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMorePrograms')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyGames')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuMyMusic')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuNetworkPlaces')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoStartMenuPinnedList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetActiveDesktop')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoActiveDesktopChanges')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoChangeStartMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'ClearRecentDocsOnExit')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoFavoritesMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoRecentDocsHistory')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSetTaskbar')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSMHelp')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoTrayContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoViewContextMenu')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWindowsUpdate')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoWinKeys')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'StartMenuLogOff')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoSimpleNetlDList')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoLowDiskSpaceChecks')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableLockWorkstation')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'NoManageMyComputerVerb')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'RestrictRun')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableTaskMgr')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableRegistryTools')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'DisableChangePassword')
                except:
                    pass
                try:
                    win32api.RegDeleteValue(key, 'Wallpaper')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableTaskMgr')
                except:
                    pass       
                try:
                    win32api.RegDeleteValue(key, 'DisableRegistryTools')
                except:
                    pass        
                try:
                    win32api.RegDeleteValue(key, 'DisableChangePassword')
                except:
                    pass           
                try:
                    win32api.RegDeleteValue(key, 'Wallpaper')
                except:
                    pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'ActiveDesktop')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'NoComponents')
                except:
                    pass          
                try:
                    win32api.RegDeleteValue(key, 'NoAddingComponents')
                except:
                    pass                  
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except:
                    pass                    
                win32api.RegCloseKey(key)
        

                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except:
                    pass    
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                except:
                    try:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    except:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft',0,win32con.KEY_ALL_ACCESS)
                        win32api.RegCreateKey(key,'MMC')
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'Restrict_Run')
                except:
                    pass
                win32api.RegCloseKey(key)
                pyas_clear()
                textPad.insert("insert", cn_success)
            except Exception as e:
                pyas_clear()
                textPad.insert("insert", cn_failed+'\n'+pyas_divider+'\n'+str(e))

################################################################################

#關於
def about_pyas_cn():
    pyas_clear()
    try:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','r')
        dev_edition_times = int(er.read())
        er.close()
    except:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write('0')
        er.close()
        dev_edition_times = 0
    if dev_edition_times >= 2:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write('0')
        er.close()
        messagebox.showinfo('?????????','''???????????????????????????????????????????????????''')
        x = ''
        pdinfo = '''
开发人员: PYAS_Dev#0629 , Mtkiao129#3921 , Dragon#5381
官方邮箱: xiaomi69ai@gmail.com
官方GIT: https://github.com/87owo/PYAS
官方网站: https://xiaomi69ai.wixsite.com/pyas
创立日期: 2020/12/17
PYAS 版本: '''+pyas_version+'''
PYAE 版本: '''+pyae_version+'''
特别感谢: Wix, Avast, Github, Google, Python, Microsoft, VirusTotal, VirusShare, LenStevens
感谢您使用 PYAS 防毒软件'''
        pygame.mixer.init()
        if not pygame.mixer.music.get_busy():
            pygame.mixer.music.load('Library/PYAS/Audio/Easteregg.ogg')
            pygame.mixer.music.play()
        for i in pdinfo:
            x = x+i
            time.sleep(0.1)
            pyas_clear()
            textPad.insert("insert",'''PYAS Infomation:
'''+str(pyas_divider)+str(x)+'_')
            root.update()
        pyas_clear()
        textPad.insert("insert",'''PYAS Infomation:
'''+str(pyas_divider)+str(pdinfo))
        root.update()
    else:
        er = open('.\Library\PYAS\Temp\PYASE.tmp','w')
        er.write(str(dev_edition_times + 1))
        er.close()
        messagebox.showinfo('Copyright','''官方网站: https://xiaomi69ai.wixsite.com/pyas
版权所有© 2020-2022 PYAS Python Antivirus Software''')

def software_version_cn():
    pyas_clear()
    messagebox.showinfo('Version','''防毒软件版本: '''+pyas_version)

def engine_version_cn():
    pyas_clear()
    messagebox.showinfo('Version','''扫毒引擎版本: '''+pyae_version)

####################################################################################

def simplified_chinese():
    if is_admin():
        try:
            pyas_clear()
            ft = open('Library/PYAS/Setup/PYAS.ini','w')
            ft.write('''simplified_chinese''')
            ft.close()
            menubar = Menu(root)
            root.config(menu = menubar)
            filemenu = Menu(menubar,tearoff=False)
            filemenu.add_command(label = '档案扫描',command = pyas_file_scan_cn)
            filemenu.add_command(label = '路径扫描',command = pyas_scan_path_init_cn)
            filemenu.add_command(label = '全盘扫描',command = pyas_scan_disk_init_cn)
            menubar.add_cascade(label = ' 扫描',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = '启动实时防护',command = protect_threading_init_cn)
            menubar.add_cascade(label = '防护',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            menubar.add_cascade(label = '工具',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='系统工具', menu=sub2menu, underline=0)
            sub2menu.add_command(label = '系统进程管理',command = process_init_cn)
            sub2menu.add_separator()
            sub2menu.add_command(label = '清理系统档案',command = system_disk_clean_cn)
            sub2menu.add_separator()
            sub2menu.add_command(label = '修复系统档案',command = repair_system_files_cn)
            sub2menu.add_command(label = '修复系统壁纸',command = recover_Wallpaper_cn)
            sub2menu.add_command(label = '修复系统权限',command = fix_cmd_permissions_cn)
            sub2menu.add_command(label = '修复系统限制',command = fixlimit_cn)
            sub2menu.add_separator()
            sub2menu.add_command(label = '启动安全模式',command = start_safe_mode_cn)
            sub2menu.add_command(label = '关闭安全模式',command = close_safe_Mode_cn)
            sub2menu.add_separator()
            sub2menu.add_command(label = '系统版本资讯',command = computer_info_cn)
            insmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='隐私工具', menu=insmenu, underline=0)
            insmenu.add_command(label = '相机隐私检测',command = camera_check_cn)
            insmenu.add_command(label = '移除私密档案',command = destroy_files_cn)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='更多工具', menu=submenu, underline=0)
            submenu.add_command(label = '寻找档案',command = find_files_init_cn)
            submenu.add_separator()
            submenu.add_command(label = '加密文字',command = input_encrypt_cn)
            submenu.add_command(label = '解密文字',command = input_decrypt_cn)
            submenu.add_separator()
            submenu.add_command(label = '传送讯息',command = input_send_text_cn)
            submenu.add_command(label = '接收讯息',command = input_receive_text_cn)
            submenu.add_separator()
            submenu.add_command(label = '更改用户密码',command = change_user_password_init_cn)
            submenu.add_separator()
            submenu.add_command(label = '网络位置查询',command = ip_detect_cn)
            submenu.add_command(label = '重制系统网络',command = reset_network_cn)
            devmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='开发工具', menu=devmenu, underline=0)
            devmenu.add_command(label = '自订 REG 指令',command = input_custom_regedit_command_cn)
            devmenu.add_command(label = '自订 CMD 指令',command = input_custom_cmd_command_cn)
            devmenu.add_separator()
            devmenu.add_command(label = '分析 EXE 哈希',command = exe_analyze_md5_cn)
            devmenu.add_command(label = '分析 EXE 位元',command = exe_analyze_file_cn)
            devmenu.add_command(label = '分析 EXE 函数',command = exe_analyze_function_cn)
            devmenu.add_separator()
            devmenu.add_command(label = '在线挡案分析',command = input_virustotal_scan_cn)
            filemenu5 = Menu(menubar,tearoff=False)
            menubar.add_cascade(label = '设置',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='软件设置', menu=sitmenu, underline=0)
            sitmenu.add_command(label="更新防毒软件", command=software_update_cn)
            sitmenu.add_command(label="更新扫毒引擎", command=engine_update_cn)
            sitmenu2 = Menu(filemenu5,tearoff=False)
            #filemenu5.add_cascade(label='引擎設置', menu=sitmenu2, underline=0)
            #sitmenu2.add_command(label="Enable Quick Scan", command=#)
            #sitmenu2.add_command(label="Disable Quick Scan", command=#)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='变更语言', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese)
            sit2menu.add_command(label="简体中文", command=simplified_chinese)
            sit2menu.add_command(label="English", command=english)
            aboutmenu = Menu(menubar,tearoff=False)
            aboutus = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='关于我们', menu=aboutus, underline=0)
            aboutus.add_command(label="关于 PYAS", command=about_pyas_cn)
            aboutversion = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='软件版本', menu=aboutversion, underline=0)
            aboutversion.add_command(label="防毒软件版本", command=software_version_cn)
            aboutversion.add_command(label="扫毒引擎版本", command=engine_version_cn)
            licmenu = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='许可条款', menu=licmenu, underline=0)
            licmenu.add_command(label = 'PYAS 许可条款',command = pyas_license_terms_en)
            menubar.add_cascade(label = '关于',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            messagebox.showerror('Error', '''此软件出现了一些问题,我们感到很抱歉。
回报错误: https://xiaomi69ai.wixsite.com/pyas
错误资讯: '''+str(e))
    else:
        windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

####################################################################################

#初始化驗證
def pyas_key():
    try:
        with open('PYAS.exe',"rb") as f:
            bytes = f.read()
            readable_hash = md5(bytes).hexdigest();
        f.close()
        ft = open('Library/PYAS/Setup/PYAS.key','r')
        fe = ft.read()
        ft.close()
        if fe == readable_hash:
            setup_pyas()
        else:
            messagebox.showerror('Error', '''The PYAS antivirus software you are using is not genuine. To ensure your safety, please download genuine antivirus software from the
Official website: https://xiaomi69ai.wixsite.com/pyas''')
    except:
        messagebox.showerror('Error', '''The PYAS antivirus software you are using is not genuine. To ensure your safety, please download genuine antivirus software from the
Official website: https://xiaomi69ai.wixsite.com/pyas''')

####################################################################################

#初始化語言
def setup_pyas():
    try:
        ft = open('Library/PYAS/Setup/PYAS.ini','r')
        fe = ft.readlines(0)
        ft.close()
        if 'english' in fe:
            english()
        elif 'traditional_chinese' in fe:
            traditional_chinese()
        elif 'simplified_chinese' in fe:
            simplified_chinese()
        else:
            english()
    except:
        messagebox.showinfo('Welcome',en_welcome)
        english()

pyas_key()
