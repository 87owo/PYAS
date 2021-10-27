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
import getpass
import json
import stat
import cryptocode
import tkinter as tk
from tkinter import *
from os import listdir
#import pyinstaller_versionfile
from tkinter import filedialog
from tkinter.messagebox import *
from functools import partial
from os.path import isfile, isdir, join
from Expansion_pack.list import *
from Expansion_pack import *
'''
pyinstaller_versionfile.create_versionfile(
    output_file="versionfile.txt",
    version="1.6.3",
    company_name="PYAS",
    file_description="Python Antivirus Software",
    internal_name="PYAS",
    legal_copyright="Copyright© 2020-2021 PYAS Python Antivirus Software.",
    original_filename="PYAS.exe",
    product_name="PYAS"
)
'''
root = Tk()
root.title('PYAS V1.6.3')
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

def pyas_license_terms():
    textPad.delete(1.0,END)
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

def microsoft_license_terms():
    textPad.delete(1.0,END)
    textPad.insert("insert", '''MICROSOFT SOFTWARE LICENSE TERMS
MICROSOFT SAFETY SCANNER 1.0
These license terms are an agreement between Microsoft Corporation (or based on where you live, one of its affiliates) and you. Please read them. They apply to the software named above, which includes the media on which you received it, if any. The terms also apply to any Microsoft
* updates,
* supplements,
* Internet-based services, and
* support services
for this software, unless other terms accompany those items. If so, those terms apply.
BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS. IF YOU DO NOT ACCEPT THEM, DO NOT USE THE SOFTWARE.
AS DESCRIBED BELOW, USING SOME FEATURES ALSO OPERATES AS YOUR CONSENT TO THE TRANSMISSION OF CERTAIN STANDARD COMPUTER INFORMATION FOR INTERNET-BASED SERVICES.
If you comply with these license terms, you have the rights below.
1. INSTALLATION AND USE RIGHTS. You may install and use one copy of the software on your device to design, develop and test your programs.
2. INTERNET-BASED SERVICES. Microsoft provides Internet-based services with the software. It may change or cancel them at any time.
a. Consent for Internet-Based Services. The software feature described below connects to Microsoft or service provider computer systems over the Internet. In some cases, you will not receive a separate notice when they connect. For more information about this feature, see the software documentation. BY USING THIS FEATURE, YOU CONSENT TO THE TRANSMISSION OF THIS INFORMATION. Microsoft does not use the information to identify or contact you.
i. Computer Information. The following feature uses Internet protocols, which send to the appropriate systems computer information, such as your Internet protocol address, the type of operating system, browser and name and version of the software you are using, and the language code of the device where you installed the software. Microsoft uses this information to make the Internet-based service available to you.
* Malicious Software Removal. The software will check for and remove certain high severity malicious software (“Malware”) stored on your device when you select this action. When the software checks your device for Malware, a report will be sent to Microsoft about any Malware detected or errors that occur while the software is checking for Malware, specific information relating to the detection, errors that occurred while the software was checking for Malware, and other information about your device that will help us improve this and other Microsoft products and services. No information that can be used to identify you is included in the report.
* Potentially Unwanted Software. The software will search your computer for low to medium severity Malware, including but not limited to, spyware, and other potentially unwanted software ("Potentially Unwanted Software"). The software will only remove or disable low to medium severity Potentially Unwanted Software if you agree. Removing or disabling this Potentially Unwanted Software may cause other software on your computer to stop working, and it may cause you to breach a license to use other software on your computer, if the other software installed this Potentially Unwanted Software on your computer as a condition of your use of the other software. You should read the license agreements for other software before authorizing the removal of this Potentially Unwanted Software. By using this software, it is possible that you or the system will also remove or disable software that is not Potentially Unwanted Software.
ii. Use of Information. We may use the computer information, and Malware reports, to improve our software and services. We may also share it with others, such as hardware and software vendors. They may use the information to improve how their products run with Microsoft software.
3. TIME-SENSITIVE SOFTWARE. The software will stop running 10 days after you download it. You will not receive any other notice. You may not be able to access data used with the software when it stops running.
4. SCOPE OF LICENSE. The software is licensed, not sold. This agreement only gives you some rights to use the software. Microsoft reserves all other rights. Unless applicable law gives you more rights despite this limitation, you may use the software only as expressly permitted in this agreement. In doing so, you must comply with any technical limitations in the software that only allow you to use it in certain ways. You may not
* disclose the results of any benchmark tests of the software to any third party without Microsoft’s prior written approval;
* work around any technical limitations in the software;
* reverse engineer, decompile or disassemble the software, except and only to the extent that applicable law expressly permits, despite this limitation;
* make more copies of the software than specified in this agreement or allowed by applicable law, despite this limitation;
* publish the software for others to copy;
* rent, lease or lend the software; or
* use the software for commercial software hosting services.
5. BACKUP COPY. You may make one backup copy of the software. You may use it only to reinstall the software.
6. DOCUMENTATION. Any person that has valid access to your computer or internal network may copy and use the documentation for your internal, reference purposes.
7. TRANSFER TO ANOTHER DEVICE. You may uninstall the software and install it on another device for your use. You may not do so to share this license between devices.
8. TRANSFER TO A THIRD PARTY. The first user of the software may transfer it and this agreement directly to a third party. Before the transfer, that party must agree that this agreement applies to the transfer and use of the software. The first user must uninstall the software before transferring it separately from the device. The first user may not retain any copies.
9. EXPORT RESTRICTIONS. The software is subject to United States export laws and regulations. You must comply with all domestic and international export laws and regulations that apply to the software. These laws include restrictions on destinations, end users and end use. For additional information, see www.microsoft.com/exporting.
10. SUPPORT SERVICES. Because this software is “as is,” we may not provide support services for it.
11. ENTIRE AGREEMENT. This agreement, and the terms for supplements, updates, Internet-based services and support services that you use, are the entire agreement for the software and support services.
12. APPLICABLE LAW.
a. United States. If you acquired the software in the United States, Washington state law governs the interpretation of this agreement and applies to claims for breach of it, regardless of conflict of laws principles. The laws of the state where you live govern all other claims, including claims under state consumer protection laws, unfair competition laws, and in tort.
b. Outside the United States. If you acquired the software in any other country, the laws of that country apply.
13. LEGAL EFFECT. This agreement describes certain legal rights. You may have other rights under the laws of your country. You may also have rights with respect to the party from whom you acquired the software. This agreement does not change your rights under the laws of your country if the laws of your country do not permit it to do so.
14. DISCLAIMER OF WARRANTY. THE SOFTWARE IS LICENSED “AS-IS.” YOU BEAR THE RISK OF USING IT. MICROSOFT GIVES NO EXPRESS WARRANTIES, GUARANTEES OR CONDITIONS. YOU MAY HAVE ADDITIONAL CONSUMER RIGHTS UNDER YOUR LOCAL LAWS WHICH THIS AGREEMENT CANNOT CHANGE. TO THE EXTENT PERMITTED UNDER YOUR LOCAL LAWS, MICROSOFT EXCLUDES THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
15. LIMITATION ON AND EXCLUSION OF REMEDIES AND DAMAGES. YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT OR INCIDENTAL DAMAGES.
This limitation applies to
* anything related to the software, services, content (including code) on third party Internet sites, or third party programs; and
* claims for breach of contract, breach of warranty, guarantee or condition, strict liability, negligence, or other tort to the extent permitted by applicable law.
It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your country may not allow the exclusion or limitation of incidental, consequential or other damages.
''')

def input_pyas_key():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('激活軟件')
    t.geometry('260x40')
    t.transient(root)
    Label(t,text=' 密鑰: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :pyas_key(e.get())).grid(row=0,column=2,sticky='e'+'w',pady=2)

def pyas_key(ipw):
    textPad.delete(1.0,END)
    pw = 'pyas1217'
    if ipw == pw:
        showinfo('Information','''軟件已成功激活。''')
        traditional_chinese_pro()
    else:
        showerror('Error', '''密碼錯誤''')

def ask_pro():
    textPad.delete(1.0,END)
    if askokcancel('Pro','''此功能僅適用於專業版用戶，您要解鎖此功能嗎?''', default="ok"):
        input_pyas_key()
    else:
        pass
    
def exe_ca():
    textPad.delete(1.0,END)
    pe = pefile.PE(filedialog.askopenfilename())
    for section in pe.sections:
        textPad.insert("insert", section.Name, hex(section.VirtualAddress),
        hex(section.Misc_VirtualSize), section.SizeOfRawData)
        
def exe_cb():
    textPad.delete(1.0,END)
    pe = pefile.PE(filedialog.askopenfilename())
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        ft = open('PYASF.txt','a')
        ft.write(str(entry.dll)+'''
''')
        ft.close()
        #textPad.insert("insert", entry.dll)
        for function in entry.imports:
            ft = open('PYASF.txt','a')
            ft.write(str(function.name)+'''
''')
            ft.close()
            #textPad.insert("insert", '\t', function.name)
    ft = open('PYASF.txt','r')
    fe = ft.read()
    ft.close()
    textPad.insert("insert",str(fe))
    os.remove('PYASF.txt')
    
def smart_scan():
    textPad.delete(1.0,END)
    f = open('FSCAN.bat','w',encoding="utf-8")
    f.write('''MSERT.exe /n''')
    f.close()
    os.system('start FSCAN.bat')
    #os.remove('FSCAN.bat')

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
                textPad.insert("insert", '✖輸入檔案錯誤，沒有副檔名')
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
    textPad.delete(1.0,END)
    if askokcancel('Warning','''啟動安全模式需要重新啟動，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        os.system('net user administrator /active:yes')
        os.system('bcdedit /set {default} safeboot minimal')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass
    
def close_safe_Mode():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''關閉安全模式需要重新啟動，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        os.system('net user administrator /active:no')
        os.system('bcdedit /deletevalue {current} safeboot')
        time.sleep(1)
        os.system('shutdown -r -t 0')
    else:
        pass

def input_custom_cmd_command():
    textPad.delete(1.0,END)
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

def input_system_autorun():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''自訂指令有可能讓心懷不軌的使用者取得
這個電腦的控制及存取權，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('自訂指令')
        t.geometry('260x130')
        t.transient(root)
        Label(t,text=' 指令01: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' 指令02: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' 指令03: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        Label(t,text=' 指令04: ').grid(row=3,column=0,sticky='e')
        v4=StringVar()
        e4=Entry(t,width=20,textvariable=v4)
        e4.grid(row=3,column=1,padx=2,pady=2,sticky='we')
        e4.focus_set()
        Label(t,text=' 指令05: ').grid(row=4,column=0,sticky='e')
        v5=StringVar()
        e5=Entry(t,width=20,textvariable=v5)
        e5.grid(row=4,column=1,padx=2,pady=2,sticky='we')
        e5.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :system_autorun(e.get(),e2.get(),e3.get(),e4.get(),e5.get())).grid(row=4,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def system_autorun(cmd1,cmd2,cmd3,cmd4,cmd5):
    textPad.delete(1.0,END)
    subprocess.run(cmd1, shell=True)
    subprocess.run(cmd2, shell=True)
    subprocess.run(cmd3, shell=True)
    subprocess.run(cmd4, shell=True)
    subprocess.run(cmd5, shell=True)
    textPad.insert("insert", '執行完畢。')

def input_custom_regedit_command():
    if askokcancel('Warning','''自訂指令有可能讓心懷不軌的使用者取得
這個電腦的控制及存取權，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
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
        Button(t,text='確定',command=lambda :custom_regedit_command(e.get(),e2.get(),e3.get(),e4.get())).grid(row=3,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def custom_regedit_command(path,cmd,reg,num):
    textPad.delete(1.0,END)
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
['''+str(path)+''']
"'''+str(cmd)+'''"='''+str(reg)+''':'''+str(num)+'''''')
    f.close()
    ctypes.windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)
    
def fix_cmd_permissions():
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000000
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableTaskMgr"=dword:00000000''')
    f.close()
    ctypes.windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)
    
def custom_cmd_command(cmd):
    textPad.delete(1.0,END)
    subprocess.run(cmd, shell=True)
    textPad.insert("insert", '執行完畢。')
    
def input_encrypt():
    textPad.delete(1.0,END)
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
    Button(t,text='確定',command=lambda :encrypt(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)
    
def encrypt(e,e2):
    textPad.delete(1.0,END)
    '''
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
    '''
    textPad.insert("insert", '您的加密內容: '+str(cryptocode.encrypt(e,e2)))
    
def input_decrypt():
    textPad.delete(1.0,END)
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
    Button(t,text='確定',command=lambda :decrypt(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)
    
def decrypt(e,e2):
    textPad.delete(1.0,END)
    '''
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
    '''
    textPad.insert("insert", '您的解密內容: '+str(cryptocode.decrypt(e, e2)))
    
def input_send_text():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''發送訊息需要對方開啟接收模式，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('發送訊息')
        t.geometry('260x90')
        t.transient(root)
        Label(t,text=' 輸入: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' 地址: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text='   埠: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :send_text(e.get(),e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass
    
def send_text(message,HOST,PORT):
    textPad.delete(1.0,END)
    try:
        #HOST = '127.0.0.1'        # IP地址
        #PORT = 50007              # 埠
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(message.encode())
    except:
        showerror('Error', '''請先將準備接收的設備開啟接收模式''')

def input_receive_text():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''等待接收過程需要一段時間，程式可能
會暫時性停止運作，是否繼續?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('接收訊息')
        t.geometry('260x70')
        t.transient(root)
        Label(t,text=' 地址: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text='   埠: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='確定',command=lambda :receive_text(e2.get(),e3.get())).grid(row=2,column=2,sticky='e'+'w',pady=0)
    else:
        pass
    
def receive_text(HOST,PORT):
    textPad.delete(1.0,END)
    max_connect = 5           # 最大連線數
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, int(PORT)))
        s.listen()
        conn, _ = s.accept()
        data = conn.recv(1024).decode()
        textPad.insert("insert",'接收到的內容: '+data)

def software_update():
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas')
    
def website():
    showinfo('Website','''官方網站: https://xiaomi69ai.wixsite.com/pyas''')
    
def about():
    showinfo('Copyright','''官方網站: https://xiaomi69ai.wixsite.com/pyas
版權所有© 2020-2021 PYAS Python Antivirus Software''')
    
def version():
    showinfo('Version','軟體版本: PYAS V1.6.3')

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
            sub2menu.add_command(label = '系統自動執行',command = input_system_autorun)
            sub2menu.add_separator()
            sub2menu.add_command(label = '修復系統檔案',command = repair_system_files)
            sub2menu.add_command(label = '修復系統權限 (PRO)',command = ask_pro)
            sub2menu.add_separator()
            sub2menu.add_command(label = '啟動安全模式 (PRO)',command = ask_pro)
            sub2menu.add_command(label = '關閉安全模式 (PRO)',command = ask_pro)
            sub2menu.add_separator()
            sub2menu.add_command(label="自訂 REG 指令 (PRO)", command=ask_pro)
            sub2menu.add_command(label="自訂 CMD 指令 (PRO)", command=ask_pro)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='更多工具', menu=submenu, underline=0)
            submenu.add_command(label = '尋找檔案',command = input_find_files)
            submenu.add_separator()
            submenu.add_command(label = '加密文字',command = input_encrypt)
            submenu.add_command(label = '解密文字',command = input_decrypt)
            submenu.add_separator()
            submenu.add_command(label = '發送訊息 (PRO)',command = ask_pro)
            submenu.add_command(label = '接收訊息 (PRO)',command = ask_pro)
            submenu.add_separator()
            submenu.add_command(label = '網路位置查詢 (PRO)',command = ask_pro)
            submenu.add_command(label = '重置系統網絡 (PRO)',command = ask_pro)
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
            sitmenu.add_command(label="啟用專業版", command=input_pyas_key)
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

def traditional_chinese_pro():
    textPad.delete(1.0,END)
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
            sub2menu.add_command(label = '系統自動執行',command = input_system_autorun)
            sub2menu.add_separator()
            sub2menu.add_command(label = '修復系統檔案',command = repair_system_files)
            sub2menu.add_command(label = '修復系統權限',command = fix_cmd_permissions)
            sub2menu.add_separator()
            sub2menu.add_command(label = '啟動安全模式',command = start_safe_mode)
            sub2menu.add_command(label = '關閉安全模式',command = close_safe_Mode)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='更多工具', menu=submenu, underline=0)
            submenu.add_command(label = '尋找檔案',command = input_find_files)
            submenu.add_separator()
            submenu.add_command(label = '加密文字',command = input_encrypt)
            submenu.add_command(label = '解密文字',command = input_decrypt)
            submenu.add_separator()
            submenu.add_command(label = '發送訊息',command = input_send_text)
            submenu.add_command(label = '接收訊息',command = input_receive_text)
            submenu.add_separator()
            submenu.add_command(label = '網路位置查詢',command = web_queries)
            submenu.add_command(label = '重置系統網絡',command = reset_network)
            #filemenu4 = Menu(menubar,tearoff=False)
            devmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='開發工具', menu=devmenu, underline=0)
            devmenu.add_command(label = '自訂 REG 指令',command = input_custom_regedit_command)
            devmenu.add_command(label = '自訂 CMD 指令',command = input_custom_cmd_command)
            devmenu.add_separator()
            devmenu.add_command(label = '分析執行檔字節',command = exe_ca)
            devmenu.add_command(label = '分析執行檔函數',command = exe_cb)
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
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='變更語言', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese_pro)
            sit2menu.add_command(label="English", command=english_pro)
            aboutmenu = Menu(menubar,tearoff=False)
            #aboutmenu.add_command(label = '官方網站',command = website)
            aboutmenu.add_command(label = '關於我們',command = about)
            aboutmenu.add_command(label = '軟體版本',command = version)
            aboutmenu.add_separator()
            licmenu = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='許可條款', menu=licmenu, underline=0)
            licmenu.add_command(label = 'PYAS 許可條款',command = pyas_license_terms)
            licmenu.add_command(label = 'Microsoft 許可條款',command = microsoft_license_terms)
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
        english_pro()
    else:
        showerror('Error', '''Password error''')

def ask_pro_en():
    if askokcancel('Unlock function','''This feature is only available for users of the professional version.
Do you want to unlock this feature?''', default="ok", icon="info"):
        input_pyas_key_en()
    else:
        pass

def smart_scan_en():
    textPad.delete(1.0,END)
    f = open('FSCAN.bat','w',encoding="utf-8")
    f.write('''MSERT.exe /n''')
    f.close()
    os.system('start FSCAN.bat')
    #os.remove('FSCAN.bat')
    
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
                textPad.insert("insert", '✖Input file error, no correct file name')
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
    
def input_custom_regedit_command_en():
    if askokcancel('Warning','''The custom command may allow a malicious user to gain
control and access to this computer, whether to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('Custom REG')
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
    f = open('PYASR.reg','w',encoding="utf-8")
    f.write('''Windows Registry Editor Version 5.00
['''+str(path)+''']
"'''+str(cmd)+'''"='''+str(reg)+''':'''+str(num)+'''''')
    f.close()
    ctypes.windll.shell32.ShellExecuteW(None, "open", 'PYASR.reg', __file__, None, 1)
    
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
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' Password: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :encrypt_en(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)
    
def encrypt_en(e,e2):
    '''
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
    '''
    textPad.insert("insert", 'Your encrypted content: '+str(cryptocode.encrypt(e,e2)))
    

def input_decrypt_en():
    textPad.delete(1.0,END)
    t=Toplevel(root)
    t.title('Input text')
    t.geometry('260x70')
    t.transient(root)
    Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
    v=StringVar()
    e=Entry(t,width=20,textvariable=v)
    e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
    e.focus_set()
    Label(t,text=' Password: ').grid(row=1,column=0,sticky='e')
    v2=StringVar()
    e2=Entry(t,width=20,textvariable=v2)
    e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
    e2.focus_set()
    c=IntVar()
    fss = 0
    Button(t,text='OK',command=lambda :decrypt_en(e.get(),e2.get())).grid(row=1,column=2,sticky='e'+'w',pady=2)
    
def decrypt_en(e,e2):
    '''
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
    '''
    textPad.insert("insert", 'Your decrypted content: '+str(cryptocode.decrypt(e, e2)))
    
def input_system_autorun_en():
    if askokcancel('Warning','''It is possible that the custom command may allow the
malicious user to gain control and access to
this computer. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('Custom CMD')
        t.geometry('260x130')
        t.transient(root)
        Label(t,text=' CMD 01: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' CMD 02: ').grid(row=1,column=0,sticky='e')
        v2=StringVar()
        e2=Entry(t,width=20,textvariable=v2)
        e2.grid(row=1,column=1,padx=2,pady=2,sticky='we')
        e2.focus_set()
        Label(t,text=' CMD 03: ').grid(row=2,column=0,sticky='e')
        v3=StringVar()
        e3=Entry(t,width=20,textvariable=v3)
        e3.grid(row=2,column=1,padx=2,pady=2,sticky='we')
        e3.focus_set()
        Label(t,text=' CMD 04: ').grid(row=3,column=0,sticky='e')
        v4=StringVar()
        e4=Entry(t,width=20,textvariable=v4)
        e4.grid(row=3,column=1,padx=2,pady=2,sticky='we')
        e4.focus_set()
        Label(t,text=' CMD 05: ').grid(row=4,column=0,sticky='e')
        v5=StringVar()
        e5=Entry(t,width=20,textvariable=v5)
        e5.grid(row=4,column=1,padx=2,pady=2,sticky='we')
        e5.focus_set()
        c=IntVar()
        fss = 0
        Button(t,text='OK',command=lambda :system_autorun_en(e.get(),e2.get(),e3.get(),e4.get(),e5.get())).grid(row=4,column=2,sticky='e'+'w',pady=0)
    else:
        pass

def system_autorun_en(cmd1,cmd2,cmd3,cmd4,cmd5):
    textPad.delete(1.0,END)
    subprocess.run(cmd1, shell=True)
    subprocess.run(cmd2, shell=True)
    subprocess.run(cmd3, shell=True)
    subprocess.run(cmd4, shell=True)
    subprocess.run(cmd5, shell=True)
    textPad.insert("insert", 'Finished.')

def input_send_text_en():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''Sending a message requires the other party to turn
on the receiving mode. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('Send Message')
        t.geometry('260x90')
        t.transient(root)
        Label(t,text=' Input: ').grid(row=0,column=0,sticky='e')
        v=StringVar()
        e=Entry(t,width=20,textvariable=v)
        e.grid(row=0,column=1,padx=2,pady=2,sticky='we')
        e.focus_set()
        Label(t,text=' IP: ').grid(row=1,column=0,sticky='e')
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
    try:
        #HOST = '127.0.0.1'        # IP地址
        #PORT = 50007              # 埠
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            s.sendall(message.encode())
    except:
        showerror('Error', '''Please turn on the receiving mode of the receiving device first''')

def input_receive_text_en():
    textPad.delete(1.0,END)
    if askokcancel('Warning','''It takes a while to wait for the receiving process.
The program may temporarily stop working. Do you want to continue?''', default="cancel", icon="warning"):
        textPad.delete(1.0,END)
        t=Toplevel(root)
        t.title('Receive Message')
        t.geometry('260x70')
        t.transient(root)
        Label(t,text=' IP: ').grid(row=1,column=0,sticky='e')
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
    textPad.delete(1.0,END)
    max_connect = 5           # 最大連線數
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, int(PORT)))
        s.listen()
        conn, _ = s.accept()
        data = conn.recv(1024).decode()
        textPad.insert("insert",'Received content: '+data)

def software_update_en():
    webbrowser.open('https://xiaomi69ai.wixsite.com/pyas')
    
def website_en():
    showinfo('Website','''Official website: https://xiaomi69ai.wixsite.com/pyas''')
    
def about_en():
    showinfo('Copyright','''Official website: https://xiaomi69ai.wixsite.com/pyas
Copyright© 2020-2021 PYAS Python Antivirus Software''')
    
def version_en():
    showinfo('Version','Software Version: PYAS V1.6.3')

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
            filemenu.add_command(label = 'Smart scan',command = smart_scan)
            filemenu.add_command(label = 'Intelligent analysis',command = ai_scan_en)
            menubar.add_cascade(label = ' Scan',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = 'Antivirus immediately',command = input_antivirus_immediately_en)
            #filemenu2.add_command(label = '偵測殺毒',command = detect_antivirus)
            #filemenu2.add_command(label = '循環殺毒',command = cyclic_antivirus)
            filemenu2.add_command(label = 'Destroy virus',command = destroy_virus_en)
            menubar.add_cascade(label = 'Antivirus',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            #filemenu3.add_command(label = '尋找檔案',command = input_find_files)
            menubar.add_cascade(label = 'Tools',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='System Tools', menu=sub2menu, underline=0)
            sub2menu.add_command(label = 'Automatic execution',command = input_system_autorun_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Repair system files',command = repair_system_files_en)
            sub2menu.add_command(label = 'Repair system permissions (PRO)',command = ask_pro_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Start safe mode (PRO)',command = ask_pro_en)
            sub2menu.add_command(label = 'Close safe mode (PRO)',command = ask_pro_en)
            sub2menu.add_separator()
            sub2menu.add_command(label="Custom REG command (PRO)", command=ask_pro_en)
            sub2menu.add_command(label="Custom CMD command (PRO)", command=ask_pro_en)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='More Tools', menu=submenu, underline=0)
            submenu.add_command(label = 'Find files',command = input_find_files_en)
            submenu.add_separator()
            submenu.add_command(label = 'Encrypted text',command = input_encrypt_en)
            submenu.add_command(label = 'Decrypt text',command = input_decrypt_en)
            submenu.add_separator()
            submenu.add_command(label = 'Send message (PRO)',command = ask_pro_en)
            submenu.add_command(label = 'Receive message (PRO)',command = ask_pro_en)
            submenu.add_separator()
            submenu.add_command(label = 'Network location query (PRO)',command = ask_pro_en)
            submenu.add_command(label = 'Reset system network (PRO)',command = ask_pro_en)
            filemenu4 = Menu(menubar,tearoff=False)
            #filemenu4.add_command(label = '修復CMD權限',command = fix_cmd_permissions)
            #menubar.add_cascade(label = '系統',menu = filemenu4)
            filemenu5 = Menu(menubar,tearoff=False)
            #filemenu5.add_command(label="自訂指令", command=input_custom_cmd_command)
            #filemenu5.add_command(label = ' ')
            menubar.add_cascade(label = 'Setting',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Software settings', menu=sitmenu, underline=0)
            sitmenu.add_command(label="Update software", command=software_update)
            #sitwmenu = Menu(sitmenu,tearoff=False)
            #filemenu5.add_cascade(label='字體大小', menu=sitwmenu, underline=0)
            #sitwmenu.add_command(label="增大字體", command=sizeb)
            #sitwmenu.add_command(label="縮小字體", command=sizes)
            sitmenu.add_command(label="Activate professional", command=input_pyas_key_en)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Change language', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese)
            sit2menu.add_command(label="English", command=english)
            aboutmenu = Menu(menubar,tearoff=False)
            #aboutmenu.add_command(label = '官方網站',command = website)
            aboutmenu.add_command(label = 'About us',command = about_en)
            aboutmenu.add_command(label = 'Software version',command = version_en)
            menubar.add_cascade(label = 'About',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            showerror('Error', '''We are sorry that there was an error in the program.
Report error: https://xiaomi69ai.wixsite.com/pyas
Error info: '''+str(e))
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 8)

def english_pro():
    textPad.delete(1.0,END)
    if is_admin():
        try:
            ft = open('PYASL.ini','w')
            ft.write('''english''')
            ft.close()
            menubar = Menu(root)
            root.config(menu = menubar)
            filemenu = Menu(menubar,tearoff=False)
            filemenu.add_command(label = 'Smart scan',command = smart_scan)
            filemenu.add_command(label = 'Intelligent analysis',command = ai_scan_en)
            menubar.add_cascade(label = ' Scan',menu = filemenu)
            filemenu2 = Menu(menubar,tearoff=False)
            filemenu2.add_command(label = 'Antivirus immediately',command = input_antivirus_immediately_en)
            #filemenu2.add_command(label = '偵測殺毒',command = detect_antivirus)
            #filemenu2.add_command(label = '循環殺毒',command = cyclic_antivirus)
            filemenu2.add_command(label = 'Destroy virus',command = destroy_virus_en)
            menubar.add_cascade(label = 'Antivirus',menu = filemenu2)
            filemenu3 = Menu(menubar,tearoff=False)
            #filemenu3.add_command(label = '尋找檔案',command = input_find_files)
            menubar.add_cascade(label = 'Tools',menu = filemenu3)
            sub2menu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='System Tools', menu=sub2menu, underline=0)
            sub2menu.add_command(label = 'Automatic execution',command = input_system_autorun_en)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Repair system files',command = repair_system_files_en)
            sub2menu.add_command(label = 'Repair system permissions',command = fix_cmd_permissions)
            sub2menu.add_separator()
            sub2menu.add_command(label = 'Start safe mode',command = start_safe_mode_en)
            sub2menu.add_command(label = 'Close safe mode',command = close_safe_Mode_en)
            submenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='More Tools', menu=submenu, underline=0)
            submenu.add_command(label = 'Find files',command = input_find_files_en)
            submenu.add_separator()
            submenu.add_command(label = 'Encrypted text',command = input_encrypt_en)
            submenu.add_command(label = 'Decrypt text',command = input_decrypt_en)
            submenu.add_separator()
            submenu.add_command(label = 'Send message',command = input_send_text_en)
            submenu.add_command(label = 'Receive message',command = input_receive_text_en)
            submenu.add_separator()
            submenu.add_command(label = 'Network location query',command = web_queries_en)
            submenu.add_command(label = 'Reset system network',command = reset_network_en)
            filemenu4 = Menu(menubar,tearoff=False)
            devmenu = Menu(filemenu3,tearoff=False)
            filemenu3.add_cascade(label='Dev Tools', menu=devmenu, underline=0)
            devmenu.add_command(label = 'Custom REG Command',command = input_custom_regedit_command_en)
            devmenu.add_command(label = 'Custom CMD Command',command = input_custom_cmd_command_en)
            devmenu.add_separator()
            devmenu.add_command(label = 'Analyze EXE bytes',command = exe_ca)
            devmenu.add_command(label = 'Analysis EXE function',command = exe_cb)
            #filemenu4.add_command(label = '修復CMD權限',command = fix_cmd_permissions)
            #menubar.add_cascade(label = '系統',menu = filemenu4)
            filemenu5 = Menu(menubar,tearoff=False)
            #filemenu5.add_command(label="自訂指令", command=input_custom_cmd_command)
            #filemenu5.add_command(label = ' ')
            menubar.add_cascade(label = 'Setting',menu = filemenu5)
            sitmenu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Software settings', menu=sitmenu, underline=0)
            sitmenu.add_command(label="Update software", command=software_update)
            #sitwmenu = Menu(sitmenu,tearoff=False)
            #filemenu5.add_cascade(label='字體大小', menu=sitwmenu, underline=0)
            #sitwmenu.add_command(label="增大字體", command=sizeb)
            #sitwmenu.add_command(label="縮小字體", command=sizes)
            sit2menu = Menu(filemenu5,tearoff=False)
            filemenu5.add_cascade(label='Change language', menu=sit2menu, underline=0)
            sit2menu.add_command(label="繁體中文", command=traditional_chinese_pro)
            sit2menu.add_command(label="English", command=english_pro)
            aboutmenu = Menu(menubar,tearoff=False)
            #aboutmenu.add_command(label = '官方網站',command = website)
            aboutmenu.add_command(label = 'About us',command = about_en)
            aboutmenu.add_command(label = 'Software version',command = version_en)
            aboutmenu.add_separator()
            licmenu = Menu(aboutmenu,tearoff=False)
            aboutmenu.add_cascade(label='license terms', menu=licmenu, underline=0)
            licmenu.add_command(label = 'PYAS license terms',command = pyas_license_terms)
            licmenu.add_command(label = 'Microsoft license terms',command = microsoft_license_terms)
            menubar.add_cascade(label = 'About',menu = aboutmenu)
            root.mainloop()
        except Exception as e:
            showerror('Error', '''We are sorry that there was an error in the program.
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
            english_pro()
        elif fe == 'traditional_chinese':
            traditional_chinese_pro()
        else:
            english_pro()
    except:
        english_pro()
        
setup_pyas()
