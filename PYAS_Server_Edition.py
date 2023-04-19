################################################################################
# Coding Python 3.11 UTF-8 [64-bit] (Python IDLE)
#
# PYAS Web: https://pyantivirus.wixsite.com/pyas
# PYAS Git: https://github.com/87owo/PYAS
#
# This is a PYAS Server Professional Beta Edition
# Copyright© 2020-2023 87owo (PYAS Security)
################################################################################

import os, requests, psutil, struct, win32api, win32con, win32file, time
from pefile import PE, DIRECTORY_ENTRY
from PYAE_Model import function_list
from threading import Thread
from hashlib import md5

################################################################################

def sign_scan(file):
    try:
        pe = PE(file, fast_load=True)
        pe.close()
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress == 0
    except:
        return True

def pe_scan(file):
    try:
        fn = []
        pe = PE(file)
        pe.close()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                fn.append(str(func.name, 'utf-8'))
        if fn in function_list:
            return True
        return False
    except:
        return False

def api_scan(types, file):
    try:
        with open(file, "rb") as f:
            file_md5 = str(md5(f.read()).hexdigest())
        response = requests.get("http://27.147.30.238:5001/pyas", params={types: file_md5}, timeout=2)
        return response.status_code == 200 and response.text == 'True'
    except:
        return False

################################################################################

def protect_system_mbr_repair():
    with open(r"\\.\PhysicalDrive0", "r+b") as f:
        mbr_value = f.read(512)
    while True:
        time.sleep(0.5)
        try:
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                if struct.unpack("<H", f.read(512)[510:512])[0] != 0xAA55:
                    f.seek(0)
                    f.write(mbr_value)
                    print(f'Sysmbr Fixed: PhysicalDrive0')
        except:
            pass

def protect_system_reg_repair():
    while True:
        time.sleep(0.5)
        try:
            Permission = ['NoControlPanel', 'NoDrives', 'NoControlPanel', 'NoFileMenu', 'NoFind', 'NoRealMode', 'NoRecentDocsMenu','NoSetFolders', \
            'NoSetFolderOptions', 'NoViewOnDrive', 'NoClose', 'NoRun', 'NoDesktop', 'NoLogOff', 'NoFolderOptions', 'RestrictRun','DisableCMD', \
            'NoViewContexMenu', 'HideClock', 'NoStartMenuMorePrograms', 'NoStartMenuMyGames', 'NoStartMenuMyMusic' 'NoStartMenuNetworkPlaces', \
            'NoStartMenuPinnedList', 'NoActiveDesktop', 'NoSetActiveDesktop', 'NoActiveDesktopChanges', 'NoChangeStartMenu', 'ClearRecentDocsOnExit', \
            'NoFavoritesMenu', 'NoRecentDocsHistory', 'NoSetTaskbar', 'NoSMHelp', 'NoTrayContextMenu', 'NoViewContextMenu', 'NoWindowsUpdate', \
            'NoWinKeys', 'StartMenuLogOff', 'NoSimpleNetlDList', 'NoLowDiskSpaceChecks', 'DisableLockWorkstation', 'NoManageMyComputerVerb',\
            'DisableTaskMgr', 'DisableRegistryTools', 'DisableChangePassword', 'Wallpaper', 'NoComponents', 'NoAddingComponents', 'Restrict_Run']
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS),'Explorer')#創建鍵
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS),'Explorer')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS),'System')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS),'System')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS),'ActiveDesktop')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS),'System')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS),'System')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft',0,win32con.KEY_ALL_ACCESS),'MMC')
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS),'{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}')
            keys = [win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS),\
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)]
            for key in keys:
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)#刪除值
                        print(f'Regedit Fixed: {i}')
                    except:
                         pass
            win32api.RegCloseKey(key)#關閉已打開的鍵
        except:
            pass

def protect_system_processes():
    while True:
        for p in psutil.process_iter():
            try:
                file, name = str(p.exe()), str(p.name())
                if '' == file or str(sys.argv[0]) == file or ':\Windows' in file or ':\Program' in file:
                    continue
                elif sign_scan(file) or pe_scan(file) or api_scan('md5', file):
                    p.kill()
                    print(f'Malware Blocked: {file}')
            except:
                continue

def protect_file_watch_event(path):
    try:
        sflist = ['.exe','.dll','.com','.bat','.vbs','.htm','.js','.jar','.doc','.xml','.msi','.scr','.cpl']
        hDir = win32file.CreateFile(path,win32con.GENERIC_READ,win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
        while True:
            try:
                for action, file in win32file.ReadDirectoryChangesW(hDir,1024,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_DIR_NAME | win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES | win32con.FILE_NOTIFY_CHANGE_SIZE | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE | win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None):
                    fullpath = str(path+file)
                    name, ext = os.path.splitext(os.path.basename(fullpath))
                    if str(sys.argv[0]) == fullpath or ':\Windows' in fullpath or ':\Program' in fullpath or 'AppData' in fullpath:
                        continue
                    elif action and ext in sflist and sign_scan(fullpath):
                        if pe_scan(fullpath) or api_scan('md5', fullpath):
                            os.remove(fullpath)
                            print(f'Malware Remove: {fullpath}')
            except:
                pass
    except:
        pass

################################################################################

if __name__ == "__main__":
    Thread(target=protect_system_mbr_repair).start()
    Thread(target=protect_system_reg_repair).start()
    Thread(target=protect_system_processes).start()
    for d in range(26):
        Thread(target=protect_file_watch_event, args=(str(chr(65+d)+':\\'),)).start()
