import hashlib
import os
from functools import partial
import json
import zipfile

def md5_file():
    for i in range(410):
        x = 5 - len(str(i))
        y = '0'*x+str(i)
        bytes = zipfile.ZipFile('Library/MD5.zip', 'r').read(str(y)+'.md5')
        

#def pyae_scan():

def scan_sha256(file):
    try:
        virus_found = False
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();
            print("SHA256: " + readable_hash)
            with open("Library/SHA256.txt",'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                    if str(readable_hash) == str(line.split(";")[0]):
                        virus_found = True
            f.close()
        if not virus_found:
            print("File is safe!")
            return False
        else:
            return True
            #print("Virus detected! File quarentined")
            #os.remove(file)
    except:
        pass

def scan_md5(file):
    #try:
        virus_found = False
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.md5(bytes).hexdigest();
            #print("MD5: " + readable_hash)
            for i in range(410):
                x = 5 - len(str(i))
                y = '0'*x+str(i)
                with open('Library/MD5/'+str(y)+'.md5','r') as f:
                    #print(str(f))
                    lines = [line.rstrip() for line in f]
                    for line in lines:
                        if str(readable_hash) == str(line.split(";")[0]):
                            #print(str(f))
                            virus_found = True
                f.close()
        if not virus_found:
            #print("File is safe!")
            return False
        else:
            #print("Virus detected! File quarentined")
            #os.remove(file)
            return True
    #except Exception as e:
    #    print(e)
    

def scan(file):
    try:
        virus_found = False
        with open(file,"rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha1(bytes).hexdigest();
            print("SHA1: " + readable_hash)
            with open('Library/SHA1 HASHES.json', 'r') as f:
                dataset = json.loads(f.read())
                for index, item in enumerate(dataset["data"]):
                    if str(item['hash']) == str(readable_hash):
                        virus_found = True
            f.close()
        if not virus_found:
            print("File is safe!")
            return False
        else:
            #print("Virus detected! File quarentined")
            #os.remove(file)
            return True
    except:
        pass
    
def pyae_scan_full(filepath):
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
    textPad.delete(1.0,END)
    try:
        textPad.insert("insert", '正在尋找: '+str(path))
        for fd in os.listdir(path):
            root.update()
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

#scan(filepath)
#scan_md5(filepath)
#scan_sha256(filepath)
#ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe
def pyae_file_scan(file):
    if scan_md5(file):
        return True
    else:
        return False

#if scan(file) or scan_sha256(file) or scan_md5(file):

