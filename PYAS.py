####################################################################################
# Coding Python 3.11 UTF-8 [64-bit] (Python IDLE)
#
# PYAS Git: https://github.com/87owo/PYAS
# PYAS Web: https://pyantivirus.wixsite.com/pyas
#
# PYAS is managed by PYDT (Python Development Team)
# Copyright© 2020-2022 PYAS Python Antivirus Software.
####################################################################################
#
##################################### 載入必要模組 ###################################

try:
    import time
    start_m = time.time()
    import os, sys, psutil, subprocess, cryptocode, threading, configparser, datetime
    from pefile import PE
    from hashlib import md5, sha1, sha256
    from PYAS_English import english_list
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import *
    from PyQt5.QtCore import *
    from PyQt5 import QtWidgets, QtGui, QtCore
    from PYAS_UI import Ui_MainWindow
    #from watchdog.events import FileSystemEventHandler #Beta Not Cplt
    #from watchdog.observers import Observer
except Exception as e:
    print('[Error] '+str(e))
print('[LOAD] Mods: '+str(time.time()-start_m)+' sec')

###################################### 錯誤日誌 #####################################

def pyas_bug_log(e):
    try:
        print('[Error] '+str(e))
        ft = open('Library/PYAS/Temp/PYASB.log','a',encoding='utf-8')
        fe = ft.write(str(e)+'\n')
        ft.close()
    except:
        pass

##################################### 測試版項目 ####################################

def pyas_vl_md5r():#不穩定
    try:
        with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
            global rfp
            rfp = fp.read()
        fp.close()
    except Exception as e:
        pyas_bug_log(e)

###################################### 密鑰認證 #####################################

def pyas_key():
    start = time.time()
    try:
        try:
            with open('PYAS.exe',"rb") as f:
                bytes = f.read()
                readable_hash = str(md5(bytes).hexdigest())
            f.close()
        except:
            with open('PYAS.py',"rb") as f:
                bytes = f.read()
                readable_hash = str(md5(bytes).hexdigest())
            f.close()
        try:
            ft = open('Library/PYAS/Setup/PYAS.key','r')
            fe = ft.read()
            ft.close()
            if fe == readable_hash:
                print('[LOAD] Key: '+str(time.time()-start)+' sec')
                return True
            else:
                print('[LOAD] Key: '+str(time.time()-start)+' sec')
                return False
        except:
            pass
    except Exception as e:
        pyas_bug_log(e)
        print('[LOAD] Key: '+str(time.time()-start)+' sec')
        return False

##################################### 資料庫檢查 ####################################

def pyas_library():
    try:
        if not os.path.isdir('Library/PYAS/Temp'):
            os.makedirs('Library/PYAS/Temp')
        if not os.path.isdir('Library/PYAS/Setup'):
            os.makedirs('Library/PYAS/Setup')
        if not os.path.isdir('Library/PYAS/Audio'):
            os.makedirs('Library/PYAS/Audio')
        if not os.path.isdir('Library/PYAS/Icon'):
            os.makedirs('Library/PYAS/Icon')
        if not os.path.isdir('Library/PYAE/Function'):
            os.makedirs('Library/PYAE/Function')
        if not os.path.isdir('Library/PYAE/Hashes'):
            os.makedirs('Library/PYAE/Hashes')
    except Exception as e:
        pyas_bug_log(e)
        pass

##################################### 移除暫存檔 ####################################

def pyasb_remove():
    try:
        os.remove('Library/PYAS/Temp/PYASB.log')
    except:
        pass

def pyasp_remove():
    try:
        os.remove('Library/PYAS/Temp/PYASP.tmp')
    except:
        pass

##################################### 更新資料庫 ####################################
    
def pyas_vl_update():
    try:
        v = open('Library/PYAE/Hashes/Viruslist.num','r').read()
    except:
        v = 0
    try:
        import requests as req
        start = time.time()
        for i in range(int(v),10000):
            try:
                x = 5 - len(str(i))
                y = '0'*x+str(i)
                file = req.get('https://virusshare.com/hashfiles/VirusShare_'+y+'.md5', allow_redirects=True)
                open('Library/PYAE/Hashes/'+y+'.md5', 'wb').write(file.content)
                with open('Library/PYAE/Hashes/'+str(y)+'.md5',"rb") as f:
                    bytes = f.read()
                    readable_hash = str(md5(bytes).hexdigest())
                f.close()
                if '449a34c34a7507dffe1d39afad3eeac9' == readable_hash:
                    v = open('Library/PYAE/Hashes/Viruslist.num','w').write(str(i))
                    os.remove('Library/PYAE/Hashes/'+str(y)+'.md5')
                    print('[INFO] Hashes Update Complete (V'+str(i-1)+')')
                    break
                else:
                    try:
                        with open('Library/PYAE/Hashes/'+str(y)+'.md5','r') as fi:
                            rfpl = fi.readlines()
                            with open('Library/PYAE/Hashes/Viruslist.md5','a') as vm:
                                for j in range(6,len(rfpl)):
                                    vm.write(str(rfpl[j])[:10]+'\n')
                        vm.close()
                        fi.close()
                    except:
                        pass
                    v = open('Library/PYAE/Hashes/Viruslist.num','w').write(str(i+1))
                    os.remove('Library/PYAE/Hashes/'+str(y)+'.md5')
            except:
                print('[INFO] Hashes Update Fail (V'+str(i-1)+')')
                break
    except Exception as e:
        pyas_bug_log(e)
        sys.exit()

###################################### 主要程式 #####################################

class MainWindow_Controller(QtWidgets.QMainWindow):#,FileSystemEventHandler):
    def __init__(self):
        start = time.time()
        super(MainWindow_Controller, self).__init__()
        self.ui = Ui_MainWindow() #繼承
        self.ui.pyas_opacity = 100
        self.setAttribute(Qt.WA_TranslucentBackground) #去掉邊框
        self.setWindowFlags(Qt.FramelessWindowHint) #取消使用Windows預設得窗口模式
        #self.setWindowFlags(Qt.WindowStaysOnTopHint|self.windowFlags()) #窗口置頂
        self.ui.setupUi(self)
        self.setup_control()
        print('[LOAD] GUI: '+str(time.time()-start)+' sec')
        
    def resizeEvent(self, event):
        width, height = event.size().width(), event.size().height()
        print('[INFO] '+str(event.size()))
    
    def setup_control(self):
        # TODO
        self.init()#調用本地函數"init"
        self.ui.Close_Button.clicked.connect(self.close)#讓物件名稱"Close_Button"連接到函數"close"
        self.ui.Minimize_Button.clicked.connect(self.showMinimized)
        self.ui.Menu_Button.clicked.connect(self.ShowMenu)
        self.ui.State_Button.clicked.connect(self.Change_to_State_widget)
        self.ui.Protection_Button.clicked.connect(self.Change_to_Rrotection_widget)
        #Virus_Scan
        self.ui.Virus_Scan_Button.clicked.connect(self.Change_to_Virus_Scan_widget)
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.Virus_Solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.Virus_Scan_Choose_Menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.Virus_Scan_Break)
        self.ui.File_Scan_Button.clicked.connect(self.File_Scan)#讓物件名稱"File_Scan_Button"連接到本地函數"File_Scan"
        self.ui.Path_Scan_Button.clicked.connect(self.Path_Scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.pyas_scan_disk_init_en)
        #More_Tools
        self.ui.Tools_Button.clicked.connect(self.Change_to_Tools_widget)
        self.ui.System_Tools_Button.clicked.connect(lambda:self.Change_Tools(self.ui.System_Tools_widget))
        self.ui.System_Tools_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.System_Tools_widget))
        self.ui.Privacy_Tools_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Privacy_Tools_widget))
        self.ui.Privacy_Tools_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Privacy_Tools_widget))
        self.ui.Develop_Tools_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Develop_Tools_widget))
        self.ui.Develop_Tools_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Develop_Tools_widget))
        self.ui.More_Tools_Button.clicked.connect(lambda:self.Change_Tools(self.ui.More_Tools_widget))
        self.ui.More_Tools_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.More_Tools_widget))
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Process_widget))
        self.ui.Process_Tools_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Process_widget))
        self.ui.System_Info_Button.clicked.connect(lambda:self.Change_Tools(self.ui.System_Info_widget))
        self.ui.System_Info_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.System_Info_widget))
        self.ui.Customize_CMD_Command_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Customize_CMD_Command_widget))
        self.ui.Customize_CMD_Command_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Customize_CMD_Command_widget))
        self.ui.Analyze_EXE_hash_Button.clicked.connect(lambda:self.Analyze_EXE(self.ui.Analyze_EXE_hash_Button))
        self.ui.Analyze_EXE_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Analyze_EXE_widget))
        self.ui.Analyze_EXE_Bit_Button.clicked.connect(lambda:self.Analyze_EXE(self.ui.Analyze_EXE_Bit_Button))
        self.ui.Analyze_EXE_Funtion_Button.clicked.connect(lambda:self.Analyze_EXE(self.ui.Analyze_EXE_Funtion_Button))
        self.ui.Look_for_File_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Look_for_File_widget))
        self.ui.Look_for_File_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Look_for_File_widget))
        self.ui.Encryption_Text_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Encryption_Text_widget))
        self.ui.Encryption_Text_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Encryption_Text_widget))
        self.ui.Customize_REG_Command_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Customize_REG_Command_widget))
        self.ui.Customize_REG_Command_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Customize_REG_Command_widget))
        self.ui.Change_Users_Password_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Change_Users_Password_widget))
        self.ui.Change_Users_Password_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Change_Users_Password_widget))

        self.ui.About_Back.clicked.connect(self.ui.About_widget.hide)
        self.ui.Setting_Back.clicked.connect(self.Setting_Back)
        
        self.ui.Repair_System_Permission_Button.clicked.connect(self.Repair_System_Permission)
        self.ui.Repair_System_Files_Button.clicked.connect(self.Repair_System_Files)
        self.ui.Clean_System_Files_Button.clicked.connect(self.Clean_System_Files)
        self.ui.Enable_Safe_Mode_Button.clicked.connect(self.Enable_Safe_Mode)
        self.ui.Disable_Safe_Mode_Button.clicked.connect(self.Disable_Safe_Mode)
        self.ui.Delete_Private_File_Button.clicked.connect(self.Delete_Private_File)
        self.ui.Customize_CMD_Command_Run_Button.clicked.connect(self.Customize_CMD_Command)
        self.ui.Look_for_File_Run_Button.clicked.connect(self.Look_for_File)
        self.ui.Encryption_Text_Run_Button.clicked.connect(self.Encryption_Text)
        self.ui.Decrypt_Text_Run_Button.clicked.connect(self.Decrypt_Text)
        self.ui.Change_Users_Password_Run_Button.clicked.connect(self.Change_Users_Password)
        self.ui.Internet_location_Query_Button.clicked.connect(self.Internet_location_Query)
        self.ui.Rework_Network_Configuration_Button.clicked.connect(self.reset_network)
        self.ui.Customize_REG_Command_Run_Button.clicked.connect(self.Customize_REG_Command)

        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.Process_list_Menu)
        #Protection
        self.ui.Protection_switch_Button.clicked.connect(self.protect_threading_init_zh)
        #Setting
        self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.clicked.connect(self.Show_Virus_Scan_Progress_Bar_switch)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.Change_language)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.Change_language)
        self.ui.Languahe_English.clicked.connect(self.Change_language)
        self.ui.Theme_White.clicked.connect(self.Change_Theme)
        self.ui.Theme_Black.clicked.connect(self.Change_Theme)
        self.ui.Theme_Green.clicked.connect(self.Change_Theme)
        self.ui.Theme_Pink.clicked.connect(self.Change_Theme)
        self.ui.Theme_Blue.clicked.connect(self.Change_Theme)
        self.ui.Theme_Red.clicked.connect(self.Change_Theme)

##################################### 視窗初始化 ####################################
    
    def init(self):
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()
        self.Process_sim = QStringListModel()
        self.Process_quantity = []
        self.Virus_Scan = 0
        self.Safe = True
        self.Process_Timer=QTimer()
        self.Process_Timer.timeout.connect(self.Process_list)
        self.pause = False
        self.ini_config = configparser.RawConfigParser()
        try:
            self.ini_config.read(r"Library/PYAS/Setup/PYAS.ini")
        except:
            try:
                with open(r"Library/PYAS/Setup/PYAS.ini",mode="w",encoding="utf-8") as file:
                    file.write("[Setting]\nhigh_sensitivity = 0\nlanguage = english")
                file.close()
            except Exception as e:
                pyas_bug_log(e)
        try:
            if self.ini_config.get("Setting","language") == "zh_TW":
                self.language = "zh_TW"
                self.lang_init_zh_tw()
                self.ui.Language_Traditional_Chinese.setChecked(True)
            elif self.ini_config.get("Setting","language") == "zh_CN":
                self.language = "zh_CN"
                self.lang_init_zh_cn()
                self.ui.Language_Simplified_Chinese.setChecked(True)
            else:
                self.language = "english"
                self.lang_init_en()
                self.ui.Languahe_English.setChecked(True)
        except Exception as e:
            pyas_bug_log(e)
            try:
                with open(r"Library/PYAS/Setup/PYAS.ini",mode="w",encoding="utf-8") as file:
                    file.write("[Setting]\nhigh_sensitivity = 0\nlanguage = english")
                file.close()
            except Exception as e:
                pyas_bug_log(e)
            self.language = "english"
            self.lang_init_en()
            self.ui.Languahe_English.setChecked(True)
        try:
            if self.ini_config.getint("Setting","high_sensitivity") == 1:
                if self.ini_config.get("Setting","language") == "zh_TW":
                    self.show_virus_scan_progress_bar = 1
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已開啟"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,200,20,100);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,200,20,120);}""")
                else:
                    self.show_virus_scan_progress_bar = 1
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已开启"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,200,20,100);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,200,20,120);}""")
            else:
                self.show_virus_scan_progress_bar = 0
        except Exception as e:
            pyas_bug_log(e)
            self.show_virus_scan_progress_bar = 0

###################################### 許可條款 #####################################
    
        self.ui.License_terms.setText('''PYAS Python Antivirus Software Security License Terms V2.0
=====================================================
#Use of PYAS antivirus software and services means that you accept these terms, if you do not accept, please do not use PYAS services.
=====================================================
1. Copyright notice
You can use this software for free, or use the open source code of this software for research, but imitation and sales of this software are strictly prohibited.
=====================================================
2. Legal Requirements
Please abide by the current regional laws and regulations, it is strictly prohibited to use PYAS to do illegal things.
=====================================================
3. User privacy protection
PYAS does not collect any personal privacy data, except for the email address required to fill in the feedback.
=====================================================
4. Permission is required to use PYAS
System Administrator, File management, And command execution rights.
=====================================================
5. Get genuine PYAS
If you do not download from the official website, we cannot guarantee the security of your data, and we are not responsible for any loss caused.''')
        self.effect_shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        self.effect_shadow.setOffset(0,0) # 偏移
        self.effect_shadow.setBlurRadius(10) # 阴影半径
        self.effect_shadow.setColor(QtCore.Qt.gray) # 阴影颜色
        self.ui.widget_2.setGraphicsEffect(self.effect_shadow) # 将设置套用到widget窗口中
        self.effect_shadow2 = QtWidgets.QGraphicsDropShadowEffect(self)
        self.effect_shadow2.setOffset(0,0)
        self.effect_shadow2.setBlurRadius(10)
        self.effect_shadow2.setColor(QtCore.Qt.gray) 
        self.ui.Navigation_Bar.setGraphicsEffect(self.effect_shadow2)
        self.effect_shadow3 = QtWidgets.QGraphicsDropShadowEffect(self)
        self.effect_shadow3.setOffset(0,0)
        self.effect_shadow3.setBlurRadius(7)
        self.effect_shadow3.setColor(QtCore.Qt.gray) 
        self.ui.Window_widget.setGraphicsEffect(self.effect_shadow3)


        self.ui.Virus_Scan_choose_widget.hide()#hide()函數的用意是隱藏物件
        self.ui.Virus_Scan_widget.hide()
        self.ui.Tools_widget.hide()
        self.ui.Protection_widget.hide()
        self.ui.System_Tools_widget.hide()
        self.ui.Privacy_Tools_widget.hide()
        self.ui.Develop_Tools_widget.hide()
        self.ui.More_Tools_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_ProgressBar.hide()
        self.ui.Process_widget.hide()
        self.ui.System_Info_widget.hide()
        self.ui.Customize_CMD_Command_widget.hide()
        self.ui.Analyze_EXE_widget.hide()
        self.ui.Look_for_File_widget.hide()
        self.ui.Encryption_Text_widget.hide()
        self.ui.About_widget.hide()
        self.ui.Change_Users_Password_widget.hide()
        self.ui.Customize_REG_Command_widget.hide()
        self.ui.Setting_widget.hide()
        
#################################### 檔案行為防護 ####################################
    
    def on_created(self, event): #不穩定(已停用)
        print("File Create: "+str(event.src_path))
        with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
            rfp = fp.read()
        if self.pyas_scan_start(event.src_path, rfp):
            try:
                os.remove(str(event.src_path))
                #self.ui.State_output.clear()
                #self.ui.State_output.append(self.text_Translate('{} > [行為防護] 成功攔截了惡意檔案創建行為。').format(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))))
            except Exception as e:
                pyas_bug_log(e)
                pass
        rfp = ""
        fp.close()

    #def on_deleted(self, event):
        #print("檔案被刪除: "+str(event.src_path))

    #def on_modified(self, event):
        #print("檔案被編輯: "+str(event.src_path))

##################################### 英文初始化 ####################################
    
    def lang_init_en(self):
        start = time.time()
        _translate = QtCore.QCoreApplication.translate
        if pyas_key():
            self.ui.State_output.clear()
            self.ui.Window_title.setText(_translate("MainWindow", "PYAS V"+pyas_version))
            now_time = datetime.datetime.now()
            try:
                ft = open('Library/PYAS/Temp/PYASP.tmp','r',encoding='utf-8')
                fe = ft.read()
                ft.close()
            except:
                self.ui.State_output.clear()
                self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + ' > [Tips] Real-time Protect is not enabled')
        else:
            self.ui.Window_title.setText(_translate("MainWindow", "PYAS V"+pyas_version+" (Security Key Error)"))
            now_time = datetime.datetime.now()
            self.ui.State_output.clear()
            self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + ' > [Warning] PYAS Security Key Error')
        self.ui.State_Button.setText(_translate("MainWindow", "State"))
        self.ui.Virus_Scan_Button.setText(_translate("MainWindow", "Scan"))
        self.ui.Tools_Button.setText(_translate("MainWindow", "Tools"))
        self.ui.Protection_Button.setText(_translate("MainWindow", "Protect"))
        self.ui.Virus_Scan_title.setText(_translate("MainWindow", "Virus Scan"))
        self.ui.Virus_Scan_text.setText(_translate("MainWindow", "Please select a scan method"))
        self.ui.Virus_Scan_choose_Button.setText(_translate("MainWindow", "Virus Scan"))
        self.ui.File_Scan_Button.setText(_translate("MainWindow", "File Scan"))
        self.ui.Path_Scan_Button.setText(_translate("MainWindow", "Path Scan"))
        self.ui.Disk_Scan_Button.setText(_translate("MainWindow", "Full Scan"))
        self.ui.Virus_Scan_Solve_Button.setText(_translate("MainWindow", "Solve Now"))
        self.ui.Virus_Scan_Break_Button.setText(_translate("MainWindow", "Stop Scan"))
        self.ui.Protection_title.setText(_translate("MainWindow", "Real-time protection"))
        self.ui.Protection_illustrate.setText(_translate("MainWindow", "Enable this option to monitor and remove malware in the system in real time."))
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已開啟"):
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "On"))
        elif self.ui.Protection_switch_Button.text() == self.text_Translate("已开启"):
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "On"))
        else:
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "Off"))
        if self.Safe:
            self.ui.State_title.setText(_translate("MainWindow", "This device has been protected"))
        else:
            self.ui.State_title.setText(_translate("MainWindow", "This device is currently unsafe"))
        self.ui.State_log.setText(_translate("MainWindow", "Log:"))
        self.ui.System_Tools_Button.setText(_translate("MainWindow", "System Tools"))
        self.ui.Privacy_Tools_Button.setText(_translate("MainWindow", "Privacy Tools"))
        self.ui.Develop_Tools_Button.setText(_translate("MainWindow", "Devs Tools"))
        self.ui.More_Tools_Button.setText(_translate("MainWindow", "More Tools"))
        self.ui.More_Tools_Back_Button.setText(_translate("MainWindow", "Tools>"))
        self.ui.System_Process_Manage_Button.setText(_translate("MainWindow", "Process Manager"))
        self.ui.Repair_System_Permission_Button.setText(_translate("MainWindow", "Repair Permission"))
        self.ui.Repair_System_Files_Button.setText(_translate("MainWindow", "Repair System Files"))
        self.ui.Clean_System_Files_Button.setText(_translate("MainWindow", "Clean System Files"))
        self.ui.Enable_Safe_Mode_Button.setText(_translate("MainWindow", "Enable Safe Mode"))
        self.ui.Disable_Safe_Mode_Button.setText(_translate("MainWindow", "Disable Safe Mode"))
        self.ui.System_Info_Button.setText(_translate("MainWindow", "System Information"))
        self.ui.System_Tools_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Privacy_Tools_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Delete_Private_File_Button.setText(_translate("MainWindow", "Delete Private File"))
        self.ui.Develop_Tools_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Customize_REG_Command_Button.setText(_translate("MainWindow", "Customize REG"))
        self.ui.Customize_CMD_Command_Button.setText(_translate("MainWindow", "Customize CMD"))
        self.ui.Analyze_EXE_hash_Button.setText(_translate("MainWindow", "Analyze File Hash"))
        self.ui.Analyze_EXE_Bit_Button.setText(_translate("MainWindow", "Analyze File Bits"))
        self.ui.Analyze_EXE_Funtion_Button.setText(_translate("MainWindow", "Analyze File Func"))
        self.ui.More_Tools_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Look_for_File_Button.setText(_translate("MainWindow", "Looking For Profiles"))
        self.ui.Encryption_Text_Button.setText(_translate("MainWindow", "Encrypt Decrypt Text"))
        self.ui.Change_Users_Password_Button.setText(_translate("MainWindow", "Change User Password"))
        self.ui.Internet_location_Query_Button.setText(_translate("MainWindow", "Internet Location Query"))
        self.ui.Rework_Network_Configuration_Button.setText(_translate("MainWindow", "Rework Network Config"))
        self.ui.Process_Tools_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Process_Total_title.setText(_translate("MainWindow", "Total process:"))
        self.ui.System_Info_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Customize_CMD_Command_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Customize_CMD_Command_Run_Button.setText(_translate("MainWindow", "Run"))
        self.ui.Customize_CMD_Command_output_title.setText(_translate("MainWindow", "Output:"))
        self.ui.Analyze_EXE_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Look_for_File_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Look_for_File_Run_Button.setText(_translate("MainWindow", "Find file"))
        self.ui.Encryption_Text_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Encryption_Text_Run_Button.setText(_translate("MainWindow", "Encrypt"))
        self.ui.Encryption_Text_title2.setText(_translate("MainWindow", "After Encrypt & Decrypt"))
        self.ui.Encryption_Text_Password_title.setText(_translate("MainWindow", "Password:"))
        self.ui.Encryption_Text_title.setText(_translate("MainWindow", "Before Encrypt & Decrypt"))
        self.ui.Decrypt_Text_Run_Button.setText(_translate("MainWindow", "Decrypt"))
        self.ui.About_Back.setText(_translate("MainWindow", "Back"))
        self.ui.PYAS_Version.setText(_translate("MainWindow", "PYAS V"+pyas_version))
        self.ui.GUI_Made_title.setText(_translate("MainWindow", "GUI Make:"))
        self.ui.GUI_Made_Name.setText(_translate("MainWindow", "mtkiao129"))
        self.ui.Core_Made_title.setText(_translate("MainWindow", "Core Make:"))
        self.ui.Core_Made_Name.setText(_translate("MainWindow", "87owo"))
        self.ui.Testers_title.setText(_translate("MainWindow", "Data Make:"))
        self.ui.Testers_Name.setText(_translate("MainWindow", "yang5487"))
        self.ui.PYAS_URL_title.setText(_translate("MainWindow", "Website:"))
        self.ui.PYAS_URL.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://pyantivirus.wixsite.com/pyas?lang=en\"><span style= \" text-decoration: underline; color:#0000ff;\">https://pyantivirus.wixsite.com/pyas</span></a></p></body></html>"))
        cy = datetime.datetime.now().strftime('%Y')
        if int(cy) < 2020:
            cy = str('2020')
        self.ui.PYAS_CopyRight.setText(_translate("MainWindow", "Copyright© 2020-"+str(cy)+" PYAS Security"))
        try:
            vl = open('Library/PYAE/Hashes/Viruslist.num','r').read()
            if int(vl)-1 < 0:
                self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (Downloading Library...)"))
            else:
                self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (Library Version: "+str(int(vl)-1)+")"))
        except:
            self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (Downloading Library...)"))
        self.ui.Change_Users_Password_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Change_Users_Password_New_Password_title.setText(_translate("MainWindow", "New password:"))
        self.ui.Change_Users_Password_User_Name_title.setText(_translate("MainWindow", "Username:"))
        self.ui.Change_Users_Password_Run_Button.setText(_translate("MainWindow", "Modify"))
        self.ui.Customize_REG_Command_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Value_Path_title.setText(_translate("MainWindow", "Value Path:"))
        self.ui.Value_Name_title.setText(_translate("MainWindow", "Value Name:"))
        self.ui.Value_Type_title.setText(_translate("MainWindow", "Value Type:"))
        self.ui.Value_Data_title.setText(_translate("MainWindow", "Value Data:"))
        self.ui.Customize_REG_Command_Run_Button.setText(_translate("MainWindow", "OK"))
        self.ui.Value_HEKY_title.setText(_translate("MainWindow", "Value HEKY:"))
        self.ui.Show_Virus_Scan_Progress_Bar_title.setText(_translate("MainWindow", "High Sensitivity Mode"))
        self.ui.Show_Virus_Scan_Progress_Bar_illustrate.setText(_translate("MainWindow", "Enable this option can improve scanning sensitivity, but it can also cause manslaughter."))
        if self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已開啟"):
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "On"))
        elif self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已开启"):
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "On"))
        else:
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "Off"))
        self.ui.Setting_Back.setText(_translate("MainWindow", "Back"))
        self.ui.Language_title.setText(_translate("MainWindow", "Language"))
        self.ui.Language_illustrate.setText(_translate("MainWindow", "Please select language"))
        self.ui.License_terms_title.setText(_translate("MainWindow", "License Terms:"))
        self.ui.Theme_title.setText(_translate("MainWindow", "Color Rendering Theme"))
        self.ui.Theme_illustrate.setText(_translate("MainWindow", "Please select a theme"))
        self.ui.Theme_White.setText(_translate("MainWindow", "White"))
        self.ui.Theme_Black.setText(_translate("MainWindow", "Black"))
        self.ui.Theme_Pink.setText(_translate("MainWindow", "Random"))
        self.ui.Theme_Red.setText(_translate("MainWindow", "Red"))
        self.ui.Theme_Green.setText(_translate("MainWindow", "Green"))
        self.ui.Theme_Blue.setText(_translate("MainWindow", "Blue"))
        print('[LOAD] Lang: '+str(time.time()-start)+' sec')

##################################### 簡中初始化 ####################################
    
    def lang_init_zh_cn(self):
        start = time.time()
        _translate = QtCore.QCoreApplication.translate
        if pyas_key():
            self.ui.State_output.clear()
            self.ui.Window_title.setText(_translate("MainWindow", "PYAS V"+pyas_version))
            now_time = datetime.datetime.now()
            try:
                ft = open('Library/PYAS/Temp/PYASP.tmp','r',encoding='utf-8')
                fe = ft.read()
                ft.close()
            except:
                self.ui.State_output.clear()
                self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + ' > [提示] 尚未启用实时防护')
        else:
            self.ui.Window_title.setText(_translate("MainWindow", "PYAS V"+pyas_version+" (安全密钥错误)"))
            now_time = datetime.datetime.now()
            self.ui.State_output.clear()
            self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + ' > [警告] PYAS 安全密钥错误')
        self.ui.State_Button.setText(_translate("MainWindow", "状态"))
        self.ui.Virus_Scan_Button.setText(_translate("MainWindow", "扫描"))
        self.ui.Tools_Button.setText(_translate("MainWindow", "工具"))
        self.ui.Protection_Button.setText(_translate("MainWindow", "防护"))
        self.ui.Virus_Scan_title.setText(_translate("MainWindow", "病毒扫描"))
        self.ui.Virus_Scan_text.setText(_translate("MainWindow", "请选择扫描方式"))
        self.ui.Virus_Scan_choose_Button.setText(_translate("MainWindow", "病毒扫描"))
        self.ui.File_Scan_Button.setText(_translate("MainWindow", "档案扫描"))
        self.ui.Path_Scan_Button.setText(_translate("MainWindow", "路径扫描"))
        self.ui.Disk_Scan_Button.setText(_translate("MainWindow", "全盘扫描"))
        self.ui.Virus_Scan_Solve_Button.setText(_translate("MainWindow", "立即解决"))
        self.ui.Virus_Scan_Break_Button.setText(_translate("MainWindow", "停止扫描"))
        self.ui.Protection_title.setText(_translate("MainWindow", "实时防护"))
        self.ui.Protection_illustrate.setText(_translate("MainWindow", "启用该选项可以实时监控进程中的恶意软体并清除。"))
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已開啟"):
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "已开启"))
        elif self.ui.Protection_switch_Button.text() == self.text_Translate("已开启"):
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "已开启"))
        else:
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "已关闭"))
        if self.Safe:
            self.ui.State_title.setText(_translate("MainWindow", "这部装置已受到保护"))
        else:
            self.ui.State_title.setText(_translate("MainWindow", "这部装置目前不安全"))
        self.ui.State_log.setText(_translate("MainWindow", "日志:"))
        self.ui.System_Tools_Button.setText(_translate("MainWindow", "系统工具"))
        self.ui.Privacy_Tools_Button.setText(_translate("MainWindow", "隐私工具"))
        self.ui.Develop_Tools_Button.setText(_translate("MainWindow", "开发工具"))
        self.ui.More_Tools_Button.setText(_translate("MainWindow", "更多工具"))
        self.ui.More_Tools_Back_Button.setText(_translate("MainWindow", "工具>"))
        self.ui.System_Process_Manage_Button.setText(_translate("MainWindow", "系统进程管理"))
        self.ui.Repair_System_Permission_Button.setText(_translate("MainWindow", "修复系统权限"))
        self.ui.Repair_System_Files_Button.setText(_translate("MainWindow", "修复系统档案"))
        self.ui.Clean_System_Files_Button.setText(_translate("MainWindow", "清理系统档案"))
        self.ui.Enable_Safe_Mode_Button.setText(_translate("MainWindow", "启动安全模式"))
        self.ui.Disable_Safe_Mode_Button.setText(_translate("MainWindow", "关闭安全模式"))
        self.ui.System_Info_Button.setText(_translate("MainWindow", "系统版本资讯"))
        self.ui.System_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Privacy_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Delete_Private_File_Button.setText(_translate("MainWindow", "删除隐私档案"))
        self.ui.Develop_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Customize_REG_Command_Button.setText(_translate("MainWindow", "自订REG指令"))
        self.ui.Customize_CMD_Command_Button.setText(_translate("MainWindow", "自订CMD指令"))
        self.ui.Analyze_EXE_hash_Button.setText(_translate("MainWindow", "分析文件哈希"))
        self.ui.Analyze_EXE_Bit_Button.setText(_translate("MainWindow", "分析文件位元"))
        self.ui.Analyze_EXE_Funtion_Button.setText(_translate("MainWindow", "分析文件函数"))
        self.ui.More_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Look_for_File_Button.setText(_translate("MainWindow", "寻找本机档案"))
        self.ui.Encryption_Text_Button.setText(_translate("MainWindow", "加密解密文字"))
        self.ui.Change_Users_Password_Button.setText(_translate("MainWindow", "变更用户密码"))
        self.ui.Internet_location_Query_Button.setText(_translate("MainWindow", "网路位置查询"))
        self.ui.Rework_Network_Configuration_Button.setText(_translate("MainWindow", "重置网路配置"))
        self.ui.Process_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Process_Total_title.setText(_translate("MainWindow", "进程总数:"))
        self.ui.System_Info_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Customize_CMD_Command_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Customize_CMD_Command_Run_Button.setText(_translate("MainWindow", "运行"))
        self.ui.Customize_CMD_Command_output_title.setText(_translate("MainWindow", "输出:"))
        self.ui.Analyze_EXE_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Look_for_File_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Look_for_File_Run_Button.setText(_translate("MainWindow", "寻找档案"))
        self.ui.Encryption_Text_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Encryption_Text_Run_Button.setText(_translate("MainWindow", "加密"))
        self.ui.Encryption_Text_title2.setText(_translate("MainWindow", "加密&解密后"))
        self.ui.Encryption_Text_Password_title.setText(_translate("MainWindow", "密码:"))
        self.ui.Encryption_Text_title.setText(_translate("MainWindow", "加密&解密前"))
        self.ui.Decrypt_Text_Run_Button.setText(_translate("MainWindow", "解密"))
        self.ui.About_Back.setText(_translate("MainWindow", "返回"))
        self.ui.PYAS_Version.setText(_translate("MainWindow", "PYAS V"+pyas_version))
        self.ui.GUI_Made_title.setText(_translate("MainWindow", "介面制作:"))
        self.ui.GUI_Made_Name.setText(_translate("MainWindow", "mtkiao129"))
        self.ui.Core_Made_title.setText(_translate("MainWindow", "核心制作:"))
        self.ui.Core_Made_Name.setText(_translate("MainWindow", "87owo"))
        self.ui.Testers_title.setText(_translate("MainWindow", "数据整理:"))
        self.ui.Testers_Name.setText(_translate("MainWindow", "yang5487"))
        self.ui.PYAS_URL_title.setText(_translate("MainWindow", "官方网站:"))
        self.ui.PYAS_URL.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://pyantivirus.wixsite.com/pyas\"><span style=\" text-decoration: underline; color:#0000ff;\">https://pyantivirus.wixsite.com/pyas</span></a></p></body></html>"))
        cy = datetime.datetime.now().strftime('%Y')
        if int(cy) < 2020:
            cy = str('2020')
        self.ui.PYAS_CopyRight.setText(_translate("MainWindow", "Copyright© 2020-"+str(cy)+" PYAS Security"))
        try:
            vl = open('Library/PYAE/Hashes/Viruslist.num','r').read()
            if int(vl)-1 < 0:
                self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (正在下载数据庫...)"))
            else:
                self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (数据庫版本: "+str(int(vl)-1)+")"))
        except:
            self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (正在下载数据庫...)"))
        self.ui.Change_Users_Password_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Change_Users_Password_New_Password_title.setText(_translate("MainWindow", "新密码:"))
        self.ui.Change_Users_Password_User_Name_title.setText(_translate("MainWindow", "用户名:"))
        self.ui.Change_Users_Password_Run_Button.setText(_translate("MainWindow", "修改"))
        self.ui.Customize_REG_Command_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Value_Path_title.setText(_translate("MainWindow", "值路径:"))
        self.ui.Value_Name_title.setText(_translate("MainWindow", "值名称:"))
        self.ui.Value_Type_title.setText(_translate("MainWindow", "值类型:"))
        self.ui.Value_Data_title.setText(_translate("MainWindow", "值资料:"))
        self.ui.Customize_REG_Command_Run_Button.setText(_translate("MainWindow", "确定"))
        self.ui.Value_HEKY_title.setText(_translate("MainWindow", "值HEKY:"))
        self.ui.Show_Virus_Scan_Progress_Bar_title.setText(_translate("MainWindow", "高灵敏度模式"))
        self.ui.Show_Virus_Scan_Progress_Bar_illustrate.setText(_translate("MainWindow", "启用该选项可以提高扫描灵敏度，但这也可能会造成误杀。"))
        if self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已開啟"):
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "已开启"))
        elif self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已开启"):
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "已开启"))
        else:
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "已关闭"))
        self.ui.Setting_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Language_title.setText(_translate("MainWindow", "语言"))
        self.ui.Language_illustrate.setText(_translate("MainWindow", "请选择语言"))
        self.ui.License_terms_title.setText(_translate("MainWindow", "许可条款:"))
        self.ui.Theme_title.setText(_translate("MainWindow", "显色主题"))
        self.ui.Theme_illustrate.setText(_translate("MainWindow", "请选择主题"))
        self.ui.Theme_White.setText(_translate("MainWindow", "白色主题"))
        self.ui.Theme_Black.setText(_translate("MainWindow", "黑色主题"))
        self.ui.Theme_Pink.setText(_translate("MainWindow", "随机主题"))
        self.ui.Theme_Red.setText(_translate("MainWindow", "红色主题"))
        self.ui.Theme_Green.setText(_translate("MainWindow", "绿色主题"))
        self.ui.Theme_Blue.setText(_translate("MainWindow", "蓝色主题"))
        print('[LOAD] Lang: '+str(time.time()-start)+' sec')

##################################### 繁中初始化 ####################################
    
    def lang_init_zh_tw(self):
        start = time.time()
        _translate = QtCore.QCoreApplication.translate
        if pyas_key():
            self.ui.State_output.clear()
            self.ui.Window_title.setText(_translate("MainWindow", "PYAS V"+pyas_version))
            now_time = datetime.datetime.now()
            try:
                ft = open('Library/PYAS/Temp/PYASP.tmp','r',encoding='utf-8')
                fe = ft.read()
                ft.close()
            except:
                self.ui.State_output.clear()
                self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + ' > [提示] 尚未啟用實時防護')
        else:
            self.ui.Window_title.setText(_translate("MainWindow", "PYAS V"+pyas_version+" (安全密鑰錯誤)"))
            now_time = datetime.datetime.now()
            self.ui.State_output.clear()
            self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + ' > [警告] PYAS 安全密鑰錯誤')
        self.ui.State_Button.setText(_translate("MainWindow", "狀態"))
        self.ui.Virus_Scan_Button.setText(_translate("MainWindow", "掃描"))
        self.ui.Tools_Button.setText(_translate("MainWindow", "工具"))
        self.ui.Protection_Button.setText(_translate("MainWindow", "防護"))
        self.ui.Virus_Scan_title.setText(_translate("MainWindow", "病毒掃描"))
        self.ui.Virus_Scan_text.setText(_translate("MainWindow", "請選擇掃描方式"))
        self.ui.Virus_Scan_choose_Button.setText(_translate("MainWindow", "病毒掃描"))
        self.ui.File_Scan_Button.setText(_translate("MainWindow", "檔案掃描"))
        self.ui.Path_Scan_Button.setText(_translate("MainWindow", "路徑掃描"))
        self.ui.Disk_Scan_Button.setText(_translate("MainWindow", "全盤掃描"))
        self.ui.Virus_Scan_Solve_Button.setText(_translate("MainWindow", "立即解決"))
        self.ui.Virus_Scan_Break_Button.setText(_translate("MainWindow", "停止掃描"))
        self.ui.Protection_title.setText(_translate("MainWindow", "實時防護"))
        self.ui.Protection_illustrate.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除。"))
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已開啟"):
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "已開啟"))
        elif self.ui.Protection_switch_Button.text() == self.text_Translate("已开启"):
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "已開啟"))
        else:
            self.ui.Protection_switch_Button.setText(_translate("MainWindow", "已關閉"))
        if self.Safe:
            self.ui.State_title.setText(_translate("MainWindow", "這部裝置已受到保護"))
        else:
            self.ui.State_title.setText(_translate("MainWindow", "這部裝置目前不安全"))
        self.ui.State_log.setText(_translate("MainWindow", "日誌:"))
        self.ui.System_Tools_Button.setText(_translate("MainWindow", "系統工具"))
        self.ui.Privacy_Tools_Button.setText(_translate("MainWindow", "隱私工具"))
        self.ui.Develop_Tools_Button.setText(_translate("MainWindow", "開發工具"))
        self.ui.More_Tools_Button.setText(_translate("MainWindow", "更多工具"))
        self.ui.More_Tools_Back_Button.setText(_translate("MainWindow", "工具>"))
        self.ui.System_Process_Manage_Button.setText(_translate("MainWindow", "系統進程管理"))
        self.ui.Repair_System_Permission_Button.setText(_translate("MainWindow", "修復系統權限"))
        self.ui.Repair_System_Files_Button.setText(_translate("MainWindow", "修復系統檔案"))
        self.ui.Clean_System_Files_Button.setText(_translate("MainWindow", "清理系統檔案"))
        self.ui.Enable_Safe_Mode_Button.setText(_translate("MainWindow", "啟動安全模式"))
        self.ui.Disable_Safe_Mode_Button.setText(_translate("MainWindow", "關閉安全模式"))
        self.ui.System_Info_Button.setText(_translate("MainWindow", "系統版本資訊"))
        self.ui.System_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Privacy_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Delete_Private_File_Button.setText(_translate("MainWindow", "刪除隱私檔案"))
        self.ui.Develop_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Customize_REG_Command_Button.setText(_translate("MainWindow", "自訂REG指令"))
        self.ui.Customize_CMD_Command_Button.setText(_translate("MainWindow", "自訂CMD指令"))
        self.ui.Analyze_EXE_hash_Button.setText(_translate("MainWindow", "分析文件哈希"))
        self.ui.Analyze_EXE_Bit_Button.setText(_translate("MainWindow", "分析文件位元"))
        self.ui.Analyze_EXE_Funtion_Button.setText(_translate("MainWindow", "分析文件函數"))
        self.ui.More_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Look_for_File_Button.setText(_translate("MainWindow", "尋找本機檔案"))
        self.ui.Encryption_Text_Button.setText(_translate("MainWindow", "加密解密文字"))
        self.ui.Change_Users_Password_Button.setText(_translate("MainWindow", "變更用戶密碼"))
        self.ui.Internet_location_Query_Button.setText(_translate("MainWindow", "網路位置查詢"))
        self.ui.Rework_Network_Configuration_Button.setText(_translate("MainWindow", "重置網路配置"))
        self.ui.Process_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Process_Total_title.setText(_translate("MainWindow", "進程總數:"))
        self.ui.System_Info_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Customize_CMD_Command_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Customize_CMD_Command_Run_Button.setText(_translate("MainWindow", "運行"))
        self.ui.Customize_CMD_Command_output_title.setText(_translate("MainWindow", "輸出:"))
        self.ui.Analyze_EXE_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Look_for_File_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Look_for_File_Run_Button.setText(_translate("MainWindow", "尋找檔案"))
        self.ui.Encryption_Text_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Encryption_Text_Run_Button.setText(_translate("MainWindow", "加密"))
        self.ui.Encryption_Text_title2.setText(_translate("MainWindow", "加密&解密後"))
        self.ui.Encryption_Text_Password_title.setText(_translate("MainWindow", "密碼:"))
        self.ui.Encryption_Text_title.setText(_translate("MainWindow", "加密&解密前"))
        self.ui.Decrypt_Text_Run_Button.setText(_translate("MainWindow", "解密"))
        self.ui.About_Back.setText(_translate("MainWindow", "返回"))
        self.ui.PYAS_Version.setText(_translate("MainWindow", "PYAS V"+pyas_version))
        self.ui.GUI_Made_title.setText(_translate("MainWindow", "介面製作:"))
        self.ui.GUI_Made_Name.setText(_translate("MainWindow", "mtkiao129"))
        self.ui.Core_Made_title.setText(_translate("MainWindow", "核心製作:"))
        self.ui.Core_Made_Name.setText(_translate("MainWindow", "87owo"))
        self.ui.Testers_title.setText(_translate("MainWindow", "數據整理:"))
        self.ui.Testers_Name.setText(_translate("MainWindow", "yang5487"))
        self.ui.PYAS_URL_title.setText(_translate("MainWindow", "官方網站:"))
        self.ui.PYAS_URL.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://pyantivirus.wixsite.com/pyas\"><span style=\" text-decoration: underline; color:#0000ff;\">https://pyantivirus.wixsite.com/pyas</span></a></p></body></html>"))
        cy = datetime.datetime.now().strftime('%Y')
        if int(cy) < 2020:
            cy = str('2020')
        self.ui.PYAS_CopyRight.setText(_translate("MainWindow", "Copyright© 2020-"+str(cy)+" PYAS Security"))
        try:
            vl = open('Library/PYAE/Hashes/Viruslist.num','r').read()
            if int(vl)-1 < 0:
                self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (正在下載資料庫...)"))
            else:
                self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (資料庫版本: "+str(int(vl)-1)+")"))
        except:
            self.ui.PYAE_Version.setText(_translate("MainWindow", "PYAE V"+pyae_version+" (正在下載資料庫...)"))
        self.ui.Change_Users_Password_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Change_Users_Password_New_Password_title.setText(_translate("MainWindow", "新密碼:"))
        self.ui.Change_Users_Password_User_Name_title.setText(_translate("MainWindow", "用戶名:"))
        self.ui.Change_Users_Password_Run_Button.setText(_translate("MainWindow", "修改"))
        self.ui.Customize_REG_Command_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Value_Path_title.setText(_translate("MainWindow", "值路徑:"))
        self.ui.Value_Name_title.setText(_translate("MainWindow", "值名稱:"))
        self.ui.Value_Type_title.setText(_translate("MainWindow", "值類型:"))
        self.ui.Value_Data_title.setText(_translate("MainWindow", "值資料:"))
        self.ui.Customize_REG_Command_Run_Button.setText(_translate("MainWindow", "確定"))
        self.ui.Value_HEKY_title.setText(_translate("MainWindow", "值HEKY:"))
        self.ui.Show_Virus_Scan_Progress_Bar_title.setText(_translate("MainWindow", "高靈敏度模式"))
        self.ui.Show_Virus_Scan_Progress_Bar_illustrate.setText(_translate("MainWindow", "啟用該選項可以提高掃描靈敏度，但這也可能會造成誤殺。"))
        if self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已開啟"):
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "已開啟"))
        elif self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已开启"):
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "已開啟"))
        else:
            self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(_translate("MainWindow", "已關閉"))
        self.ui.Setting_Back.setText(_translate("MainWindow", "返回"))
        self.ui.Language_title.setText(_translate("MainWindow", "語言"))
        self.ui.Language_illustrate.setText(_translate("MainWindow", "請選擇語言"))
        self.ui.License_terms_title.setText(_translate("MainWindow", "許可條款:"))
        self.ui.Theme_title.setText(_translate("MainWindow", "顯色主題"))
        self.ui.Theme_illustrate.setText(_translate("MainWindow", "請選擇主題"))
        self.ui.Theme_White.setText(_translate("MainWindow", "白色主題"))
        self.ui.Theme_Black.setText(_translate("MainWindow", "黑色主題"))
        self.ui.Theme_Pink.setText(_translate("MainWindow", "隨機主題"))
        self.ui.Theme_Red.setText(_translate("MainWindow", "紅色主題"))
        self.ui.Theme_Green.setText(_translate("MainWindow", "綠色主題"))
        self.ui.Theme_Blue.setText(_translate("MainWindow", "藍色主題"))
        print('[LOAD] Lang: '+str(time.time()-start)+' sec')

##################################### 繁簡中翻譯 ####################################
    
    def text_Translate(self,text):
        if self.language == "zh_CN":
            text = text.replace("嗎","吗")
            text = text.replace("項","项")
            text = text.replace("護","护")
            text = text.replace("攔","拦")
            text = text.replace("請","请")
            text = text.replace("後","后")
            text = text.replace("系統","系统")
            text = text.replace("錯誤","错误")
            text = text.replace("實時","实时")
            text = text.replace("發現","发现")
            text = text.replace("權限","权限")
            text = text.replace("軟體","软件")
            text = text.replace("惡意","恶意")
            text = text.replace("設定","设置")
            text = text.replace("關於","关于")
            text = text.replace("當前","当前")
            text = text.replace("確定","确定")
            text = text.replace("修復","修复")
            return text
        elif self.language == "english":
            translator = english_list[text]
            return translator
        else:
            return text

################################### 視窗動畫特效 ####################################
    
    def Change_animation(self,widget):
        x = 170
        y = widget.pos().y()#獲取物件的y軸座標
        self.anim = QPropertyAnimation(widget, b"geometry")#動畫
        widget.setGeometry(QtCore.QRect(x - 100,y, 671,481))#設定物件"widget"的座標大小
        self.anim.setKeyValueAt(0.2, QRect(x - 60,y,671,481))
        self.anim.setKeyValueAt(0.4, QRect(x - 10,y,671,481))
        self.anim.setKeyValueAt(0.7, QRect(x - 3,y,671,481))
        self.anim.setKeyValueAt(1, QRect(x,y,671,481))
        self.anim.start()#動畫開始

    def Change_animation_2(self,nx,ny):
        x = self.ui.label.pos().x()
        y = self.ui.label.pos().y()
        self.anim2 = QPropertyAnimation(self.ui.label, b"geometry")
        if y > ny:
            self.anim2.setKeyValueAt(0.4, QRect(nx,ny + 25, 5, 35))
            self.anim2.setKeyValueAt(0.5, QRect(nx,ny + 12, 5, 34))
            self.anim2.setKeyValueAt(0.7, QRect(nx,ny + 6, 5, 33))
            self.anim2.setKeyValueAt(0.8, QRect(nx,ny + 4, 5, 32))
            self.anim2.setKeyValueAt(0.9, QRect(nx,ny + 2, 5, 31))
            self.anim2.setKeyValueAt(1, QRect(nx,ny, 5, 30))
        else:
            self.anim2.setKeyValueAt(0.4, QRect(nx,ny - 25, 5, 35))
            self.anim2.setKeyValueAt(0.5, QRect(nx,ny - 12, 5, 34))
            self.anim2.setKeyValueAt(0.7, QRect(nx,ny - 6, 5, 33))
            self.anim2.setKeyValueAt(0.8, QRect(nx,ny - 4, 5, 32))
            self.anim2.setKeyValueAt(0.9, QRect(nx,ny - 2, 5, 31))
            self.anim2.setKeyValueAt(1, QRect(nx,ny, 5, 30))
        self.anim2.start()
    
    def Change_animation_3(self,widget,time):
        #這裡是設定透明度
        if self.Virus_Scan != 1:
            self.opacity = QtWidgets.QGraphicsOpacityEffect()
            self.opacity.setOpacity(0)
            widget.setGraphicsEffect(self.opacity)
            widget.setAutoFillBackground(True)
            self.draw(widget=widget,time=time)

    def Change_animation_4(self,widget,time,ny,ny2):
        x = widget.pos().x()
        y = widget.pos().y()
        self.anim4 = QPropertyAnimation(widget, b"geometry")
        self.anim4.setDuration(time)
        self.anim4.setStartValue(QRect(x, y, 141, ny))
        self.anim4.setEndValue(QRect(x, y, 141, ny2))
        self.anim4.start()

    def Change_animation5(self,widget,x1,y1,nx,ny):
        x = x1
        y = y1
        self.anim = QPropertyAnimation(widget, b"geometry")#動畫
        widget.setGeometry(QtCore.QRect(x,y - 45, nx,ny))#設定物件"widget"的座標大小
        self.anim.setKeyValueAt(0.2, QRect(x,y - 30,nx,ny))
        self.anim.setKeyValueAt(0.4, QRect(x,y - 10,nx,ny))
        self.anim.setKeyValueAt(0.7, QRect(x,y - 3,nx,ny))
        self.anim.setKeyValueAt(1, QRect(x,y,nx,ny))
        self.anim.start()#動畫開始


    def draw(self,widget,time):
        self.opacity.i = 1
        def timeout():
            self.opacity.setOpacity(self.opacity.i/100)
            widget.setGraphicsEffect(self.opacity)
            self.opacity.i += 1
            if self.opacity.i >= 100:
                self.timer.stop()
                self.timer.deleteLater()
        self.timer = QTimer()
        self.timer.setInterval(0)
        self.timer.timeout.connect(timeout)
        self.timer.start()

    def Change_to_State_widget(self):
        if self.ui.State_widget.isHidden():#isHidden()函數用意是偵測物件是否在隱藏狀態

            self.Change_animation_2(25,41)
            self.Change_animation_3(self.ui.State_widget,1)
            self.Change_animation(self.ui.State_widget)

            self.ui.State_widget.show()#show()函數用意是讓隱藏函數顯示出來
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.System_Tools_widget.hide()
            self.ui.Privacy_Tools_widget.hide()
            self.ui.Develop_Tools_widget.hide()
            self.ui.More_Tools_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.System_Info_widget.hide()
            self.ui.Customize_CMD_Command_widget.hide()
            self.ui.Analyze_EXE_widget.hide()
            self.ui.Look_for_File_widget.hide()
            self.ui.Encryption_Text_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Change_Users_Password_widget.hide()
            self.ui.Customize_REG_Command_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_to_Virus_Scan_widget(self):
        if self.ui.Virus_Scan_widget.isHidden():

            self.Change_animation_2(25,164)
            self.Change_animation_3(self.ui.Virus_Scan_widget,1)
            self.Change_animation(self.ui.Virus_Scan_widget)

            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.show()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.System_Tools_widget.hide()
            self.ui.Privacy_Tools_widget.hide()
            self.ui.Develop_Tools_widget.hide()
            self.ui.More_Tools_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.System_Info_widget.hide()
            self.ui.Customize_CMD_Command_widget.hide()
            self.ui.Analyze_EXE_widget.hide()
            self.ui.Look_for_File_widget.hide()
            self.ui.Encryption_Text_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Change_Users_Password_widget.hide()
            self.ui.Customize_REG_Command_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_to_Tools_widget(self):
        if self.ui.Tools_widget.isHidden():

            self.Change_animation_2(25,287)
            self.Change_animation_3(self.ui.Tools_widget,1)
            self.Change_animation(self.ui.Tools_widget)

            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.show()
            self.ui.Protection_widget.hide()
            self.ui.System_Tools_widget.hide()
            self.ui.Privacy_Tools_widget.hide()
            self.ui.Develop_Tools_widget.hide()
            self.ui.More_Tools_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.System_Info_widget.hide()
            self.ui.Customize_CMD_Command_widget.hide()
            self.ui.Analyze_EXE_widget.hide()
            self.ui.Look_for_File_widget.hide()
            self.ui.Encryption_Text_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Change_Users_Password_widget.hide()
            self.ui.Customize_REG_Command_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_to_Rrotection_widget(self):
        if self.ui.Protection_widget.isHidden():

            self.Change_animation_2(25,410)
            self.Change_animation_3(self.ui.Protection_widget,1)
            self.Change_animation(self.ui.Protection_widget)

            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.show()
            self.ui.System_Tools_widget.hide()
            self.ui.Privacy_Tools_widget.hide()
            self.ui.Develop_Tools_widget.hide()
            self.ui.More_Tools_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.System_Info_widget.hide()
            self.ui.Customize_CMD_Command_widget.hide()
            self.ui.Analyze_EXE_widget.hide()
            self.ui.Look_for_File_widget.hide()
            self.ui.Encryption_Text_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Change_Users_Password_widget.hide()
            self.ui.Customize_REG_Command_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_Tools(self,widget):
        self.ui.Tools_widget.hide()
        self.ui.System_Tools_widget.hide()
        self.ui.Develop_Tools_widget.hide()
        self.ui.Analyze_EXE_widget.hide()
        self.ui.More_Tools_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.start(200)
        elif widget == self.ui.System_Info_widget:
            self.System_Info_update()
        self.Change_animation_3(widget,1)
        self.Change_animation(widget)
        widget.show()

    def Back_To_More_Tools(self,widget):
        widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.stop()
        self.Change_animation_3(self.ui.Tools_widget,1)
        self.Change_animation(self.ui.Tools_widget)
        self.ui.Tools_widget.show()

##################################### 病毒掃描 #####################################
    
    def Virus_Scan_Break(self):
        self.Virus_Scan = 0

    def Virus_Solve(self):
        try:
            for line in self.Virus_List:
                if 'C:/Windows' in str(line):
                    pass
                else:
                    self.ui.Virus_Scan_text.setText(self.text_Translate('正在刪除: ')+str(line))
                    QApplication.processEvents()
                    try:
                        os.remove(str(line))
                    except Exception as e:
                        continue
            self.ui.Virus_Scan_text.setText(self.text_Translate('✔成功: 已執行成功。'))
            self.ui.Virus_Scan_Solve_Button.hide()
            self.ui.State_icon.setPixmap(QtGui.QPixmap(":/icon/Icon/check.png"))
            self.ui.State_title.setText(self.text_Translate("這部裝置已受到保護"))
            self.Safe = True
        except Exception as e:
            self.ui.Virus_Scan_text.setText(self.text_Translate("✖錯誤: 執行失敗。"))
            pyas_bug_log(e)
            self.Safe = False

    def list_allfile(self,path,all_files):  
        try:  
            if os.path.exists(path):
                files=os.listdir(path)
            else:
                print('[Error] This path is not exist')
            for file in files:
                if os.path.isdir(os.path.join(path,file)):
                    all_files.append(os.path.join(path,file))
                    self.list_allfile(os.path.join(path,file),all_files)
                else:
                    all_files.append(os.path.join(path,file))
            return all_files
        except Exception as e:
            pyas_bug_log(e)
            return 0

    def pyas_scan_start(self,file,rfp):
        try:
            with open(file,"rb") as f:
                bytes = f.read()
            f.close()
            QApplication.processEvents()
            readable_hash = str(md5(bytes).hexdigest())
            if readable_hash[:10] in str(rfp):
                return True
            else:
                return False
        except Exception as e:
            pyas_bug_log(e)
            return False
        
    #定義紀錄掃描
    def pyas_scan_write_en(self,file):
        try:
            if 'C:/Windows' in str(file):
                pass
            else:
                try:
                    ft = open('Library/PYAS/Temp/PYASV.tmp','a',encoding='utf-8')
                    self.Virus_List.append(file)
                    fe = ft.write(file+'\n')
                    ft.close()
                except:
                    pass
        except Exception as e:
            pyas_bug_log(e)
            pass

    #定義讀取紀錄
    def pyas_scan_read_en(self):
        try:
            ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
            ft.close()
            self.Virus_List_output.setStringList(self.Virus_List)
            self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
            now_time = datetime.datetime.now()
            self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + self.text_Translate(" > [病毒掃描] 掃描出") + str(len(self.Virus_List)) + self.text_Translate("個病毒"))
            self.ui.State_icon.setPixmap(QtGui.QPixmap(":/icon/Icon/X2.png"))
            self.ui.State_title.setText(self.text_Translate("這部裝置目前不安全"))
            self.ui.Virus_Scan_Solve_Button.show()
            self.ui.Virus_Scan_choose_Button.show()
            self.ui.Virus_Scan_Break_Button.hide()
            self.Virus_Scan = 0
            self.Safe = False
            print('[SCAN] Malware has been detected')
            return self.text_Translate("✖當前已發現惡意軟體共{}項。").format(len(self.Virus_List))
        except:
            self.ui.Virus_Scan_Break_Button.hide()
            self.ui.Virus_Scan_choose_Button.show()
            self.Virus_Scan = 0
            self.Safe = True
            print('[SCAN] No malware currently found')
            return self.text_Translate('✔當前未發現惡意軟體。')
        
    def pyas_scan_answer_en(self):
        self.ui.Virus_Scan_text.setText(self.pyas_scan_read_en())
        try:
            ft = open('Library/PYAS/Temp/PYASV.tmp','r',encoding='utf-8')
            self.lines = ft.readlines()
            ft.close()
        except:
            pass
        try:
            os.remove('Library/PYAS/Temp/PYASV.tmp')
        except:
            pass

    def pyas_scan_path_en(self,path,rfp,rfn,fts):
        try:
            for fd in os.listdir(path):
                try:
                    if self.Virus_Scan == 0:
                        self.ui.Virus_Scan_Break_Button.hide()
                        break
                    else:
                        fullpath = os.path.join(path,fd)
                        if 'C:/Windows' in str(fullpath) or 'C:/Program' in str(fullpath) or 'AppData' in str(fullpath):
                            pass
                        else:
                            if os.path.isdir(fullpath):
                                self.pyas_scan_path_en(fullpath,rfp,rfn,fts)
                            else:
                                scan_text = self.text_Translate('正在掃描: ')
                                try:
                                    self.ui.Virus_Scan_text.setText(scan_text + fullpath)
                                    QApplication.processEvents()
                                    if self.pyas_scan_start(fullpath,rfp):
                                        self.pyas_scan_write_en(fullpath)
                                    else:
                                        if self.show_virus_scan_progress_bar != 0:
                                            pe = PE(fullpath)
                                            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                                for function in entry.imports:
                                                    if fts != True:
                                                        if str(function.name.decode('utf-8')) in rfn:
                                                            fts = True
                                            if fts:
                                                self.pyas_scan_write_en(fullpath)
                                                fts = False
                                except:
                                    self.ui.Virus_Scan_text.setText(scan_text + fullpath)
                                    QApplication.processEvents()
                                    if self.pyas_scan_start(fullpath,rfp):
                                        self.pyas_scan_write_en(fullpath)
                except:
                    continue
        except Exception as e:
            pyas_bug_log(e)
            pass

##################################### 檔案掃描 #####################################
    
    def File_Scan(self):
        print('[SCAN] Start Scan Action (File Scan)')
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_ProgressBar.hide()
        self.Virus_List = []
        self.Virus_List_output=QStringListModel()
        self.Virus_List_output.setStringList(self.Virus_List)
        self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
        file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("病毒掃描"),"C:/",'')
        try:
            os.remove('Library/PYAS/Temp/PYASV.tmp')
        except:
            pass
        if file != "":
            try:
                self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中，請稍後..."))
                self.Virus_Scan = 1
                self.ui.Virus_Scan_choose_Button.hide()
                QApplication.processEvents()
                try:
                    print('[INFO] Reading Viruslist Database')
                    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
                        rfp = fp.read()
                    fp.close()
                    if self.show_virus_scan_progress_bar != 0 and os.path.isfile(filepath) == True:
                        with open('Library/PYAE/Function/Viruslist.func','r') as fn:
                            rfn = fn.read()
                        fn.close()
                except Exception as e:
                    pyas_bug_log(e)
                if self.pyas_scan_start(file,rfp):
                    self.pyas_scan_write_en(file)
                    self.ui.Virus_Scan_text.setText(self.text_Translate("✖當前已發現惡意軟體。"))
                else:
                    if self.show_virus_scan_progress_bar != 0:
                        fts = False
                        try:
                            pe = PE(file)
                            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                for function in entry.imports:
                                    if fts != True:
                                        if str(function.name.decode('utf-8')) in rfn:
                                            fts = True
                            if fts:
                                self.pyas_scan_write_en(file)
                                fts = False
                                print('[SCAN] Malware has been detected')
                                self.ui.Virus_Scan_text.setText(self.text_Translate("✖當前已發現惡意軟體。"))
                        except Exception as e:
                            pyas_bug_log(e)
                            self.ui.Virus_Scan_text.setText(self.text_Translate("✖掃描失敗。"))
                self.pyas_scan_answer_en()
            except Exception as e:
                pyas_bug_log(e)
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)
        else:
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))

##################################### 路徑掃描 #####################################
    
    def Path_Scan(self):
        print('[SCAN] Start Scan Action (Path Scan)')
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_ProgressBar.hide()
        self.ini_config = configparser.RawConfigParser()
        try:
            self.ini_config.read(r"Library/PYAS/Setup/PYAS.ini")
        except Exception as e:
            pyas_bug_log(e)
        self.Virus_List = []
        self.Virus_List_output=QStringListModel()
        self.Virus_List_output.setStringList(self.Virus_List)
        self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
        file = QFileDialog.getExistingDirectory(self,self.text_Translate("病毒掃描"),"C:/") 
        try:
            os.remove('Library/PYAS/Temp/PYASV.tmp')
        except:
            pass
        if file != "":
            try:
                self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中，請稍後..."))
                self.Virus_Scan = 1
                self.ui.Virus_Scan_choose_Button.hide()
                self.ui.Virus_Scan_Break_Button.show()
                QApplication.processEvents()
                try:
                    print('[INFO] Reading Viruslist Database')
                    with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
                        rfp = fp.read()
                    fp.close()
                    with open('Library/PYAE/Function/Viruslist.func','r') as fn:
                        rfn = fn.read()
                    fn.close()
                except Exception as e:
                    pyas_bug_log(e)
                self.pyas_scan_path_en(file,rfp,rfn,False)
                self.pyas_scan_answer_en()
            except Exception as e:
                pyas_bug_log(e)
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)
        else:
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))

##################################### 全盤掃描 #####################################
    
    def pyas_scan_disk_init_en(self):
        print('[SCAN] Start Scan Action (Disk Scan)')
        self.Virus_Scan = 1
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_ProgressBar.hide()
        self.ui.Virus_Scan_choose_Button.hide()
        self.ui.Virus_Scan_Break_Button.show()
        self.Virus_List = []
        self.Virus_List_output=QStringListModel()
        self.Virus_List_output.setStringList(self.Virus_List)
        self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
        self.scaning = self.text_Translate("正在掃描: ")
        try:
            os.remove('Library/PYAS/Temp/PYASV.tmp')
        except:
            pass
        try:
            self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中，請稍後..."))
            QApplication.processEvents()
            try:
                print('[INFO] Reading Viruslist Database')
                with open('Library/PYAE/Hashes/Viruslist.md5','r') as self.fp:
                    rfp = self.fp.read()
                self.fp.close()
            except Exception as e:
                pyas_bug_log(e)
            self.pyas_scan_disk_en('A:/',rfp)
            self.pyas_scan_disk_en('B:/',rfp)
            self.pyas_scan_disk_en('C:/',rfp)
            self.pyas_scan_disk_en('D:/',rfp)
            self.pyas_scan_disk_en('E:/',rfp)
            self.pyas_scan_disk_en('F:/',rfp)
            self.pyas_scan_disk_en('G:/',rfp)
            self.pyas_scan_disk_en('H:/',rfp)
            self.pyas_scan_disk_en('I:/',rfp)
            self.pyas_scan_disk_en('J:/',rfp)
            self.pyas_scan_disk_en('K:/',rfp)
            self.pyas_scan_disk_en('L:/',rfp)
            self.pyas_scan_disk_en('M:/',rfp)
            self.pyas_scan_disk_en('N:/',rfp)
            self.pyas_scan_disk_en('O:/',rfp)
            self.pyas_scan_disk_en('P:/',rfp)
            self.pyas_scan_disk_en('Q:/',rfp)
            self.pyas_scan_disk_en('R:/',rfp)
            self.pyas_scan_disk_en('S:/',rfp)
            self.pyas_scan_disk_en('T:/',rfp)
            self.pyas_scan_disk_en('U:/',rfp)
            self.pyas_scan_disk_en('V:/',rfp)
            self.pyas_scan_disk_en('W:/',rfp)
            self.pyas_scan_disk_en('X:/',rfp)
            self.pyas_scan_disk_en('Y:/',rfp)
            self.pyas_scan_disk_en('Z:/',rfp)
            self.pyas_scan_answer_en()
        except Exception as e:
            pyas_bug_log(e)
            QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)

    def pyas_scan_disk_en(self,path,rfp):
        try:
            for fd in os.listdir(path):
                try:
                    fullpath = os.path.join(path,fd)
                    if os.path.isdir(fullpath):
                        self.pyas_scan_disk_en(fullpath,rfp)
                    else:
                        if 'C:/Windows' in str(fullpath) or 'C:/Program' in str(fullpath) or 'AppData' in str(fullpath):
                            pass
                        else:
                            if self.Virus_Scan == 0:
                                self.ui.Virus_Scan_Break_Button.hide()
                                break
                            elif '.exe' in str(fd) or '.EXE' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.cmd' in str(fd) or '.CMD' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.bat' in str(fd) or '.BAT' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.com' in str(fd) or '.COM' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.vbs' in str(fd) or '.VBS' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.js' in str(fd) or '.JS' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.xls' in str(fd) or '.XLS' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.doc' in str(fd) or '.DOC' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.dll' in str(fd) or '.DLL' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            elif '.scr' in str(fd) or '.SCR' in str(fd):
                                self.ui.Virus_Scan_text.setText(self.scaning+fullpath)
                                QApplication.processEvents()
                                if self.pyas_scan_start(fullpath,rfp):
                                    self.pyas_scan_write_en(fullpath)
                            else:
                                pass
                except:
                    continue
        except:
            pass

    def Virus_Scan_Choose_Menu(self):
        if self.ui.Virus_Scan_choose_widget.isHidden():
            self.ui.Virus_Scan_choose_widget.show()
            self.Change_animation_4(self.ui.Virus_Scan_choose_widget,100,0,101)
        else:
            self.ui.Virus_Scan_choose_widget.hide()

##################################### 實用工具 #####################################

    def Repair_System_Permission(self):
        #QMessageBox跟tkinter.messagebox是差不多的東西 yes的回傳值為16384
        question = QMessageBox.warning(self,self.text_Translate('修復系統權限'),self.text_Translate("您確定要修復系統權限嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
        if question == 16384:
            Permission = ['NoControlPanel', 'NoDrives', 'NoControlPanel', 'NoFileMenu', 'NoFind', 'NoRealMode', 'NoRecentDocsMenu', \
            'NoSetFolders', 'NoSetFolderOptions', 'NoViewOnDrive', 'NoClose', 'NoRun', 'NoDesktop', 'NoLogOff', 'NoFolderOptions', \
            'NoViewContexMenu', 'HideClock', 'NoStartMenuMorePrograms', 'NoStartMenuMyGames', 'NoStartMenuMyMusic' 'NoStartMenuNetworkPlaces', \
            'NoStartMenuPinnedList', 'NoActiveDesktop', 'NoSetActiveDesktop', 'NoActiveDesktopChanges', 'NoChangeStartMenu', 'ClearRecentDocsOnExit', \
            'NoFavoritesMenu', 'NoRecentDocsHistory', 'NoSetTaskbar', 'NoSMHelp', 'NoTrayContextMenu', 'NoViewContextMenu', 'NoWindowsUpdate', \
            'NoWinKeys', 'StartMenuLogOff', 'NoSimpleNetlDList', 'NoLowDiskSpaceChecks', 'DisableLockWorkstation', 'NoManageMyComputerVerb', 'RestrictRun']
            try:
                import win32api,win32con
                try:
                    #開啟註冊表鍵
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    #創建鍵
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                for i in Permission:
                    try:
                        #刪除值
                        win32api.RegDeleteValue(key,i)
                    except Exception as e:
                        pyas_bug_log(e)
                        pass
                #關閉已打開的鍵
                win32api.RegCloseKey(key)
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'Explorer')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',0,win32con.KEY_ALL_ACCESS)
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)
                    except Exception as e:
                        pyas_bug_log(e)
                        pass
                win32api.RegCloseKey(key)

                Permission = ['DisableTaskMgr', 'DisableRegistryTools', 'DisableChangePassword', 'Wallpaper']
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)
                    except Exception as e:
                        pyas_bug_log(e)
                        pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',0,win32con.KEY_ALL_ACCESS)
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)
                    except Exception as e:
                        pyas_bug_log(e)
                        pass
                win32api.RegCloseKey(key)

                Permission = ['NoComponents', 'NoAddingComponents']
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'ActiveDesktop')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',0,win32con.KEY_ALL_ACCESS)
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)
                    except Exception as e:
                        pyas_bug_log(e)
                        pass
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except Exception as e:
                    pyas_bug_log(e)
                    pass                    
                win32api.RegCloseKey(key)
        

                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'System')
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Policies\Microsoft\Windows\System',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'DisableCMD')
                except Exception as e:
                    pyas_bug_log(e)
                    pass    
                win32api.RegCloseKey(key)


                try:
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                except Exception as e:
                    pyas_bug_log(e)
                    try:
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    except Exception as e:
                        pyas_bug_log(e)
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft',0,win32con.KEY_ALL_ACCESS)
                        win32api.RegCreateKey(key,'MMC')
                        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC',0,win32con.KEY_ALL_ACCESS)
                    win32api.RegCreateKey(key,'{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}')
                    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}',0,win32con.KEY_ALL_ACCESS)
                try:
                    win32api.RegDeleteValue(key, 'Restrict_Run')
                except Exception as e:
                    pyas_bug_log(e)
                    pass
                win32api.RegCloseKey(key)

                QMessageBox.information(self,self.text_Translate('完成'),self.text_Translate("修復完成!"),QMessageBox.Ok,QMessageBox.Ok)
            except Exception as e:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)

    def Repair_System_Files(self):
        question = QMessageBox.warning(self,self.text_Translate("修復系統檔案"),self.text_Translate("您確定要修復系統檔案嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
        if question == 16384:
            runc = os.system('start sfc /scannow')
            try:
                if runc == 0:
                    pass
                    #QMessageBox.information(self,self.text_Translate('完成'),self.text_Translate("修復完成"),QMessageBox.Ok)
                else:
                    QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate("修復失敗"),QMessageBox.Ok)
            except Exception as e:
                pyas_bug_log(e)

    def Clean_System_Files(self):
        question = QMessageBox.warning(self,self.text_Translate('清理系統檔案'),self.text_Translate("您確定要清理系統檔案嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
        if question == 16384:
            runc = os.system('start cleanmgr')
            try:
                if runc == 0:
                    pass
                    #QMessageBox.information(self,self.text_Translate('完成'),self.text_Translate("清理完成"),QMessageBox.Ok)
                else:
                    QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate("清理失敗"),QMessageBox.Ok)
            except Exception as e:
                pyas_bug_log(e)

    def Enable_Safe_Mode(self):
        question = QMessageBox.warning(self,self.text_Translate('啟用安全模式'),self.text_Translate("您確定啟用安全模式嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
        if question == 16384:
            runc = os.system('bcdedit /set {default} safeboot minimal')
            if runc == 0:
                question = QMessageBox.warning(self,'reboot',self.text_Translate("使用該選項後需要重啟，現在要重啟嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
                if question == 16384:
                    os.system('shutdown -r -t 0')
            else:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate("啟用失敗"),QMessageBox.Ok)  

    def Disable_Safe_Mode(self):
        question = QMessageBox.warning(self,self.text_Translate('禁用安全模式'),self.text_Translate("您確定禁用安全模式嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
        if question == 16384:
            runc = os.system('bcdedit /deletevalue {current} safeboot')
            if runc == 0:
                question = QMessageBox.warning(self,'reboot',self.text_Translate("使用該選項後需要重啟，現在要重啟嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
                if question == 16384:
                    os.system('shutdown -r -t 0')
            else:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate("禁用失敗"),QMessageBox.Ok)  

    def System_Info_update(self):
        import platform
        self.ui.System_Info_View.setText('System information:'+
                                         '\nCore version: '+str(platform.platform())+
                                         '\nMachine type: '+str(platform.machine())+
                                         '\nSystem Info: '+str(platform.architecture())+
                                         '\nComputer Name: '+str(platform.node())+
                                         '\nProcessor Name: '+str(platform.processor()))

    def Delete_Private_File(self):
        file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("刪除檔案"),"C:/",'')
        if file =="":
            pass
        elif "PYAS" in file:
            QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate('存取被拒'),QMessageBox.Ok)
            pass
        else:
            question = QMessageBox.warning(self,self.text_Translate('刪除檔案'),self.text_Translate("您確定刪除該檔案嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if question == 16384:
                try:
                    os.remove(file)
                    QMessageBox.information(self,self.text_Translate("刪除成功"),self.text_Translate("刪除成功"),QMessageBox.Ok)
                except Exception as e:
                    pyas_bug_log(e)
                    QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate("刪除失敗"),QMessageBox.Ok)
     
    def Customize_CMD_Command(self):
        CMD_Command = self.ui.Customize_CMD_Command_lineEdit.text()
        if CMD_Command == "":
            return
        if CMD_Command.lower() == "never gonna give you up" or CMD_Command.lower() == "rickroll" or CMD_Command.lower() == "rick roll":
            import webbrowser
            webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ")#rickroll easter egg
            return
        if CMD_Command == "python antivirus software" or CMD_Command == "Python Antivirus Software" \
        or CMD_Command == "PYAS" or CMD_Command == "pyas":
            self.ui.Customize_CMD_Command_output.setText(english_list["PYAS"])#about pyas
            return
        try: #Not Cplt
            if str(cryptocode.decrypt(CMD_Command,pyas_version)) == 'professional':
                self.ui.Window_title.setText("PYAS V"+pyas_version+' (Professional Edition)')
                return
            if str(cryptocode.decrypt(CMD_Command,pyas_version)) == 'business':
                self.ui.Window_title.setText("PYAS V"+pyas_version+' (Business Edition)')
                return
            if str(cryptocode.decrypt(CMD_Command,pyas_version)) == 'professional_ltsc':
                self.ui.Window_title.setText("PYAS V"+pyas_version+' (Professional Edition LTSC)')
                return
            if str(cryptocode.decrypt(CMD_Command,pyas_version)) == 'business_ltsc':
                self.ui.Window_title.setText("PYAS V"+pyas_version+' (Business Edition LTSC)')
                return
        except:
            pass
        try:
            if CMD_Command.split()[0].lower() == "/add" or CMD_Command.split()[0].lower() == "/a":
                self.ui.Customize_CMD_Command_output.setText("Tips: Custom rules need to wait for the rule conditions to be met before proceeding to the next step.")
                QApplication.processEvents()
                if CMD_Command.split()[1].lower() == "--library" or CMD_Command.split()[1].lower() == "-l":
                    if CMD_Command.split()[2].lower() == "--md5" or CMD_Command.split()[2].lower() == "-m":
                        try:
                            value = str(CMD_Command.split()[3])
                            with open('Library/PYAE/Hashes/Viruslist.md5','a') as vm:
                                vm.write(str(value)[:10]+'\n')
                            self.ui.Customize_CMD_Command_output.setText("Successfully added MD5 to the database!")
                        except:
                            self.ui.Customize_CMD_Command_output.setText("Error: Add MD5 database failed")
                        return
                    if CMD_Command.split()[2].lower() == "--func" or CMD_Command.split()[2].lower() == "-f":
                        try:
                            value = CMD_Command.split()[3]
                            with open('Library/PYAE/Function/Viruslist.func','a') as vm:
                                vm.write(str(value)+'\n')
                            self.ui.Customize_CMD_Command_output.setText("Successfully added Function to the database!")
                        except:
                            self.ui.Customize_CMD_Command_output.setText("Error: Add Function database failed")
                        return
                if CMD_Command.split()[1].lower() == "--rules" or CMD_Command.split()[1].lower() == "-r":
                    if CMD_Command.split()[2].lower() == "--reg" or CMD_Command.split()[2].lower() == "-r":
                        value = CMD_Command.split()[3]
                    if CMD_Command.split()[2].lower() == "--perf" or CMD_Command.split()[2].lower() == "-p":
                        value = CMD_Command.split()[3]
                        while 1:
                            QApplication.processEvents()
                            x = int(psutil.cpu_percent(interval=0.1))
                            if x > int(value):
                                print(str(x))
                    if CMD_Command.split()[2].lower() == "--file" or CMD_Command.split()[2].lower() == "-f":
                        value = CMD_Command.split()[3]
                    if CMD_Command.split()[2].lower() == "--task" or CMD_Command.split()[2].lower() == "-t":
                        value = CMD_Command.split()[3]
                        while 1:
                            QApplication.processEvents()
                            for p in psutil.process_iter():
                                if str(value) == str(p.name()):
                                    return
        except Exception as e:
            pyas_bug_log(e)
            QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+ '\"' + CMD_Command + '\"' + self.text_Translate("不是有效命令"),QMessageBox.Ok,QMessageBox.Ok)
            return
        if CMD_Command != '':
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                p = subprocess.Popen(CMD_Command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,)#encoding='utf-8')
                out = p.stdout.read()
                try:
                    self.ui.Customize_CMD_Command_output.setText(str(out.decode('utf-8')))
                except Exception as e:
                    pyas_bug_log(e)
                    self.ui.Customize_CMD_Command_output.setText(str(out))
                QMessageBox.information(self,self.text_Translate("完成"),self.text_Translate("運行成功"),QMessageBox.Ok,QMessageBox.Ok)
            except Exception as e:
                pyas_bug_log(e)
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+ '\"' + CMD_Command + '\"' + self.text_Translate("不是有效命令"),QMessageBox.Ok,QMessageBox.Ok)
        
    def Customize_REG_Command(self):
        import win32api,win32con
        continue_v = True
        Value_name = self.ui.Value_Name_input.text()
        Value_Path = self.ui.Value_Path_input.text()
        Value_Data = self.ui.Value_Data_input.text()
        Value_Type = self.ui.Value_Type_input.text()
        Value_HEKY = self.ui.Value_HEKY_input.text()
        if Value_HEKY == "HKEY_CLASSES_ROOT":
            Value_HEKY = win32con.HKEY_LOCAL_MACHINE
        elif Value_HEKY == "HKEY_CURRENT_USER":
            Value_HEKY = win32con.HKEY_CURRENT_USER
        elif Value_HEKY == "HKEY_LOCAL_MACHINE":
            Value_HEKY = win32con.HKEY_LOCAL_MACHINE
        elif Value_HEKY == "HKEY_USERS":
            Value_HEKY = win32con.HKEY_USERS
        elif Value_HEKY == "HKEY_CURRENT_CONFIG":
            Value_HEKY = win32con.HKEY_CURRENT_CONFIG
        else:
            QMessageBox.critical(self,self.text_Translate("錯誤"),self.text_Translate('錯誤: ')+self.text_Translate("您輸入了錯誤的HEKY"),QMessageBox.Ok)
            continue_v = False
        if continue_v:
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要新增值或是修改值嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                try:
                    key = win32api.RegOpenKey(Value_HEKY,Value_Path,0,win32con.KEY_ALL_ACCESS())
                    win32api.RegSetValueEx(key, Value_name,0,Value_Type,Value_Data)
                    QMessageBox.information(self,self.text_Translate("完成"),self.text_Translate("成功的創建或修改註冊表值"),QMessageBox.Ok)
                except Exception as e:
                    QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)

    def Analyze_EXE(self,button):
        if button == self.ui.Analyze_EXE_Funtion_Button:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("分析文件函數"),"C:/",'EXE OR DLL File *.exe *.dll')
            if file != '':
                pe = PE(file)
                self.ui.Analyze_EXE_Output.setText("")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for function in entry.imports:
                        try:
                            self.ui.Analyze_EXE_Output.append(str(function.name.decode('utf-8')))
                        except:
                            self.ui.Analyze_EXE_Output.append(str(function.name))
                self.Change_Tools(self.ui.Analyze_EXE_widget)
                QApplication.processEvents()
            else:
                pass
        elif button == self.ui.Analyze_EXE_hash_Button:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("分析文件哈希值"),"C:/",'All File *.*')
            if file != '':
                self.ui.Analyze_EXE_Output.setText("")
                with open(file,"rb") as f:
                    bytes = f.read()
                    readable_hash = str(md5(bytes).hexdigest())
                    readable_hash2 = str(sha1(bytes).hexdigest())
                    readable_hash3 = str(sha256(bytes).hexdigest())
                    self.ui.Analyze_EXE_Output.append('MD5: '+readable_hash+'\nSHA1: '+readable_hash2+'\nSHA256: '+readable_hash3)
                self.Change_Tools(self.ui.Analyze_EXE_widget)
                QApplication.processEvents()
                f.close()
            else:
                pass
        else:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("分析文件位元"),"C:/",'EXE OR DLL File *.exe *.dll')
            if file != '':
                pe = PE(file)
                self.ui.Analyze_EXE_Output.setText("")
                for section in pe.sections:
                    try:
                        self.ui.Analyze_EXE_Output.append(str(section.Name.decode('utf-8')) + str(hex(section.VirtualAddress)) + str(hex(section.Misc_VirtualSize)) + str(section.SizeOfRawData))
                    except:
                        self.ui.Analyze_EXE_Output.append(str(section.Name) + str(hex(section.VirtualAddress)) + str(hex(section.Misc_VirtualSize)) + str(section.SizeOfRawData))
                self.Change_Tools(self.ui.Analyze_EXE_widget)
                QApplication.processEvents()

    def Look_for_File(self):
        File_Name = self.ui.Look_for_File_input.text()
        if File_Name != "":
            self.find_files_info_zh(File_Name)
        else:
            QMessageBox.information(self,self.text_Translate("提示"),'['+self.text_Translate("提示")+'] '+self.text_Translate("請輸入需要尋找的檔案"),QMessageBox.Ok)


    def find_files_info_zh(self,ffile):
        try:
            start = time.time()
            self.findfile_zh('A:/',ffile,start)
            self.findfile_zh('B:/',ffile,start)
            self.findfile_zh('C:/',ffile,start)
            self.findfile_zh('D:/',ffile,start)
            self.findfile_zh('E:/',ffile,start)
            self.findfile_zh('F:/',ffile,start)
            self.findfile_zh('G:/',ffile,start)
            self.findfile_zh('H:/',ffile,start)
            self.findfile_zh('I:/',ffile,start)
            self.findfile_zh('J:/',ffile,start)
            self.findfile_zh('K:/',ffile,start)
            self.findfile_zh('L:/',ffile,start)
            self.findfile_zh('M:/',ffile,start)
            self.findfile_zh('N:/',ffile,start)
            self.findfile_zh('O:/',ffile,start)
            self.findfile_zh('P:/',ffile,start)
            self.findfile_zh('Q:/',ffile,start)
            self.findfile_zh('R:/',ffile,start)
            self.findfile_zh('S:/',ffile,start)
            self.findfile_zh('T:/',ffile,start)
            self.findfile_zh('U:/',ffile,start)
            self.findfile_zh('V:/',ffile,start)
            self.findfile_zh('W:/',ffile,start)
            self.findfile_zh('X:/',ffile,start)
            self.findfile_zh('Y:/',ffile,start)
            self.findfile_zh('Z:/',ffile,start)
            end = time.time()
            if os.path.isfile('Library/PYAS/Temp/PYASF.tmp'):
                try:
                    ft = open('Library/PYAS/Temp/PYASF.tmp','r',encoding="utf-8")
                    fe = ft.read()
                    ft.close()
                except Exception as e:
                    QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)
                self.ui.Look_for_File_output.setText("")
                self.ui.Look_for_File_output.append(self.text_Translate('尋找結果:')+'\n'+str(fe))
                QApplication.processEvents()
                self.Change_Tools(self.ui.Look_for_File_widget)
            else:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+self.text_Translate('未找到檔案'),QMessageBox.Ok)
        except Exception as e:
            pyas_bug_log(e)
            pass
        try:
            os.remove('Library/PYAS/Temp/PYASF.tmp')
        except Exception as e:
            pyas_bug_log(e)
            pass

    def findfile_zh(self,path,ffile,start):
        try:
            self.ui.Look_for_File_output.setText(self.text_Translate('正在尋找: ')+str(path))
            for fd in os.listdir(path):
                try:
                    QApplication.processEvents()
                    fullpath = os.path.join(path,fd)
                    if 'C:/Windows' in fullpath or 'AppData' in fullpath:
                        pass
                    else:
                        if os.path.isdir(fullpath):
                            self.findfile_zh(fullpath,ffile,start)
                        else:
                            if ffile in str(fd):
                                try:
                                    date = time.ctime(os.path.getmtime(fullpath))
                                    ft = open('Library/PYAS/Temp/PYASF.tmp','a',encoding="utf-8")
                                    ft.write(str(self.text_Translate('找到檔案:')+str(fullpath)+'\n'+self.text_Translate('創建日期:')+str(date)+'\n'+'\n'))
                                    ft.close()
                                except Exception as e:
                                    pyas_bug_log(e)
                except:
                    continue
        except Exception as e:
            pyas_bug_log(e)

    def Process_list(self):
        try:
            self.Process_list_app = []
            self.Process_list_app_exe = []
            self.Process_list_app_pid = []
            self.Process_list_app_name = []
            self.Process_list_app_user = []
            for p in psutil.process_iter():
                if p.name() == '' or p.name() == 'System' or p.name() == 'System Idle Process' or p.name() == 'Registry':
                    pass
                else:
                    try:
                        self.Process_list_app.append(p.name() +" ("+ str(p.pid) +") > "+ p.exe())
                        self.Process_list_app_pid.append(p.pid)
                        self.Process_list_app_exe.append(p.exe())
                        self.Process_list_app_name.append(p.name())
                        self.Process_list_app_user.append(p.username())
                    except:
                        self.Process_list_app.append(p.name() +" ("+ str(p.pid) +")")
                        self.Process_list_app_pid.append(p.pid)
                        self.Process_list_app_exe.append('None')
                        self.Process_list_app_name.append(p.name())
                        self.Process_list_app_user.append(p.username())
            if len(self.Process_list_app_name) != self.Process_quantity:
                self.Process_quantity = len(self.Process_list_app_name)
                self.ui.Process_Total_View.setText(str(self.Process_quantity))
                self.Process_sim.setStringList(self.Process_list_app)
                self.ui.Process_list.setModel(self.Process_sim)
        except Exception as e:
            if str(type(e)) == "<class 'psutil.AccessDenied'>":
                print('[Error] Psutil Permission Denied')
            else:
                pyas_bug_log(e)

    def Encryption_Text(self):
        input_text = self.ui.Encryption_Text_input.toPlainText()
        password = self.ui.Encryption_Text_Password_input.text()
        self.encrypt_zh(input_text,password)
    
    def Decrypt_Text(self):
        input_text = self.ui.Encryption_Text_input.toPlainText()
        password = self.ui.Encryption_Text_Password_input.text()
        self.decrypt_zh(input_text,password)

    def encrypt_zh(self,e,e2):
        self.ui.Encryption_Text_output.setText(str(cryptocode.encrypt(e,e2)))

    def decrypt_zh(self,e,e2):
        self.ui.Encryption_Text_output.setText(str(cryptocode.decrypt(e,e2)))

    def Change_Users_Password(self):
        username = self.ui.Change_Users_Password_User_Name_input.text()
        password = self.ui.Change_Users_Password_New_Password_input.text()
        if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要修改用戶密碼嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
            try:
                if password == "":
                    subprocess.call("net user {} {}".format(username,""))
                else:
                    subprocess.call("net user {} {}".format(username,password))
            except Exception as e:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)

    def Internet_location_Query(self):
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            QMessageBox.information(self,self.text_Translate("IP查詢"),self.text_Translate("您的ip地址為:{}").format(s.getsockname()[0]),QMessageBox.Ok)
            s.close()
        except Exception as e:
            pyas_bug_log(e)
            pass

    def reset_network(self):
        if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要重置網路配置嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
            try:
                subprocess.call("netsh winsock reset", shell=True)
                QMessageBox.information(self,self.text_Translate("完成"),self.text_Translate("重置網路配置成功"),QMessageBox.Ok)
            except Exception as e:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)

    def Setting_Back(self):
        self.ui.Navigation_Bar.show()
        self.ui.Setting_widget.hide()

    def Process_list_Menu(self,pos):
        try:
            self.item = self.ui.Process_list.selectedIndexes()
            for i in self.item:
                item = i.row()
                self.pid = self.Process_list_app_pid[item]
                self.exefile = self.Process_list_app_exe[item]
                self.exename = self.Process_list_app_name[item]
            self.Process_popMenu = QMenu()
            self.kill_Process = QAction(self.text_Translate("結束進程"),self)
            self.Process_popMenu.addAction(self.kill_Process)
            ques = self.Process_popMenu.exec_(self.ui.Process_list.mapToGlobal(pos))
            if ques == self.kill_Process:
                for p in psutil.process_iter():
                    if p.pid == self.pid:
                        p.kill()
        except Exception as e:
            pyas_bug_log(e)
            pass

##################################### 實時防護 #####################################
    
    def protect_threading_init_zh(self):
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已開啟"):
            pyasp_remove()
            self.ui.Protection_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{
                border:none;
                background-color:rgba(20,20,20,30);
                border-radius: 15px;}
            QPushButton:hover{
                background-color:rgba(20,20,20,50);}""")
            self.Virus_Scan = 0
            self.ui.State_output.clear()
            now_time = datetime.datetime.now()
            self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + self.text_Translate(' > [提示] 尚未啟用實時防護'))
            QApplication.processEvents()
            self.pause = True
        elif self.ui.Protection_switch_Button.text() == self.text_Translate("已开启"):
            pyasp_remove()
            self.ui.Protection_switch_Button.setText(self.text_Translate("已关闭"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{
                border:none;
                background-color:rgba(20,20,20,30);
                border-radius: 15px;}
            QPushButton:hover{
                background-color:rgba(20,20,20,50);}""")
            self.Virus_Scan = 0
            self.ui.State_output.clear()
            now_time = datetime.datetime.now()
            self.ui.State_output.append(str(now_time.strftime('%Y/%m/%d %H:%M:%S')) + self.text_Translate(' > [提示] 尚未启用实时防护'))
            QApplication.processEvents()
            self.pause = True
        else:
            try:
                self.ui.State_output.clear()
                self.ui.Protection_illustrate.setText(self.text_Translate("正在初始化中，請稍後..."))
                self.pause = False
                QApplication.processEvents()
                threading.Thread(target = self.pyas_protect_init_zh).start()
            except Exception as e:
                QMessageBox.critical(self,self.text_Translate('錯誤'),self.text_Translate('錯誤: ')+str(e),QMessageBox.Ok)

    def pyas_protect_init_zh(self):
        print('[INFO] Start Action (Real-time Protect)')
        try:
            ft = open('Library/PYAS/Temp/PYASP.tmp','w',encoding='utf-8')
            fe = ft.write('')
            ft.close()
        except Exception as e:
            pyas_bug_log(e)
            pass
        try:
            print('[INFO] Reading Viruslist Database')
            with open('Library/PYAE/Hashes/Viruslist.md5','r') as fp:
                rfp = fp.read()
            fp.close()
        except Exception as e:
            pyas_bug_log(e)
        self.Virus_Scan = 1
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已關閉"):
            self.ui.Protection_illustrate.setText(self.text_Translate("啟用該選項可以實時監控進程中的惡意軟體並清除。"))
            self.ui.Protection_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{
                border:none;
                background-color:rgba(20,200,20,100);
                border-radius: 15px;}
            QPushButton:hover{
                background-color:rgba(20,200,20,120);}""")
        else:
            self.ui.Protection_illustrate.setText(self.text_Translate("启用该选项可以实时监控进程中的恶意软件并清除。"))
            self.ui.Protection_switch_Button.setText(self.text_Translate("已开启"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{
                border:none;
                background-color:rgba(20,200,20,100);
                border-radius: 15px;}
            QPushButton:hover{
                background-color:rgba(20,200,20,120);}""")
        while 1:
            if not self.pause:
                if not os.path.isfile('Library/PYAS/Temp/PYASP.tmp'):
                    self.pause = True
                    break
                else:
                    self.Virus_Scan = 1
                    #print('[INFO] Real-time Protect Process Refresh')
                    for p in psutil.process_iter():
                        try:
                            if '' == str(p.exe()):
                                pass
                            elif 'C:\Windows' in str(p.exe()) or 'C:\Program' in str(p.exe()):
                                pass
                            elif 'MemCompression' in str(p.exe()) or 'Registry' in str(p.exe()) or 'PYAS' in str(p.exe()):
                                pass
                            else:
                                if self.pyas_scan_start(p.exe(),rfp):
                                    try:
                                        if subprocess.call('taskkill /f /im "'+str(p.name())+'" /t',shell=True) == 0:
                                            print('[INFO] Malware blocking success: '+str(p.name()))
                                            self.ui.State_output.append(self.text_Translate('{} > [實時防護] 成功攔截了一個惡意軟體:').format(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')))+str(p.name()))
                                        else:
                                            print('[INFO] Malware blocking failed: '+str(p.name()))
                                            self.ui.State_output.append(self.text_Translate('{} > [實時防護] 惡意軟體攔截失敗:').format(datetime.datetime.now())+str(p.name()))
                                        #try:
                                            #observer = Observer()
                                            #observer.schedule(MainWindow_Controller(), os.path.dirname(p.exe()), False)
                                            #observer.start()
                                        #except Exception as e:
                                            #pass
                                        os.remove(str(p.exe()))
                                    except Exception as e:
                                        pyas_bug_log(e)
                                        pass
                        except:
                            continue
            else:
                break

##################################### 系統設置 #####################################

    def ShowMenu(self):
        self.WindowMenu = QMenu()
        Main_Settings = QAction(self.text_Translate("設定"),self)
        Main_About = QAction(self.text_Translate("關於"),self)
        self.WindowMenu.addAction(Main_Settings)
        self.WindowMenu.addAction(Main_About)
        pos = QtCore.QPoint(0, 30)
        Qusetion = self.WindowMenu.exec_(self.ui.Menu_Button.mapToGlobal(pos))
        if Qusetion == Main_About:
            if self.ui.About_widget.isHidden():
                self.ui.About_widget.show()
                self.ui.About_widget.raise_()
                self.ui.Navigation_Bar.raise_()
                self.ui.Window_widget.raise_()
                self.Change_animation_3(self.ui.About_widget,0.5)
                self.Change_animation5(self.ui.About_widget,170,50,671,481)
                self.Setting_Back()
        if Qusetion == Main_Settings:
            if self.ui.Setting_widget.isHidden():
                self.ui.Setting_widget.show()
                self.ui.About_widget.hide()
                self.ui.Setting_widget.raise_()
                self.ui.Window_widget.raise_()
                self.Change_animation_3(self.ui.Setting_widget,0.5)
                self.Change_animation5(self.ui.Setting_widget,10,50,831,481)

    def Show_Virus_Scan_Progress_Bar_switch(self):
        try:
            try:
                self.ini_config = configparser.RawConfigParser()
                self.ini_config.read(r"Library/PYAS/Setup/PYAS.ini")
            except Exception as e:
                pyas_bug_log(e)
                self.ini_config = configparser.RawConfigParser()
                self.ini_config.read(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini")
            try:
                if self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已關閉"):
                    self.ini_config.set("Setting", "high_sensitivity", 1)
                    try:
                        self.ini_config.write(open(r"Library/PYAS/Setup/PYAS.ini", 'w'))
                    except Exception as e:
                        pyas_bug_log(e)
                        self.ini_config.write(open(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini", 'w'))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已開啟"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,200,20,100);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,200,20,120);}""")
                    self.show_virus_scan_progress_bar = 1
                elif self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已关闭"):
                    self.ini_config.set("Setting", "high_sensitivity", 1)
                    try:
                        self.ini_config.write(open(r"Library/PYAS/Setup/PYAS.ini", 'w'))
                    except Exception as e:
                        pyas_bug_log(e)
                        self.ini_config.write(open(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini", 'w'))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已开启"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,200,20,100);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,200,20,120);}""")
                    self.show_virus_scan_progress_bar = 1
                elif self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已开启"):
                    self.ini_config.set("Setting", "high_sensitivity", 0)
                    try:
                        self.ini_config.write(open(r"Library/PYAS/Setup/PYAS.ini", 'w'))
                    except Exception as e:
                        pyas_bug_log(e)
                        self.ini_config.write(open(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini", 'w'))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已关闭"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,20,20,30);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,20,20,50);}""")
                    self.show_virus_scan_progress_bar = 0
                elif self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.text() == self.text_Translate("已開啟"):
                    self.ini_config.set("Setting", "high_sensitivity", 0)
                    try:
                        self.ini_config.write(open(r"Library/PYAS/Setup/PYAS.ini", 'w'))
                    except Exception as e:
                        pyas_bug_log(e)
                        self.ini_config.write(open(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini", 'w'))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已關閉"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,20,20,30);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,20,20,50);}""")
                    self.show_virus_scan_progress_bar = 0
                else:
                    self.ini_config.set("Setting", "high_sensitivity", 0)
                    try:
                        self.ini_config.write(open(r"Library/PYAS/Setup/PYAS.ini", 'w'))
                    except Exception as e:
                        pyas_bug_log(e)
                        self.ini_config.write(open(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini", 'w'))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setText(self.text_Translate("已關閉"))
                    self.ui.Show_Virus_Scan_Progress_Bar_switch_Button.setStyleSheet("""
                    QPushButton{
                        border:none;
                        background-color:rgba(20,20,20,30);
                        border-radius: 15px;}
                    QPushButton:hover{
                        background-color:rgba(20,20,20,50);}""")
                    self.show_virus_scan_progress_bar = 0
            except Exception as e:
                pyas_bug_log(e)
                try:
                    with open(r"Library/PYAS/Setup/PYAS.ini",mode="w",encoding="utf-8") as file:
                        file.write("[Setting]\nhigh_sensitivity = 0\nlanguage = english")
                    file.close()
                except Exception as e:
                    pyas_bug_log(e)
        except Exception as e:
            pyas_bug_log(e)
            pass

##################################### 更改語言 #####################################
    
    def Change_language(self):
        try:
            try:
                self.ini_config = configparser.RawConfigParser()
                self.ini_config.read(r"Library/PYAS/Setup/PYAS.ini")
            except Exception as e:
                pyas_bug_log(e)
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.lang_init_zh_tw()
                self.language = "zh_TW"
                self.ini_config.set("Setting", "language", "zh_TW") 
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.lang_init_zh_cn()
                self.language = "zh_CN"
                self.ini_config.set("Setting", "language", "zh_CN") 
            else:
                self.lang_init_en()
                self.language = "english"
                self.ini_config.set("Setting", "language", "english") 
        except Exception as e:
            pyas_bug_log(e)
        try:
            try:
                self.ini_config.write(open(r"Library/PYAS/Setup/PYAS.ini", 'w'))
            except Exception as e:
                pyas_bug_log(e)
                self.ini_config.write(open(r"C:/Program Files (x86)/PYAS/Library/PYAS/Setup/PYAS.ini", 'w'))
        except Exception as e:
            pyas_bug_log(e)
            pass

##################################### 主題顏色 #####################################
    
    def Change_Theme(self):#UPDhere
        if self.ui.Theme_Red.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(255,140,140,200);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(255,130,130,200);}""")
            return

        elif self.ui.Theme_White.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(240,240,240);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(230,230,230);}""")
            return

        elif self.ui.Theme_Black.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(90,90,90,130);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(80,80,80,150);}""")
            return

        elif self.ui.Theme_Green.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(120,240,130,180);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(100,240,110,200);}""")
            return

        elif self.ui.Theme_Pink.isChecked():
            import random
            r,g,b = random.randrange(50, 250),random.randrange(50, 250),random.randrange(50, 250)
            self.ui.Window_widget.setStyleSheet("""
            QWidget#Window_widget {background-color:rgba("""+str(r)+""","""+str(g)+""","""+str(b)+""",240);}""")
            self.ui.Navigation_Bar.setStyleSheet("""
            QWidget#Navigation_Bar {background-color:rgba("""+str(r-20)+""","""+str(g-20)+""","""+str(b-20)+""",240);}""")
            return

        elif self.ui.Theme_Blue.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(0,120,240,100);}""")
            self.ui.Navigation_Bar.setStyleSheet("""
            QWidget#Navigation_Bar {background-color:rgba(0,120,240,120);}""")
            return
        
##################################### 操作事件 #####################################

    def mousePressEvent(self, event):
        x = event.x()
        y = event.y()
        if event.button()==Qt.LeftButton and x >= 10 and x <= 841 and y >= 10 and y <= 49:
            self.m_flag=True
            self.m_Position=event.globalPos()-self.pos() #獲取鼠標相對窗口的位置
            event.accept()
            while self.ui.pyas_opacity > 60 and self.m_flag == True:
                time.sleep(0.01)
                self.ui.pyas_opacity -= 2
                window.setWindowOpacity(self.ui.pyas_opacity/100)
                QApplication.processEvents()
        
    def mouseMoveEvent(self, QMouseEvent):
        try:
            if Qt.LeftButton and self.m_flag:
                self.move(QMouseEvent.globalPos()-self.m_Position)#更改窗口位置
                QMouseEvent.accept()
        except:
            pass
        
    def mouseReleaseEvent(self, QMouseEvent):
        self.m_flag=False
        self.setCursor(QCursor(Qt.ArrowCursor))
        while self.ui.pyas_opacity < 100 and self.m_flag == False:
            time.sleep(0.01)
            self.ui.pyas_opacity += 2
            window.setWindowOpacity(self.ui.pyas_opacity/100)
            QApplication.processEvents()

    def paintEvent(self, event):
        # 圓角
        pat2 = QPainter(self)
        pat2.setRenderHint(QPainter.Antialiasing)
        pat2.setBrush(Qt.white)
        pat2.setPen(Qt.transparent)
        rect = self.rect()
        rect.setLeft(10)
        rect.setTop(10)
        rect.setWidth(rect.width()-10)
        rect.setHeight(rect.height()-10)
        pat2.drawRoundedRect(rect, 1, 1)

##################################### 主初始化 #####################################

if __name__ == '__main__':
    try:
        pyasb_remove()
        pyasp_remove()
        pyas_library()
        pyas_version = "2.4.8"
        pyae_version = "2.1.9"
        threading.Thread(target = pyas_vl_update).start()
        QtCore.QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)# 自適應窗口縮放
        QtGui.QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)# 自適應窗口縮放
        app = QtWidgets.QApplication(sys.argv)
        window = MainWindow_Controller()
        window.setWindowOpacity(1)
        window.show()
        print('[INFO] PYAS V'+pyas_version+' , PYAE V'+pyae_version)
        print('[LOAD] Total: '+str(time.time()-start_m)+' sec')
        sys.exit(app.exec_())
    except Exception as e:
        pyas_bug_log(e)

####################################################################################
#Copyright© 2020-2022 PYAS Python Antivirus Software.
